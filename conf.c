/* $Id: conf.c,v 1.56 2008/09/07 00:13:34 manu Exp $ */

/*
 * Copyright (c) 2004 Emmanuel Dreyfus
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *        This product includes software developed by Emmanuel Dreyfus
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,  
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: conf.c,v 1.56 2008/09/07 00:13:34 manu Exp $");
#endif
#endif

#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <pthread.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>

#include "spf.h"
#include "acl.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#ifdef USE_CURL
#include "urlcheck.h"
#endif
#ifdef USE_LDAP
#include "ldapcheck.h"
#endif
#ifdef USE_DKIM
#include "dkimcheck.h"
#endif
#ifdef USE_P0F
#include "p0f.h"
#endif
#include "autowhite.h"
#include "conf.h"
#include "sync.h"
#include "pending.h"
#include "dump.h"
#include "list.h"
#include "macro.h"
#include "milter-greylist.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

/* #define CONF_DEBUG */

/* Default configuration */
struct conf_rec defconf;
pthread_key_t conf_key;
char *conffile = CONFFILE;
int conf_cold = 1;

#define CONF_LOCK pthread_mutex_lock(&conf_lock);
#define CONF_UNLOCK pthread_mutex_unlock(&conf_lock);
static pthread_mutex_t conf_lock = PTHREAD_MUTEX_INITIALIZER;
static struct conf_list conf_list_head;
static pthread_cond_t conf_update_cond = PTHREAD_COND_INITIALIZER;
static int conf_updating;

void
conf_init(void) {
	int error;

	TAILQ_INIT(&conf_list_head);

	if ((error = pthread_key_create(&conf_key, 0)) != 0) {
		mg_log(LOG_ERR, 
		    "pthread_key_create failed: %s", strerror(error));
		exit(EX_OSERR);
	}

	return;
}

#ifdef CONF_DEBUG
static void
conf_dump(void) {
	struct conf_rec *c;

	TAILQ_FOREACH_REVERSE(c, &conf_list_head, conf_list, c_chain) {
		char textdate[DATELEN];
		struct tm tm;

		localtime_r(&c->c_timestamp, &tm);
		strftime(textdate, sizeof textdate, "%Y-%m-%d %T",  &tm);
		mg_log(LOG_DEBUG, "conf_dump: stamp %s ref %d",
			   textdate, c->c_refcount);
	}
}
#endif /* CONF_DEBUG */

static void *
conf_load_internal(timestamp)
	void *timestamp;
{
	FILE *stream;
	struct timeval tv1, tv2, tv3;
	struct conf_rec *currconf, *threadconf, *newconf;

	CONF_LOCK;
	currconf = TAILQ_FIRST(&conf_list_head);
	CONF_UNLOCK;
	assert(conf_cold ? (currconf == NULL) : (currconf != NULL));
	threadconf = GET_CONF();

	if (!(newconf = (struct conf_rec *)malloc(sizeof *newconf))) {
		mg_log(LOG_ERR, "conf malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	/*
	 * Reset the configuration to its default 
	 * (This includes command line flags)
	 */
	memcpy(newconf, &defconf, sizeof *newconf);
	newconf->c_refcount = 1;
	newconf->c_timestamp = *(time_t *)timestamp;

	(void)gettimeofday(&tv1, NULL);

	if (!conf_cold || newconf->c_debug)
		mg_log(LOG_INFO, "%sloading config file \"%s\"", 
		    conf_cold ? "" : "re", conffile);

	errno = 0;
	if ((stream = Fopen(conffile, "r")) == NULL) {
		mg_log(LOG_ERR, "cannot open config file %s: %s", 
		    conffile, 
		    (errno == 0) ? "out of stdio streams" : strerror(errno));

		if (conf_cold)
			exit(EX_OSERR);
	} else {
		TSS_SET(conf_key, newconf);

		peer_clear();
		ACL_WRLOCK;
#ifdef USE_DNSRBL
		dnsrbl_clear();
#endif
#ifdef USE_CURL
		urlcheck_clear();
#endif
#ifdef USE_LDAP
		ldapcheck_clear();
#endif
#ifdef USE_DKIM
		dkimcheck_clear();
#endif
#ifdef USE_P0F
		p0f_clear();
#endif
		all_list_clear();
		macro_clear();
		acl_clear();

		conf_in = stream;
		conf_line = 1;
		conf_acl_end = 0;
		conf_racl_end = 0;
		conf_dacl_end = 0;

		conf_parse();
		conf_dispose_input_file();
		ACL_UNLOCK;

		TSS_SET(conf_key, threadconf);

		Fclose(stream);

		if (!conf_cold || newconf->c_debug) {
			(void)gettimeofday(&tv2, NULL);
			timersub(&tv2, &tv1, &tv3);
			mg_log(LOG_INFO,
			    "%sloaded config file \"%s\" in %ld.%06lds", 
			    conf_cold ? "" : "re", conffile, 
			    tv3.tv_sec, tv3.tv_usec);
		}
	}

	/*
	 * Dump the ACL for debugging purposes
	 */
	if (newconf->c_debug || newconf->c_acldebug)
		acl_dump();

	CONF_LOCK;
	assert(TAILQ_FIRST(&conf_list_head) == currconf);
	if (currconf && --currconf->c_refcount == 0) {
		TAILQ_REMOVE(&conf_list_head, currconf, c_chain);
		free(currconf);
	}
	TAILQ_INSERT_HEAD(&conf_list_head, newconf, c_chain);
	CONF_UNLOCK;

#ifdef CONF_DEBUG
	conf_dump();
#endif
	dump_conf_changed();
	return NULL;
}

/* Functions other than main() must not invoke this */
void
conf_load(void) {
	struct stat st;

	if (stat(conffile, &st))
		st.st_mtime = (time_t)0;
	conf_load_internal(&st.st_mtime);
}

void
conf_update(void) {
	struct stat st;
	pthread_t tid;
	pthread_attr_t attr;
	int error;
	int need_update;
	
	if (stat(conffile, &st) != 0) {
		mg_log(LOG_ERR, "config file \"%s\" unavailable", 
		    conffile);
		return;
	}

	CONF_LOCK;
	while (conf_updating)
		pthread_cond_wait(&conf_update_cond, &conf_lock);
	conf_updating = need_update =
		st.st_mtime > TAILQ_FIRST(&conf_list_head)->c_timestamp;
	CONF_UNLOCK;

	if (!need_update)
		return;

	/*
	 * On some platforms, the thread stack limit is too low and
	 * conf_parse will get a SIGSEGV because it overflows the
	 * stack.
	 *
	 * In order to fix this, we spawn a new thread just for 
	 * parsing the config file, and we request a stack big 
	 * enough to hold the parser data. 2 MB seems okay.
	 *
	 * We do not do that during the initial config load because
	 * it is useless and it will trigger a bug on some systems
	 * (launching a thread before a fork seems to be a problem)
	 */
	if ((error = pthread_attr_init(&attr)) != 0) {
		mg_log(LOG_ERR, "pthread_attr_init failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_attr_setstacksize(&attr, 
	    2 * 1024 * 1024)) != 0) {
		mg_log(LOG_ERR, "pthread_attr_setstacksize failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_create(&tid, &attr, 
	    conf_load_internal, &st.st_mtime)) != 0) {
		mg_log(LOG_ERR, "pthread_create failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_attr_destroy(&attr)) != 0) {
		mg_log(LOG_ERR, "pthread_attr_destroy failed: %s",
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_join(tid, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_join failed: %s",
		    strerror(error));
		exit(EX_OSERR);
	}

	CONF_LOCK;
	conf_updating = 0;
	CONF_UNLOCK;
	if ((error = pthread_cond_broadcast(&conf_update_cond)) != 0) {
		mg_log(LOG_ERR, "pthread_cond_broadcast failed: %s", 
		       strerror(error));
		abort();
	}

	return;
}

void
conf_retain(void) {
	struct conf_rec *c;

	if (GET_CONF()) {
		mg_log(LOG_ERR, "%s:%d BUG: conf_retain called twice?",
				__FILE__, __LINE__);
		assert(0);
	}

	CONF_LOCK;
	c = TAILQ_FIRST(&conf_list_head);
#ifdef CONF_DEBUG
	{
		char textdate[DATELEN];
		struct tm tm;
		
		localtime_r(&c->c_timestamp, &tm);
		strftime(textdate, sizeof textdate, "%Y-%m-%d %T",  &tm);
		mg_log(LOG_DEBUG, "conf_retain: stamp %s ref %d -> %d",
		       textdate, c->c_refcount, c->c_refcount + 1);
	}
#endif
	++c->c_refcount;
	CONF_UNLOCK;

	TSS_SET(conf_key, c);
}

void
conf_release(void) {
	struct conf_rec *c = GET_CONF();

	if (!c) {
		mg_log(LOG_ERR, "%s:%d BUG: conf_release before conf_retain",
				__FILE__, __LINE__);
		assert(0);
		return;
	}

	CONF_LOCK;
#ifdef CONF_DEBUG
	{
		char textdate[DATELEN];
		struct tm tm;
		
		localtime_r(&c->c_timestamp, &tm);
		strftime(textdate, sizeof textdate, "%Y-%m-%d %T",  &tm);
		mg_log(LOG_DEBUG, "conf_release: stamp %s ref %d -> %d",
		       textdate, c->c_refcount, c->c_refcount - 1);
	}
#endif
	if (--c->c_refcount == 0) {
		TAILQ_REMOVE(&conf_list_head, c, c_chain);
		free(c);
	}
	CONF_UNLOCK;

	TSS_SET(conf_key, NULL);
}

/*
 * Write path into dst, stripping leading and trailing quotes
 */
char *
quotepath(dst, path, len)
	char *dst;
	char *path;
	size_t len;
{
	path++;	/* strip first quote */
	strncpy(dst, path, len);
	dst[len] = '\0';

	/* Strip trailing quote */
	if ((len = strlen(dst)) > 0)
		dst[len - 1] = '\0';

	return dst;
}

void
conf_defaults(c)
	struct conf_rec *c;
{
	c->c_refcount = -1;
	c->c_timestamp = (time_t)0;

	c->c_forced = C_GLNONE;
	c->c_debug = 0;
	c->c_acldebug = 0;
	c->c_quiet = 0;
	c->c_noauth = 0;
	c->c_noaccessdb = 0;
	c->c_nospf = 0;
	c->c_delayedreject = 0;
	c->c_testmode = 0;
	c->c_delay = GLDELAY;
	c->c_autowhite_validity = AUTOWHITE_VALIDITY;
	c->c_pidfile = NULL;
	c->c_dumpfile = DUMPFILE;
	c->c_dumpfile_mode = -1;
	prefix2mask4(32, &c->c_match_mask);
#ifdef AF_INET6
	prefix2mask6(128, &c->c_match_mask6);
#endif
	c->c_syncaddr = NULL;
	c->c_syncport = NULL;
	c->c_syncsrcaddr = NULL;
	c->c_syncsrcport = NULL;
	c->c_socket = NULL;
	c->c_socket_mode = -1;
	c->c_user = NULL;
	c->c_nodetach = 0;
	c->c_report = C_ALL;
	c->c_dumpfreq = DUMPFREQ;
	c->c_timeout = TIMEOUT;
	c->c_extendedregex = 0;
	c->c_dracdb = DRACDB;
	c->c_nodrac = 0;
	c->c_maxpeek = 0;
#ifdef USE_DKIM
	c->c_dkim = NULL;
#endif
#ifdef USE_P0F
	c->c_p0fsock[0] = '\0';
#endif
	return;
}
