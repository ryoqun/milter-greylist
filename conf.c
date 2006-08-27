/* $Id: conf.c,v 1.39 2006/08/27 20:54:40 manu Exp $ */

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
__RCSID("$Id: conf.c,v 1.39 2006/08/27 20:54:40 manu Exp $");
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

#include "acl.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#include "autowhite.h"
#include "conf.h"
#include "sync.h"
#include "pending.h"
#include "dump.h"
#include "milter-greylist.h"

/* Default configuration */
struct conf defconf;

struct conf conf;

char c_pidfile[QSTRLEN + 1];
char c_dumpfile[QSTRLEN + 1];
char c_socket[QSTRLEN + 1];
char c_user[QSTRLEN + 1];
char c_syncaddr[IPADDRSTRLEN + 1];
char c_syncport[NUMLEN + 1];
char c_syncsrcaddr[IPADDRSTRLEN + 1];
char c_syncsrcport[NUMLEN + 1];
char c_dracdb[QSTRLEN + 1];

char *conffile = CONFFILE;
struct timeval conffile_modified;
int numb_of_conf_update_threads;

#define MAX_NUMB_OF_CONF_UPDATE_THREADS 1
/*
 * this lock does not protect conf_update any more,
 * only conffile_modified and numb_of_conf_update_threads.
 * there are lot of non-auto variables above to protect as well,
 * so it is safer to limit the maximum number of configuration loading
 * processes to one for the time being.
 */
pthread_rwlock_t conf_lock;

void
conf_init(void) {
	int error;

	if ((error = pthread_rwlock_init(&conf_lock, NULL)) != 0) {
		mg_log(LOG_ERR, 
		    "pthread_rwlock_init failed: %s", strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void
conf_load(void)
{
	FILE *stream;
	struct timeval tv1, tv2, tv3;

	/*
	 * Reset the configuration to its default 
	 * (This includes command line flags)
	 */
	memcpy(&conf, &defconf, sizeof(conf));

	(void)gettimeofday(&tv1, NULL);

	if ((stream = fopen(conffile, "r")) == NULL) {
		mg_log(LOG_ERR, "cannot open config file %s: %s", 
		    conffile, strerror(errno));
		mg_log(LOG_ERR, "continuing with no exception list");
	} else {

		peer_clear();
		ACL_WRLOCK;
#ifdef USE_DNSRBL
		dnsrbl_clear();
#endif
		acl_clear();

		conf_in = stream;
		conf_line = 1;

		conf_parse();
		ACL_UNLOCK;

		fclose(stream);

		(void)gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		mg_log(LOG_DEBUG, "%sloaded config file in %ld.%06lds", 
		    conf.c_cold ? "" : "re", tv3.tv_sec, tv3.tv_usec);
	}

	if (conf.c_cold) {
		(void)gettimeofday(&conffile_modified, NULL);
	} else {
		CONF_WRLOCK;
		--numb_of_conf_update_threads;
		CONF_UNLOCK;
	}

	if (conf.c_debug || conf.c_acldebug)
		acl_dump();

	return;
}

void
conf_update(void) {
	struct stat st;
	pthread_t tid;
	pthread_attr_t attr;
	int error;
	
	if (stat(conffile, &st) != 0) {
		mg_log(LOG_ERR, "config file \"%s\" unavailable", 
		    conffile);
		return;
	}

	CONF_WRLOCK;
	numb_of_conf_update_threads++;
	if (st.st_mtime <= conffile_modified.tv_sec ||
		numb_of_conf_update_threads > MAX_NUMB_OF_CONF_UPDATE_THREADS) {
		--numb_of_conf_update_threads;
		CONF_UNLOCK;
		return;
	}
	conffile_modified.tv_sec = st.st_mtime;
	CONF_UNLOCK;

	mg_log(LOG_INFO, "reloading \"%s\"", conffile);

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
	    (void *(*)(void *))conf_load, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_create failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_detach(tid)) != 0) {
		mg_log(LOG_ERR, "pthread_detach failed: %s",
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_attr_destroy(&attr)) != 0) {
		mg_log(LOG_ERR, "pthread_attr_destroy failed: %s",
		    strerror(error));
		exit(EX_OSERR);
	}

	return;
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
	struct conf *c;
{
	c->c_cold = 1;
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
	prefix2mask4(32, &c->c_match_mask);
#ifdef AF_INET6
	prefix2mask6(128, &c->c_match_mask6);
#endif
	c->c_syncaddr = NULL;
	c->c_syncport = NULL;
	c->c_syncsrcaddr = NULL;
	c->c_syncsrcport = NULL;
	c->c_socket = NULL;
	c->c_user = NULL;
	c->c_nodetach = 0;
	c->c_report = C_ALL;
	c->c_dumpfreq = DUMPFREQ;
	c->c_timeout = TIMEOUT;
	c->c_extendedregex = 0;
	c->c_dracdb = DRACDB;
	c->c_nodrac = 0;

	return;
}
