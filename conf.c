/* $Id: conf.c,v 1.28 2004/10/11 20:57:42 manu Exp $ */

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
__RCSID("$Id: conf.c,v 1.28 2004/10/11 20:57:42 manu Exp $");
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

#include "autowhite.h"
#include "conf.h"
#include "except.h"
#include "sync.h"
#include "pending.h"
#include "dump.h"
#include "milter-greylist.h"

/* Default configuration */
struct conf defconf;

struct conf conf;

char c_pidfile[PATHLEN + 1];
char c_dumpfile[PATHLEN + 1];
char c_socket[PATHLEN + 1];
char c_user[PATHLEN + 1];
char c_syncaddr[IPADDRSTRLEN + 1];
char c_syncport[NUMLEN + 1];

char *conffile = CONFFILE;
struct timeval conffile_modified;

pthread_rwlock_t conf_lock; 	/* protects conf_update */

void
conf_init(void) {
	int error;

	if ((error = pthread_rwlock_init(&conf_lock, NULL)) != 0) {
		syslog(LOG_ERR, 
		    "pthread_rwlock_init failed: %s", strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void
conf_load(void) 	/* exceptlist must be write-locked */
{
	FILE *stream;
	pthread_t tid;
	pthread_attr_t attr;
	int error;

	/*
	 * Reset the configuration to its default 
	 * (This includes command line flags)
	 */
	memcpy(&conf, &defconf, sizeof(conf));

	/* 
	 * And load the new one
	 */
	if ((stream = fopen(conffile, "r")) == NULL) {
		fprintf(stderr, "cannot open config file %s: %s\n", 
		    conffile, strerror(errno));
		fprintf(stderr, "continuing with no exception list\n");
		return;
	}

	conf_in = stream;

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
	if (conf.c_cold) {
		conf_parse();
		conf.c_cold = 0;
		defconf.c_cold = 0;
	} else {
		if ((error = pthread_attr_init(&attr)) != 0) {
			syslog(LOG_ERR, "pthread_attr_init failed: %s", 
			    strerror(error));
			exit(EX_OSERR);
		}

		if ((error = pthread_attr_setstacksize(&attr, 
		    2 * 1024 * 1024)) != 0) {
			syslog(LOG_ERR, "pthread_attr_setstacksize failed: %s", 
			    strerror(error));
			exit(EX_OSERR);
		}

		if ((error = pthread_create(&tid, &attr, 
		    (void *(*)(void *))conf_parse, NULL)) != 0) {
			syslog(LOG_ERR, "pthread_create failed: %s", 
			    strerror(error));
			exit(EX_OSERR);
		}

		if ((error = pthread_join(tid, NULL)) != 0) {
			syslog(LOG_ERR, "pthread_join failed: %s",
			    strerror(error));
			exit(EX_OSERR);
		}

		if ((error = pthread_attr_destroy(&attr)) != 0) {
			syslog(LOG_ERR, "pthread_attr_destroy failed: %s",
			    strerror(error));
			exit(EX_OSERR);
		}
	}

	fclose(stream);

	(void)gettimeofday(&conffile_modified, NULL);

	return;
}

void
conf_update(void) {
	struct stat st;
	struct timeval tv1, tv2, tv3;
	
	if (stat(conffile, &st) != 0) {
		syslog(LOG_ERR, "config file \"%s\" unavailable", 
		    conffile);
		return;
	}

	/* 
	 * conffile_modified is updated in conf_load()
	 */
	if (st.st_mtime < conffile_modified.tv_sec) 
		return;

	syslog(LOG_INFO, "reloading \"%s\"", conffile);
	if (conf.c_debug)
		(void)gettimeofday(&tv1, NULL);

	peer_clear();
	EXCEPT_WRLOCK;
	except_clear();
	conf_load();
	EXCEPT_UNLOCK;

	if (conf.c_debug) {
		(void)gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		syslog(LOG_DEBUG, "reloaded config file in %ld.%06lds", 
		    tv3.tv_sec, tv3.tv_usec);
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
	c->c_quiet = 0;
	c->c_noauth = 0;
	c->c_nospf = 0;
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
	c->c_socket = NULL;
	c->c_user = NULL;
	c->c_nodetach = 0;
	c->c_report = C_ALL;
	c->c_dumpfreq = DUMPFREQ;
	c->c_timeout = TIMEOUT;

	return;
}
