/* $Id: dump.c,v 1.24 2004/10/13 09:35:23 manu Exp $ */

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
__RCSID("$Id: dump.c,v 1.24 2004/10/13 09:35:23 manu Exp $");
#endif
#endif

#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else
#include <sys/queue.h>
#endif 

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <errno.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "conf.h"
#include "sync.h"
#include "dump.h"
#include "autowhite.h"
#include "milter-greylist.h"

pthread_cond_t dump_sleepflag;

int dump_parse(void);
int dump_dirty = 0;

void
dump_init(void) {
	int error;

	if ((error = pthread_cond_init(&dump_sleepflag, NULL)) != 0) {
		syslog(LOG_ERR, 
		    "pthread_cond_init failed: %s", strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void
dumper_start(void) {
	pthread_t tid;
	int error;

	if ((error = pthread_create(&tid, NULL, dumper, NULL)) != 0) {
		syslog(LOG_ERR,
		    "cannot start dumper thread: %s", strerror(error));
		exit(EX_OSERR);
	}
	return;
}
	
/* ARGSUSED0 */
void *
dumper(dontcare) 
	void *dontcare;
{
	int error;
	pthread_mutex_t mutex;

	if ((error = pthread_mutex_init(&mutex, NULL)) != 0) {
		syslog(LOG_ERR, "pthread_mutex_init failed: %s\n",
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_mutex_lock(&mutex)) != 0) {
		syslog(LOG_ERR, "pthread_mutex_lock failed: %s\n", 
		    strerror(error));
		exit(EX_OSERR);
	}

	for (;;) {
		/* XXX Not really dynamically adjustable */
		switch (conf.c_dumpfreq) {
		case -1:
			sleep(DUMPFREQ);
			break;

		case 0:
			if ((error = pthread_cond_wait(&dump_sleepflag, 
			    &mutex)) != 0)
			    syslog(LOG_ERR, "pthread_cond_wait failed: %s\n",
				strerror(error));
			break;

		default:
			sleep(conf.c_dumpfreq);
			break;
		}

		/*
		 * If there is no change to dump, go back to sleep
		 */
		if ((conf.c_dumpfreq == -1) || (dump_dirty == 0))
			continue;

		dump_perform();
	}

	/* NOTREACHED */
	syslog(LOG_ERR, "dumper unexpectedly exitted");
	exit(EX_SOFTWARE);

	return NULL;
}

void
dump_perform(void) {
	FILE *dump;
	int dumpfd;
	struct timeval tv1, tv2, tv3;
	char newdumpfile[MAXPATHLEN + 1];
	int done;
	int greylisted_count;
	int whitelisted_count;

	if (conf.c_debug) {
		(void)gettimeofday(&tv1, NULL);
		syslog(LOG_DEBUG, "dumping %d modifications", 
		    dump_dirty);
	}

	/* 
	 * dump_dirty is not protected by a lock,
	 * hence it could be modified between the 
	 * display and the actual dump. This debug
	 * message does not give an accurate information
	 */
	dump_dirty = 0;

	/* 
	 * Dump the database in a temporary file and 
	 * then replace the old one by the new one.
	 * On decent systems, rename(2) garantees that 
	 * even if the machine crashes, we will not 
	 * loose both files.
	 */
	snprintf(newdumpfile, MAXPATHLEN, 
	    "%s-XXXXXXXX", conf.c_dumpfile);

	if ((dumpfd = mkstemp(newdumpfile)) == -1) {
		syslog(LOG_ERR, "mkstemp(\"%s\") failed: %s", 
		    newdumpfile, strerror(errno));
		exit(EX_OSERR);
	}

	if ((dump = fdopen(dumpfd, "w")) == NULL) {
		syslog(LOG_ERR, "cannot write dumpfile \"%s\": %s", 
		    newdumpfile, strerror(errno));
		exit(EX_OSERR);
	}

	dump_header(dump);
	greylisted_count = pending_textdump(dump);
	whitelisted_count = autowhite_textdump(dump);
	done = greylisted_count + whitelisted_count;

	fprintf(dump, "#\n# Summary: %d records, %d greylisted, %d "
	    "whitelisted\n#\n", done, greylisted_count, whitelisted_count);

	fclose(dump);

	if (rename(newdumpfile, conf.c_dumpfile) != 0) {
		syslog(LOG_ERR, "cannot replace \"%s\" by \"%s\": %s\n",
		    conf.c_dumpfile, newdumpfile, strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug) {
		(void)gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		syslog(LOG_DEBUG, "dumping %d records in %ld.%06lds",
		    done, tv3.tv_sec, tv3.tv_usec);
	}

	return;
}


void
dump_reload(void) {
	FILE *dump;

	/* 
	 * Re-import a saved greylist
	 */
	if ((dump = fopen(conf.c_dumpfile, "r")) == NULL) {
		syslog(LOG_ERR, "cannot read dumpfile \"%s\"", conf.c_dumpfile);
		syslog(LOG_ERR, "starting with an empty greylist");
	} else {
		dump_in = dump;
		PENDING_WRLOCK;
		AUTOWHITE_WRLOCK;
		dump_parse();

		/* 
		 * dump_dirty has been bumped on each pending_get call,
		 * whereas there is nothing to flush. Fix that.
		 */
		dump_dirty = 0;

		AUTOWHITE_UNLOCK;
		PENDING_UNLOCK;
		fclose(dump);
	}

	return;
}

void
dump_flush(void) {
	int error;

	if ((error = pthread_cond_signal(&dump_sleepflag)) != 0) {
		syslog(LOG_ERR, "cannot wakeup dumper: %s", strerror(error));
		exit(EX_SOFTWARE);
	}

	return;
}

void
dump_header(stream)
	FILE *stream;
{
	char textdate[DATELEN + 1];
	struct tm tm;
	time_t t;

	t = time(NULL);
	localtime_r(&t, &tm);
	strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);

	fprintf(stream, "#\n# milter-greylist databases, "
	    "dumped by milter-greylist-%s on %s.\n",
	    PACKAGE_VERSION, textdate);
	fprintf(stream, "# DO NOT EDIT while milter-greylist is running, "
	    "changes will be overwritten.\n#\n");

	return;
}
