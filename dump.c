/* $Id: dump.c,v 1.35 2007/12/29 19:06:49 manu Exp $ */

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
__RCSID("$Id: dump.c,v 1.35 2007/12/29 19:06:49 manu Exp $");
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
#include <sys/stat.h>
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

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

/*
 * The dump_dirty indicates number of changes from the last dump, but
 * inaccurately. This is something like a condition variable. If someone
 * increments dump_dirty, it is ensured that the dumper updates the dump
 * file in future, but not always immediately. Dumping might also occur
 * even though unnecessary.
 */

static pthread_mutex_t dump_todo_lock = PTHREAD_MUTEX_INITIALIZER;
static int dump_todo = 0;
static pthread_cond_t dump_sleepflag;
#define DUMP_TODO_CONF_UPDATE 0x1
#define DUMP_TODO_FLUSH 0x2
#define DUMP_TODO_TERMINATE 0x4

int dump_parse(void);
void dump_dispose_input_file(void);
static pthread_mutex_t dump_dirty_lock = PTHREAD_MUTEX_INITIALIZER;
static int dump_dirty = 0;

static pthread_t dumper_tid;

void
dump_init(void) {
	int error;

	if ((error = pthread_cond_init(&dump_sleepflag, NULL)) != 0) {
		mg_log(LOG_ERR, 
		    "pthread_cond_init failed: %s", strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void
dumper_start(void) {
	int error;

	if ((error = pthread_create(&dumper_tid, NULL, dumper, NULL)) != 0) {
		mg_log(LOG_ERR,
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
	struct conf_rec *confp;
	struct timeval start;

	conf_retain();
	confp = GET_CONF();
	gettimeofday(&start, NULL);
	for (;;) {
		int error;
		int todo;
		
		pthread_mutex_lock(&dump_todo_lock);
		while (dump_todo == 0 ||
		       (confp->c_dumpfreq != 0 &&
			dump_todo == DUMP_TODO_FLUSH)) {
			if (confp->c_dumpfreq > 0) {
				struct timespec timeout;

				timeout.tv_sec = start.tv_sec +
					confp->c_dumpfreq;
				timeout.tv_nsec = start.tv_usec * 1000;
				error = pthread_cond_timedwait(&dump_sleepflag,
							       &dump_todo_lock,
							       &timeout);
			} else {
				error = pthread_cond_wait(&dump_sleepflag,
							  &dump_todo_lock);
			}
			if (error == ETIMEDOUT) {
				break;
			} else if (error != 0) {
				mg_log(LOG_ERR,
				       "pthread_cond_(timed)wait failed: %s",
				       strerror(error));
				abort();
			}
		}
		todo = (dump_todo & DUMP_TODO_CONF_UPDATE) ?
			DUMP_TODO_CONF_UPDATE :
			(dump_todo & DUMP_TODO_TERMINATE) ?
			(DUMP_TODO_FLUSH | DUMP_TODO_TERMINATE):
			DUMP_TODO_FLUSH;
		dump_todo &= ~todo;
		pthread_mutex_unlock(&dump_todo_lock);

		/*
		 * Since following operations require locking, so we do
		 * them outside the above loop.
		 */
		switch (todo) {
			case DUMP_TODO_CONF_UPDATE:
				conf_release();
				conf_retain();
				confp = GET_CONF();
				break;
#ifndef WORKAROUND_LIBMILTER_RACE_CONDITION
			case DUMP_TODO_FLUSH | DUMP_TODO_TERMINATE:
				dump_perform(1);
				break;
#endif
			case DUMP_TODO_FLUSH:
				dump_perform(0);
				gettimeofday(&start, NULL);
				break;
		}
		if (todo & DUMP_TODO_TERMINATE)
			break;
	}
	conf_release();

	return NULL;
}

void
dump_perform(final)
	int final;
{
	FILE *dump;
	int dumpfd;
	struct timeval tv1, tv2, tv3;
	char newdumpfile[MAXPATHLEN + 1];
	int done;
	int greylisted_count;
	int whitelisted_count;
	char *s_buffer = NULL;
	int dirty;

	pthread_mutex_lock(&dump_dirty_lock);
	dirty = dump_dirty;
	dump_dirty = 0;
	pthread_mutex_unlock(&dump_dirty_lock);

	if (final)
		mg_log(LOG_INFO,
		       dirty ? "Final database dump" :
			       "Final database dump: no change to dump");

	/*
	 * If there is no change to dump, go back to sleep
	 */
	if (!dirty)
		return;

	if (conf.c_debug) {
		(void)gettimeofday(&tv1, NULL);
		mg_log(LOG_DEBUG, "dumping %d modifications", 
		    dirty);
	}

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
		mg_log(LOG_ERR, "mkstemp(\"%s\") failed: %s", 
		    newdumpfile, strerror(errno));
		close(dumpfd);
		unlink(newdumpfile);		/* clean up ... */
		exit(EX_OSERR);
	}

	if ((conf.c_dumpfile_mode != -1) &&
	    (fchmod(dumpfd, conf.c_dumpfile_mode) == -1)) {
			mg_log(LOG_ERR, "chmod(\"%s\", 0%o) failed: %s", 
			    newdumpfile, conf.c_dumpfile_mode, strerror(errno));
			close(dumpfd);
			unlink(newdumpfile);		/* clean up ... */
			exit(EX_OSERR);
	}

	errno = 0;
	if ((dump = Fdopen(dumpfd, "w")) == NULL) {
		mg_log(LOG_ERR, "cannot write dumpfile \"%s\": %s", 
		    newdumpfile, 
		    (errno == 0) ? "out of stdio streams" : strerror(errno));
		exit(EX_OSERR);
	}
	
#define BIG_BUFFER	(10 * 1024 * 1024)
	/* XXX TODO: make this configurable */
	if ((s_buffer = calloc(1, BIG_BUFFER + 1)) == NULL) { 
		mg_log(LOG_ERR, "Unable to allocate big buffer for \"%s\": %s "
		    "- continuing with sys default", 
		    newdumpfile, strerror(errno));
	} else {
		setvbuf(dump, s_buffer, _IOFBF, BIG_BUFFER);
	}
	
	dump_header(dump);
	greylisted_count = pending_textdump(dump);
	whitelisted_count = autowhite_textdump(dump);
	done = greylisted_count + whitelisted_count;

	fprintf(dump, "#\n# Summary: %d records, %d greylisted, %d "
	    "whitelisted\n#\n", done, greylisted_count, whitelisted_count);

	Fclose(dump);
	if (s_buffer)
		free(s_buffer);

	if (rename(newdumpfile, conf.c_dumpfile) != 0) {
		mg_log(LOG_ERR, "cannot replace \"%s\" by \"%s\": %s\n",
		    conf.c_dumpfile, newdumpfile, strerror(errno));
		unlink(newdumpfile);		/* clean up ... */
		exit(EX_OSERR);
	}

	if (conf.c_debug) {
		(void)gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		mg_log(LOG_DEBUG, "dumping %d records in %ld.%06lds",
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
	if ((dump = Fopen(conf.c_dumpfile, "r")) == NULL) {
		mg_log(LOG_ERR, "cannot read dumpfile \"%s\"", conf.c_dumpfile);
		mg_log(LOG_ERR, "starting with an empty greylist");
	} else {
		dump_in = dump;
		PENDING_LOCK;
		AUTOWHITE_LOCK;

		dump_parse();
		dump_dispose_input_file();

		AUTOWHITE_UNLOCK;
		PENDING_UNLOCK;
		Fclose(dump);

		/* 
		 * dump_dirty has been bumped on each pending_get call,
		 * whereas there is nothing to flush. Fix that.
		 */
		pthread_mutex_lock(&dump_dirty_lock);
		dump_dirty = 0;
		pthread_mutex_unlock(&dump_dirty_lock);
	}

	return;
}

void
dump_flush(void) {
	int error;

	pthread_mutex_lock(&dump_todo_lock);
	dump_todo |= DUMP_TODO_FLUSH;
	pthread_mutex_unlock(&dump_todo_lock);
	if ((error = pthread_cond_signal(&dump_sleepflag)) != 0) {
		mg_log(LOG_ERR, "cannot wakeup dumper: %s", strerror(error));
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

void
dump_touch(n_modifications)
	int n_modifications;
{
	if (n_modifications) {
		pthread_mutex_lock(&dump_dirty_lock);
		dump_dirty += n_modifications;
		pthread_mutex_unlock(&dump_dirty_lock);
	}

	return;
}

void
dump_conf_changed(void) {
	pthread_mutex_lock(&dump_todo_lock);
	dump_todo |= DUMP_TODO_CONF_UPDATE;
	pthread_mutex_unlock(&dump_todo_lock);
	pthread_cond_signal(&dump_sleepflag);

	return;
}

void
dumper_stop(void) {
	int error;

	pthread_mutex_lock(&dump_todo_lock);
	dump_todo |= DUMP_TODO_TERMINATE;
	pthread_mutex_unlock(&dump_todo_lock);
	pthread_cond_signal(&dump_sleepflag);

	if ((error = pthread_join(dumper_tid, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_join failed: %s",
		    strerror(error));
		exit(EX_OSERR);
	}

	return;
}
