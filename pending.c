/* $Id: pending.c,v 1.28 2004/03/16 16:47:51 manu Exp $ */

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

#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: pending.c,v 1.28 2004/03/16 16:47:51 manu Exp $");
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <errno.h>
#include <sysexits.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "sync.h"
#include "pending.h"
#include "milter-greylist.h"

struct pendinglist pending_head;
int pending_dirty;
pthread_rwlock_t pending_lock; 	/* protects pending_head and pending_dirty */
pthread_cond_t dump_sleepflag;

int delay = DELAY;
char *dumpfile = DUMPFILE;
int dump_parse(void);

int
pending_init(void) {
	int error;

	TAILQ_INIT(&pending_head);

	if ((error = pthread_rwlock_init(&pending_lock, NULL)) == 0)
		return error;

	if ((error = pthread_cond_init(&dump_sleepflag, NULL)) == 0)
		return error;

	return 0;
}


struct pending *
pending_get(in, from, rcpt, date)  /* pending_lock must be write-locked */
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t date;
{
	struct pending *pending;
	struct timeval tv;

	if ((pending = malloc(sizeof(*pending))) == NULL)
		goto out;

	bzero(pending, sizeof(pending));

	if (date == 0) {
		gettimeofday(&pending->p_tv, NULL);
		pending->p_tv.tv_sec += delay;
	} else {
		pending->p_tv.tv_sec = date;
	}

	inet_ntop(AF_INET, in, pending->p_addr, IPADDRLEN);
	strncpy(pending->p_from, from, ADDRLEN);
	pending->p_from[ADDRLEN] = '\0';
	strncpy(pending->p_rcpt, rcpt, ADDRLEN);
	pending->p_rcpt[ADDRLEN] = '\0';
	TAILQ_INSERT_TAIL(&pending_head, pending, p_list); 

	if (debug)
		pending_dirty++;

	(void)gettimeofday(&tv, NULL);
	syslog(LOG_INFO, "created: %s from %s to %s, delayed for %ld s",
	    pending->p_addr, pending->p_from, pending->p_rcpt, 
	    pending->p_tv.tv_sec - tv.tv_sec);

out:
	return pending;
}

void
pending_put(pending) /* pending list should be write-locked */
	struct pending *pending;
{
	syslog(LOG_INFO, "removed: %s from %s to %s",
	    pending->p_addr, pending->p_from, pending->p_rcpt);
	TAILQ_REMOVE(&pending_head, pending, p_list);	
	free(pending);

	if (debug)
		pending_dirty++;

	return;
}

void
pending_del(in, from, rcpt, time)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t time;
{
	char addr[IPADDRLEN + 1];
	struct pending *pending;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	(void)inet_ntop(AF_INET, in, addr, IPADDRLEN);

	PENDING_WRLOCK;	/* XXX take it as read and upgrade it */
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		/*
		 * Look for our entry.
		 */
		if ((strncmp(addr, pending->p_addr, IPADDRLEN) == 0) &&
		    (strncmp(from, pending->p_from, ADDRLEN) == 0) &&
		    (strncmp(rcpt, pending->p_rcpt, ADDRLEN) == 0) &&
		    (pending->p_tv.tv_sec == time)) {
			pending_put(pending);
			goto out;
		}

		/*
		 * Check for expired entries 
		 */
		if (tv.tv_sec - pending->p_tv.tv_sec > TIMEOUT) {
			syslog(LOG_INFO, "del: %s from %s to %s timed out", 
			    pending->p_addr, pending->p_from, pending->p_rcpt);
			pending_put(pending);
		}
	}
out:
	PENDING_UNLOCK;
	return;
}

int
pending_check(in, from, rcpt, remaining, elapsed)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t *remaining;
	time_t *elapsed;
{
	char addr[IPADDRLEN + 1];
	struct pending *pending;
	struct timeval tv;
	time_t rest = -1;
	int dirty = 0;

	gettimeofday(&tv, NULL);
	(void)inet_ntop(AF_INET, in, addr, IPADDRLEN);

	PENDING_WRLOCK;	/* XXX take a read lock and upgrade */
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		/*
		 * Look for our entry.
		 */
		if ((strncmp(addr, pending->p_addr, IPADDRLEN) == 0) &&
		    (strncmp(from, pending->p_from, ADDRLEN) == 0) &&
		    (strncmp(rcpt, pending->p_rcpt, ADDRLEN) == 0)) {
			rest = (time_t)(pending->p_tv.tv_sec - tv.tv_sec);

			syslog(LOG_DEBUG, "got the entry");
			if (rest < 0) {
				peer_delete(pending);
				pending_put(pending);
				rest = 0;
				dirty = 1;
			}

			goto out;
		}

		/*
		 * Check for expired entries 
		 */
		if (tv.tv_sec - pending->p_tv.tv_sec > TIMEOUT) {
			syslog(LOG_INFO, "check: %s from %s to %s timed out", 
			    pending->p_addr, pending->p_from, pending->p_rcpt);
			pending_put(pending);
			dirty = 1;
		}
	}

	/* 
	 * It was not found. Create it and propagagte it to peers.
	 * Error handling is useless here, we will tempfail anyway
	 */
	pending = pending_get(in, from, rcpt, 0);
	peer_create(pending);
	rest = delay;
	dirty = 1;

out:
	PENDING_UNLOCK;

	if (remaining != NULL)
		*remaining = rest; 

	if (elapsed != NULL)
		*elapsed = (time_t)(tv.tv_sec - (pending->p_tv.tv_sec - delay));

	if (dirty)
		pending_flush();

	if (rest == 0)
		return 1;
	else
		return 0;
}

#define DATELEN	40
int
pending_textdump(stream)
	FILE *stream;
{
	struct pending *pending;
	struct timeval tv;
	char textdate[DATELEN + 1];
	int done = 0;

	gettimeofday(&tv, NULL);
	strftime(textdate, DATELEN, "%Y-%m-%d %T",
	    localtime((time_t *)&tv.tv_sec));

	fprintf(stream, "#\n# Greylist database, "
	    "dumped by milter-greylist-%s on %s.\n",
	    PACKAGE_VERSION, textdate);
	fprintf(stream, "# DO NOT EDIT while milter-greylist is running, "
	    "changes will be overwritten.\n#\n\n");
	fprintf(stream, "# Sender IP	%32s	%32s	Time accepted\n", 
	    "Sender e-mail", "Recipient e-mail");

	PENDING_RDLOCK;
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		strftime(textdate, DATELEN, "%Y-%m-%d %T", 
		    localtime((time_t *)&pending->p_tv.tv_sec));

		fprintf(stream, "%s	%32s	%32s	%ld # %s\n", 
		    pending->p_addr, pending->p_from, 
		    pending->p_rcpt, pending->p_tv.tv_sec, textdate);
		
		done++;
	}
	PENDING_UNLOCK;

	return done;
}

void
pending_dumper_start(void) {
	pthread_t tid;

	if (pthread_create(&tid, NULL, (void *)pending_dumper, NULL) != 0) {
		syslog(LOG_ERR, 
		    "cannot start dumper thread: %s", strerror(errno));
		exit(EX_OSERR);
	}
	return;
}
	
void
pending_dumper(dontcare) 
	void *dontcare;
{
	FILE *dump;
	int dumpfd;
	struct timeval tv1, tv2, tv3;
	pthread_mutex_t mutex;
	char newdumpfile[MAXPATHLEN + 1];
	int error;
	int done;

	if (pthread_mutex_init(&mutex, NULL) != 0) {
		syslog(LOG_ERR, "pthread_mutex_init failed: %s\n",
		    strerror(errno));
		exit(EX_OSERR);
	}

	while (1) {
		if ((error = pthread_cond_wait(&dump_sleepflag, &mutex)) != 0)
		    syslog(LOG_ERR, "pthread_cond_wait failed: %s\n",
			strerror(errno));

		if (debug) {
			(void)gettimeofday(&tv1, NULL);
			syslog(LOG_DEBUG, "dumping %d modifications", 
			    pending_dirty);
			/* 
			 * pending_dirty is not protected by a lock,
			 * hence it could be modified between the 
			 * display and the actual dump. This debug
			 * message does not give an accurate information
			 */
			pending_dirty = 0;
		}

		/* 
		 * Dump the database in a temporary file and 
		 * then replace the old one by the new one.
		 * On decent systems, rename(2) garantees that 
		 * even if the machine crashes, we will not 
		 * loose both files.
		 */
		snprintf(newdumpfile, MAXPATHLEN, "%s-XXXXXXXX", dumpfile);

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

		done = pending_textdump(dump);
		fclose(dump);
		if (rename(newdumpfile, dumpfile) != 0) {
			syslog(LOG_ERR, "cannot replace \"%s\" by \"%s\": %s\n",
			    dumpfile, newdumpfile, strerror(errno));
			exit(EX_OSERR);
		}

		if (debug) {
			(void)gettimeofday(&tv2, NULL);
			timersub(&tv2, &tv1, &tv3);
			syslog(LOG_DEBUG, "dumping %d records in %ld.%06lds",
			    done, tv3.tv_sec, tv3.tv_usec);
		}

	}

	/* NOTREACHED */
	syslog(LOG_ERR, "pending_dumper unexpectedly exitted");
	exit(EX_SOFTWARE);

	return;
}

void
pending_reload(void) {
	FILE *dump;

	/* 
	 * Re-import a saved greylist
	 */
	if ((dump = fopen(dumpfile, "r")) == NULL) {
		syslog(LOG_ERR, "cannot read dumpfile \"%s\"", dumpfile);
		syslog(LOG_ERR, "starting with an empty greylist");
	} else {
		dump_in = dump;
		PENDING_WRLOCK;
		dump_parse();

		/* 
		 * pending_dirty has been bumped on each pending_get call,
		 * whereas there is nothing to flush. Fix that.
		 */
		pending_dirty = 0;

		PENDING_UNLOCK;
		fclose(dump);
	}

	return;
}

void
pending_flush(void) {
	int error; 

	if ((error = pthread_cond_signal(&dump_sleepflag)) != 0) {
		syslog(LOG_ERR, "cannot wakeup dumper: %s", strerror(errno));
		exit(EX_SOFTWARE);
	}

	return;
}
