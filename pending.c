/* $Id: pending.c,v 1.48.2.1 2004/05/06 13:54:01 manu Exp $ */

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
__RCSID("$Id: pending.c,v 1.48.2.1 2004/05/06 13:54:01 manu Exp $");
#endif
#endif

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <sysexits.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "sync.h"
#include "dump.h"
#include "conf.h"
#include "pending.h"
#include "autowhite.h"
#include "milter-greylist.h"

struct pendinglist pending_head;
pthread_rwlock_t pending_lock; 	/* protects pending_head and dump_dirty */

void
pending_init(void) {

	TAILQ_INIT(&pending_head);
	pthread_rwlock_init(&pending_lock, NULL);

	return;
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
	int delay = conf.c_delay;

	if ((pending = malloc(sizeof(*pending))) == NULL)
		goto out;

	bzero((void *)pending, sizeof(pending));

	if (date == 0) {
		gettimeofday(&pending->p_tv, NULL);
		pending->p_tv.tv_sec += delay;
	} else {
		pending->p_tv.tv_sec = date;
	}

	pending->p_in.s_addr = in->s_addr;
	inet_ntop(AF_INET, in, pending->p_addr, IPADDRLEN);
	strncpy(pending->p_from, from, ADDRLEN);
	pending->p_from[ADDRLEN] = '\0';
	strncpy(pending->p_rcpt, rcpt, ADDRLEN);
	pending->p_rcpt[ADDRLEN] = '\0';
	TAILQ_INSERT_TAIL(&pending_head, pending, p_list); 

	if (conf.c_debug)
		dump_dirty++;

	(void)gettimeofday(&tv, NULL);

	if (conf.c_debug) {
		syslog(LOG_DEBUG, "created: %s from %s to %s delayed for %lds",
		    pending->p_addr, pending->p_from, pending->p_rcpt, 
		    pending->p_tv.tv_sec - tv.tv_sec);
	}
out:
	return pending;
}

void
pending_put(pending) /* pending list should be write-locked */
	struct pending *pending;
{
	if (conf.c_debug) {
		syslog(LOG_DEBUG, "removed: %s from %s to %s",
		    pending->p_addr, pending->p_from, pending->p_rcpt);
	}

	TAILQ_REMOVE(&pending_head, pending, p_list);	
	free(pending);

	if (conf.c_debug)
		dump_dirty++;

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
	struct pending *prev_pending = NULL;
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
			break;
		}

		/*
		 * Check for expired entries 
		 */
		if (tv.tv_sec - pending->p_tv.tv_sec > TIMEOUT) {
			if (conf.c_debug) {
				syslog(LOG_DEBUG, 
				    "del: %s from %s to %s timed out", 
				    pending->p_addr, pending->p_from, 
				    pending->p_rcpt);
			}

			pending_put(pending);

			if (TAILQ_EMPTY(&pending_head))
				break;
			if ((pending = prev_pending) == NULL)
				pending = TAILQ_FIRST(&pending_head);
			continue;
		}
		prev_pending = pending;
	}
	PENDING_UNLOCK;
	return;
}

int
pending_check(in, from, rcpt, remaining, elapsed, queueid)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t *remaining;
	time_t *elapsed;
	char *queueid;
{
	char addr[IPADDRLEN + 1];
	struct pending *pending;
	struct pending *prev_pending = NULL;
	struct timeval tv;
	time_t rest = -1;
	int dirty = 0;
	int delay = conf.c_delay;

	gettimeofday(&tv, NULL);
	(void)inet_ntop(AF_INET, in, addr, IPADDRLEN);

	PENDING_WRLOCK;	/* XXX take a read lock and upgrade */
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		/*
		 * Look for our entry.
		 */
		if ((IP_MATCH(&pending->p_in, in)) &&
		    (strncmp(from, pending->p_from, ADDRLEN) == 0) &&
		    (strncmp(rcpt, pending->p_rcpt, ADDRLEN) == 0)) {
			rest = (time_t)(pending->p_tv.tv_sec - tv.tv_sec);

			if (rest < 0) {
				peer_delete(pending);
				pending_put(pending);
				autowhite_add(in, from, rcpt, NULL, queueid);
				rest = 0;
				dirty = 1;
			}

			goto out;
		}

		/*
		 * Check for expired entries 
		 */
		if (tv.tv_sec - pending->p_tv.tv_sec > TIMEOUT) {
			if (conf.c_debug) {
				syslog(LOG_DEBUG, 
				    "check: %s from %s to %s timed out", 
				    pending->p_addr, pending->p_from, 
				    pending->p_rcpt);
			}

			pending_put(pending);
			dirty = 1;

			if (TAILQ_EMPTY(&pending_head))
				break;
			if ((pending = prev_pending) == NULL)
				pending = TAILQ_FIRST(&pending_head);
			continue;
		}
		prev_pending = pending;
	}

	/* 
	 * It was not found. Create it and propagagte it to peers.
	 * Error handling is useless here, we will tempfail anyway
	 */
	pending = pending_get(in, from, rcpt, (time_t)0);
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
		dump_flush();

	if (rest == 0)
		return 1;
	else
		return 0;
}

int
pending_textdump(stream)
	FILE *stream;
{
	struct pending *pending;
	int done = 0;
	char textdate[DATELEN + 1];
	struct tm tm;

	fprintf(stream, "\n\n#\n# greylisted tuples\n#\n");
	fprintf(stream, "# Sender IP	%32s	%32s	Time accepted\n", 
	    "Sender e-mail", "Recipient e-mail");

	PENDING_RDLOCK;
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		localtime_r((time_t *)&pending->p_tv.tv_sec, &tm);
		strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);

		fprintf(stream, "%s	%32s	%32s	%ld # %s\n", 
		    pending->p_addr, pending->p_from, 
		    pending->p_rcpt, (long)pending->p_tv.tv_sec, textdate);
		
		done++;
	}
	PENDING_UNLOCK;

	return done;
}

