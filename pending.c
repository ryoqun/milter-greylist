/* $Id: pending.c,v 1.1.1.1 2004/02/21 00:01:17 manu Exp $ */

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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sysexits.h>
#include <syslog.h>

#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "pending.h"

extern int debug;

struct pendinglist pending_head;
pthread_rwlock_t pending_lock;
int delay = DELAY;

#define PENDING_WRLOCK if (pthread_rwlock_wrlock(&pending_lock) != 0) {	\
		syslog(LOG_ERR, "%s:%d pthread_rwlock_wrlock failed\n",	\
		    __FILE__, __LINE__);				\
		exit(EX_SOFTWARE);					\
	}
#define PENDING_RDLOCK if (pthread_rwlock_rdlock(&pending_lock) != 0) {	\
		syslog(LOG_ERR, "%s:%d pthread_rwlock_rdlock failed\n",	\
		    __FILE__, __LINE__);				\
		exit(EX_SOFTWARE);					\
	}
#define PENDING_UNLOCK if (pthread_rwlock_unlock(&pending_lock) != 0) {	\
		syslog(LOG_ERR, "%s:%d pthread_rwlock_unlock failed\n",	\
		    __FILE__, __LINE__);				\
		exit(EX_SOFTWARE);					\
	}

int
pending_init(void) {
	int error;

	TAILQ_INIT(&pending_head);
	if ((error = pthread_rwlock_init(&pending_lock, NULL)) == NULL)
		return error;

	return 0;
}


struct pending *
pending_get(addr, in, from, rcpt, date)  /* pending_lock must be write-locked */
	char *addr;
	struct in_addr *in;
	char *from;
	char *rcpt;
	long date;
{
	struct pending *pending;

	if ((pending = malloc(sizeof(*pending))) == NULL)
		goto out;

	bzero(pending, sizeof(pending));

	if (date == 0) {
		gettimeofday(&pending->p_tv, NULL);
		pending->p_tv.tv_sec += delay;
	} else {
		pending->p_tv.tv_sec = date;
	}

	strncpy(pending->p_addr, addr, IPADDRLEN);
	strncpy(pending->p_from, from, ADDRLEN);
	strncpy(pending->p_rcpt, rcpt, ADDRLEN);
	TAILQ_INSERT_TAIL(&pending_head, pending, p_list); 

	syslog(LOG_INFO, "created: %s from %s to %s, delayed for %ld s\n",
	    pending->p_addr, pending->p_from, pending->p_rcpt, (long)delay);

out:
	return pending;
}

void
pending_put(pending) /* pending list should be write-locked */
	struct pending *pending;
{
	syslog(LOG_INFO, "removed: %s from %s to %s, delayed for %ld s\n",
	    pending->p_addr, pending->p_from, 
	    pending->p_rcpt, pending->p_tv.tv_sec);
	TAILQ_REMOVE(&pending_head, pending, p_list);	
	free(pending);

	return;
}

void
pending_log(pending)
	struct pending *pending;
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	syslog(LOG_INFO, "log: %s from %s to %s, delayed for %ld s\n",
	    pending->p_addr, pending->p_from, 
	    pending->p_rcpt, pending->p_tv.tv_sec - tv.tv_sec);

	return;
}


void
pending_purge(void) {
	struct pending *pending;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	PENDING_WRLOCK;
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		if (tv.tv_sec - pending->p_tv.tv_sec > TIMEOUT) {
			syslog(LOG_INFO, "purge: %s from %s to %s timed out\n", 
			    pending->p_addr, pending->p_from, pending->p_rcpt);
			pending_put(pending);
		}
	}
	PENDING_UNLOCK;

	return;
}


long
pending_check(in, from, rcpt)
	struct in_addr *in;
	char *from;
	char *rcpt;
{
	char addr[IPADDRLEN + 1];
	struct pending *pending;
	struct timeval tv;
	long remain = -1;

	gettimeofday(&tv, NULL);
	strncpy(addr, inet_ntoa(*in), IPADDRLEN);

	PENDING_WRLOCK;
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		/*
		 * Look for our entry.
		 */
		if ((strncmp(addr, pending->p_addr, IPADDRLEN) == 0) &&
		    (strncmp(from, pending->p_from, ADDRLEN) == 0) &&
		    (strncmp(rcpt, pending->p_rcpt, ADDRLEN) == 0)) {
			remain = pending->p_tv.tv_sec - tv.tv_sec;

			syslog(LOG_INFO, 
			    "check: addr %s from %s to %s: %ld s to wait\n",
			    addr, from, rcpt, remain);

			if (remain < 0) {
				pending_put(pending);
				remain = 0;
			}
			goto out;
		}

		/*
		 * Check for expired entries 
		 */
		if (tv.tv_sec - pending->p_tv.tv_sec > TIMEOUT) {
			syslog(LOG_INFO, 
			    "check: %s from %s to %s timed out\n", 
			    pending->p_addr, pending->p_from, pending->p_rcpt);
			pending_put(pending);
		}
	}

	/* 
	 * It was not found. Create it.
	 * Error handling is useless here, we will tempfail anyway
	 */
	pending = pending_get(addr, in, from, rcpt, 0);
	remain = pending->p_tv.tv_sec - tv.tv_sec;

out:
	PENDING_UNLOCK;
	return remain;
}

void
pending_textdump(stream)
	FILE *stream;
{
	struct pending *pending;

	PENDING_RDLOCK;
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		fprintf(stream, "%s	%s	%s	%ld\n", 
		    pending->p_addr, pending->p_from, 
		    pending->p_rcpt, pending->p_tv.tv_sec);
	}
	PENDING_UNLOCK;
	return;
}

void
pending_import(stream)
	FILE *stream;
{
	char addr[IPADDRLEN + 1];
	char from[ADDRLEN + 1];
	char rcpt[ADDRLEN + 1];
	char format[ADDRLEN + 1];
	struct in_addr in;
	long date;
	int readen;

	snprintf(format, ADDRLEN, "%%%d[^\t]\t%%%d[^\t]\t%%%d[^\t]\t%%ld\n", 
	    IPADDRLEN, ADDRLEN, ADDRLEN);

	if (debug)
		syslog(LOG_DEBUG, "format=\"%s\"\n", format);

	PENDING_WRLOCK;
	while (feof(stream) == 0) {
		readen = fscanf(stream, format, &addr, &from, &rcpt, &date);
		if (debug)
			syslog(LOG_DEBUG, "import: readen %d\n", readen);
		if (readen != 4)
			break;
		if (inet_aton(addr, &in) != 1) {
			syslog(LOG_ERR, "import: skip bad address %s\n", addr);
			break;
		}

		if (debug)
			syslog(LOG_DEBUG, "import: \"%s\" \"%s\" \"%s\", %ld\n",
			    addr, from, rcpt, date);

		pending_get(addr, &in, from, rcpt, date);
	}
	PENDING_UNLOCK;

	return;
}

