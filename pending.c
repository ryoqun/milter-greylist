/* $Id: pending.c,v 1.5 2004/03/05 14:21:27 manu Exp $ */

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

#define _XOPEN_SOURCE 500
#define _BSD_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <sysexits.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "pending.h"
#include "milter-greylist.h"

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
	if ((error = pthread_rwlock_init(&pending_lock, NULL)) == 0)
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

	strncpy(pending->p_addr, addr, IPADDRLEN);
	pending->p_addr[IPADDRLEN] = '\0';
	strncpy(pending->p_from, from, ADDRLEN);
	pending->p_from[ADDRLEN] = '\0';
	strncpy(pending->p_rcpt, rcpt, ADDRLEN);
	pending->p_rcpt[ADDRLEN] = '\0';
	TAILQ_INSERT_TAIL(&pending_head, pending, p_list); 

	(void)gettimeofday(&tv, NULL);
	syslog(LOG_INFO, "created: %s from %s to %s, delayed for %ld s\n",
	    pending->p_addr, pending->p_from, pending->p_rcpt, 
	    tv.tv_sec - pending->p_tv.tv_sec);

out:
	return pending;
}

void
pending_put(pending) /* pending list should be write-locked */
	struct pending *pending;
{
	syslog(LOG_INFO, "removed: %s from %s to %s\n",
	    pending->p_addr, pending->p_from, pending->p_rcpt);
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


int
pending_check(in, from, rcpt, remaining, elapsed)
	struct in_addr *in;
	char *from;
	char *rcpt;
	long *remaining;
	long *elapsed;
{
	char addr[IPADDRLEN + 1];
	struct pending *pending;
	struct timeval tv;
	long rest = -1;

	gettimeofday(&tv, NULL);
	(void)inet_ntop(AF_INET, in, addr, IPADDRLEN);

	PENDING_WRLOCK;
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		/*
		 * Look for our entry.
		 */
		if ((strncmp(addr, pending->p_addr, IPADDRLEN) == 0) &&
		    (strncmp(from, pending->p_from, ADDRLEN) == 0) &&
		    (strncmp(rcpt, pending->p_rcpt, ADDRLEN) == 0)) {
			rest = pending->p_tv.tv_sec - tv.tv_sec;

			if (rest < 0) {
				pending_put(pending);
				rest = 0;
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
	rest = delay;

out:
	PENDING_UNLOCK;

	if (remaining != NULL)
		*remaining = rest; 

	if (elapsed != NULL)
		*elapsed = tv.tv_sec - (pending->p_tv.tv_sec - delay);

	if (rest == 0)
		return 1;
	else
		return 0;
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
		if (inet_pton(AF_INET, addr, &in) != 1) {
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

