/* $Id: pending.c,v 1.62 2004/08/02 12:11:48 manu Exp $ */

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
__RCSID("$Id: pending.c,v 1.62 2004/08/02 12:11:48 manu Exp $");
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
/*
 * protects pending->p_refcnt
 * since we hold many pending entries, requied memory for the lock
 * object is considerably large to have it in each pending entry.  so,
 * we use just one lock object for all pending entries.
 */
static pthread_rwlock_t refcnt_lock;

void
pending_init(void) {
	int error;

	TAILQ_INIT(&pending_head);
	if ((error = pthread_rwlock_init(&pending_lock, NULL)) != 0 ||
	    (error = pthread_rwlock_init(&refcnt_lock, NULL)) != 0) {
		syslog(LOG_ERR, 
		    "pthread_rwlock_init failed: %s", strerror(error));
		exit(EX_OSERR);
	}

	return;
}


struct pending *
pending_get(sa, salen, from, rcpt, date)  /* pending_lock must be write-locked */
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t date;
{
	struct pending *pending;
	struct timeval tv;
	int delay = conf.c_delay;
	char addr[IPADDRSTRLEN];

	if ((pending = malloc(sizeof(*pending))) == NULL)
		goto out;

	bzero((void *)pending, sizeof(pending));

	if (date == 0) {
		gettimeofday(&pending->p_tv, NULL);
		pending->p_tv.tv_sec += delay;
	} else {
		pending->p_tv.tv_sec = date;
	}

	if ((pending->p_sa = malloc(salen)) == NULL) {
		free(pending);
		pending = NULL;
		goto out;
	}
	memcpy(pending->p_sa, sa, salen);
	pending->p_salen = salen;
	if (!iptostring(sa, salen, addr, sizeof(addr)) ||
	    (pending->p_addr = strdup(addr)) == NULL) {
		free(pending->p_sa);
		free(pending);
		pending = NULL;
		goto out;
	}
	strncpy(pending->p_from, from, ADDRLEN);
	pending->p_from[ADDRLEN] = '\0';
	strncpy(pending->p_rcpt, rcpt, ADDRLEN);
	pending->p_rcpt[ADDRLEN] = '\0';

	pending->p_refcnt = 1;

	TAILQ_INSERT_TAIL(&pending_head, pending, p_list); 

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
	pending_free(pending);

	dump_dirty++;

	return;
}

void
pending_del(sa, salen, from, rcpt, time)
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t time;
{
	char addr[IPADDRSTRLEN];
	struct pending *pending;
	struct pending *next;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return;

	PENDING_WRLOCK;	/* XXX take it as read and upgrade it */
	for (pending = TAILQ_FIRST(&pending_head); pending; pending = next) {
		next = TAILQ_NEXT(pending, p_list);

		/*
		 * Look for our entry.
		 */
		if ((strncmp(addr, pending->p_addr, sizeof(addr)) == 0) &&
		    (strncmp(from, pending->p_from, ADDRLEN) == 0) &&
		    (strncmp(rcpt, pending->p_rcpt, ADDRLEN) == 0) &&
		    (pending->p_tv.tv_sec == time)) {
			pending_put(pending);
			break;
		}

		/*
		 * Check for expired entries
		 */
		if (tv.tv_sec - pending->p_tv.tv_sec > conf.c_timeout) {
			if (conf.c_debug) {
				syslog(LOG_DEBUG,
				    "del: %s from %s to %s timed out",
				    pending->p_addr, pending->p_from,
				    pending->p_rcpt);
			}

			pending_put(pending);
			continue;
		}
	}
	PENDING_UNLOCK;
	return;
}

int
pending_check(sa, salen, from, rcpt, remaining, elapsed, queueid)
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t *remaining;
	time_t *elapsed;
	char *queueid;
{
	char addr[IPADDRSTRLEN];
	struct pending *pending;
	struct pending *next;
	time_t now;
	time_t rest = -1;
	time_t accepted = -1;
	int dirty = 0;
	int delay = conf.c_delay;
	ipaddr *mask = NULL;

	now = time(NULL);
	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return 1;

	PENDING_WRLOCK;	/* XXX take a read lock and upgrade */
	for (pending = TAILQ_FIRST(&pending_head); pending; pending = next) {
		next = TAILQ_NEXT(pending, p_list);

		/*
		 * The time the entry shall be accepted
		 */
		accepted = pending->p_tv.tv_sec;

		/*
		 * Check for expired entries
		 */
		if (now - accepted > conf.c_timeout) {
			if (conf.c_debug) {
				syslog(LOG_DEBUG,
				    "check: %s from %s to %s timed out",
				    pending->p_addr, pending->p_from,
				    pending->p_rcpt);
			}

			pending_put(pending);
			dirty = 1;
			continue;
		}

		/*
		 * Look for our entry.
		 */
		switch (pending->p_sa->sa_family) {
		case AF_INET:
			mask = (ipaddr *)&conf.c_match_mask;
			break;
#ifdef AF_INET6
		case AF_INET6:
			mask = (ipaddr *)&conf.c_match_mask6;
			break;
#endif
		}
		if (ip_match(sa, pending->p_sa, mask) &&
		    (strncmp(from, pending->p_from, ADDRLEN) == 0) &&
		    (strncmp(rcpt, pending->p_rcpt, ADDRLEN) == 0)) {
			rest = accepted - now;

			if (rest < 0) {
				peer_delete(pending);
				pending_put(pending);
				autowhite_add(sa, salen, from, rcpt, NULL,
				    queueid);
				rest = 0;
				dirty = 1;
			}

			goto out;
		}
	}

	/* 
	 * It was not found. Create it and propagagte it to peers.
	 * Error handling is useless here, we will tempfail anyway
	 */
	pending = pending_get(sa, salen, from, rcpt, (time_t)0);
	peer_create(pending);
	rest = delay;
	dirty = 1;

out:
	PENDING_UNLOCK;

	if (remaining != NULL)
		*remaining = rest; 

	if (elapsed != NULL)
		*elapsed = now - (accepted - delay);

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

struct pending *
pending_ref(pending)
	struct pending *pending;
{
	WRLOCK(refcnt_lock);
	pending->p_refcnt++;
	UNLOCK(refcnt_lock);
	return pending;
}

void
pending_free(pending)
	struct pending *pending;
{
	WRLOCK(refcnt_lock);
	pending->p_refcnt--;
	if (pending->p_refcnt > 0) {
		UNLOCK(refcnt_lock);
		return;
	}
	UNLOCK(refcnt_lock);
	free(pending->p_sa);
	free(pending->p_addr);
	free(pending);
}

int
ip_match(sa, pat, mask)
	struct sockaddr *sa;
	struct sockaddr *pat;
	ipaddr *mask;
{
#ifdef AF_INET6
	int i;
#endif

	if (sa->sa_family != pat->sa_family)
		return 0;
	switch (sa->sa_family) {
	case AF_INET:
		if ((SADDR4(sa)->s_addr & mask->in4.s_addr) !=
		    (SADDR4(pat)->s_addr & mask->in4.s_addr))
			return 0;
		break;
#ifdef AF_INET6
	case AF_INET6:
#ifdef HAVE_GETADDRINFO
		if (SA6(pat)->sin6_scope_id != 0 &&
		    SA6(sa)->sin6_scope_id != SA6(pat)->sin6_scope_id)
			return 0;
#endif
		for (i = 0; i < 16; i += 4) {
			if ((*(u_int32_t *)&SADDR6(sa)->s6_addr[i] &
			     *(u_int32_t *)&mask->in6.s6_addr[i]) !=
			    (*(u_int32_t *)&SADDR6(pat)->s6_addr[i] &
			     *(u_int32_t *)&mask->in6.s6_addr[i]))
				return 0;
		}
		break;
#endif
	default:
		return 0;
	}
	return 1;
}

int
ip_equal(sa, pat)
	struct sockaddr *sa;
	struct sockaddr *pat;
{
	if (sa->sa_family != pat->sa_family)
		return 0;
	switch (sa->sa_family) {
	case AF_INET:
		if (SADDR4(sa)->s_addr != SADDR4(pat)->s_addr)
			return 0;
		break;
#ifdef AF_INET6
	case AF_INET6:
#ifdef HAVE_GETADDRINFO
		if (SA6(pat)->sin6_scope_id != 0 &&
		    SA6(sa)->sin6_scope_id != SA6(pat)->sin6_scope_id)
			return 0;
#endif
		if (memcmp(SADDR6(sa), SADDR6(pat),
		    sizeof(struct in6_addr)) != 0)
			return 0;
	    break;
#endif
	default:
		return 0;
	}
	return 1;
}

char *
iptostring(sa, salen, buf, buflen)
	struct sockaddr *sa;
	socklen_t salen;
	char *buf;
	size_t buflen;
{
#ifdef HAVE_GETNAMEINFO
	if (getnameinfo(sa, salen, buf, buflen, NULL, 0, NI_NUMERICHOST) == 0)
		return buf;
#else
	void *addr;

	switch (sa->sa_family) {
	case AF_INET:
		addr = (void *)SADDR4(sa);
		break;
#ifdef AF_INET6
	case AF_INET6:
		addr = (void *)SADDR6(sa);
		break;
#endif
	default:
		return NULL;
	}
	if (inet_ntop(sa->sa_family, addr, buf, buflen) != NULL)
		return buf;
#endif
	return NULL;
}

int
ipfromstring(str, sa, salen, family)
	char *str;
	struct sockaddr *sa;
	socklen_t *salen;
	sa_family_t family;
{
#ifdef HAVE_GETADDRINFO
	struct addrinfo hints, *res;

	bzero(&hints, sizeof(hints));
 	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(str, "0", &hints, &res) != 0)
		return 0;
	if (*salen < res->ai_addrlen)
		return -1;
	memcpy(sa, res->ai_addr, res->ai_addrlen);
	*salen = res->ai_addrlen;
	freeaddrinfo(res);
	return 1;
#else
	struct in_addr addr;
#ifdef AF_INET6
	struct in6_addr addr6;
#endif

	if ((family == AF_UNSPEC || family == AF_INET) &&
	    inet_pton(AF_INET, str, (void *)&addr) == 1) {
		if (*salen < sizeof(struct sockaddr_in))
			return -1;
		bzero(sa, *salen);
		memcpy(SADDR4(sa), &addr, sizeof(struct in_addr));
		SA4(sa)->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
		SA4(sa)->sin_len = sizeof(struct sockaddr_in);
#endif
		*salen = sizeof(struct sockaddr_in);
		return 1;
	}
#ifdef AF_INET6
	if ((family == AF_UNSPEC || family == AF_INET6) &&
	    inet_pton(AF_INET6, str, (void *)&addr6) == 1) {
		if (*salen < sizeof(struct sockaddr_in6))
			return -1;
		bzero(sa, *salen);
		memcpy(SADDR6(sa), &addr6, sizeof(struct in6_addr));
		SA6(sa)->sin6_family = AF_INET6;
#ifdef SIN6_LEN
		SA6(sa)->sin6_len = sizeof(struct sockaddr_in6);
#endif
		*salen = sizeof(struct sockaddr_in6);
		return 1;
	}
#endif
	return 0;
#endif
}
