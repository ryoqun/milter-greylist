/* $Id: pending.c,v 1.81.2.1 2006/09/04 22:05:59 manu Exp $ */

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
__RCSID("$Id: pending.c,v 1.81.2.1 2006/09/04 22:05:59 manu Exp $");
#endif
#endif

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
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
struct pending_bucket *pending_buckets;
pthread_rwlock_t pending_lock; 	/* protects pending_head and dump_dirty */
pthread_mutex_t pending_change_lock;
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
	int i;

	TAILQ_INIT(&pending_head);
	if ((pending_buckets = calloc(PENDING_BUCKETS, 
	    sizeof(struct pending_bucket))) == NULL) {
		mg_log(LOG_ERR, 
		    "Unable to allocate pending list buckets: %s", 
		    strerror(errno));
		exit(EX_OSERR);
	}
	
	if ((error = pthread_rwlock_init(&pending_lock, NULL)) != 0 ||
	    (error = pthread_rwlock_init(&refcnt_lock, NULL)) != 0 ||
	    (error = pthread_mutex_init(&pending_change_lock, NULL)) != 0) {
		mg_log(LOG_ERR, 
		    "pthread_rwlock_init failed: %s", strerror(error));
		exit(EX_OSERR);
	}
	
	for(i = 0; i < PENDING_BUCKETS; i++) {
		TAILQ_INIT(&pending_buckets[i].b_pending_head);
		
		if ((error = pthread_mutex_init(&pending_buckets[i].bucket_mtx,
		    NULL)) != 0) {
			mg_log(LOG_ERR, 
			    "pthread_mutex_init failed: %s", strerror(error));
			exit(EX_OSERR);
		}
		
	}

	return;
}

/* pending_lock must be write-locked & bucket must be locked */
struct pending *
pending_get(sa, salen, from, rcpt, date)  
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t date;
{
	struct pending *pending;
	struct timeval tv;
	char addr[IPADDRSTRLEN];

	if ((pending = malloc(sizeof(*pending))) == NULL)
		goto out;

	bzero((void *)pending, sizeof(pending));
	pending->p_tv.tv_sec = date;

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
	if ((pending->p_from = strdup(from)) == NULL) {
		free(pending->p_addr);
		free(pending->p_sa);
		free(pending);
		pending = NULL;
		goto out;
	}
	if ((pending->p_rcpt = strdup(rcpt)) == NULL) {
		free(pending->p_from);
		free(pending->p_addr);
		free(pending->p_sa);
		free(pending);
		pending = NULL;
		goto out;
	}

	pending->p_refcnt = 1;

	pthread_mutex_lock(&pending_change_lock);
	TAILQ_INSERT_TAIL(&pending_head, pending, p_list); 
	TAILQ_INSERT_TAIL(&pending_buckets[BUCKET_HASH(pending->p_sa, 
	    from, rcpt, PENDING_BUCKETS)].b_pending_head, pending, pb_list); 

	dump_dirty++;

	(void)gettimeofday(&tv, NULL);

	if (conf.c_debug) {
		mg_log(LOG_DEBUG, "created: %s from %s to %s delayed for %lds",
		    pending->p_addr, pending->p_from, pending->p_rcpt, 
		    pending->p_tv.tv_sec - tv.tv_sec);
	}
	pthread_mutex_unlock(&pending_change_lock);
out:
	return pending;
}

/* pending list should be write-locked & bucket must be locked */
void
pending_put(pending) 
	struct pending *pending;
{
	if (conf.c_debug) {
		mg_log(LOG_DEBUG, "removed: %s from %s to %s",
		    pending->p_addr, pending->p_from, pending->p_rcpt);
	}

	pthread_mutex_lock(&pending_change_lock);
	TAILQ_REMOVE(&pending_head, pending, p_list);	
	TAILQ_REMOVE(&pending_buckets[BUCKET_HASH(pending->p_sa, 
	    pending->p_from, pending->p_rcpt, PENDING_BUCKETS)].b_pending_head,
	    pending, pb_list); 
	
	pending_free(pending);

	dump_dirty++;
	pthread_mutex_unlock(&pending_change_lock);

	return;
}

int
pending_timeout(void)
{
	struct pending *pending;
	struct pending *next;
	struct timeval now;
	int dirty = 0;
	
	gettimeofday(&now, NULL);
	
	PENDING_WRLOCK;
	for (pending = TAILQ_FIRST(&pending_head); pending; pending = next) {
		next = TAILQ_NEXT(pending, p_list);
		/*
		 * Check for expired entries
		 */
		if (now.tv_sec - pending->p_tv.tv_sec > conf.c_timeout) {
			if (conf.c_debug || conf.c_logexpired) {
				mg_log(LOG_DEBUG,
				    "(local): %s from %s to %s: greylisted "
				    "entry timed out",
				    pending->p_addr, pending->p_from,
				    pending->p_rcpt);
			}
			dirty = 1;
			pending_put(pending);
			continue;
		}
		break; /* The rest of the entries are OK */
	}
	PENDING_UNLOCK;

	return dirty;
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
	struct pending_bucket *b;

	gettimeofday(&tv, NULL);
	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return;

	PENDING_RDLOCK;
	b = &pending_buckets[BUCKET_HASH(sa, from, rcpt, PENDING_BUCKETS)];
	pthread_mutex_lock(&b->bucket_mtx);
	for (pending = TAILQ_FIRST(&b->b_pending_head); 
	    pending; pending = next) {
		next = TAILQ_NEXT(pending, pb_list);

		/*
		 * Look for our entry.
		 */
		if ((strncmp(addr, pending->p_addr, sizeof(addr)) == 0) &&
		    (strcmp(from, pending->p_from) == 0) &&
		    (strcmp(rcpt, pending->p_rcpt) == 0) &&
		    (pending->p_tv.tv_sec == time)) {
			pending_put(pending);
			break;
		}

	}
	pthread_mutex_unlock(&b->bucket_mtx);
	PENDING_UNLOCK;
	
	pending_timeout();
	
	return;
}

int
pending_check(sa, salen, from, rcpt, remaining, elapsed, queueid, delay, aw)
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t *remaining;
	time_t *elapsed;
	char *queueid;
	time_t delay;
	time_t aw;
{
	char addr[IPADDRSTRLEN];
	struct pending *pending;
	struct pending *next;
	time_t now;
	time_t rest = -1;
	time_t accepted = -1;
	int dirty = 0;
	struct pending_bucket *b;
	ipaddr *mask = NULL;
	time_t date;

	now = time(NULL);
	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return 1;

	dirty = pending_timeout();
	
	PENDING_RDLOCK;
	b = &pending_buckets[BUCKET_HASH(sa, from, rcpt, PENDING_BUCKETS)];
	pthread_mutex_lock(&b->bucket_mtx);
	for (pending = TAILQ_FIRST(&b->b_pending_head); 
	    pending; pending = next) {
		next = TAILQ_NEXT(pending, pb_list);

		/*
		 * The time the entry shall be accepted
		 */
		accepted = pending->p_tv.tv_sec;

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
		    (strcmp(from, pending->p_from) == 0) &&
		    (strcmp(rcpt, pending->p_rcpt) == 0)) {
			rest = accepted - now;

			if (rest <= 0) {
				date = now + aw;
				peer_delete(pending, date);
				pending_put(pending);
				autowhite_add(sa, salen, from, rcpt, 
				    &date, queueid);
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
	date = now + delay;
	pending = pending_get(sa, salen, from, rcpt, date);
	peer_create(pending); /* XXXmanu if pending == NULL? */
	rest = pending->p_tv.tv_sec - now;
	dirty = 1;

out:
	pthread_mutex_unlock(&b->bucket_mtx);
	PENDING_UNLOCK;

	if (remaining != NULL)
		*remaining = rest; 

	if (elapsed != NULL)
		*elapsed = now - (accepted - delay);

	if (dirty)
		dump_flush();

	if (rest <= 0)
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
	fprintf(stream, "# Sender IP\t%s\t%s\tTime accepted\n", 
	    "Sender e-mail", "Recipient e-mail");

	PENDING_RDLOCK;
	pthread_mutex_lock(&pending_change_lock);
	TAILQ_FOREACH(pending, &pending_head, p_list) {
		if (conf.c_dump_no_time_translation) {
			fprintf(stream, "%s\t%s\t%s\t%ld\n", 
			    pending->p_addr, pending->p_from, 
			    pending->p_rcpt, (long)pending->p_tv.tv_sec);
		} else {
			localtime_r((time_t *)&pending->p_tv.tv_sec, &tm);
			strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);
		
			fprintf(stream, "%s\t%s\t%s\t%ld # %s\n", 
			    pending->p_addr, pending->p_from, 
			    pending->p_rcpt, 
			    (long)pending->p_tv.tv_sec, textdate);
		}
		
		done++;
	}
	pthread_mutex_unlock(&pending_change_lock);
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
	free(pending->p_from);
	free(pending->p_rcpt);
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
#if defined(HAVE_SIN6_SCOPE_ID) && defined(HAVE_GETADDRINFO)
		if (SA6(pat)->sin6_scope_id != 0 &&
		    SA6(sa)->sin6_scope_id != SA6(pat)->sin6_scope_id)
			return 0;
#endif
		for (i = 0; i < 16; i += 4) {
			if ((*(uint32_t *)&SADDR6(sa)->s6_addr[i] &
			     *(uint32_t *)&mask->in6.s6_addr[i]) !=
			    (*(uint32_t *)&SADDR6(pat)->s6_addr[i] &
			     *(uint32_t *)&mask->in6.s6_addr[i]))
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
#if defined(HAVE_SIN6_SCOPE_ID) && defined(HAVE_GETADDRINFO)
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
/*
 * This was ifdef HAVE_GETNAMEINFO, but we hit an ABI clash on some systems.
 * From <netdb.h> of libbind:
 *	#define NI_NOFQDN       0x00000001
 *	#define NI_NUMERICHOST  0x0000000
 * From <netdb.h> of glibc:
 *	# define NI_NUMERICHOST 1
 *	# define NI_NUMERICSERV 2
 * The result is that on Linux, when linking with libspf_alt (which is
 * linked with libbind), we get NI_NOFQDN where we expect NI_NUMERICHOST.
 * Symptom: the dump file gets hostnames instead of IP addresses.
 * 
 * Disabling the use of getnameinfo() breaks IPv6 Scope-Id, which is
 * not handled by Sendmail anyway.
 */
#if 0
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
	if (*salen < res->ai_addrlen) {
		freeaddrinfo(res);
		return -1;
	}
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

void
pending_del_addr(sa, salen, queueid, acl_line)
	struct sockaddr *sa;
	socklen_t salen;
	char *queueid;
	int acl_line;
{
	char addr[IPADDRSTRLEN];
	struct pending *pending;
	struct pending *next;
	int sync_flush_done = 0;
	int count_pending = 0;
	int count_white = 0;
        char aclstr[16];

	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return;

	PENDING_RDLOCK;
	for (pending = TAILQ_FIRST(&pending_head); pending; pending = next) {
		next = TAILQ_NEXT(pending, p_list);

		if (strncmp(addr, pending->p_addr, sizeof(addr)) == 0) {
			if (!sync_flush_done) {
				peer_flush(pending);
				sync_flush_done = 1;
			}
			pending_put(pending);
			count_pending++;
		}

	}
	PENDING_UNLOCK;

	/* And flush autowhite list as well... */
	count_white = autowhite_del_addr(sa, salen);
	
	if (queueid != NULL) {
		*aclstr = '\0';
        	if (acl_line != 0)
			snprintf(aclstr, sizeof(aclstr), " (ACL %d)", acl_line);
		mg_log(LOG_INFO, "%s: addr %s flushed, removed %d grey and %d autowhite%s",
			queueid, addr, count_pending, count_white, aclstr);
	}
	return;
}
