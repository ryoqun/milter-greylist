/* $Id: autowhite.c,v 1.42 2006/01/08 00:38:24 manu Exp $ */

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

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: autowhite.c,v 1.42 2006/01/08 00:38:24 manu Exp $");
#endif
#endif

#include "config.h"
#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <stdlib.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <string.h>
#include <time.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "conf.h"
#include "pending.h"
#include "dump.h"
#include "autowhite.h"
#include "acl.h"
#include "sync.h"

struct autowhitelist autowhite_head;
struct autowhite_bucket *autowhite_buckets;
pthread_rwlock_t autowhite_lock;
pthread_mutex_t autowhite_change_lock;

void
autowhite_init(void) {
	int error, i;

	TAILQ_INIT(&autowhite_head);
	if ((autowhite_buckets = calloc(AUTOWHITE_BUCKETS, 
	    sizeof(struct autowhite_bucket))) == NULL) {
		syslog(LOG_ERR, 
		    "Unable to allocate autowhite list buckets: %s", 
		    strerror(errno));
		exit(EX_OSERR);
	}
	
	if ((error = pthread_rwlock_init(&autowhite_lock, NULL)) != 0 ||
	    (error = pthread_mutex_init(&autowhite_change_lock, NULL)) != 0) {
		syslog(LOG_ERR, "pthread_rwlock_init failed: %s",
		    strerror(error));
		    exit(EX_OSERR);
	}	

	for(i = 0; i < AUTOWHITE_BUCKETS; i++) {
		TAILQ_INIT(&autowhite_buckets[i].b_autowhite_head);
		
		if ((error = 
		    pthread_mutex_init(&autowhite_buckets[i].bucket_mtx, 
		    NULL)) != 0) {
			syslog(LOG_ERR, 
			    "pthread_mutex_init failed: %s", strerror(error));
			exit(EX_OSERR);
		}
		
	}

	return;
}

int
autowhite_timeout(void)
{
	struct autowhite *aw;
	struct autowhite *next_aw;
	struct timeval now;
	int dirty = 0;
	
	gettimeofday(&now, NULL);
	
	AUTOWHITE_WRLOCK;
	for (aw = TAILQ_FIRST(&autowhite_head); aw; aw = next_aw) {
		next_aw = TAILQ_NEXT(aw, a_list);
		
		/*
		 * Expiration
		 */
		if (aw->a_tv.tv_sec < now.tv_sec) {
			char buf[IPADDRLEN + 1];

			iptostring(aw->a_sa, aw->a_salen, buf, sizeof(buf));
			syslog(LOG_INFO, "addr %s from %s rcpt %s: "
			    "autowhitelisted entry expired",
			    buf, aw->a_from, aw->a_rcpt);

			autowhite_put(aw);

			dirty++;

			continue;
		}
		break;
	}
	AUTOWHITE_UNLOCK;
	
	return dirty;
}

void
autowhite_add(sa, salen, from, rcpt, date, queueid)
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t *date;
	char *queueid;
{
	struct autowhite *aw;
	struct autowhite *next_aw;
	struct timeval now, delay;
	char addr[IPADDRSTRLEN];
	time_t autowhite_validity;
	int h, mn, s;
	int dirty = 0;
	ipaddr *mask = NULL;
	struct autowhite_bucket *b;

	if ((autowhite_validity = conf.c_autowhite_validity) == 0)
		return;

	gettimeofday(&now, NULL);
	delay.tv_sec = autowhite_validity;
	delay.tv_usec = 0;

	h = autowhite_validity / 3600;
	mn = ((autowhite_validity % 3600) / 60);
	s = (autowhite_validity % 3600) % 60;

	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return;

	switch (sa->sa_family) {
	case AF_INET:
		mask = (ipaddr *)&conf.c_match_mask;
		break;
#ifdef AF_INET6
	case AF_INET6:
		mask = (ipaddr *)&conf.c_match_mask6;
		break;
#endif
	}

	dirty = autowhite_timeout();
	
	AUTOWHITE_RDLOCK;
	b = &autowhite_buckets[BUCKET_HASH(sa, from, rcpt, AUTOWHITE_BUCKETS)];
	pthread_mutex_lock(&b->bucket_mtx);
	for (aw = TAILQ_FIRST(&b->b_autowhite_head); aw; aw = next_aw) {
		next_aw = TAILQ_NEXT(aw, ab_list);

		/*
		 * Expiration (left this one in too until the list gets sorted)
		 */
		if (aw->a_tv.tv_sec < now.tv_sec) {
			char buf[IPADDRLEN + 1];

			iptostring(aw->a_sa, aw->a_salen, buf, sizeof(buf));
			syslog(LOG_INFO, "addr %s from %s rcpt %s: "
			    "autowhitelisted entry expired",
			    buf, aw->a_from, aw->a_rcpt);

			autowhite_put(aw);

			dirty++;

			continue;
		}

		/*
		 * Look for an already existing entry
		 */
		if (ip_match(sa, aw->a_sa, mask) &&
		    ((conf.c_lazyaw == 1) ||
		    ((strcasecmp(from, aw->a_from) == 0) &&
		    (strcasecmp(rcpt, aw->a_rcpt) == 0)))) {
			timeradd(&now, &delay, &aw->a_tv);

			/* Push it at the back of the big queue */
			pthread_mutex_lock(&autowhite_change_lock);
			TAILQ_REMOVE(&autowhite_head, aw, a_list);
			TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);
			pthread_mutex_unlock(&autowhite_change_lock);

			dirty++;

			syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
				"autowhitelisted for more %02d:%02d:%02d",
				queueid, addr, from, rcpt, h, mn, s);
			break;
		}
	}

	/*
	 * Entry not found, create it
	 */
	if (aw == NULL) {
		aw = autowhite_get(sa, salen, from, rcpt, date);

		dirty++;

		syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
		    "autowhitelisted for %02d:%02d:%02d", 
		    queueid, addr, from, rcpt, h, mn, s);
	}
	pthread_mutex_unlock(&b->bucket_mtx);
	AUTOWHITE_UNLOCK;

	if (dirty != 0)
		dump_dirty += dirty;

	return;
}

int
autowhite_check(sa, salen, from, rcpt, queueid)
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	char *queueid;
{
	struct autowhite *aw;
	struct autowhite *next_aw;
	struct pending *pending;
	struct timeval now, delay;
	char addr[IPADDRSTRLEN];
	time_t autowhite_validity;
	int h, mn, s;
	int dirty = 0;
	ipaddr *mask = NULL;
	struct autowhite_bucket *b;

	if ((autowhite_validity = conf.c_autowhite_validity) == 0)
		return EXF_NONE;

	gettimeofday(&now, NULL);
	delay.tv_sec = autowhite_validity;
	delay.tv_usec = 0;

	h = autowhite_validity / 3600;
	mn = ((autowhite_validity % 3600) / 60);
	s = (autowhite_validity % 3600) % 60;

	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return EXF_NONE;

	switch (sa->sa_family) {
	case AF_INET:
		mask = (ipaddr *)&conf.c_match_mask;
		break;
#ifdef AF_INET6
	case AF_INET6:
		mask = (ipaddr *)&conf.c_match_mask6;
		break;
#endif
	}

	dirty = autowhite_timeout();
	
	AUTOWHITE_RDLOCK;
	b = &autowhite_buckets[BUCKET_HASH(sa, from, rcpt, AUTOWHITE_BUCKETS)];
	pthread_mutex_lock(&b->bucket_mtx);
	for (aw = TAILQ_FIRST(&b->b_autowhite_head); aw; aw = next_aw) {
		next_aw = TAILQ_NEXT(aw, ab_list);

		/*
		 * Do expiration first as we don't want
		 * an outdated record to match
		 * I've left this one too until the lists
		 * gets sorted
		 */
		if (aw->a_tv.tv_sec < now.tv_sec) {
			char buf[IPADDRSTRLEN];

			iptostring(aw->a_sa, aw->a_salen, buf, sizeof(buf));
			syslog(LOG_INFO, "addr %s from %s rcpt %s: "
			    "autowhitelisted entry expired",
			    buf, aw->a_from, aw->a_rcpt);

			autowhite_put(aw);
			aw = NULL;

			dirty++;

			continue;
		}

		/*
		 * Look for our record
		 */
		if (ip_match(sa, aw->a_sa, mask) &&
		    ((conf.c_lazyaw == 1) ||
		    ((strcasecmp(from, aw->a_from) == 0) &&
		    (strcasecmp(rcpt, aw->a_rcpt) == 0)))) {
			timeradd(&now, &delay, &aw->a_tv);

			/* Push it at the back of the big queue */
			pthread_mutex_lock(&autowhite_change_lock);
			TAILQ_REMOVE(&autowhite_head, aw, a_list);
			TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);
			pthread_mutex_unlock(&autowhite_change_lock);

			dirty++;

			break;
		}
	}
	pthread_mutex_unlock(&b->bucket_mtx);
	AUTOWHITE_UNLOCK;

	if (dirty != 0)
		dump_dirty += dirty;

	if (aw == NULL) 
		return EXF_NONE;

	syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
		"autowhitelisted for more %02d:%02d:%02d",
		queueid, addr, from, rcpt, h, mn, s);
	/*
	 * We need to tell our peers about this, we use a
	 * fictive pending record
	 */
	PENDING_WRLOCK;
	pending = pending_get(sa, salen, from, rcpt, 
	    (time_t)0);
	if (pending != NULL) {
		peer_delete(pending);
		pending_put(pending);
	}
	PENDING_UNLOCK;
	return EXF_AUTO;	
}

int
autowhite_textdump(stream)
	FILE *stream;
{
	struct autowhite *aw;
	int done = 0;
	char textdate[DATELEN + 1];
	char textaddr[IPADDRSTRLEN];
	struct tm tm;

	fprintf(stream, "\n\n#\n# Auto-whitelisted tuples\n#\n");
	fprintf(stream, "# Sender IP\t%s\t%s\tExpire\n",
	    "Sender e-mail", "Recipient e-mail");

	AUTOWHITE_RDLOCK;
	pthread_mutex_lock(&autowhite_change_lock);
	TAILQ_FOREACH(aw, &autowhite_head, a_list) {
		iptostring(aw->a_sa, aw->a_salen, textaddr, sizeof(textaddr));
	
		if (conf.c_dump_no_time_translation) {
			fprintf(stream, 
			    "%s\t%s\t%s\t%ld AUTO\n",
			    textaddr, aw->a_from, aw->a_rcpt, 
			    (long)aw->a_tv.tv_sec);
		} else {
			localtime_r((time_t *)&aw->a_tv.tv_sec, &tm);
			strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);
	
			fprintf(stream, 
			    "%s\t%s\t%s\t%ld AUTO # %s\n",
			    textaddr, aw->a_from, aw->a_rcpt, 
			    (long)aw->a_tv.tv_sec, textdate);
		}

		done++;
	}
	pthread_mutex_unlock(&autowhite_change_lock);
	AUTOWHITE_UNLOCK;

	return done;
}

struct autowhite *
autowhite_get(sa, salen, from, rcpt, date) /* autowhite list must be locked */
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t *date;
{
	struct autowhite *aw;
	struct timeval now, delay;
	time_t autowhite_validity = conf.c_autowhite_validity;

	gettimeofday(&now, NULL);
	delay.tv_sec = autowhite_validity;
	delay.tv_usec = 0;

	if ((aw = malloc(sizeof(*aw))) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	bzero((void *)aw, sizeof(*aw));

	if ((aw->a_sa = malloc(salen)) == NULL ||
	    (aw->a_from = strdup(from)) == NULL ||
	    (aw->a_rcpt = strdup(rcpt)) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	memcpy(aw->a_sa, sa, salen);
	aw->a_salen = salen;

	if (date == NULL)
		timeradd(&now, &delay, &aw->a_tv);
	else
		aw->a_tv.tv_sec = *date;

	pthread_mutex_lock(&autowhite_change_lock);
	TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);
	TAILQ_INSERT_TAIL(&autowhite_buckets[BUCKET_HASH(aw->a_sa, 
	    from, rcpt, AUTOWHITE_BUCKETS)].b_autowhite_head, aw, ab_list);
	pthread_mutex_unlock(&autowhite_change_lock);

	return aw;
}

void
autowhite_put(aw)	/* autowhite list must be write-locked */
	struct autowhite *aw;
{
	pthread_mutex_lock(&autowhite_change_lock);
	TAILQ_REMOVE(&autowhite_head, aw, a_list);	
	TAILQ_REMOVE(&autowhite_buckets[BUCKET_HASH(aw->a_sa, 
	    aw->a_from, aw->a_rcpt, AUTOWHITE_BUCKETS)].b_autowhite_head, 
	    aw, ab_list);
	pthread_mutex_unlock(&autowhite_change_lock);
	free(aw->a_sa);
	free(aw->a_from);
	free(aw->a_rcpt);
	free(aw);

	return;
}
