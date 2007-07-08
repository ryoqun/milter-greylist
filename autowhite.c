/* $Id: autowhite.c,v 1.55 2007/07/08 21:02:28 manu Exp $ */

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
__RCSID("$Id: autowhite.c,v 1.55 2007/07/08 21:02:28 manu Exp $");
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

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

pthread_mutex_t autowhite_lock = PTHREAD_MUTEX_INITIALIZER;
struct autowhitelist autowhite_head;
struct autowhite_bucket *autowhite_buckets;

void
autowhite_init(void) {
	int i;

	TAILQ_INIT(&autowhite_head);
	if ((autowhite_buckets = calloc(AUTOWHITE_BUCKETS, 
	    sizeof(struct autowhite_bucket))) == NULL) {
		mg_log(LOG_ERR, 
		    "Unable to allocate autowhite list buckets: %s", 
		    strerror(errno));
		exit(EX_OSERR);
	}

	for(i = 0; i < AUTOWHITE_BUCKETS; i++) {
		TAILQ_INIT(&autowhite_buckets[i].b_autowhite_head);
	}

	return;
}

/* List must be locked */
int
autowhite_timeout(aw, now)
	struct autowhite *aw;
	struct timeval *now;
{
	int dirty = 0;
	
	if (aw->a_tv.tv_sec < now->tv_sec) {
		char buf[IPADDRSTRLEN];

		iptostring(aw->a_sa, aw->a_salen, buf, sizeof(buf));
		mg_log(LOG_INFO, "(local): addr %s from %s rcpt %s: "
		    "autowhitelisted entry expired",
		    buf, aw->a_from, aw->a_rcpt);

		autowhite_put(aw);
		dirty = 1;
	}

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
	struct autowhite *aw_next;
	struct timeval now;
	char addr[IPADDRSTRLEN];
	int h, mn, s;
	int dirty = 0;
	ipaddr *mask = NULL;
	struct autowhite_bucket *b;
	time_t autowhite;

	gettimeofday(&now, NULL);
	autowhite = *date - now.tv_sec;

	h = autowhite / 3600;
	mn = ((autowhite % 3600) / 60);
	s = (autowhite % 3600) % 60;

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

	AUTOWHITE_LOCK;
	b = &autowhite_buckets[BUCKET_HASH(sa, from, rcpt, AUTOWHITE_BUCKETS)];
	for (aw = TAILQ_FIRST(&b->b_autowhite_head); aw; aw = aw_next) {
		aw_next = TAILQ_NEXT(aw, ab_list);

		if (autowhite_timeout(aw, &now)) {
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
			aw->a_tv.tv_sec = *date;

			/* Rearrange the big queue */
			TAILQ_REMOVE(&autowhite_head, aw, a_list);
			TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);

			dirty++;

			mg_log(LOG_INFO, "%s: addr %s from %s rcpt %s: "
				"autowhitelisted for more %02d:%02d:%02d",
				queueid, addr, from, rcpt, h, mn, s);
			break;
		}
	}

	/*
	 * Entry not found, create it
	 */
	if (aw == NULL) {
		aw = autowhite_get(sa, salen, from, rcpt, *date);

		dirty++;

		mg_log(LOG_INFO, "%s: addr %s from %s rcpt %s: "
		    "autowhitelisted for %02d:%02d:%02d", 
		    queueid, addr, from, rcpt, h, mn, s);
	}
	AUTOWHITE_UNLOCK;

	dump_touch(dirty);

	return;
}

int
autowhite_check(sa, salen, from, rcpt, queueid, gldelay, autowhite)
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	char *queueid;
	time_t gldelay;
	time_t autowhite;
{
	struct autowhite *aw;
	struct autowhite *next_aw;
	struct pending *pending;
	struct timeval now, delay;
	char addr[IPADDRSTRLEN];
	int h, mn, s;
	int dirty = 0;
	ipaddr *mask = NULL;
	struct autowhite_bucket *b;

	if (autowhite == 0)
		return EXF_NONE;

	gettimeofday(&now, NULL);
	delay.tv_sec = autowhite;
	delay.tv_usec = 0;

	h = autowhite / 3600;
	mn = ((autowhite % 3600) / 60);
	s = (autowhite % 3600) % 60;

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

	AUTOWHITE_LOCK;
	b = &autowhite_buckets[BUCKET_HASH(sa, from, rcpt, AUTOWHITE_BUCKETS)];
	for (aw = TAILQ_FIRST(&autowhite_head); aw; aw = next_aw) {
		next_aw = TAILQ_NEXT(aw, a_list);
		
		if (autowhite_timeout(aw, &now)) {
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

			/* Rearrange the big queue */
			TAILQ_REMOVE(&autowhite_head, aw, a_list);
			TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);

			dirty++;

			break;
		}
	}
	AUTOWHITE_UNLOCK;

	dump_touch(dirty);
	dirty = 0;

	if (aw == NULL) 
		return EXF_NONE;

	mg_log(LOG_INFO, "%s: addr %s from %s rcpt %s: "
		"autowhitelisted for more %02d:%02d:%02d",
		queueid, addr, from, rcpt, h, mn, s);
	/*
	 * We need to tell our peers about this, we use a
	 * fictive pending record
	 */
	PENDING_LOCK;
	pending = pending_get(sa, salen, from, rcpt, now.tv_sec + gldelay);
	if (pending != NULL) {
		peer_delete(pending, now.tv_sec + autowhite);
		pending_put(pending);
		++dirty;
	}
	PENDING_UNLOCK;
	dump_touch(dirty);

	return EXF_WHITELIST | EXF_AUTO;	
}

int
autowhite_textdump(stream)
	FILE *stream;
{
	struct autowhite *aw;
	struct autowhite *next_aw;
	struct timeval now;
	int done = 0;
	char textdate[DATELEN + 1];
	char textaddr[IPADDRSTRLEN];
	struct tm tm;

	(void)gettimeofday(&now, NULL);

	fprintf(stream, "\n\n#\n# Auto-whitelisted tuples\n#\n");
	fprintf(stream, "# Sender IP\t%s\t%s\tExpire\n",
	    "Sender e-mail", "Recipient e-mail");

	AUTOWHITE_LOCK;
	for (aw = TAILQ_FIRST(&autowhite_head); aw; aw = next_aw) {
		next_aw = TAILQ_NEXT(aw, a_list);

		if (autowhite_timeout(aw, &now))
			continue;

		iptostring(aw->a_sa, aw->a_salen, textaddr, sizeof(textaddr));
	
		if (conf.c_dump_no_time_translation) {
			fprintf(stream, 
			    "%s\t%s\t%s\t%ld AUTO\n",
			    textaddr, aw->a_from, aw->a_rcpt, 
			    (long)aw->a_tv.tv_sec);
		} else {
			time_t ti;

			ti = aw->a_tv.tv_sec;
			localtime_r(&ti, &tm);
			strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);
	
			fprintf(stream, 
			    "%s\t%s\t%s\t%ld AUTO # %s\n",
			    textaddr, aw->a_from, aw->a_rcpt, 
			    (long)aw->a_tv.tv_sec, textdate);
		}

		done++;
	}
	AUTOWHITE_UNLOCK;

	return done;
}

/*
 * A new entry is inserted to the back of the queue in most cases,
 * but it is not true in these situations:
 * - The conf.c_autowhite_validity was shortened
 * - System clock was turned to the past
 *
 * To ensure that the queue is sorted by expiration times (a_tv),
 * we need to find the right position where to insert a new entry.
 */

struct autowhite *
autowhite_get(sa, salen, from, rcpt, date) /* autowhite list must be locked */
	struct sockaddr *sa;
	socklen_t salen;
	char *from;
	char *rcpt;
	time_t date;
{
	struct autowhite *aw;

	if ((aw = malloc(sizeof(*aw))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	bzero((void *)aw, sizeof(*aw));

	if ((aw->a_sa = malloc(salen)) == NULL ||
	    (aw->a_from = strdup(from)) == NULL ||
	    (aw->a_rcpt = strdup(rcpt)) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	aw->a_tv.tv_sec = date;

	memcpy(aw->a_sa, sa, salen);
	aw->a_salen = salen;

	TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);
	TAILQ_INSERT_TAIL(&autowhite_buckets[BUCKET_HASH(aw->a_sa, 
	    from, rcpt, AUTOWHITE_BUCKETS)].b_autowhite_head, aw, ab_list);

	return aw;
}

void
autowhite_put(aw)	/* autowhite list must be locked */
	struct autowhite *aw;
{
	TAILQ_REMOVE(&autowhite_head, aw, a_list);
	TAILQ_REMOVE(&autowhite_buckets[BUCKET_HASH(aw->a_sa, 
	    aw->a_from, aw->a_rcpt, AUTOWHITE_BUCKETS)].b_autowhite_head, 
	    aw, ab_list);
	free(aw->a_sa);
	free(aw->a_from);
	free(aw->a_rcpt);
	free(aw);

	return;
}

int
autowhite_del_addr(sa, salen)
	struct sockaddr *sa;
	socklen_t salen;
{
	struct autowhite *aw;
	struct autowhite *next_aw;
	int count = 0;
	
	AUTOWHITE_LOCK;
	for (aw = TAILQ_FIRST(&autowhite_head); aw; aw = next_aw) {
		next_aw = TAILQ_NEXT(aw, a_list);
		
		if (memcmp(sa, aw->a_sa, salen) == 0) {
			char buf[IPADDRSTRLEN];

			iptostring(aw->a_sa, aw->a_salen, buf, sizeof(buf));
                      mg_log(LOG_INFO, "(local): addr %s from %s rcpt %s: "
			    "autowhitelisted entry expired",
			    buf, aw->a_from, aw->a_rcpt);

			autowhite_put(aw);
			count++;
		}
	}
	AUTOWHITE_UNLOCK;
	
	dump_touch(count);
	return count;
}
