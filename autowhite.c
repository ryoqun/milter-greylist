/* $Id: autowhite.c,v 1.37 2004/09/13 18:41:54 manu Exp $ */

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
__RCSID("$Id: autowhite.c,v 1.37 2004/09/13 18:41:54 manu Exp $");
#endif
#endif

#include "config.h"
#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <stdlib.h>
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
#include "except.h"
#include "pending.h"
#include "dump.h"
#include "autowhite.h"

struct autowhitelist autowhite_head;
pthread_rwlock_t autowhite_lock;

void
autowhite_init(void) {
	int error;

	TAILQ_INIT(&autowhite_head);
	if ((error = pthread_rwlock_init(&autowhite_lock, NULL)) != 0) {
		syslog(LOG_ERR, "pthread_rwlock_init failed: %s",
		    strerror(error));
		    exit(EX_OSERR);
	}	

	return;
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

		/*
		 * Look for an already existing entry
		 */
		if (ip_equal(sa, aw->a_sa) &&
		    ((conf.c_lazyaw == 1) ||
		    ((strcasecmp(from, aw->a_from) == 0) &&
		    (strcasecmp(rcpt, aw->a_rcpt) == 0)))) {
			timeradd(&now, &delay, &aw->a_tv);

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
	struct timeval now, delay;
	char addr[IPADDRSTRLEN];
	time_t autowhite_validity;
	int h, mn, s;
	int dirty = 0;
	ipaddr *mask = NULL;

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

	AUTOWHITE_WRLOCK;
	for (aw = TAILQ_FIRST(&autowhite_head); aw; aw = next_aw) {
		next_aw = TAILQ_NEXT(aw, a_list);

		/*
		 * Do expiration first as we don't want
		 * an outdated record to match
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
		if (ip_match(sa, aw->a_sa, mask) &&
		    ((conf.c_lazyaw == 1) ||
		    ((strcasecmp(from, aw->a_from) == 0) &&
		    (strcasecmp(rcpt, aw->a_rcpt) == 0)))) {
			timeradd(&now, &delay, &aw->a_tv);

			dirty++;

			syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
				"autowhitelisted for more %02d:%02d:%02d",
				queueid, addr, from, rcpt, h, mn, s);
			break;
		}
	}
	AUTOWHITE_UNLOCK;

	if (dirty != 0)
		dump_dirty += dirty;

	if (aw != NULL) 
		return EXF_AUTO;	

	return EXF_NONE;
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
	TAILQ_FOREACH(aw, &autowhite_head, a_list) {
		localtime_r((time_t *)&aw->a_tv.tv_sec, &tm);
		strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);

		iptostring(aw->a_sa, aw->a_salen, textaddr, sizeof(textaddr));

		fprintf(stream, 
		    "%s\t%s\t%s\t%ld AUTO # %s\n",
		    textaddr, aw->a_from, aw->a_rcpt, 
		    (long)aw->a_tv.tv_sec, textdate);

		done++;
	}
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

	TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);

	return aw;
}

void
autowhite_put(aw)	/* autowhite list must be write-locked */
	struct autowhite *aw;
{
	TAILQ_REMOVE(&autowhite_head, aw, a_list);	
	free(aw->a_sa);
	free(aw->a_from);
	free(aw->a_rcpt);
	free(aw);

	return;
}
