/* $Id: autowhite.c,v 1.19.2.1 2004/05/06 13:54:00 manu Exp $ */

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
__RCSID("$Id: autowhite.c,v 1.19.2.1 2004/05/06 13:54:00 manu Exp $");
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

	TAILQ_INIT(&autowhite_head);
	pthread_rwlock_init(&autowhite_lock, NULL);

	return;
}

void
autowhite_add(in, from, rcpt, date, queueid)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t *date;
	char *queueid;
{
	struct autowhite *aw = NULL;
	struct autowhite *prev_aw = NULL;
	struct timeval now, delay;
	char addr[IPADDRLEN + 1];
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

	inet_ntop(AF_INET, in, addr, IPADDRLEN);

	AUTOWHITE_WRLOCK;
	if (!TAILQ_EMPTY(&autowhite_head)) {
		TAILQ_FOREACH(aw, &autowhite_head, a_list) {

			/*
			 * Expiration
			 */
			if (aw->a_tv.tv_sec < now.tv_sec) {
				autowhite_put(aw);
				aw = NULL;

				dirty++;

				syslog(LOG_INFO, "addr %s from %s rcpt %s: "
				    "autowhitelisted entry expired",
				    addr, from, rcpt);

				if (TAILQ_EMPTY(&autowhite_head))
					break;
				if ((aw = prev_aw) == NULL)
					aw = TAILQ_FIRST(&autowhite_head);
				continue;
			}
			prev_aw = aw;

			/*
			 * Look for an already existing entry
			 */
			if ((in->s_addr == aw->a_in.s_addr) &&
			    (strncmp(from, aw->a_from, ADDRLEN) == 0) &&
			    (strncmp(rcpt, aw->a_rcpt, ADDRLEN) == 0)) {
				timeradd(&now, &delay, &aw->a_tv);

				dirty++;

				syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
				    "autowhitelisted for more %02d:%02d:%02d", 
				    queueid, addr, from, rcpt, h, mn, s);
				break;
			}
		}		
	}

	/* 
	 * Entry not found, create it 
	 */
	if (aw == NULL) {
		aw = autowhite_get(in, from, rcpt, date);

		dirty++;

		syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
		    "autowhitelisted for %02d:%02d:%02d", 
		    queueid, addr, from, rcpt, h, mn, s);
	}
	AUTOWHITE_UNLOCK;

	if (dirty != 0) {
		dump_dirty += dirty;
		dump_flush();
	}

	return;
}

int
autowhite_check(in, from, rcpt, queueid)
	struct in_addr *in;
	char *from;
	char *rcpt;
	char *queueid;
{
	struct autowhite *aw = NULL;
	struct autowhite *prev_aw = NULL;
	struct timeval now, delay;
	char addr[IPADDRLEN + 1];
	time_t autowhite_validity;
	int h, mn, s;
	int dirty = 0;

	if ((autowhite_validity = conf.c_autowhite_validity) == 0)
		return EXF_NONE;

	gettimeofday(&now, NULL);
	delay.tv_sec = autowhite_validity;
	delay.tv_usec = 0;

	h = autowhite_validity / 3600;
	mn = ((autowhite_validity % 3600) / 60);
	s = (autowhite_validity % 3600) % 60;

	inet_ntop(AF_INET, in, addr, IPADDRLEN);

	AUTOWHITE_WRLOCK;
	if (!TAILQ_EMPTY(&autowhite_head)) {
		TAILQ_FOREACH(aw, &autowhite_head, a_list) {
			/* 
			 * Do expiration first as we don't want
			 * an outdated record to match
			 */
			if (aw->a_tv.tv_sec < now.tv_sec) {
				autowhite_put(aw);
				aw = NULL;

				dirty++;

				syslog(LOG_INFO, "addr %s from %s rcpt %s: "
				    "autowhitelisted entry expired",
				    addr, from, rcpt);

				if (TAILQ_EMPTY(&autowhite_head))
					break;
				if ((aw = prev_aw) == NULL)
					aw = TAILQ_FIRST(&autowhite_head);
				continue;
			}
			prev_aw = aw;

			/*
			 * Look for our record
			 */
			if ((IP_MATCH(in, &aw->a_in)) &&
			    (strncmp(from, aw->a_from, ADDRLEN) == 0) &&
			    (strncmp(rcpt, aw->a_rcpt, ADDRLEN) == 0)) {
				timeradd(&now, &delay, &aw->a_tv);

				dirty++;

				syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
				    "autowhitelisted for more %02d:%02d:%02d", 
				    queueid, addr, from, rcpt, h, mn, s);
				break;
			}
		}
	}
	AUTOWHITE_UNLOCK;

	if (dirty != 0) {
		dump_dirty += dirty;
		dump_flush();
	}

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
	char textaddr[IPADDRLEN + 1];
	struct tm tm;

	fprintf(stream, "\n\n#\n# Auto-whitelisted tuples\n#\n");
	fprintf(stream, "# Sender IP    %32s    %32s    Expire\n",
	    "Sender e-mail", "Recipient e-mail");

	AUTOWHITE_RDLOCK;
	TAILQ_FOREACH(aw, &autowhite_head, a_list) {
		localtime_r((time_t *)&aw->a_tv.tv_sec, &tm);
		strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);

		inet_ntop(AF_INET, &aw->a_in, textaddr, IPADDRLEN);

		fprintf(stream, 
		    "%s     %32s    %32s    %ld AUTO # %s\n",
		    textaddr, aw->a_from, aw->a_rcpt, 
		    (long)aw->a_tv.tv_sec, textdate);
	}
	AUTOWHITE_UNLOCK;

	return done;
}

struct autowhite *
autowhite_get(in, from, rcpt, date) /* autowhite list must be locked */
	struct in_addr *in;
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

	aw->a_in.s_addr = in->s_addr;
	strncpy(aw->a_from, from, ADDRLEN);
	aw->a_from[ADDRLEN] = '\0';
	strncpy(aw->a_rcpt, rcpt, ADDRLEN);
	aw->a_rcpt[ADDRLEN] = '\0';

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
	free(aw);

	return;
}
