/* $Id: autowhite.c,v 1.1 2004/03/16 23:16:52 manu Exp $ */

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
__RCSID("$Id: autowhite.c,v 1.1 2004/03/16 23:16:52 manu Exp $");
#endif

#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <string.h>
#include <strings.h>

#include <sys/queue.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "except.h"
#include "autowhite.h"

struct autowhitelist autowhite_head;
pthread_rwlock_t autowhite_lock;

int
autowhite_init(void) {
	int error;

	TAILQ_INIT(&autowhite_head);

	if ((error = pthread_rwlock_init(&autowhite_lock, NULL)) == 0)
		return error;

	return 0;
}

void
autowhite_add(in, from, rcpt)
	struct in_addr *in;
	char *from;
	char *rcpt;
{
	struct autowhite *aw = NULL;
	struct timeval tv1, tv2, tv3;
	char addr[IPADDRLEN + 1];

	gettimeofday(&tv1,NULL);
	tv2.tv_sec = AUTOWHITE_VALIDITY;
	tv2.tv_usec = 0;
	timeradd(&tv1, &tv2, &tv3);

	inet_ntop(AF_INET, in, addr, IPADDRLEN);

	AUTOWHITE_WRLOCK;
	if (!TAILQ_EMPTY(&autowhite_head)) {
		TAILQ_FOREACH(aw, &autowhite_head, a_list) {
			if ((in->s_addr == aw->a_in.s_addr) &&
			    (strncmp(from, aw->a_from, ADDRLEN) == 0) &&
			    (strncmp(rcpt, aw->a_rcpt, ADDRLEN) == 0)) {
				aw->a_tv.tv_sec = tv3.tv_sec;
				syslog(LOG_INFO, "addr %s from %s rcpt %s: "
				    "autowhitelisted for one more day", 
				    addr, from, rcpt);
				break;
			}

			if (aw->a_tv.tv_sec < tv1.tv_sec) {
				TAILQ_REMOVE(&autowhite_head, aw, a_list);
				syslog(LOG_INFO, "addr %s from %s rcpt %s: "
				    "autowhitelisted entry expired",
				    addr, from, rcpt);
			}
		}
	}

	if (aw == NULL) {
		if ((aw = malloc(sizeof(*aw))) == NULL) {
			syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		bzero(aw, sizeof(*aw));

		aw->a_in.s_addr = in->s_addr;
		strncpy(aw->a_from, from, ADDRLEN);
		aw->a_from[ADDRLEN] = '\0';
		strncpy(aw->a_rcpt, rcpt, ADDRLEN);
		aw->a_rcpt[ADDRLEN] = '\0';
		aw->a_tv.tv_sec = tv3.tv_sec;
		TAILQ_INSERT_TAIL(&autowhite_head, aw, a_list);

		syslog(LOG_INFO, "addr %s from %s rcpt %s: "
		    "autowhitelisted for a day", addr, from, rcpt);
	}
	AUTOWHITE_UNLOCK;

	return;
}

int
autowhite_check(in, from, rcpt)
	struct in_addr *in;
	char *from;
	char *rcpt;
{
	struct autowhite *aw = NULL;
	struct timeval tv1, tv2, tv3;
	char addr[IPADDRLEN + 1];

	gettimeofday(&tv1,NULL);
	tv2.tv_sec = AUTOWHITE_VALIDITY;
	tv2.tv_usec = 0;
	timeradd(&tv1, &tv2, &tv3);

	inet_ntop(AF_INET, in, addr, IPADDRLEN);

	AUTOWHITE_WRLOCK;
	if (!TAILQ_EMPTY(&autowhite_head)) {
		TAILQ_FOREACH(aw, &autowhite_head, a_list) {
			if ((in->s_addr == aw->a_in.s_addr) &&
			    (strncmp(from, aw->a_from, ADDRLEN) == 0) &&
			    (strncmp(rcpt, aw->a_rcpt, ADDRLEN) == 0)) {
				aw->a_tv.tv_sec = tv3.tv_sec;
				break;
			}

			if (aw->a_tv.tv_sec < tv1.tv_sec) {
				TAILQ_REMOVE(&autowhite_head, aw, a_list);
				syslog(LOG_INFO, "addr %s from %s rcpt %s: "
				    "autowhitelisted entry expired",
				    addr, from, rcpt);
			}
		}
	}
	AUTOWHITE_UNLOCK;

	if (aw != NULL) 
		return EXF_AUTO;	

	return EXF_NONE;
}


