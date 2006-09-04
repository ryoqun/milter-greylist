/* $Id: pending.h,v 1.37.2.1 2006/09/04 22:05:59 manu Exp $ */

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
#ifndef _PENDING_H_
#define _PENDING_H_

#include "config.h"
#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef GLDELAY
#define GLDELAY	1800	/* 1800 seconds = 30 minutes */
#endif

#ifndef TIMEOUT
#define TIMEOUT (3600 * 24 * 5) /* 432000 seconds = 5 days */
#endif

#ifndef PENDING_BUCKETS
#define PENDING_BUCKETS 32768
#endif

#include "milter-greylist.h"

#define PENDING_WRLOCK WRLOCK(pending_lock)
#define PENDING_RDLOCK RDLOCK(pending_lock)
#define PENDING_UNLOCK UNLOCK(pending_lock)

TAILQ_HEAD(pendinglist, pending);

struct pending {
	char *p_addr;
	struct sockaddr *p_sa;
	socklen_t p_salen;
	char *p_from;
	char *p_rcpt;
	struct timeval p_tv;
	int p_refcnt;
	TAILQ_ENTRY(pending) p_list;
	TAILQ_ENTRY(pending) pb_list;
};

struct pending_bucket {
	pthread_mutex_t	bucket_mtx;
	TAILQ_HEAD(, pending) b_pending_head;
};

extern pthread_rwlock_t pending_lock;
extern pthread_mutex_t pending_change_lock;

void pending_init(void);
struct pending *pending_get(struct sockaddr *, socklen_t, char *, char *,
    time_t);
int pending_check(struct sockaddr *, socklen_t, char *, char *, time_t *,
    time_t *, char *, time_t, time_t);
void pending_del(struct sockaddr *, socklen_t, char *, char *, time_t);
void pending_put(struct pending *);
int pending_textdump(FILE *);
struct pending *pending_ref(struct pending *);
void pending_free(struct pending *);
int ip_match(struct sockaddr *, struct sockaddr *, ipaddr *);
int ip_equal(struct sockaddr *, struct sockaddr *);
char *iptostring(struct sockaddr *, socklen_t, char *, size_t);
int ipfromstring(char *, struct sockaddr *, socklen_t *, sa_family_t);
void pending_del_addr(struct sockaddr *, socklen_t, char *, int);


#endif /* _PENDING_H_ */
