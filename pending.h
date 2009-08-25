/* $Id: pending.h,v 1.39 2009/04/21 03:28:45 manu Exp $ */
/* vim: set sw=8 ts=8 sts=8 noet cino=(0: */

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

#ifndef AUTOWHITE_VALIDITY
#define AUTOWHITE_VALIDITY (24 * 3600) /* 1 day */
#endif

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

typedef enum {
	T_NONEANDFIRST = 3,
	T_AUTOWHITE = 2,
	T_PENDING = 1,
	T_NONE = 0
} tuple_t;

TAILQ_HEAD(pendinglist, pending);

struct pending {
	char *p_addr;
	struct sockaddr *p_sa;
	socklen_t p_salen;
	char *p_from;
	char *p_rcpt;
	struct timeval p_tv;	/* activation time for pending, 
				   expiration time for autowhite */
	int p_refcnt;		/* mutex; pending entry is 
				   shared with sync queue */
        tuple_t	p_type;		/* pending or autowhite entry? */
	TAILQ_ENTRY(pending) p_list;
	TAILQ_ENTRY(pending) pb_list;
};

struct pending_bucket {
	TAILQ_HEAD(, pending) b_pending_head;
};

typedef struct {
	int pending;
	int autowhite;
} tuple_cnt_t;

#define PENDING_LOCK pthread_mutex_lock(&pending_lock);
#define PENDING_UNLOCK pthread_mutex_unlock(&pending_lock);
extern pthread_mutex_t pending_lock;

void pending_init(void);
struct pending *pending_get(struct sockaddr *, socklen_t, char *, char *,
    time_t, tuple_t);
tuple_t pending_check(struct sockaddr *, socklen_t, char *, char *, 
    time_t *, time_t *, char *, time_t, time_t);
void pending_force(struct sockaddr *, socklen_t, char *, char *, 
    char *, time_t, time_t, tuple_t);
void pending_del(struct sockaddr *, socklen_t, char *, char *, time_t, 
    time_t);
void pending_rem(struct pending *);
void pending_put(struct pending *, time_t);
tuple_cnt_t pending_textdump(FILE *);
struct pending *pending_ref(struct pending *);
void pending_free(struct pending *);
int ip_match(struct sockaddr *, struct sockaddr *, ipaddr *);
int ip_equal(struct sockaddr *, struct sockaddr *);
char *iptostring(struct sockaddr *, socklen_t, char *, size_t);
int ipfromstring(char *, struct sockaddr *, socklen_t *, sa_family_t);
void pending_del_addr(struct sockaddr *, socklen_t, char *, int);


#endif /* _PENDING_H_ */
