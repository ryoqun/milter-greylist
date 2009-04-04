/* $Id: sync.h,v 1.22 2009/04/04 03:09:43 manu Exp $ */
/* vim: set sw=8 ts=8 sts=8 noet cino=(0: */

/*
 * Copyright (c) 2004-2007 Emmanuel Dreyfus
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

#ifndef _SYNC_H_
#define _SYNC_H_

#include "pending.h"
#include "milter-greylist.h"

#ifndef SYNC_MAXQLEN
#define SYNC_MAXQLEN	1024
#endif

#define CMDLEN 10
#define LINELEN 512

#define MXGLSYNC_NAME "mxglsync"
#define MXGLSYNC_PORT "5252"

#define MXGLSYNC_BACKLOG 5 /* Maximum connections */

/* socket communication default time out */
#define COM_TIMEOUT 3

#ifdef HAVE_MISSING_SOCKLEN_T
typedef unsigned int socklen_t;
#endif

#define PEER_WRLOCK WRLOCK(peer_lock);
#define PEER_RDLOCK RDLOCK(peer_lock);
#define PEER_UNLOCK UNLOCK(peer_lock);

LIST_HEAD(peerlist, peer);
TAILQ_HEAD(synclist, sync);

struct peer {
	char *p_name;
	FILE *p_stream;
	int p_socket;
	time_t p_socket_timeout;
	/* p_mtx protects p_deferred and p_qlen.
	 * peer list must be read or rw locked before. */
	pthread_mutex_t p_mtx;
	struct synclist p_deferred;
	LIST_ENTRY(peer) p_list;
	unsigned int p_qlen;
	int p_flags;
	int p_vers;
};

#define P_LOCAL	1

typedef enum { PS_CREATE, PS_DELETE, PS_DELETE2, PS_FLUSH } peer_sync_t;

struct sync {
	struct peer *s_peer;
	struct pending *s_pending;
	peer_sync_t s_type;
	time_t s_autowhite;
	TAILQ_ENTRY(sync) s_list;
};

void peer_init(void);
void peer_clear(void);
void peer_add(char *, time_t);
int peer_connect(struct peer *);
void peer_create(struct pending *);
void peer_delete(struct pending *, time_t);
void peer_flush(struct pending *);

int sync_send(struct peer *, peer_sync_t,  struct pending *, time_t);
void sync_sender_start(void);
void sync_queue(struct peer *, peer_sync_t, struct pending *, time_t);
void sync_free(struct sync *);

void sync_sender(void *);
void sync_master_restart(void);
void sync_master_stop(void);
void *sync_master(void *);
void sync_server(void *);
void sync_help(FILE *);
int sync_waitdata(int, time_t);


#endif /* _SYNC_H_ */
