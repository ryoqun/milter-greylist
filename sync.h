/* $Id: sync.h,v 1.8 2004/03/21 23:51:47 manu Exp $ */

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

#ifndef _MXGLSYNC_H_
#define _MXGLSYNC_H_

#include "pending.h"
#include "milter-greylist.h"

#define SYNC_MAXQLEN	1024

#define CMDLEN 10
#define LINELEN 512

#define MXGLSYNC_NAME "mxglsync"
#define MXGLSYNC_PORT 5252

#define MXGLSYNC_BACKLOG 5 /* Maximum connexions */

#ifdef HAVE_MISSING_SOCKLEN_T
typedef unsigned int socklen_t;
#endif

#define PEER_WRLOCK WRLOCK(peer_lock);
#define PEER_RDLOCK RDLOCK(peer_lock);
#define PEER_UNLOCK UNLOCK(peer_lock);

#define SYNC_WRLOCK WRLOCK(sync_lock);
#define SYNC_RDLOCK RDLOCK(sync_lock);
#define SYNC_UNLOCK UNLOCK(sync_lock);

LIST_HEAD(peerlist, peer);
TAILQ_HEAD(synclist, sync);

struct peer {
	char p_name[IPADDRLEN + 1];
	struct in_addr p_addr;
	FILE *p_stream;
	int p_socket;
	struct synclist p_deferred;
	LIST_ENTRY(peer) p_list;
	size_t p_qlen;
};

typedef enum { PS_CREATE, PS_DELETE } peer_sync_t;

struct sync {
	struct peer *s_peer;
	struct pending s_pending;
	peer_sync_t s_type;
	TAILQ_ENTRY(sync) s_list;
};

int peer_init(void);
void peer_clear(void);
void peer_add(struct in_addr *);
int peer_connect(struct peer *);
void peer_create(struct pending *);
void peer_delete(struct pending *);

int sync_send(struct peer *, peer_sync_t,  struct pending *);
void sync_sender_start(void);
void sync_queue(struct peer *, peer_sync_t, struct pending *);

void sync_sender(void *);
void sync_master_restart(void);
void sync_master(void *);
void sync_server(void *);
void sync_help(FILE *);
int sync_waitdata(int);


#endif /* _MXGLSYNC_H_ */
