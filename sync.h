/* $Id: sync.h,v 1.3 2004/03/10 16:07:07 manu Exp $ */

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

#define CMDLEN 10
#define LINELEN 512

#define MXGLSYNC_NAME "mxglsync"
#define MXGLSYNC_PORT 5252

#define MXGLSYNC_BACKLOG 5 /* Maximum connexions */

LIST_HEAD(peerlist, peer);

struct peer {
	char p_name[IPADDRLEN + 1];
	struct in_addr p_addr;
	FILE *p_stream;
	int p_socket;
	LIST_ENTRY(peer) p_list;
};

typedef enum { PS_CREATE, PS_DELETE } peer_sync_t;

int peer_init(void);
void peer_clear(void);
void peer_add(struct in_addr *);
int peer_connect(struct peer *);
void peer_send(struct peer *, peer_sync_t,  struct pending *);
void peer_create(struct pending *);
void peer_delete(struct pending *);

void sync_master_restart(void);
void sync_master(void *);
void sync_server(void *);
void sync_help(FILE *);
int sync_waitdata(int);


#endif /* _MXGLSYNC_H_ */
