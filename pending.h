/* $Id: pending.h,v 1.7 2004/03/08 21:58:21 manu Exp $ */

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

#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef DELAY
#define DELAY	1800	/* 1800 seconds = 30 minutes */
#endif

#ifndef TIMEOUT
#define TIMEOUT (3600 * 24 * 5) /* 432000 seconds = 5 days */
#endif

#ifndef DUMPFILE
#define DUMPFILE "/var/milter-greylist/greylist.db"
#endif

#define ADDRLEN	31
#define IPADDRLEN sizeof("255.255.255.255")

TAILQ_HEAD(pendinglist, pending);

struct pending {
	char p_addr[IPADDRLEN + 1];
	struct in_addr p_in;
	char p_from[ADDRLEN + 1];
	char p_rcpt[ADDRLEN + 1];
	struct timeval p_tv;
	TAILQ_ENTRY(pending) p_list;
};

extern FILE *dump_in;
extern int dump_line;
extern int delay;
extern char *dumpfile;

int pending_init(void);
struct pending *pending_get(struct in_addr *, char *, char *, time_t);
int pending_check(struct in_addr *, char *, char *, time_t *, time_t *);
void pending_put(struct pending *);
void pending_log(struct pending *);
void pending_textdump(FILE *);
void pending_import(FILE *);
void pending_flush(void);
void pending_reload(void);

#endif /* _PENDING_H_ */
