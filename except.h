/* $Id: except.h,v 1.21 2004/04/13 08:31:50 manu Exp $ */

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

#ifndef _EXCEPT_H_
#define _EXCEPT_H_

#include "config.h"
#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

#include "pending.h"
#include "milter-greylist.h"

#define EXCEPT_WRLOCK WRLOCK(except_lock) 
#define EXCEPT_RDLOCK RDLOCK(except_lock) 
#define EXCEPT_UNLOCK UNLOCK(except_lock)

LIST_HEAD(exceptlist, except);

typedef enum { E_NETBLOCK, E_FROM, E_RCPT, E_FROM_RE, E_RCPT_RE } except_type_t;
#define e_addr e_data.d_netblock.nb_addr
#define e_mask e_data.d_netblock.nb_mask
#define e_from e_data.d_from
#define e_rcpt e_data.d_rcpt
#define e_from_re e_data.d_from_re
#define e_rcpt_re e_data.d_rcpt_re
struct except {
	except_type_t e_type;
	union {
		struct {
			struct in_addr nb_addr;
			struct in_addr nb_mask;
		} d_netblock;
		char d_from[ADDRLEN + 1];
		char d_rcpt[ADDRLEN + 1];
		regex_t d_from_re;
		regex_t d_rcpt_re;
	} e_data;
	LIST_ENTRY(except) e_list;
};

extern int testmode;
extern pthread_rwlock_t except_lock;

int except_init(void);
void except_clear(void);
void except_add_netblock(struct in_addr *, int);
void except_add_from(char *);
void except_add_rcpt(char *);
void except_add_from_regex(char *);
void except_add_rcpt_regex(char *);
int except_rcpt_filter(char *, char *);
int except_sender_filter(struct in_addr *, char *, char *);

/* except_filter() return codes */
#define EXF_UNSET	0
#define EXF_ADDR	1
#define EXF_FROM	2
#define EXF_RCPT	3
#define EXF_AUTO	4
#define EXF_NONE	5
#define EXF_AUTH	6
#define EXF_SPF		7
#define EXF_NONIPV4	8

#endif /* _EXCEPT_H_ */
