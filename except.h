/* $Id: except.h,v 1.7 2004/02/29 22:35:09 manu Exp $ */

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

#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pending.h"
#include "config.h"

#ifndef EXCEPTFILE
#define EXCEPTFILE "/etc/mail/greylist.except"
#endif

LIST_HEAD(exceptlist, except);

typedef enum { E_NETBLOCK, E_FROM, E_RCPT } except_type_t;
#define e_addr e_data.d_netblock.nb_addr
#define e_mask e_data.d_netblock.nb_mask
#define e_from e_data.d_from
#define e_rcpt e_data.d_rcpt
struct except {
	except_type_t e_type;
	union {
		struct {
			struct in_addr nb_addr;
			struct in_addr nb_mask;
		} d_netblock;
		char d_from[ADDRLEN + 1];
		char d_rcpt[ADDRLEN + 1];
	} e_data;
	LIST_ENTRY(except) e_list;
};

extern char *exceptfile;
extern int testmode;

int except_init(void);
void except_load(void);
void except_add_netblock(struct in_addr *, int);
void except_add_from(char *);
void except_add_rcpt(char *);
int except_filter(struct in_addr *, char *, char *);

extern FILE *except_in;
extern int except_line;
int except_parse(void);

#endif /* _EXCEPT_H_ */
