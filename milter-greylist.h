/* $Id: milter-greylist.h,v 1.9 2004/03/04 09:40:12 manu Exp $ */

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

#ifndef _MILTER_GREYLIST_H_
#define _MILTER_GREYLIST_H_

#include <libmilter/mfapi.h>

#define HDRLEN 160
#define HEADERNAME "X-Greylist"

struct mlfi_priv {
	struct in_addr priv_addr;
	char priv_from[ADDRLEN + 1];
	long priv_elapsed;
	int priv_whitelist;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_envrcpt(SMFICTX *, char **);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
void usage(char *);
void cleanup_sock(char *);

/* 
 * Theses definitions are missing from Linux's <sys/queue.h>
 */
#ifndef TAILQ_FOREACH
#define TAILQ_FOREACH(var, head, field)			\
	for ((var) = ((head)->tqh_first);		\
		(var);					\
		(var) = ((var)->field.tqe_next))
#endif

#ifndef LIST_FOREACH
#define LIST_FOREACH(var, head, field)			\
	for ((var) = ((head)->lh_first);		\
		(var);					\
		(var) = ((var)->field.le_next))
#endif

#ifndef LIST_FIRST
#define LIST_FIRST(head)                ((head)->lh_first)
#endif

#ifndef LIST_EMPTY
#define LIST_EMPTY(head)                ((head)->lh_first == NULL)
#endif
		
#endif /* _MILTER_GREYLIST_H_ */
