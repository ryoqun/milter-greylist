/* $Id: autowhite.h,v 1.1 2004/03/16 23:16:52 manu Exp $ */

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

#ifndef _AUTOWHITE_H_
#define _AUTOWHITE_H_

#include "milter-greylist.h"

#define AUTOWHITE_VALIDITY (24 * 2600) /* 1 day */

#define AUTOWHITE_WRLOCK WRLOCK(autowhite_lock) 
#define AUTOWHITE_RDLOCK RDLOCK(autowhite_lock) 
#define AUTOWHITE_UNLOCK UNLOCK(autowhite_lock)

TAILQ_HEAD(autowhitelist, autowhite);

struct autowhite {
	struct in_addr a_in;
	char a_from[ADDRLEN + 1];
	char a_rcpt[ADDRLEN + 1];
	struct timeval a_tv;
	TAILQ_ENTRY(autowhite) a_list;
};

int autowhite_init(void);
void autowhite_add(struct in_addr *, char *, char *);
int autowhite_check(struct in_addr *, char *, char *);

#endif /* _AUTOWHITE_H_ */