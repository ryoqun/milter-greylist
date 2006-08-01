/* $Id: autowhite.h,v 1.19 2006/08/01 14:55:20 manu Exp $ */

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

#ifndef AUTOWHITE_VALIDITY
#define AUTOWHITE_VALIDITY (24 * 3600) /* 1 day */
#endif

#ifndef AUTOWHITE_BUCKETS
#define AUTOWHITE_BUCKETS 512
#endif

#define AUTOWHITE_WRLOCK WRLOCK(autowhite_lock) 
#define AUTOWHITE_RDLOCK RDLOCK(autowhite_lock) 
#define AUTOWHITE_UNLOCK UNLOCK(autowhite_lock)

TAILQ_HEAD(autowhitelist, autowhite);

struct autowhite {
	struct sockaddr *a_sa;
	socklen_t a_salen;
	char *a_from;
	char *a_rcpt;
	struct timeval a_tv;
	TAILQ_ENTRY(autowhite) a_list;
	TAILQ_ENTRY(autowhite) ab_list;
};

struct autowhite_bucket {
	pthread_mutex_t	bucket_mtx;
	TAILQ_HEAD(, autowhite) b_autowhite_head;
};

extern pthread_rwlock_t autowhite_lock;
extern pthread_mutex_t autowhite_change_lock;

void autowhite_init(void);
struct autowhite *autowhite_get(struct sockaddr *, socklen_t, char *, char *,
    time_t);
void autowhite_put(struct autowhite *);
void autowhite_add(struct sockaddr *, socklen_t, char *, char *, time_t *,
    char *);
int autowhite_check(struct sockaddr *, socklen_t, char *, char *, 
    char *, time_t, time_t);
int autowhite_textdump(FILE *);
void autowhite_del_addr(struct sockaddr *, socklen_t);

#endif /* _AUTOWHITE_H_ */
