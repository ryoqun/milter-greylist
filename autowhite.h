/* $Id: autowhite.h,v 1.13 2004/05/23 13:03:41 manu Exp $ */

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

#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_DB_185_H
#include <db_185.h>
#else 
#include <db.h>
#endif

#ifndef AUTOWHITE_VALIDITY
#define AUTOWHITE_VALIDITY (24 * 3600) /* 1 day */
#endif

#define AUTOWHITE_WRLOCK WRLOCK(autowhite_lock) 
#define AUTOWHITE_RDLOCK RDLOCK(autowhite_lock) 
#define AUTOWHITE_UNLOCK UNLOCK(autowhite_lock)

#ifndef KEYLEN
#define KEYLEN 1024
#endif

struct autowhite {
	struct in_addr a_in;
	char a_from[ADDRLEN + 1];
	char a_rcpt[ADDRLEN + 1];
	time_t a_expire;
};

typedef enum {AS_COLD, AS_WARM} autowhite_startup_t;

extern DB *aw_db;
extern pthread_rwlock_t autowhite_lock;

int autowhite_init(void);
void autowhite_get(struct in_addr *, char *, 
    char *, time_t *, struct autowhite *);
void autowhite_put(char *);
void autowhite_add(struct in_addr *, char *, char *, time_t *, char *);
int autowhite_check(struct in_addr *, char *, char *, char *);
char *autowhite_makekey(char *, size_t, struct in_addr *, char *, char *);
int autowhite_update(int, FILE *);
int autowhite_db_options(autowhite_startup_t);
void autowhite_destroy(void);
void autowhite_shutdown(void);

#endif /* _AUTOWHITE_H_ */
