/* $Id: milter-greylist.h,v 1.26 2004/04/01 07:16:30 manu Exp $ */

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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <libmilter/mfapi.h>
#include "config.h"
#include "dump.h"

#define NUMLEN 20
#define PATHLEN 1024
#define HDRLEN 160
#define HEADERNAME "X-Greylist"

struct mlfi_priv {
	struct in_addr priv_addr;
	char priv_from[ADDRLEN + 1];
	time_t priv_elapsed;
	int priv_whitelist;
	char *priv_queueid;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_envrcpt(SMFICTX *, char **);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
void usage(char *);
int humanized_atoi(char *);
in_addr_t *cidr2mask(int, in_addr_t *);
void cleanup_sock(char *);
int main(int, char **);

/*
 * Locking management
 */
#define WRLOCK(lock) if (pthread_rwlock_wrlock(&(lock)) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_wrlock failed: %s", \
		    __FILE__, __LINE__, strerror(errno));		  \
		exit(EX_SOFTWARE);					  \
	}
#define RDLOCK(lock) if (pthread_rwlock_rdlock(&(lock)) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_rdlock failed: %s", \
		    __FILE__, __LINE__, strerror(errno));		  \
		exit(EX_SOFTWARE);					  \
	}

/*
 * There is a bug in GNU pth-2.0.0 that will cause a spurious EPERM
 * error when a thread releases a read lock that has been shared by
 * two threads and already released by the other one. As a workaround
 * for that problem, we just avoid quitting on this error.
 */
#ifndef HAVE_BROKEN_RWLOCK
#define UNLOCK(lock) if (pthread_rwlock_unlock(&(lock)) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_unlock failed: %s", \
		    __FILE__, __LINE__, strerror(errno));		  \
		exit(EX_SOFTWARE);					  \
	}
#else
#define UNLOCK(lock) if (pthread_rwlock_unlock(&(lock)) != 0) {		  \
		syslog(LOG_DEBUG, "%s:%d pthread_rwlock_unlock failed: "  \
		    "%s (ignored)", __FILE__, __LINE__, strerror(errno)); \
	}
#endif

/*
 * Some systems don't know about LOG_PERROR. By defining it
 * to zero, we make it nilpotent
 */
#ifdef HAVE_MISSING_LOG_PERROR
#define LOG_PERROR 0
#endif

#ifdef HAVE_MISSING_TIMERADD
#define	timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (/* CONSTCOND */ 0)
#endif

#endif /* _MILTER_GREYLIST_H_ */

