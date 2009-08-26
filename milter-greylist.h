/* $Id: milter-greylist.h,v 1.77 2008/11/26 05:20:13 manu Exp $ */

/*
 * Copyright (c) 2004-2007 Emmanuel Dreyfus
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef USE_DKIM
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
#include <dkim.h>
#endif

#include <libmilter/mfapi.h>
#include "config.h"
#include "dump.h"

/* environment of Solaris workaround for stdio descriptor limitation */
#include "fd_pool.h"

#define NUMLEN 20
#define QSTRLEN 1024
#define REGEXLEN 1024
#define HDRLEN 1024
#define HEADERNAME "X-Greylist"
/* 
 * Maximum URL length. This is just a hint, 
 * the code will adjust the buffer if needed.
 */
#define URLMAXLEN	2083

LIST_HEAD(urlchecklist, urlcheck_entry);



#if defined(HAVE_GETNAMEINFO)
#define IPADDRSTRLEN	NI_MAXHOST
#elif defined(INET6_ADDRSTRLEN)
#define IPADDRSTRLEN	INET6_ADDRSTRLEN
#else
#define IPADDRSTRLEN	IPADDRLEN
#endif

typedef union {
	struct in_addr in4;
#ifdef AF_INET6
	struct in6_addr in6;
#endif
} ipaddr;

typedef union {
	struct sockaddr sa;
	struct sockaddr_in sin;
#ifdef AF_INET6
	struct sockaddr_in6 sin6;
#endif
} sockaddr_t;

#define SA(sa)		((struct sockaddr *)(sa))
#define SA4(sa)		((struct sockaddr_in *)(sa))
#define SADDR4(sa)	(&SA4(sa)->sin_addr)
#ifdef AF_INET6
#define SA6(sa)		((struct sockaddr_in6 *)(sa))
#define SADDR6(sa)	(&SA6(sa)->sin6_addr)
#endif

/* Notes:
 * -For IPv6 not using s6_addr32 as Solaris 8 for some reason has it only 
 *  defined for its kernel... 
 * -Using also first two characters in "from" and "rcpt" to distribute 
 *  potentially lot of triplets coming from a single host (first two chars 
 *  only because "<>" is the "shortest" email address)
 */
#define F2B(s) (tolower((int)*(s)) | (tolower((int)*((s)+1)) << 8))
#define F2B_SPICE(from, rcpt) (conf.c_lazyaw ? 0 : (F2B(from) ^ F2B(rcpt)))

#define BUCKET_HASH_V4(v4a, v4m, from, rcpt, bucket_count) 	\
  ((ntohl((v4a)->s_addr & (v4m)->s_addr)			\
    ^ F2B_SPICE(from, rcpt))					\
   % bucket_count) 

#ifdef AF_INET6
#define IN6CAST32(_a) ((uint32_t *)(&(_a)->s6_addr))

#define BUCKET_HASH_V6(v6a, v6m, from, rcpt, bucket_count)	\
  ((ntohl(IN6CAST32(v6a)[0] & IN6CAST32(v6m)[0]) ^		\
    ntohl(IN6CAST32(v6a)[1] & IN6CAST32(v6m)[1]) ^		\
    ntohl(IN6CAST32(v6a)[2] & IN6CAST32(v6m)[2]) ^		\
    ntohl(IN6CAST32(v6a)[3] & IN6CAST32(v6m)[3])		\
    ^ F2B_SPICE(from, rcpt))					\
   % bucket_count)

#define BUCKET_HASH(sa, from, rcpt, bucket_count)		\
  (sa->sa_family == AF_INET ?					\
   BUCKET_HASH_V4(SADDR4(sa), 					\
		  &conf.c_match_mask,				\
		  from, rcpt, bucket_count)			\
   : sa->sa_family == AF_INET6 ? 				\
   BUCKET_HASH_V6(SADDR6(sa),					\
		  &conf.c_match_mask6, 				\
		  from, rcpt, bucket_count)			\
   : 0)

#else /* AF_INET6 */

#define BUCKET_HASH(sa, from, rcpt, bucket_count) 		\
  (sa->sa_family == AF_INET ?					\
   BUCKET_HASH_V4(SADDR4(sa), 					\
		  &conf.c_match_mask,				\
		  from, rcpt, bucket_count)			\
   : 0)

#endif

struct smtp_reply {
	int sr_whitelist;
	int sr_nowhitelist;
	time_t sr_elapsed;
	time_t sr_remaining;
	int sr_acl_line;
	char *sr_acl_id;
	time_t sr_delay;
	time_t sr_autowhite;
	char *sr_code;
	char *sr_ecode;
	char *sr_msg;
	char *sr_msg_x;
	char *sr_report;
	char *sr_report_x;
	char *sr_addheader;
	sfsistat sr_retcode;
	int sr_nmatch;
	char **sr_pmatch;
};

struct rcpt {
	char r_addr[ADDRLEN + 1];
	LIST_ENTRY(rcpt) r_list;
};

struct header {
	char *h_line;
	TAILQ_ENTRY(header) h_list;
};

struct body {
	char *b_lines;
	TAILQ_ENTRY(body) b_list;
};

struct mlfi_priv {
	SMFICTX *priv_ctx;
	sockaddr_t priv_addr;
	socklen_t priv_addrlen;
	char priv_hostname[ADDRLEN + 1];
	char priv_helo[ADDRLEN + 1];
	char priv_from[ADDRLEN + 1];
	LIST_HEAD(, rcpt) priv_rcpt;
	char *priv_cur_rcpt;
	int priv_rcptcount;
	TAILQ_HEAD(, header) priv_header;
	TAILQ_HEAD(, body) priv_body;
#ifdef USE_GEOIP
	const char *priv_ccode;
#endif
	size_t priv_msgcount;
	char *priv_buf;
	size_t priv_buflen;
	char *priv_queueid;
	int priv_delayed_reject;
	struct smtp_reply priv_sr;
	time_t priv_max_elapsed;
	int priv_last_whitelist;
#if defined(USE_CURL) || defined(USE_LDAP)
	LIST_HEAD(, prop) priv_prop;
#endif
#ifdef USE_DNSRBL
	LIST_HEAD(, dnsrbl_list) priv_dnsrbl;
#endif
#ifdef USE_DKIM
	DKIM *priv_dkim;
	DKIM_STAT priv_dkimstat;
#endif
#ifdef USE_P0F
	char *priv_p0f;
#endif
#ifdef USE_SPAMD
	int priv_spamd_flags;
	int priv_spamd_score10;
#endif
	char tarpitted;
	time_t tarpit_duration;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_helo(SMFICTX *, char *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_envrcpt(SMFICTX *, char **);
sfsistat mlfi_header(SMFICTX *, char *, char *);
sfsistat mlfi_eoh(SMFICTX *);
sfsistat mlfi_body(SMFICTX *, unsigned char *, size_t);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_abort(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
void usage(char *);
int humanized_atoi(char *);
#ifndef USE_POSTFIX
char *local_ipstr(struct mlfi_priv *);
#endif
struct in_addr *prefix2mask4(int, struct in_addr *);
#ifdef AF_INET6
struct in6_addr *prefix2mask6(int, struct in6_addr *);
#endif
void unmappedaddr(struct sockaddr *, socklen_t *);
void final_dump(void);
int main(int, char **);
void mg_log(int, char *, ...);
char *strncpy_rmsp(char *, char *, size_t);
char *fstring_expand(struct mlfi_priv *, 
    char *, const char *);
char *fstring_escape(char *);

#ifdef HAVE_STRLCAT
/* #include <string.h> */
#define mystrlcat strlcat
#else
size_t mystrlcat(char *, const char *src, size_t size);
#endif

/*
 * Locking management
 */
#define WRLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_wrlock(&(lock))) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_wrlock failed: %s", \
		    __FILE__, __LINE__, strerror(err));			  \
		exit(EX_SOFTWARE);					  \
	}								  \
}

#define RDLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_rdlock(&(lock))) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_rdlock failed: %s", \
		    __FILE__, __LINE__, strerror(err));			  \
		exit(EX_SOFTWARE);					  \
	}								  \
}

#define TSS_SET(key, val) do {						  \
	int err;							  \
									  \
	if ((err = pthread_setspecific(key, val)) != 0) {		  \
		mg_log(LOG_ERR, "%s:%d pthread_setspecific failed: %s",	  \
		    __FILE__, __LINE__, strerror(err));			  \
		exit(EX_SOFTWARE);					  \
	}								  \
} while (/*CONSTCOND*/ 0)

/*
 * There is a bug in GNU pth-2.0.0 that will cause a spurious EPERM
 * error when a thread releases a read lock that has been shared by
 * two threads and already released by the other one. As a workaround
 * for that problem, we just avoid quitting on this error.
 */
#ifndef HAVE_BROKEN_RWLOCK
#define UNLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_unlock(&(lock))) != 0) {		  \
		syslog(LOG_ERR, "%s:%d pthread_rwlock_unlock failed: %s", \
		    __FILE__, __LINE__, strerror(err));			  \
		exit(EX_SOFTWARE);					  \
	}								  \
}
#else
#define UNLOCK(lock) {							  \
	int err;							  \
									  \
	if ((err = pthread_rwlock_unlock(&(lock))) != 0) {		  \
		syslog(LOG_DEBUG, "%s:%d pthread_rwlock_unlock failed: "  \
		    "%s (ignored)", __FILE__, __LINE__, strerror(err));	  \
	}								  \
}
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

#define ADD_REASON(whystr, reason)					\
	{								\
		if (whystr[0] != '\0')					\
			mystrlcat(whystr, ", ", sizeof(whystr));	\
		mystrlcat(whystr, reason, sizeof(whystr));		\
	}

/*
 * Due to race conditions in the libmilter shipped with sendmail <= 8.13.8,
 * the whole process may die after receiving a signal.
 * It makes impossible the final dump. Apply the following patch ASAP:
 * http://www.j10n.org/files/libmilter-8.13.8-signal.patch
 *
 * If you don't want to apply it, the following knob enables an uncertain
 * effort to workaround the bug. Do not ask me about this.
 * 
 */
/* #define WORKAROUND_LIBMILTER_RACE_CONDITION */

#endif /* _MILTER_GREYLIST_H_ */

