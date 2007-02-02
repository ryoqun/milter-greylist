/* $Id: acl.h,v 1.23 2007/02/02 07:00:06 manu Exp $ */

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

#ifndef _ACL_H_
#define _ACL_H_

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

typedef enum { A_GREYLIST, A_WHITELIST, A_BLACKLIST, } acl_type_t;
typedef enum { AS_NONE, AS_RCPT, AS_DATA, AS_ANY, } acl_stage_t;
typedef enum { AT_NONE, AT_STRING, AT_REGEX, AT_NETBLOCK, AT_OPNUM, 
	       AT_CLOCKSPEC, AT_DNSRBL, AT_URLCHECK, AT_MACRO, 
	       AT_LIST } acl_data_type_t;

typedef enum {
	AC_NONE,
	AC_LIST,
	AC_EMAIL,
	AC_REGEX,
	AC_STRING,
	AC_FROM,
	AC_FROM_RE,
	AC_FROM_LIST,
	AC_RCPT,
	AC_RCPT_RE,
	AC_RCPT_LIST,
	AC_DOMAIN,
	AC_DOMAIN_RE,
	AC_DOMAIN_LIST,
	AC_NETBLOCK,
	AC_NETBLOCK_LIST,
	AC_BODY,
	AC_BODY_LIST,
	AC_BODY_RE,
	AC_HEADER,
	AC_HEADER_LIST,
	AC_HEADER_RE,
	AC_DNSRBL,
	AC_DNSRBL_LIST,
	AC_MACRO,
	AC_MACRO_RE,
	AC_MACRO_LIST,
	AC_URLCHECK,
	AC_URLCHECK_LIST,
	AC_AUTH,
	AC_AUTH_RE,
	AC_AUTH_LIST,
	AC_TLS,
	AC_TLS_RE,
	AC_TLS_LIST,
	AC_SPF,
	AC_MSGSIZE,
	AC_RCPTCOUNT,
	AC_CLOCKSPEC,
	AC_CLOCKSPEC_LIST,
	AC_GEOIP,
	AC_GEOIP_LIST,
} acl_clause_t;

struct acl_clause;
struct acl_param;

#include "pending.h"
#include "milter-greylist.h"

#define ACL_WRLOCK WRLOCK(acl_lock) 
#define ACL_RDLOCK RDLOCK(acl_lock) 
#define ACL_UNLOCK UNLOCK(acl_lock)

TAILQ_HEAD(acllist, acl_entry);

enum operator { OP_EQ, OP_NE, OP_GT, OP_LT, OP_GE, OP_LE };

struct acl_opnum_data {
	enum operator op;
	int num;
};

struct acl_netblock_data {
        struct sockaddr *addr;
        ipaddr *mask;
	socklen_t salen;
	int cidr;
};

struct acl_param {
	acl_type_t ap_type;
	time_t ap_delay;
	time_t ap_autowhite;
	int ap_flags;
	char *ap_code;
	char *ap_ecode;
	char *ap_msg;
	char *ap_report;
};

/* a_flags */
#define A_FLUSHADDR		0x01
#define A_FREE_CODE		0x02
#define A_FREE_ECODE		0x04
#define A_FREE_MSG		0x08
#define A_FREE_REPORT		0x10

struct all_list_entry;
enum list_type;

typedef union acl_data {
	struct acl_netblock_data netblock;
	char *string;
	struct {
		regex_t *re;
		char *re_copy;
	} regex;
	struct all_list_entry *list;
	struct macro_entry *macro;
#ifdef USE_DNSRBL
	struct dnsrbl_entry *dnsrbl;
#endif
#ifdef USE_CURL
	struct urlcheck_entry *urlcheck;
#endif
	struct acl_opnum_data opnum;
	struct clockspec *clockspec;
} acl_data_t;

struct acl_clause_rec {
	acl_clause_t acr_type;
	enum { UNIQUE, MULTIPLE_OK } acr_unicity;
	acl_stage_t acr_stage;
	char *acr_name;
	acl_data_type_t acr_data_type;
	acl_clause_t acr_list_type;
	acl_clause_t acr_item_type;
	int acr_exf;
	char *(*acr_print)(acl_data_t *, char *, size_t);
	void (*acr_add)(acl_data_t *, void *data);
	void (*acr_free)(acl_data_t *);
	int (*acr_filter)(acl_data_t *, acl_stage_t, 
			  struct acl_param *, struct mlfi_priv *);
};

struct acl_clause {
	acl_clause_t ac_type;
	enum { PLAIN, NEGATED } ac_negation;
	union acl_data ac_data;
	struct acl_clause_rec *ac_acr;
	LIST_ENTRY(acl_clause) ac_list;
};

#define a_addr a_netblock.nb_addr
#define a_addrlen a_netblock.nb_addrlen
#define a_mask a_netblock.nb_mask

struct acl_entry {
	int a_line;
	acl_type_t a_type;
	acl_stage_t a_stage;
	LIST_HEAD(,acl_clause) a_clause;
	time_t a_delay;
	time_t a_autowhite;
	int a_flags;
	char *a_code;
	char *a_ecode;
	char *a_msg;
	char *a_report;
	TAILQ_ENTRY(acl_entry) a_list;
};

extern int testmode;
extern pthread_rwlock_t acl_lock;

char *stage_string(acl_stage_t);
struct acl_clause_rec *get_acl_clause_rec(acl_clause_t);
struct acl_clause_rec *acl_list_item_fixup(acl_data_type_t, acl_data_type_t);
void acl_init(void);
void acl_clear(void);
void acl_add_clause(acl_clause_t, void *);
void acl_negate_clause(void);
void acl_add_delay(time_t);
void acl_add_autowhite(time_t);
void acl_add_flushaddr(void);
void acl_add_code(char *);
void acl_add_ecode(char *);
void acl_add_msg(char *);
void acl_add_report(char *);
struct acl_entry *acl_register_entry_first(acl_stage_t, acl_type_t);
struct acl_entry *acl_register_entry_last(acl_stage_t, acl_type_t);
void acl_filter(acl_stage_t, SMFICTX *, struct mlfi_priv *);
char *acl_entry(char *, size_t, struct acl_entry *);
void acl_dump(void);
int emailcmp(char *, char *);        

int acl_netblock_filter(acl_data_t *, acl_stage_t, 
			struct acl_param *, struct mlfi_priv *);
int acl_list_filter(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_from_cmp(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_from_regexec(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_rcpt_cmp(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_rcpt_regexec(acl_data_t *, acl_stage_t, 
		 struct acl_param *, struct mlfi_priv *);
int acl_auth_strcmp(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_auth_regexec(acl_data_t *, acl_stage_t, 
		     struct acl_param *, struct mlfi_priv *);
int acl_tls_strcmp(acl_data_t *, acl_stage_t, 
		   struct acl_param *, struct mlfi_priv *);
int acl_tls_regexec(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_domain_cmp(acl_data_t *, acl_stage_t, 
	           struct acl_param *, struct mlfi_priv *);
int acl_domain_regexec(acl_data_t *, acl_stage_t, 
		       struct acl_param *, struct mlfi_priv *);
int acl_body_strstr(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);
int acl_header_strstr(acl_data_t *, acl_stage_t, 
		      struct acl_param *, struct mlfi_priv *);
int acl_body_regexec(acl_data_t *, acl_stage_t, 
		     struct acl_param *, struct mlfi_priv *);
int acl_header_regexec(acl_data_t *, acl_stage_t, 
		       struct acl_param *, struct mlfi_priv *);
int acl_rcptcount_cmp(acl_data_t *, acl_stage_t, 
		      struct acl_param *, struct mlfi_priv *);
int acl_msgsize_cmp(acl_data_t *, acl_stage_t, 
		    struct acl_param *, struct mlfi_priv *);

/* acl_filter() return codes */
#define	EXF_UNSET	0
#define	EXF_GREYLIST	(1 << 0)
#define EXF_WHITELIST	(1 << 1)

#define	EXF_DEFAULT	(1 << 2)
#define	EXF_ADDR	(1 << 3)
#define	EXF_DOMAIN	(1 << 4)
#define	EXF_FROM	(1 << 5)
#define	EXF_RCPT	(1 << 6)
#define	EXF_AUTO	(1 << 7)
#define	EXF_NONE	(1 << 8)
#define	EXF_AUTH	(1 << 9)
#define	EXF_SPF		(1 << 10)
#define	EXF_NONIP	(1 << 11)
#define	EXF_STARTTLS	(1 << 12)
#define EXF_ACCESSDB	(1 << 13)
#define EXF_DRAC	(1 << 14)
#define EXF_DNSRBL	(1 << 15)
#define EXF_BLACKLIST	(1 << 16)
#define EXF_MACRO	(1 << 17)
#define EXF_URLCHECK	(1 << 18)
#define EXF_HEADER	(1 << 19)
#define EXF_BODY	(1 << 20)
#define EXF_MSGSIZE	(1 << 21)
#define EXF_RCPTCOUNT	(1 << 22)
#define EXF_CLOCKSPEC	(1 << 23)
#define EXF_GEOIP	(1 << 24)
#endif /* _ACL_H_ */
