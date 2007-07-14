/* $Id: acl.c,v 1.66 2007/07/14 03:49:22 manu Exp $ */

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

#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: acl.c,v 1.66 2007/07/14 03:49:22 manu Exp $");
#endif
#endif

#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <pthread.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

#include "acl.h"
#include "conf.h"
#include "sync.h"
#include "list.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#ifdef USE_CURL
#include "urlcheck.h"
#endif
#ifdef USE_GEOIP
#include "geoip.h"
#endif
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2)) 
#include "spf.h"
#endif
#include "macro.h"
#include "clock.h"
#include "milter-greylist.h"

#ifdef USE_DMALLOC
#include <dmalloc.h>
#endif

struct acllist acl_head;
pthread_rwlock_t acl_lock;

static struct acl_entry *gacl;
int gneg;

char *acl_print_netblock(acl_data_t *, char *, size_t);
char *acl_print_string(acl_data_t *, char *, size_t);
char *acl_print_regex(acl_data_t *, char *, size_t);
char *acl_print_list(acl_data_t *, char *, size_t);
char *acl_print_null(acl_data_t *, char *, size_t);
char *acl_print_opnum(acl_data_t *, char *, size_t);
int acl_opnum_cmp(int, enum operator, int);
void acl_free_netblock(acl_data_t *);
void acl_free_string(acl_data_t *);
void acl_free_regex(acl_data_t *);
void acl_add_netblock(acl_data_t *, void *);
void acl_add_string(acl_data_t *, void *);
void acl_add_regex(acl_data_t *, void *);
void acl_add_body_string(acl_data_t *, void *);
void acl_add_body_regex(acl_data_t *, void *);
void acl_add_macro(acl_data_t *, void *);
void acl_add_opnum(acl_data_t *, void *);
void acl_add_opnum_body(acl_data_t *, void *);
void acl_add_list(acl_data_t *, void *);
char *acl_print_macro(acl_data_t *, char *, size_t);
#ifdef USE_DNSRBL
void acl_add_dnsrbl(acl_data_t *, void *);
char *acl_print_dnsrbl(acl_data_t *, char *, size_t);
#endif
#ifdef USE_CURL
void acl_add_urlcheck(acl_data_t *, void *);
char *acl_print_urlcheck(acl_data_t *, char *, size_t);
void acl_add_prop_string(acl_data_t *, void *);
void acl_add_prop_regex(acl_data_t *, void *);
char *acl_print_prop_string(acl_data_t *, char *, size_t);
char *acl_print_prop_regex(acl_data_t *, char *, size_t);
void acl_free_prop_string(acl_data_t *);
void acl_free_prop_regex(acl_data_t *);
#endif

struct acl_clause_rec acl_clause_rec[] = {
	/* Temporary types for lists */
	{ AC_LIST, MULTIPLE_OK, AS_NONE, "list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_NONE,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_EMAIL, MULTIPLE_OK, AS_NONE, "email", 
	  AT_NONE, AC_NONE, AC_NONE, EXF_NONE,
	  acl_print_string, acl_add_string, 
	  acl_free_string, NULL },
	{ AC_REGEX, MULTIPLE_OK, AS_NONE, "regex", 
	  AT_NONE, AC_NONE, AC_NONE, EXF_NONE,
	  acl_print_regex, acl_add_regex, 
	  acl_free_regex, NULL },
	{ AC_STRING, MULTIPLE_OK, AS_NONE, "string", 
	  AT_NONE, AC_NONE, AC_NONE, EXF_NONE,
	  acl_print_string, acl_add_string, 
	  acl_free_string, NULL },

	/* Real types used in clauses */
	{ AC_NETBLOCK, UNIQUE, AS_ANY, "net", 
	  AT_NETBLOCK, AC_NETBLOCK_LIST, AC_NETBLOCK, EXF_ADDR,
	  acl_print_netblock, acl_add_netblock,
	  acl_free_netblock, acl_netblock_filter },
	{ AC_NETBLOCK_LIST, UNIQUE, AS_ANY, "net_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_ADDR,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_DOMAIN, UNIQUE, AS_ANY, "domain", 
	  AT_STRING, AC_DOMAIN_LIST, AC_DOMAIN, EXF_DOMAIN,
	  acl_print_string, acl_add_string,
	  acl_free_string, acl_domain_cmp },
	{ AC_DOMAIN_RE, UNIQUE, AS_ANY, "domain_re", 
	  AT_REGEX, AC_DOMAIN_LIST, AC_REGEX, EXF_DOMAIN,
	  acl_print_regex, acl_add_regex,
	  acl_free_regex, acl_domain_regexec },
	{ AC_DOMAIN_LIST, UNIQUE, AS_ANY, "domain_list", 
	  AT_LIST,  AC_NONE, AC_NONE, EXF_DOMAIN,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_HELO, UNIQUE, AS_RCPT, "helo", 
	  AT_STRING, AC_HELO_LIST, AC_STRING, EXF_HELO,
	  acl_print_string, acl_add_string, 
	  acl_free_string, acl_helo_strstr },
	{ AC_HELO_RE, UNIQUE, AS_RCPT, "helo_re", 
	  AT_REGEX, AC_HELO_LIST, AC_REGEX, EXF_HELO,
	  acl_print_regex, acl_add_regex, 
	  acl_free_regex, acl_helo_regexec },
	{ AC_HELO_LIST, UNIQUE, AS_RCPT, "helo_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_HELO,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_FROM, UNIQUE, AS_ANY, "from", 
	  AT_STRING, AC_FROM_LIST, AC_EMAIL, EXF_FROM,
	  acl_print_string, acl_add_string,
	  acl_free_string, acl_from_cmp },
	{ AC_FROM_RE, UNIQUE, AS_ANY, "from_re", 
	  AT_REGEX, AC_FROM_LIST, AC_REGEX, EXF_FROM,
	  acl_print_regex, acl_add_regex,
	  acl_free_regex, acl_from_regexec },
	{ AC_FROM_LIST, UNIQUE, AS_ANY, "from_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_FROM,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_RCPT, MULTIPLE_OK, AS_ANY, "rcpt", 
	  AT_STRING, AC_RCPT_LIST, AC_EMAIL, EXF_RCPT,
	  acl_print_string, acl_add_string,
	  acl_free_string, acl_rcpt_cmp },
	{ AC_RCPT_RE, MULTIPLE_OK, AS_ANY, "rcpt_re", 
	  AT_REGEX, AC_RCPT_LIST, AC_REGEX, EXF_RCPT,
	  acl_print_regex, acl_add_regex,
	  acl_free_regex, acl_rcpt_regexec },
	{ AC_RCPT_LIST, MULTIPLE_OK, AS_ANY, "rcpt_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_RCPT,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_BODY, MULTIPLE_OK, AS_DATA, "body", 
	  AT_STRING, AC_BODY_LIST, AC_STRING, EXF_BODY,
	  acl_print_string, acl_add_body_string, 
	  acl_free_string, acl_body_strstr },
	{ AC_BODY_RE, MULTIPLE_OK, AS_DATA, "body_re", 
	  AT_REGEX, AC_BODY_LIST, AC_REGEX, EXF_BODY,
	  acl_print_regex, acl_add_body_regex, 
	  acl_free_regex, acl_body_regexec },
	{ AC_BODY_LIST, MULTIPLE_OK, AS_DATA, "body_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_BODY,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_HEADER, MULTIPLE_OK, AS_DATA, "header", 
	  AT_STRING, AC_HEADER_LIST, AC_STRING, EXF_HEADER,
	  acl_print_string, acl_add_body_string, 
	  acl_free_string, acl_header_strstr },
	{ AC_HEADER_RE, MULTIPLE_OK, AS_DATA, "header_re", 
	  AT_REGEX, AC_HEADER_LIST, AC_REGEX, EXF_HEADER,
	  acl_print_regex, acl_add_body_regex, 
	  acl_free_regex, acl_header_regexec },
	{ AC_HEADER_LIST, MULTIPLE_OK, AS_DATA, "header_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_HEADER,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_MACRO, MULTIPLE_OK, AS_ANY, "macro", 
	  AT_MACRO, AC_MACRO_LIST, AC_STRING, EXF_MACRO,
	  acl_print_macro, acl_add_macro,
	  NULL, macro_check },
	{ AC_MACRO_LIST, MULTIPLE_OK, AS_ANY, "macro_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_MACRO,
	  acl_print_list, acl_add_list,
	  NULL, acl_list_filter },
#ifdef USE_DNSRBL
	{ AC_DNSRBL, MULTIPLE_OK, AS_ANY, "dnsrbl", 
	  AT_DNSRBL, AC_DNSRBL_LIST, AC_STRING, EXF_DNSRBL,
	  acl_print_dnsrbl, acl_add_dnsrbl,
	  NULL, dnsrbl_check_source },
	{ AC_DNSRBL_LIST, MULTIPLE_OK, AS_ANY, "dnsrbl_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_DNSRBL,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
#endif
#ifdef USE_CURL
	{ AC_URLCHECK, MULTIPLE_OK, AS_ANY, "urlcheck", 
	  AT_URLCHECK, AC_URLCHECK_LIST, AC_STRING, EXF_URLCHECK,
	  acl_print_urlcheck, acl_add_urlcheck,
	  NULL, urlcheck_validate },
	{ AC_URLCHECK_LIST, MULTIPLE_OK, AS_ANY, "urlcheck_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_URLCHECK,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_PROP, MULTIPLE_OK, AS_ANY, "prop", 
	  AT_PROP, AC_NONE, AC_PROP, EXF_PROP,
	  acl_print_prop_string, acl_add_prop_string,
	  acl_free_prop_string, urlcheck_prop_string_validate },
	{ AC_PROP, MULTIPLE_OK, AS_ANY, "propre", 
	  AT_PROP, AC_NONE, AC_PROPRE, EXF_PROP,
	  acl_print_prop_regex, acl_add_prop_regex,
	  acl_free_prop_regex, urlcheck_prop_regex_validate },
#endif
	{ AC_AUTH, MULTIPLE_OK, AS_ANY, "auth", 
	  AT_STRING, AC_AUTH_LIST, AC_STRING, EXF_AUTH,
	  acl_print_string, acl_add_string,
	  acl_free_string, acl_auth_strcmp },
	{ AC_AUTH_RE, MULTIPLE_OK, AS_ANY, "auth_re", 
	  AT_REGEX, AC_AUTH_LIST, AC_REGEX, EXF_AUTH,
	  acl_print_regex, acl_add_regex,
	  acl_free_regex, acl_auth_regexec },
	{ AC_AUTH_LIST, MULTIPLE_OK, AS_ANY, "auth_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_AUTH,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
	{ AC_TLS, MULTIPLE_OK, AS_ANY, "tls", 
	  AT_STRING, AC_TLS_LIST, AC_STRING, EXF_STARTTLS,
	  acl_print_string, acl_add_string,
	  acl_free_string, acl_tls_strcmp },
	{ AC_TLS_RE, MULTIPLE_OK, AS_ANY, "tls_re", 
	  AT_REGEX, AC_TLS_LIST, AC_REGEX, EXF_STARTTLS,
	  acl_print_regex, acl_add_regex,
	  acl_free_regex, acl_tls_regexec },
	{ AC_TLS_LIST, MULTIPLE_OK, AS_ANY, "tls_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_STARTTLS,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2)) 
	{ AC_SPF, UNIQUE, AS_ANY, "spf",
	  AT_NONE, AC_NONE, AC_SPF,  EXF_SPF,
	  acl_print_null, NULL,
	  NULL, spf_check },
#endif
	{ AC_MSGSIZE, MULTIPLE_OK, AS_DATA, "msgsize", 
	  AT_OPNUM, AC_NONE, AC_MSGSIZE, EXF_MSGSIZE,
	  acl_print_opnum, acl_add_opnum,
	  NULL, acl_msgsize_cmp },
	{ AC_RCPTCOUNT, MULTIPLE_OK, AS_ANY, "rcptcount", 
	  AT_OPNUM, AC_NONE, AC_RCPTCOUNT, EXF_RCPTCOUNT,
	  acl_print_opnum, acl_add_opnum_body,
	  NULL, acl_rcptcount_cmp },
	{ AC_CLOCKSPEC, MULTIPLE_OK, AS_ANY, "time",
	  AT_CLOCKSPEC, AC_NONE, AC_CLOCKSPEC, EXF_CLOCKSPEC,
	  print_clockspec, add_clockspec,
	  clockspec_free, clockspec_filter },
	{ AC_CLOCKSPEC_LIST, MULTIPLE_OK, AS_ANY, "time_list",
	  AT_LIST, AC_NONE, AC_NONE, EXF_CLOCKSPEC,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
#ifdef USE_GEOIP
	{ AC_GEOIP, MULTIPLE_OK, AS_ANY, "geoip", 
	  AT_STRING, AC_GEOIP_LIST, AC_STRING, EXF_GEOIP,
	  acl_print_string, acl_add_string,
	  acl_free_string, geoip_filter },
	{ AC_GEOIP_LIST, MULTIPLE_OK, AS_ANY, "geoip_list", 
	  AT_LIST, AC_NONE, AC_NONE, EXF_GEOIP,
	  acl_print_list, acl_add_list, 
	  NULL, acl_list_filter },
#endif
};

struct {
	acl_stage_t ss_stage;
	char *ss_string;
} stage_string_rec[] = {
	{ AS_NONE, "NONE" },
	{ AS_RCPT, "RCPT" },
	{ AS_DATA, "DATA" },
	{ AS_ANY, "ANY" },
};

char *
stage_string(stage)
	acl_stage_t stage;
{
	int i;
	int count =  sizeof(stage_string_rec) / sizeof(*stage_string_rec);

	for (i = 0; i < count; i++)
		if (stage_string_rec[i].ss_stage == stage)
			return stage_string_rec[i].ss_string;

	mg_log(LOG_ERR, "unexpected ACL stage %d", stage);
	exit(EX_SOFTWARE);
	/* NOTREACHED */
	return NULL;
}

int 
acl_opnum_cmp(val1, op, val2)
	int val1;
	enum operator op;
	int val2;
{
	switch(op) {
	case OP_EQ:
		return (val1 == val2);
		break;
	case OP_NE:
		return (val1 != val2);
		break;
	case OP_LT:
		return (val1 < val2);
		break;
	case OP_GT:
		return (val1 > val2);
		break;
	case OP_LE:
		return (val1 <= val2);
		break;
	case OP_GE:
		return (val1 >= val2);
		break;
	default:
		mg_log(LOG_ERR, "unexpected operator");
		exit(EX_SOFTWARE);
		break;
	}
	/* NOTREACHED */
	return 0;
}

int
acl_rcptcount_cmp(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (acl_opnum_cmp(priv->priv_rcptcount, ad->opnum.op, ad->opnum.num))
		return 1;

	return 0;
}

int
acl_msgsize_cmp(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (acl_opnum_cmp(priv->priv_msgcount, ad->opnum.op, ad->opnum.num))
		return 1;

	return 0;
}

int
acl_domain_cmp(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *host = priv->priv_hostname;
	char *domain = ad->string;
	int hidx, didx;

	if ((host[0] == '\0') && domain[0] == '\0')
		return 1;

	if ((host[0] == '\0') || domain[0] == '\0') 
		return 0;

	hidx = strlen(host) - 1;
	didx = strlen(domain) - 1;

	while ((hidx >= 0) && (didx >= 0)) {
		if (tolower((int)host[hidx]) != tolower((int)domain[didx])) {
			return (0);
		}
		hidx--;
		didx--;
	}

	if (didx >= 0)
		return (0);

	return (1);
}

int
acl_header_strstr(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct header *h;
	 
	if (stage != AS_DATA) {
		mg_log(LOG_ERR, "header filter called at non DATA stage");
		exit(EX_SOFTWARE);
	}

	TAILQ_FOREACH(h, &priv->priv_header, h_list)
		if (strstr(h->h_line, ad->string) != NULL)
			return 1;
	return 0;
}

int
acl_body_strstr(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct body *b;
	 
	if (stage != AS_DATA) {
		mg_log(LOG_ERR, "body filter called at non DATA stage");
		exit(EX_SOFTWARE);
	}

	TAILQ_FOREACH(b, &priv->priv_body, b_list)
		if (strstr(b->b_lines, ad->string) != NULL)
			return 1;

	return 0;
}

int
myregexec(priv, ad, ap, string)
	struct mlfi_priv *priv;
	acl_data_t *ad;
	struct acl_param *ap;
	const char *string;
{
	size_t len;
	int nmatch;
	regmatch_t *pmatch = NULL;
	int retval;
	int i;

	/* 
	 * Add room for matched strings
	 */
	len = (ap->ap_nmatch + ad->regex.nmatch) * sizeof(*ap->ap_pmatch);;
	if (len > 0) {
		if ((ap->ap_pmatch = realloc(ap->ap_pmatch, len)) == NULL) {
			mg_log(LOG_ERR, "realloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
	}
	/* Move the previous matches to the end of the array */
	if (ap->ap_nmatch != 0) {
		memmove(&ap->ap_pmatch[ad->regex.nmatch], 
		    &ap->ap_pmatch[0], ap->ap_nmatch * sizeof(char *));
		bzero(&ap->ap_pmatch[0], ad->regex.nmatch * sizeof(char *));
	}

	/* 
	 * Placeholder for information from regexec, +1 for \0 
	 */
	nmatch = ad->regex.nmatch + 1;
	if ((pmatch = malloc(nmatch * sizeof(*pmatch))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	bzero(pmatch, nmatch * sizeof(*pmatch));

	/*
	 * The real regexec
	 */
	retval = regexec(ad->regex.re, string, nmatch, pmatch, 0);
	if (retval != 0)	/* No match */
		goto out;

	/* 
	 * Gather the strings, skiping the first one (\0) 
	 */
	for (i = 1; i < nmatch; i++) {
		if (pmatch[i].rm_so == -1) {
			mg_log(LOG_ERR, "unexpected void backreference no %d "
			    "in regex %s against \"%s\"", 
			    i, ad->regex.re_copy, string);
			exit(EX_SOFTWARE);
		}	

		len = pmatch[i].rm_eo - pmatch[i].rm_so + 1;
		if ((ap->ap_pmatch[i - 1] = malloc(len)) == NULL) {
			mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		memcpy(ap->ap_pmatch[i - 1], string + pmatch[i].rm_so, len - 1);
		ap->ap_pmatch[i - 1][len - 1] = '\0';

		if (conf.c_debug)
			mg_log(LOG_DEBUG, 
			    "regex /%s/ against \"%s\": match[%d] = \"%s\"",
			    ad->regex.re_copy, string, i, ap->ap_pmatch[i - 1]);
	}
out:
	ap->ap_nmatch += ad->regex.nmatch;

	if (pmatch != NULL)
		free(pmatch);

#if 0
	if (conf.c_debug) {
		int i;

		for (i = 0; i < ap->ap_nmatch; i++)
			mg_log(LOG_DEBUG, 
			    "  match[%d] = \"%s\"",
			    i, ap->ap_pmatch[i]);
	}
#endif

	return retval;
	
}

int
acl_helo_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (myregexec(priv, ad, ap, priv->priv_helo) == 0)
		return 1;
	return 0;
}

int
acl_from_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (myregexec(priv, ad, ap, priv->priv_from) == 0)
		return 1;
	return 0;
}

int
acl_auth_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *auth_authen;

	auth_authen = smfi_getsymval(priv->priv_ctx, "{auth_authen}");
	if (auth_authen == NULL)
		return 0;

	if (myregexec(priv, ad, ap, auth_authen) == 0)
		return 1;
	return 0;
}

int
acl_tls_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *verify;
	char *dn;

	if (((verify = smfi_getsymval(priv->priv_ctx, "{verify}")) == NULL) ||
	    (strcmp(verify, "OK") != 0) ||
	    ((dn = smfi_getsymval(priv->priv_ctx, "{cert_subject}")) == NULL))
		return 0;

	if (myregexec(priv, ad, ap, dn) == 0)
		return 1;
	return 0;
}

int
acl_rcpt_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (stage != AS_RCPT) {
		mg_log(LOG_ERR, "rcpt filter called at non RCPT stage");
		exit(EX_SOFTWARE);
	}

	if (myregexec(priv, ad, ap, priv->priv_cur_rcpt) == 0)
		return 1;
	return 0;
}

int
acl_domain_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (myregexec(priv, ad, ap, priv->priv_hostname) == 0)
		return 1;
	return 0;
}

int
acl_header_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct header *h;
	 
	if (stage != AS_DATA) {
		mg_log(LOG_ERR, "header filter called at non DATA stage");
		exit(EX_SOFTWARE);
	}

	TAILQ_FOREACH(h, &priv->priv_header, h_list)
		if (myregexec(priv, ad, ap, h->h_line) == 0)
			return 1;
	return 0;
}

int
acl_helo_strstr(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *helo = ad->string;

	printf("-> %s/%s\n", priv->priv_helo, helo);
	if (strstr(priv->priv_helo, helo) != NULL) 
		return 1;
	return 0;
}

int
acl_from_cmp(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *from = ad->string;

	if (emailcmp(priv->priv_from, from) == 0) 
		return 1;
	return 0;
}

int
acl_rcpt_cmp(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *rcpt = ad->string;

	if (stage == AS_RCPT) {
		if (emailcmp(priv->priv_cur_rcpt, rcpt) == 0)
			return 1;
	} else {
		struct rcpt *r;

		 LIST_FOREACH(r, &priv->priv_rcpt, r_list)
			if (emailcmp(r->r_addr, rcpt) == 0)
				return 1;
	}

	return 0;
}

int
acl_auth_strcmp(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *auth_authen;

	auth_authen = smfi_getsymval(priv->priv_ctx, "{auth_authen}");
	if (auth_authen == NULL)
		return 0;

	if (strcmp(auth_authen, ad->string) == 0)
		return 1;

	return 0;
}

int
acl_tls_strcmp(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *verify;
	char *dn;

	if (((verify = smfi_getsymval(priv->priv_ctx, "{verify}")) == NULL) ||
	    (strcmp(verify, "OK") != 0) ||
	    ((dn = smfi_getsymval(priv->priv_ctx, "{cert_subject}")) == NULL))
		return 0;

	if (strcmp(dn, ad->string) == 0)
		return 1;

	return 0;
}

int
acl_list_filter(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct all_list_entry *ale;
	struct list_entry *le;
	int retval;	    
			       
	ale = ad->list;
	
	LIST_FOREACH(le, &ale->al_head, l_list) {
		retval = (*le->l_acr->acr_filter)(&le->l_data, stage, ap, priv);
		if (retval != 0)
			return retval;
	}

	return 0;
}

int
acl_body_regexec(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct body *b;
	 
	if (stage != AS_DATA) {
		mg_log(LOG_ERR, "body filter called at non DATA stage");
		exit(EX_SOFTWARE);
	}

	TAILQ_FOREACH(b, &priv->priv_body, b_list)
		if (myregexec(priv, ad, ap, b->b_lines) == 0)
			return 1;
	return 0;
}



struct acl_clause_rec *
acl_list_item_fixup(item_type, list_type)
	acl_clause_t item_type;
	acl_clause_t list_type;
{
	struct acl_clause_rec *cur_acr;
	int i;
	int count = sizeof(acl_clause_rec) / sizeof(*acl_clause_rec);

	for (i = 0; i < count; i++) {
		cur_acr = &acl_clause_rec[i];

		    if ((cur_acr->acr_list_type == list_type) &&
			(cur_acr->acr_item_type == item_type))
			return cur_acr;
	}

	return NULL;
}

struct acl_clause_rec *
get_acl_clause_rec(type)
	acl_clause_t type;
{
	int i;
	int count = sizeof(acl_clause_rec) / sizeof(*acl_clause_rec);

	for (i = 0; i < count; i++)
		if (acl_clause_rec[i].acr_type == type)
			return &acl_clause_rec[i];

	mg_log(LOG_ERR, "unexpected acl clause type %d", type);
	exit(EX_SOFTWARE);
	/* NOTREACHED */
	return NULL;
}

char *
acl_print_string(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	snprintf(buf, len, "\"%s\"", ad->string);
	return buf;
}

char *
acl_print_regex(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	snprintf(buf, len, "%s", ad->regex.re_copy);
	return buf;
}

char *
acl_print_list(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	snprintf(buf, len, "\"%s\"", ad->list->al_name);
	return buf;
}

char *
acl_print_null(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	if (len > 0)
		buf[0] = '\0';
	return buf;
}

char *
acl_print_opnum(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	struct {
		enum operator op;
		char *str;
	} op_to_str[] = {
		{ OP_EQ, "==" },
		{ OP_NE, "!=" },
		{ OP_GT, ">" },
		{ OP_LT, "<" },
		{ OP_GE, ">=" },
		{ OP_LE, "<=" },
	};
	int i;
	char *str = NULL;

	for (i = 0; i < sizeof(op_to_str) / sizeof(*op_to_str); i++) {
		if (op_to_str[i].op == ad->opnum.op) {
			str = op_to_str[i].str;
			break;
		}
	}
	if (str == NULL) {
		mg_log(LOG_ERR, "unexpected operator");
		exit(EX_SOFTWARE);
	}

	snprintf(buf, len, "%s %d", str, ad->opnum.num);

	return buf;
}

void
acl_add_string(ad, data)
	acl_data_t *ad;
	void *data;
{
	char *string = data;	

	if ((ad->string = strdup(string)) == NULL) {
		mg_log(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	return;
}

void
acl_add_body_string(ad, data)
	acl_data_t *ad;
	void *data;
{
	if (conf.c_maxpeek == 0)
		conf.c_maxpeek = -1;

	acl_add_string(ad, data);
	return;
}

void 
acl_add_body_regex(ad, data)
	acl_data_t *ad;
	void *data;
{
	if (conf.c_maxpeek == 0)
		conf.c_maxpeek = -1;

	acl_add_regex(ad, data);
	return;
}
#define ERRLEN 1024
void
acl_add_regex(ad, data)
	acl_data_t *ad;
	void *data;
{
	char *regexstr = data;	
	regex_t *regex;
	char errstr[ERRLEN + 1];
	char *cp;
	int skip;
	int error;
	int flags;

	if ((regex = malloc(sizeof(*regex))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	ad->regex.re = regex;

	if ((ad->regex.re_copy = strdup(regexstr)) == NULL) {
		mg_log(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	/* Remove leading and trailing / */
	if (regexstr[0] == '/')
		regexstr++;
	if ((strlen(regexstr) > 0) && (regexstr[strlen(regexstr) - 1] == '/'))
		regexstr[strlen(regexstr) - 1] = '\0';

	/* Change escaped / into / */
	for (cp = regexstr; *cp; cp++) {
		if ((*cp == '\\') && (*(cp + 1) == '/'))
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
	}
	
	flags = (REG_ICASE | REG_NEWLINE);
	if (conf.c_extendedregex)
		flags |= REG_EXTENDED;

	if ((error = regcomp(regex, regexstr, flags)) != 0) {
		regerror(error, regex, errstr, ERRLEN);
		mg_log(LOG_ERR, "bad regular expression \"%s\": %s", 
		    regexstr, errstr);
		exit(EX_OSERR);
	}

	/* Cout how many back-references we have */
	skip = 0;
	ad->regex.nmatch = 0;
	for (cp = regexstr; *cp; cp++) {
		if (skip)
			continue;
		if ((cp[0] == '\\') && (cp[0] != '\0') && (cp[1] == '(')) 
			ad->regex.nmatch++;
	}

	return;
}

void
acl_free_string(ad)
	acl_data_t *ad;
{
	free(ad->string);
	return;
}

void
acl_free_regex(ad)
	acl_data_t *ad;
{
	regfree(ad->regex.re);
	free(ad->regex.re_copy);
	return;
}

static struct acl_entry *
acl_init_entry(void)
{
	struct acl_entry *acl;

	if ((acl = malloc(sizeof(*acl))) == NULL) {
		mg_log(LOG_ERR, "ACL malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	memset(acl, 0, sizeof(*acl));
	acl->a_delay = -1;
	acl->a_autowhite = -1;
	TAILQ_INIT(&acl->a_clause);

	return acl;
}

void
acl_init(void) {
	int error;

	TAILQ_INIT(&acl_head);
	if ((error = pthread_rwlock_init(&acl_lock, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_rwlock_init failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}
	gacl = acl_init_entry();
	gneg = PLAIN;

	return;
}

void
acl_add_flushaddr(void) {
	gacl->a_flags |= A_FLUSHADDR;
	return;	
}

void
acl_add_netblock(ad, data)
	acl_data_t *ad;
	void *data;
{
	struct acl_netblock_data *and = data;
	struct sockaddr *sa;
	socklen_t salen;
	int cidr;
	ipaddr mask;
	int maxcidr, masklen;
#ifdef AF_INET6
	int i;
#endif

	sa = and->addr;
	salen = and->salen;
	cidr = and->cidr;

	switch (sa->sa_family) {
	case AF_INET:
		maxcidr = 32;
		masklen = sizeof(mask.in4);
		break;
#ifdef AF_INET6
	case AF_INET6:
		maxcidr = 128;
		masklen = sizeof(mask.in6);
		break;
#endif
	default:
		mg_log(LOG_ERR,
		    "bad address family in acl list line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	if (cidr > maxcidr || cidr < 0) {
		mg_log(LOG_ERR, "bad mask in acl list line %d", 
		    conf_line);
		exit(EX_DATAERR);
	}

	switch (sa->sa_family) {
	case AF_INET:
		prefix2mask4(cidr, &mask.in4);
		SADDR4(sa)->s_addr &= mask.in4.s_addr;
		break;
#ifdef AF_INET6
	case AF_INET6:
		prefix2mask6(cidr, &mask.in6);
		for (i = 0; i < 16; i += 4)
			*(uint32_t *)&SADDR6(sa)->s6_addr[i] &=
			    *(uint32_t *)&mask.in6.s6_addr[i];
		break;
#endif
	}

	if ((ad->netblock.addr = malloc(salen)) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((ad->netblock.mask = malloc(sizeof(*ad->netblock.mask))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	ad->netblock.salen = salen;
	ad->netblock.cidr = cidr;
	memcpy(ad->netblock.addr, sa, salen);
	memcpy(ad->netblock.mask, &mask, masklen);

	return;
}

void
acl_free_netblock(ad)
	acl_data_t *ad;
{
	free(ad->netblock.addr);
	free(ad->netblock.mask);
	return;
}

char *
acl_print_netblock(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	char addrstr[IPADDRSTRLEN];
	char maskstr[IPADDRSTRLEN];
	
	iptostring(ad->netblock.addr, ad->netblock.salen,
		   addrstr, sizeof(addrstr));
	inet_ntop(ad->netblock.addr->sa_family,
		  ad->netblock.mask,
		  maskstr, sizeof(maskstr));
	snprintf(buf, len, "%s/%s", addrstr, maskstr);
	return buf;
}

int
acl_netblock_filter(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct sockaddr *sa;

	sa = SA(&priv->priv_addr);

	if (ip_match(sa, 
		     ad->netblock.addr, 
		     ad->netblock.mask))
		return 1;
	return 0;
}

#ifdef USE_DNSRBL
void
acl_add_dnsrbl(ad, data)
	acl_data_t *ad;
	void *data;
{
	char *dnsrbl = data;
	
	if ((ad->dnsrbl = dnsrbl_byname(dnsrbl)) == NULL) {
		mg_log(LOG_ERR, "unknown DNSRBL \"%s\"", dnsrbl);
		exit(EX_DATAERR);
	}
		
	return;
}

char *
acl_print_dnsrbl(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	snprintf(buf, len, "\"%s\"", ad->dnsrbl->d_name);
	return buf;
}
#endif

#ifdef USE_CURL
void
acl_add_urlcheck(ad, data)
	acl_data_t *ad;
	void *data;
{
	char *urlcheck = data;

	if ((ad->urlcheck = urlcheck_byname(urlcheck)) == NULL) {
		mg_log(LOG_ERR, "unknown URL check \"%s\"", urlcheck);
		exit(EX_DATAERR);
	}
		
	return;
}

char *
acl_print_urlcheck(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	snprintf(buf, len, "\"%s\"", ad->urlcheck->u_name);
	return buf;
}

void
acl_add_prop_string(ad, data)
	acl_data_t *ad;
	void *data;
{
	struct urlcheck_prop_data *upd;

	upd = (struct urlcheck_prop_data *)data;

	if ((ad->prop = malloc(sizeof(*ad->prop))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((ad->prop->upd_name = strdup(upd->upd_name + 1)) == NULL) {
		mg_log(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	acl_add_string((acl_data_t *)&ad->prop->upd_data, upd->upd_data);

	return;
}
void 
acl_add_prop_regex(ad, data)
	acl_data_t *ad;
	void *data;
{
	struct urlcheck_prop_data *upd;

	upd = (struct urlcheck_prop_data *)data;

	if ((ad->prop = malloc(sizeof(*ad->prop))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((ad->prop->upd_name = strdup(upd->upd_name + 1)) == NULL) {
		mg_log(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	acl_add_regex((acl_data_t *)&ad->prop->upd_data, upd->upd_data);

	return;
}

char *
acl_print_prop_string(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	size_t written;

	written = snprintf(buf, len, "$%s ", ad->prop->upd_name);
	acl_print_string((acl_data_t *)&ad->prop->upd_data, 
	    buf + written, len - written);

	return buf;
}

char *
acl_print_prop_regex(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	size_t written;

	written = snprintf(buf, len, "$%s ", ad->prop->upd_name);
	acl_print_regex((acl_data_t *)&ad->prop->upd_data, 
	    buf + written, len - written);

	return buf;
}

void 
acl_free_prop_string(ad)
	acl_data_t *ad;
{
	free(ad->prop->upd_name);
	acl_free_string((acl_data_t *)&ad->prop->upd_data);
	free(ad->prop);

	return;
}
void 
acl_free_prop_regex(ad)
	acl_data_t *ad;
{
	free(ad->prop->upd_name);
	acl_free_regex((acl_data_t *)&ad->prop->upd_data);
	free(ad->prop);

	return;
}

#endif

void
acl_add_macro(ad, data)
	acl_data_t *ad;
	void *data;
{
	char *macro = data;

	if ((ad->macro = macro_byname(macro)) == NULL) {
		mg_log(LOG_ERR, "unknown sm_macro \"%s\"", macro);
		exit(EX_DATAERR);
	}
		
	return;
}

char *
acl_print_macro(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	snprintf(buf, len, "\"%s\"", ad->macro->m_name);
	return buf;
}

void
acl_negate_clause(void)
{
	gneg = NEGATED;

	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load negation");

	return;
}

void
acl_add_clause(type, data)
	acl_clause_t type;
	void *data;
{
	struct acl_clause *ac;
	struct acl_clause *cac;
	struct acl_clause_rec *acr;

	acr = get_acl_clause_rec(type);

	if ((ac = malloc(sizeof(*ac))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (acr->acr_unicity == UNIQUE) {
		TAILQ_FOREACH(cac, &gacl->a_clause, ac_list) {
			if (cac->ac_type == type) {
				mg_log(LOG_ERR, 
				    "Multiple %s clauses in ACL line %d",
				    acr->acr_name, conf_line);
				exit(EX_DATAERR);
			}
		}
	}

	ac->ac_type = type;
	ac->ac_negation = gneg;
	gneg = PLAIN;
	ac->ac_acr = acr;
	if (acr->acr_add != NULL)
		(*acr->acr_add)(&ac->ac_data, data);
	TAILQ_INSERT_TAIL(&gacl->a_clause, ac, ac_list);
		
	/* 
	 * Lists deserve a special treatment: the clause is parsed with 
	 * a generic type AC_LIST, and we need to lookup the real list type
	 */
	if (ac->ac_type == AC_LIST) {
		if (conf.c_debug || conf.c_acldebug) {
			char tmpbuf[64];

			mg_log(LOG_DEBUG, 
			    "switching ACL clause %s from type %s to %s",
			    (*acr->acr_print)
				(&ac->ac_data, tmpbuf, sizeof(tmpbuf)),
			    acr->acr_name,
			    ac->ac_data.list->al_acr->acr_name);
		}
			
		ac->ac_type = ac->ac_data.list->al_acr->acr_type;
		ac->ac_acr = ac->ac_data.list->al_acr;
	}

	if (conf.c_debug || conf.c_acldebug) {
		char tmpbuf[64];

		mg_log(LOG_DEBUG, "load acl %s %s", acr->acr_name, 
		    (*acr->acr_print)(&ac->ac_data, tmpbuf, sizeof(tmpbuf)));
	}

	if (conf.c_maxpeek == 0)
		conf.c_maxpeek = -1;

	return;
}

struct acl_entry *
acl_register_entry_first(acl_stage, acl_type)/* acllist must be write-locked */
	acl_stage_t acl_stage;
	acl_type_t acl_type;
{
	struct acl_entry *acl;
	struct acl_clause *ac;

	TAILQ_FOREACH(ac, &gacl->a_clause, ac_list) {
		if (ac->ac_acr->acr_stage == AS_ANY)
			continue;
		if (ac->ac_acr->acr_stage != acl_stage) {
			char b[1024];

			mg_log(LOG_ERR, "%s %s clause should be used in %s "
			    "stage and is present %s stage ACL line %d",
			    ac->ac_acr->acr_name, 
			    (*ac->ac_acr->acr_print)
				(&ac->ac_data, b, sizeof(b)),
			    stage_string(ac->ac_acr->acr_stage),
			    stage_string(acl_stage),
			    conf_line - 1);
			exit(EX_DATAERR);
		}
	}

	if (acl_stage == AS_DATA) {
		if (conf_dacl_end != 0)
			mg_log(LOG_WARNING, "ignored dacl entry after dacl "
			    "default rule at line %d", conf_line - 1);
		if (conf_acl_end != 0) {
			conf_dacl_end = 1;
			conf_acl_end = 0;
		}

		if (acl_type == A_GREYLIST) {
			mg_log(LOG_ERR, "greylist action in DATA stage ACL "
			    "at line %d", conf_line - 1);
			exit(EX_DATAERR);
		}
	} else {
		if (conf_racl_end != 0)
			mg_log(LOG_WARNING, "ignored racl entry after racl "
			    "default rule at line %d", conf_line - 1);
		if (conf_acl_end != 0) {
			conf_racl_end = 1;
			conf_acl_end = 0;
		}
	}

	if ((acl = malloc(sizeof(*acl))) == NULL) {
		mg_log(LOG_ERR, "ACL malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	acl = gacl;
	acl->a_type = acl_type;
	acl->a_stage = acl_stage;
	acl->a_line = conf_line - 1;
	TAILQ_INSERT_HEAD(&acl_head, acl, a_list);
	gacl = acl_init_entry ();

	if (conf.c_debug || conf.c_acldebug) {
		switch(acl_type) {
		case A_GREYLIST:
			mg_log(LOG_DEBUG, "register acl first GREYLIST");
			break;
		case A_WHITELIST:
			mg_log(LOG_DEBUG, "register acl first WHITELIST");
			break;
		case A_BLACKLIST:
			mg_log(LOG_DEBUG, "register acl first BLACKLIST");
			break;
		default:
			mg_log(LOG_ERR, "unecpected acl_type %d", acl_type);
			exit(EX_SOFTWARE);
			break;
		}
	}

	return acl;
}

struct acl_entry *
acl_register_entry_last(acl_stage, acl_type)/* acllist must be write-locked */
	acl_stage_t acl_stage;
	acl_type_t acl_type;
{
	struct acl_entry *acl;
	struct acl_clause *ac;

	TAILQ_FOREACH(ac, &gacl->a_clause, ac_list) {
		if (ac->ac_acr->acr_stage == AS_ANY)
			continue;
		if (ac->ac_acr->acr_stage != acl_stage) {
			char b[1024];

			mg_log(LOG_ERR, "%s %s clause should be used in %s "
			    "stage and is present %s stage ACL line %d",
			    ac->ac_acr->acr_name, 
			    (*ac->ac_acr->acr_print)
				(&ac->ac_data, b, sizeof(b)),
			    stage_string(ac->ac_acr->acr_stage),
			    stage_string(acl_stage),
			    conf_line - 1);
			exit(EX_DATAERR);
		}
	}

	if (acl_stage == AS_DATA) {
		if (conf_dacl_end != 0)
			mg_log(LOG_WARNING, "ignored dacl entry after dacl "
			    "default rule at line %d", conf_line - 1);
		if (conf_acl_end != 0) {
			conf_dacl_end = 1;
			conf_acl_end = 0;
		}

		if (acl_type == A_GREYLIST) {
			mg_log(LOG_ERR, "greylist action in DATA stage ACL "
			    "at line %d", conf_line - 1);
			exit(EX_DATAERR);
		}
	} else {
		if (conf_racl_end != 0)
			mg_log(LOG_WARNING, "ignored racl entry after racl "
			    "default rule at line %d", conf_line - 1);
		if (conf_acl_end != 0) {
			conf_racl_end = 1;
			conf_acl_end = 0;
		}
	}

	acl = gacl;
	acl->a_stage = acl_stage;
	acl->a_type = acl_type;
	acl->a_line = conf_line - 1;
	TAILQ_INSERT_TAIL(&acl_head, acl, a_list);
	gacl = acl_init_entry();

	if (conf.c_debug || conf.c_acldebug) {
		switch(acl_type) {
		case A_GREYLIST:
			mg_log(LOG_DEBUG, "register acl last GREYLIST");
			break;
		case A_WHITELIST:
			mg_log(LOG_DEBUG, "register acl last WHITELIST");
			break;
		case A_BLACKLIST:
			mg_log(LOG_DEBUG, "register acl last BLACKLIST");
			break;
		default:
			mg_log(LOG_ERR, "unecpected acl_type %d", acl_type);
			exit(EX_SOFTWARE);
			break;
		}
	}

	return acl;
}

void
acl_filter(stage, ctx, priv)
	acl_stage_t stage;
	SMFICTX *ctx;
	struct mlfi_priv *priv;
{
	struct sockaddr *sa;
	socklen_t salen;
	char *hostname;
	char *from;
	char *queueid;
	struct acl_entry *acl;
	char addrstr[IPADDRSTRLEN];
	char whystr[HDRLEN];
	char tmpstr[HDRLEN];
	int retval = 0;
	int noretval = 0;
	char *notstr = " not";
	char *vstr = "";
	int found;
	int testmode = conf.c_testmode;
	struct acl_param ap;
	char *cur_rcpt;
	struct acl_clause *ac;
#ifdef USE_GEOIP
	const char *ccode = "??";
#endif

	sa = SA(&priv->priv_addr);
	salen = priv->priv_addrlen;
	hostname = priv->priv_hostname;
	from = priv->priv_from;
	queueid = priv->priv_queueid;
	cur_rcpt = priv->priv_cur_rcpt;
#ifdef USE_GEOIP
	if (priv->priv_ccode != NULL) {
		ccode = priv->priv_ccode;
	}
#endif

	ACL_RDLOCK;

	TAILQ_FOREACH(acl, &acl_head, a_list) {
		if (acl->a_stage != stage)
			continue;

		retval = 0;
		noretval = 0;
		found = -1;

		ap.ap_type = acl->a_type;
		ap.ap_delay = acl->a_delay;
		ap.ap_autowhite = acl->a_autowhite;
		ap.ap_flags = acl->a_flags;
		ap.ap_code = acl->a_code;
		ap.ap_ecode = acl->a_ecode;
		ap.ap_msg = acl->a_msg;
		ap.ap_report = acl->a_report;
		ap.ap_nmatch = 0;
		ap.ap_pmatch = NULL;

		TAILQ_FOREACH(ac, &acl->a_clause, ac_list) {
			found = (*ac->ac_acr->acr_filter)
				(&ac->ac_data, stage, &ap, priv);

			if (ac->ac_negation == NEGATED)
				found = (found == 0) ? 1 : 0;

			if (found == 0)
				break;

			retval |= ac->ac_acr->acr_exf;

			if (ac->ac_negation == NEGATED)
				noretval |= ac->ac_acr->acr_exf;
		}
		if (found == 0)
			continue;

		/*
		 * We found an entry that matches, exit the evaluation
		 * loop
		 */
		break;
	}

	if (acl) {
		if (retval == 0)
			retval = EXF_DEFAULT;
		switch (ap.ap_type) {
		case A_GREYLIST:
			retval |= EXF_GREYLIST;
			break;
		case A_WHITELIST:
			retval |= EXF_WHITELIST;
			break;
		case A_BLACKLIST:
			retval |= EXF_BLACKLIST;
			break;
		default:
			mg_log(LOG_ERR, "corrupted acl list");
			exit(EX_SOFTWARE);
			break;
		}

		priv->priv_sr.sr_acl_line = acl->a_line;

		priv->priv_sr.sr_delay =
		    (ap.ap_delay != -1) ? ap.ap_delay : conf.c_delay;
		priv->priv_sr.sr_autowhite =
		    (ap.ap_autowhite != -1) ? 
		    ap.ap_autowhite : conf.c_autowhite_validity;

		if (ap.ap_code) {
			priv->priv_sr.sr_code = strdup(ap.ap_code);
			if (priv->priv_sr.sr_code == NULL) { 
				mg_log(LOG_ERR, "strdup failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}
		}
		if (ap.ap_ecode) {
			priv->priv_sr.sr_ecode = strdup(ap.ap_ecode);
			if (priv->priv_sr.sr_ecode == NULL) {
				mg_log(LOG_ERR, "strdup failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}
		}
		if (ap.ap_msg) {
			priv->priv_sr.sr_msg = strdup(ap.ap_msg);
			if (priv->priv_sr.sr_msg == NULL) {
				mg_log(LOG_ERR, "strdup failed");
				exit(EX_OSERR);
			}
		}
		if (ap.ap_report) {
			priv->priv_sr.sr_report = strdup(ap.ap_report);
			if (priv->priv_sr.sr_report == NULL) {
				mg_log(LOG_ERR, "strdup failed");
				exit(EX_OSERR);
			}
		}

		priv->priv_sr.sr_nmatch = ap.ap_nmatch;
		priv->priv_sr.sr_pmatch = ap.ap_pmatch;
			
		/* Free temporary memory if nescessary */
		if (ap.ap_flags & A_FREE_CODE)
			free(ap.ap_code);
		if (ap.ap_flags & A_FREE_ECODE)
			free(ap.ap_ecode);
		if (ap.ap_flags & A_FREE_MSG)
			free(ap.ap_msg);
		if (ap.ap_flags & A_FREE_REPORT)
			free(ap.ap_report);

		if (ap.ap_flags & A_FLUSHADDR)
			pending_del_addr(sa, salen, queueid, acl->a_line);

		if (conf.c_debug || conf.c_acldebug) {
			char aclstr[HDRLEN + 1];

			iptostring(sa, salen, addrstr, sizeof(addrstr));
			mg_log(LOG_DEBUG, "Mail from=%s, rcpt=%s, addr=%s[%s] "
			    "is matched by entry %s", from, 
			    (cur_rcpt != NULL) ? cur_rcpt : "(nil)",
			    hostname, addrstr, acl_entry(aclstr, HDRLEN, acl));
		}
	} else {
		/*
		 * No match: use the default action
		 */
		if (testmode)
			retval = EXF_WHITELIST;
		else
			retval = EXF_GREYLIST;
		retval |= EXF_DEFAULT;

		priv->priv_sr.sr_delay = conf.c_delay;
		priv->priv_sr.sr_autowhite = conf.c_autowhite_validity;
	}

	if (retval & EXF_WHITELIST) {
		whystr[0] = '\0';
		if (retval & EXF_ADDR) {
			iptostring(sa, salen, addrstr, sizeof(addrstr));
			snprintf(tmpstr, sizeof(tmpstr),
			     "address %s is whitelisted", addrstr);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_DNSRBL) {
			iptostring(sa, salen, addrstr, sizeof(addrstr));
			snprintf(tmpstr, sizeof(tmpstr),
			    "address %s is%s in DNSRBL", addrstr,
			    (noretval & EXF_DNSRBL) ? notstr : vstr);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_URLCHECK) {
			iptostring(sa, salen, addrstr, sizeof(addrstr));
			snprintf(tmpstr, sizeof(tmpstr),
			    "URL check%s passed",
			    (noretval & EXF_URLCHECK) ? notstr : vstr);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_DOMAIN) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "sender DNS name %s is whitelisted", hostname);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_FROM) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "sender %s is whitelisted", from);
			ADD_REASON(whystr, tmpstr);
		}
		if ((retval & EXF_RCPT) && (cur_rcpt != NULL)) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "recipient %s is whitelisted", cur_rcpt);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_MACRO) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "macro rule is%s satisfied",
			     (noretval & EXF_MACRO) ? notstr : vstr);
			ADD_REASON(whystr, tmpstr);
		}
#ifdef USE_GEOIP
		if (retval & EXF_GEOIP) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "geoip ccode %s is whitelisted", ccode);
			ADD_REASON(whystr, tmpstr);
		}
#endif
		if (retval & EXF_DEFAULT) {
			ADD_REASON(whystr, "this is the default action");
		}
		iptostring(sa, salen, addrstr, sizeof(addrstr));
		snprintf(tmpstr, sizeof(tmpstr),
		    "(from=%s, rcpt=%s, addr=%s[%s])", from, 
		    (cur_rcpt != NULL) ? cur_rcpt : "(nil)",
		    hostname, addrstr);
		ADD_REASON(whystr, tmpstr);

		mg_log(LOG_INFO, "%s: skipping greylist because %s",
		    queueid, whystr);
	}
	ACL_UNLOCK;

	priv->priv_sr.sr_whitelist = retval;

	return;
}



int 
emailcmp(big, little)
	char *big;
	char *little;
{
	int i;
	int retval = -1;
	char *cbig;
	char *clittle;
	char *ocbig;
	char *oclittle;

	if ((cbig = malloc(strlen(big) + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	ocbig = cbig;
	strcpy(cbig, big);

	if ((clittle = malloc(strlen(little) + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	oclittle = clittle;
	strcpy(clittle, little);

	/* Strip leading <, tabs and spaces */
	while (strchr("< \t", cbig[0]) != NULL)
		cbig++;
	while (strchr("< \t", clittle[0]) != NULL)
		clittle++;

	/* Strip trailing >, tabs and spaces */
	i = strlen(cbig) - 1;
	while ((i >= 0) && (strchr("> \t", cbig[i]) != NULL))
		cbig[i--] = '\0';
	i = strlen(clittle) - 1;
	while ((i >= 0) && (strchr("> \t", clittle[i]) != NULL))
		clittle[i--] = '\0';

	while (cbig[0] && clittle[0]) {
		if (tolower((int)cbig[0]) != tolower((int)clittle[0]))
			break;
		cbig++;
		clittle++;
	}
		
	if (cbig[0] || clittle[0])
		retval = -1;
	else
		retval = 0;

	free(ocbig);
	free(oclittle);

	return retval;
}

void
acl_clear(void) {	/* acllist must be write locked */
	struct acl_entry *acl;
	struct acl_clause *ac;

	while (!TAILQ_EMPTY(&acl_head)) {
		acl = TAILQ_FIRST(&acl_head);
		TAILQ_REMOVE(&acl_head, acl, a_list);

		while (!TAILQ_EMPTY(&acl->a_clause)) {
			ac = TAILQ_FIRST(&acl->a_clause);
			TAILQ_REMOVE(&acl->a_clause, ac, ac_list);
			if (ac->ac_acr->acr_free)
				(*ac->ac_acr->acr_free)(&ac->ac_data);
			free(ac);
		}

		if (acl->a_code != NULL)
			free(acl->a_code);
		if (acl->a_ecode != NULL)
			free(acl->a_ecode);
		if (acl->a_msg != NULL)
			free(acl->a_msg);
		if (acl->a_report != NULL)
			free(acl->a_report);
		free(acl);
	}

	return;
}

char *
acl_entry(entrystr, len, acl)
	char *entrystr;
	size_t len;
	struct acl_entry *acl;
{
	char tempstr[HDRLEN];
	int def = 1;
	struct acl_clause *ac;

	switch (acl->a_stage) {
	case AS_RCPT:
		snprintf(entrystr, len, "racl %d ", acl->a_line);
		break;
	case AS_DATA:
		snprintf(entrystr, len, "dacl %d ", acl->a_line);
		break;
	default:
		mg_log(LOG_ERR, "unexpected stage %d", acl->a_stage);
		exit(EX_SOFTWARE);
		break;		
	}

	switch (acl->a_type) {
	case A_GREYLIST:
		mystrlcat(entrystr, "greylist ", len);
		break;
	case A_WHITELIST:
		mystrlcat(entrystr, "whitelist ", len);
		break;
	case A_BLACKLIST:
		mystrlcat(entrystr, "blacklist ", len);
		break;
	default:
		mg_log(LOG_ERR, "corrupted acl list");
		exit(EX_SOFTWARE);
		break;
	}

	TAILQ_FOREACH(ac, &acl->a_clause, ac_list) {
		char tempstr2[HDRLEN];
		acl_data_t *ad;
		char *notstr = "not ";
		char *vstr = "";

		ad = &ac->ac_data;
		snprintf(tempstr, sizeof(tempstr), "%s%s %s ",
		    (ac->ac_negation == NEGATED) ? notstr : vstr,
		    ac->ac_acr->acr_name, 
		    (*ac->ac_acr->acr_print)(ad, tempstr2, sizeof(tempstr2)));
		mystrlcat(entrystr, tempstr, len);
		def = 0;
	}

	if (acl->a_delay != -1) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[delay %ld] ", (long)acl->a_delay);
		mystrlcat(entrystr, tempstr, len);
	}

	if (acl->a_autowhite != -1) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[aw %ld] ", (long)acl->a_autowhite);
		mystrlcat(entrystr, tempstr, len);
	}

	if (acl->a_flags & A_FLUSHADDR) {
		snprintf(tempstr, sizeof(tempstr), "[flushaddr] ");
		mystrlcat(entrystr, tempstr, len);
	}

	if (acl->a_code) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[code \"%s\"] ", acl->a_code);
		mystrlcat(entrystr, tempstr, len);
	}

	if (acl->a_ecode) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[ecode \"%s\"] ", acl->a_ecode);
		mystrlcat(entrystr, tempstr, len);
	}

	if (acl->a_msg) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[msg \"%s\"] ", acl->a_msg);
		mystrlcat(entrystr, tempstr, len);
	}

	if (acl->a_report) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[report \"%s\"] ", acl->a_report);
		mystrlcat(entrystr, tempstr, len);
	}

	if (def)
		mystrlcat(entrystr, "default", len);
	return entrystr;
}

void
acl_dump (void) {	/* acllist must be write locked */
	struct acl_entry *acl;
	char *entry;
	FILE *debug = NULL;

	/*
	 * We log the ACL to syslogd
	 * We can also write the ACL in a file because syslogd seems to lose
	 * some debugging messages on FreeBSD 4.10 :-(
	 * XXX This is disabled by default (#if 0 above) since it creates
	 * security hazards: /tmp/access-list.debug could already exist and
	 * be a link to some system file which would be overwritten.
	 * Enable it if you need it, but you may be better changing the path
	 */
#if 0
	debug = fopen("/tmp/access-list.debug", "w");
#endif
	ACL_RDLOCK;
	mg_log(LOG_INFO, "Access list dump:");
	TAILQ_FOREACH(acl, &acl_head, a_list) {
		char aclstr[HDRLEN + 11];

		entry = acl_entry(aclstr, HDRLEN, acl);
		mg_log(LOG_INFO, "%s", entry);
		if (debug != NULL)
			fprintf(debug, "%s", entry);
	}
	ACL_UNLOCK;
	if (debug != NULL)
		fclose(debug);
}

void 
acl_add_delay(delay)
	time_t delay;
{
	if (gacl->a_delay != -1) {
		mg_log(LOG_ERR,
		    "delay specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	gacl->a_delay = delay;
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl delay %ld", (long)delay);

	return;
}

void
acl_add_autowhite(delay)
	time_t delay;
{
	if (gacl->a_autowhite != -1) {
		mg_log(LOG_ERR,
		    "autowhite specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	gacl->a_autowhite = delay;
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl delay %ld", (long)delay);

	return;
}

void
acl_add_list(ad, data)
	acl_data_t *ad;
	void *data;
{
	char *list = data;
	struct all_list_entry *ale;
	struct acl_clause *cac;

	if ((ale = all_list_byname(list)) == NULL) {
		mg_log(LOG_ERR, "inexistent list \"%s\" line %d",
		    list, conf_line);
		exit(EX_DATAERR);
	}

	TAILQ_FOREACH(cac, &gacl->a_clause, ac_list) {
		if (cac->ac_acr->acr_list_type != ale->al_acr->acr_type)
			continue;
		if (cac->ac_acr->acr_unicity == UNIQUE) {
			mg_log(LOG_ERR,
			    "multiple %s statement (list \"%s\", line %d)",
			    cac->ac_acr->acr_name, list, conf_line);
			exit(EX_DATAERR);
		}
	}

	ad->list = ale;

	return;
}

void
acl_add_opnum_body(ad, data)
	acl_data_t *ad;
	void *data;
{
	if (conf.c_maxpeek == 0)
		conf.c_maxpeek = -1;

	acl_add_opnum(ad, data);
	return;
}

void
acl_add_opnum(ad, data)
	acl_data_t *ad;
	void *data;
{
	struct acl_opnum_data *aod;

	aod = (struct acl_opnum_data *)data;

	ad->opnum.op = aod->op;
	ad->opnum.num = aod->num;
}

void 
acl_add_code(code)
	char *code;
{
	if (gacl->a_code) {
		mg_log(LOG_ERR,
		    "code specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	if ((gacl->a_code = strdup(code)) == NULL) {
		mg_log(LOG_ERR,
		    "malloc failed in ACL line %d", conf_line);
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl code \"%s\"", code);

	return;
}

void 
acl_add_ecode(ecode)
	char *ecode;
{
	if (gacl->a_ecode) {
		mg_log(LOG_ERR,
		    "ecode specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	if ((gacl->a_ecode = strdup(ecode)) == NULL) {
		mg_log(LOG_ERR,
		    "malloc failed in ACL line %d", conf_line);
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl ecode \"%s\"", ecode);

	return;
}

void 
acl_add_msg(msg)
	char *msg;
{
	if (gacl->a_msg) {
		mg_log(LOG_ERR,
		    "msg specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	if ((gacl->a_msg = strdup(msg)) == NULL) {
		mg_log(LOG_ERR,
		    "malloc failed in ACL line %d", conf_line);
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl msg \"%s\"", msg);

	return;
}

void 
acl_add_report(report)
	char *report;
{
	if (gacl->a_report) {
		mg_log(LOG_ERR,
		    "report specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	if ((gacl->a_report = strdup(report)) == NULL) {
		mg_log(LOG_ERR,
		    "malloc failed in ACL line %d", conf_line);
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl report \"%s\"", report);

	return;
}
