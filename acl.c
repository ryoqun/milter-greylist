/* $Id: acl.c,v 1.38 2006/12/20 21:57:52 manu Exp $ */

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

#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: acl.c,v 1.38 2006/12/20 21:57:52 manu Exp $");
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
#include "macro.h"
#include "milter-greylist.h"

struct acllist acl_head;
pthread_rwlock_t acl_lock;

static struct acl_entry gacl;

static void
acl_init_entry (void) {
	memset (&gacl, 0, sizeof (gacl));
	gacl.a_delay = -1;
	gacl.a_autowhite = -1;
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
	acl_init_entry();

	return;
}

void
acl_add_flushaddr(void) {
	gacl.a_flags |= A_FLUSHADDR;
	return;	
}

void
acl_add_netblock(sa, salen, cidr)
	struct sockaddr *sa;
	socklen_t salen;
	int cidr;
{
	ipaddr mask;
	char addrstr[IPADDRSTRLEN];
	char maskstr[IPADDRSTRLEN];
	int maxcidr, masklen;
#ifdef AF_INET6
	int i;
#endif

	if (gacl.a_addr != NULL) {
		mg_log(LOG_ERR,
		    "addr specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
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

	if ((gacl.a_addr = malloc(salen)) == NULL ||
	    (gacl.a_mask = malloc(masklen)) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	gacl.a_addrlen = salen;
	memcpy(gacl.a_addr, sa, salen);
	memcpy(gacl.a_mask, &mask, masklen);

	if (conf.c_debug || conf.c_acldebug) {
		iptostring(gacl.a_addr, gacl.a_addrlen, addrstr,
		    sizeof(addrstr));
		inet_ntop(gacl.a_addr->sa_family, gacl.a_mask, maskstr,
		    sizeof(maskstr));
		mg_log(LOG_DEBUG, "load acl net %s/%s", addrstr, maskstr);
	}

	return;
}

void
acl_add_from(email)
	char *email;
{
	if (gacl.a_from != NULL || 
	    gacl.a_from_re != NULL ||
	    gacl.a_fromlist != NULL ) {
		mg_log(LOG_ERR,
		    "from specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_from = strdup(email)) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl from %s", email);

	return;
}

#ifdef USE_DNSRBL
void
acl_add_dnsrbl(dnsrbl)
	char *dnsrbl;
{
	if (gacl.a_dnsrbl != NULL ||
	    gacl.a_dnsrbllist != NULL) {
		mg_log(LOG_ERR,
		    "dnsrbl specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_dnsrbl = dnsrbl_byname(dnsrbl)) == NULL) {
		mg_log(LOG_ERR, "unknown DNSRBL \"%s\"", dnsrbl);
		exit(EX_DATAERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl dnsrbl %s", dnsrbl);

	return;
}
#endif

#ifdef USE_CURL
void
acl_add_urlcheck(urlcheck)
	char *urlcheck;
{
	if (gacl.a_urlcheck != NULL ||
	    gacl.a_urlchecklist != NULL) {
		mg_log(LOG_ERR,
		    "urlcheck specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_urlcheck = urlcheck_byname(urlcheck)) == NULL) {
		mg_log(LOG_ERR, "unknown URL check \"%s\"", urlcheck);
		exit(EX_DATAERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl urlcheck %s", urlcheck);

	return;
}
#endif

void
acl_add_macro(macro)
	char *macro;
{
	if (gacl.a_macro != NULL ||
	    gacl.a_macrolist != NULL) {
		mg_log(LOG_ERR,
		    "sm_macro specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_macro = macro_byname(macro)) == NULL) {
		mg_log(LOG_ERR, "unknown sm_macro \"%s\"", macro);
		exit(EX_DATAERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl sm_macro %s", macro);

	return;
}

void
acl_add_rcpt(email)
	char *email;
{
	if (gacl.a_rcpt != NULL || 
	    gacl.a_rcpt_re != NULL ||
	    gacl.a_rcptlist != NULL) {
		mg_log(LOG_ERR,
		    "rcpt specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_rcpt = strdup(email)) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl rcpt %s", email);

	return;
}

void
acl_add_domain(domain)
	char *domain;
{
	if (gacl.a_domain != NULL || 
	    gacl.a_domain_re != NULL ||
	    gacl.a_domainlist != NULL) {
		mg_log(LOG_ERR,
		    "domain specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_domain = strdup(domain)) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl domain %s", domain);

	return;
}

#define ERRLEN 1024
void
acl_add_from_regex(regexstr)
	char *regexstr;
{
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	if (gacl.a_from != NULL || 
	    gacl.a_from_re != NULL ||
	    gacl.a_fromlist != NULL) {
		mg_log(LOG_ERR,
		    "from specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((gacl.a_from_re = malloc(sizeof(*gacl.a_from_re))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((error = regcomp(gacl.a_from_re, regexstr, 
	    (conf.c_extendedregex ? REG_EXTENDED : 0) | REG_ICASE)) != 0) {
		regerror(error, gacl.a_from_re, errstr, ERRLEN);
		mg_log(LOG_ERR, "bad regular expression \"%s\": %s", 
		    regexstr, errstr);
		exit(EX_OSERR);
	}

	if ((gacl.a_from_re_copy = strdup(regexstr)) == NULL) {
		mg_log(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl from regex %s", regexstr);

	return;
}

void
acl_add_rcpt_regex(regexstr)
	char *regexstr;
{
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	if (gacl.a_rcpt != NULL || 
	    gacl.a_rcpt_re != NULL ||
	    gacl.a_rcptlist != NULL) {
		mg_log(LOG_ERR,
		    "rcpt specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((gacl.a_rcpt_re = malloc(sizeof(*gacl.a_rcpt_re))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((error = regcomp(gacl.a_rcpt_re, regexstr,
	    (conf.c_extendedregex ? REG_EXTENDED : 0) | REG_ICASE)) != 0) {
		regerror(error, gacl.a_rcpt_re, errstr, ERRLEN);
		mg_log(LOG_ERR, "bad regular expression \"%s\": %s", 
		    regexstr, errstr);
		exit(EX_OSERR);
	}

	if ((gacl.a_rcpt_re_copy = strdup(regexstr)) == NULL) {
		mg_log(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl rcpt regex %s", regexstr);

	return;
}

void
acl_add_domain_regex(regexstr)
	char *regexstr;
{
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	if (gacl.a_domain != NULL || 
	    gacl.a_domain_re != NULL ||
	    gacl.a_domainlist != NULL) {
		mg_log(LOG_ERR,
		    "domain specified twice in ACL line %d",
		    conf_line);
		exit(EX_DATAERR);
	}
	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((gacl.a_domain_re = malloc(sizeof(*gacl.a_domain_re))) == NULL) {
		mg_log(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((error = regcomp(gacl.a_domain_re, regexstr,
	    (conf.c_extendedregex ? REG_EXTENDED : 0) | REG_ICASE)) != 0) {
		regerror(error, gacl.a_domain_re, errstr, ERRLEN);
		mg_log(LOG_ERR, "bad regular expression \"%s\": %s", 
		    regexstr, errstr);
		exit(EX_OSERR);
	}

	if ((gacl.a_domain_re_copy = strdup(regexstr)) == NULL) {
		mg_log(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl domain regex %s", regexstr);

	return;
}

struct acl_entry *
acl_register_entry_first(acl_stage, acl_type)/* acllist must be write-locked */
	acl_stage_t acl_stage;
	acl_type_t acl_type;
{
	struct acl_entry *acl;

	if (acl_stage == AS_DATA) {
		if ((gacl.a_rcptlist || gacl.a_rcpt || gacl.a_rcpt_re)) {
			mg_log(LOG_ERR, "rcpt clause in DATA stage ACL "
			    "at line %d", conf_line - 1);
			exit(EX_DATAERR);
		}
		if (acl_type == A_GREYLIST) {
			mg_log(LOG_ERR, "greylist action in DATA stage ACL "
			    "at line %d", conf_line - 1);
			exit(EX_DATAERR);
		}
	}

	if ((acl = malloc(sizeof(*acl))) == NULL) {
		mg_log(LOG_ERR, "ACL malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	*acl = gacl;
	acl->a_type = acl_type;
	acl->a_stage = acl_stage;
	acl->a_line = conf_line - 1;
	TAILQ_INSERT_HEAD(&acl_head, acl, a_list);
	acl_init_entry ();

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
	acl_type_t acl_stage;
	acl_type_t acl_type;
{
	struct acl_entry *acl;

	if (acl_stage == AS_DATA) {
		if ((gacl.a_rcptlist || gacl.a_rcpt || gacl.a_rcpt_re)) {
			mg_log(LOG_ERR, "rcpt clause in DATA stage ACL "
			    "at line %d", conf_line - 1);
			exit(EX_DATAERR);
		}
		if (acl_type == A_GREYLIST) {
			mg_log(LOG_ERR, "greylist action in DATA stage ACL "
			    "at line %d", conf_line - 1);
			exit(EX_DATAERR);
		}
	}

	if ((acl = malloc(sizeof(*acl))) == NULL) {
		mg_log(LOG_ERR, "ACL malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	*acl = gacl;
	acl->a_stage = acl_stage;
	acl->a_type = acl_type;
	acl->a_line = conf_line - 1;
	TAILQ_INSERT_TAIL(&acl_head, acl, a_list);
	acl_init_entry ();

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

int 
acl_filter(stage, ctx, priv, rcpt)
	acl_stage_t stage;
	SMFICTX *ctx;
	struct mlfi_priv *priv;
	char *rcpt;
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
	int retval;
	int testmode = conf.c_testmode;
	struct acl_param ap;

	sa = SA(&priv->priv_addr);
	salen = priv->priv_addrlen;
	hostname = priv->priv_hostname;
	from = priv->priv_from;
	queueid = priv->priv_queueid;

	ACL_RDLOCK;

	TAILQ_FOREACH(acl, &acl_head, a_list) {
		if (acl->a_stage != stage)
			continue;

		retval = 0;

		ap.ap_type = acl->a_type;
		ap.ap_delay = acl->a_delay;
		ap.ap_autowhite = acl->a_autowhite;
		ap.ap_flags = acl->a_flags;
		ap.ap_code = acl->a_code;
		ap.ap_ecode = acl->a_ecode;
		ap.ap_msg = acl->a_msg;

		if (acl->a_addrlist != NULL) {
			if (list_addr_filter(acl->a_addrlist, sa)) {
				retval |= EXF_ADDR;
			} else {
				continue;
			}
		}

		if (acl->a_addr != NULL) {
			if (ip_match(sa, acl->a_addr, acl->a_mask)) {
				retval |= EXF_ADDR;
			} else  {
				continue;
			}
		}

		if (acl->a_domainlist != NULL) {
			if (list_domain_filter(acl->a_domainlist, hostname)) {
				retval |= EXF_DOMAIN;
			} else {
				continue;
			}
		}

		if (acl->a_domain != NULL) {
			if (domaincmp(hostname, acl->a_domain)) {
				retval |= EXF_DOMAIN;
			} else {
				continue;
			}
		}

		if (acl->a_domain_re != NULL) {
			if (regexec(acl->a_domain_re,
			    hostname, 0, NULL, 0) == 0) {
				retval |= EXF_DOMAIN;
			} else {
				continue;
			}
		}

		if (acl->a_fromlist != NULL) {
			if (list_from_filter(acl->a_fromlist, from)) {
				retval |= EXF_FROM;
			} else {
				continue;
			}
		}

		if (acl->a_from != NULL) {
			if (emailcmp(from, acl->a_from) == 0) {
				retval |= EXF_FROM;
			} else {
				continue;
			}
		}

		if (acl->a_from_re != NULL) {
			if (regexec(acl->a_from_re, from, 0, NULL, 0) == 0) {
				retval |= EXF_FROM;
			} else {
				continue;
			}
		}

		if (acl->a_rcptlist != NULL) {
			if (list_rcpt_filter(acl->a_rcptlist, rcpt)) {
				retval |= EXF_RCPT;
			} else {
				continue;
			}
		}

		if (acl->a_rcpt != NULL) {
			if (emailcmp(rcpt, acl->a_rcpt) == 0) {
			retval |= EXF_RCPT;
			} else {
				continue;
			}
		}

		if (acl->a_rcpt_re != NULL) {
			if (regexec(acl->a_rcpt_re, rcpt, 0, NULL, 0) == 0) {
				retval |= EXF_RCPT;
			} else {
				continue;
			}
		}
#ifdef USE_DNSRBL
		if (acl->a_dnsrbllist != NULL) {
			if (list_dnsrbl_filter(acl->a_dnsrbllist, salen, sa)) {
				retval |= EXF_DNSRBL;
			} else {
				continue;
			}
		}

		if (acl->a_dnsrbl != NULL) {
			if (dnsrbl_check_source(sa, 
			    salen, acl->a_dnsrbl) == 1) {
				retval |= EXF_DNSRBL;
			} else {
				continue;
			}
		}
#endif
#ifdef USE_CURL
		if (acl->a_urlchecklist != NULL) {
			if (list_urlcheck_filter(acl->a_urlchecklist, 
			    priv, rcpt, &ap)) {
				retval |= EXF_URLCHECK;
			} else {
				continue;
			}
		}

		if (acl->a_urlcheck != NULL) {
			if (urlcheck_validate(priv, rcpt, 
			    acl->a_urlcheck, &ap) == 1) {
				retval |= EXF_URLCHECK;
			} else {
				continue;
			}
		}
#endif
		if (acl->a_macrolist != NULL) {
			if (list_macro_filter(acl->a_macrolist, ctx)) {
				retval |= EXF_MACRO;
			} else {
				continue;
			}
		}
		if (acl->a_macro != NULL) {
			if (macro_check(ctx, acl->a_macro) == 0) {
				retval |= EXF_MACRO;
			} else {
				continue;
			}
		}
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
				mg_log(LOG_ERR, "strdup failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}
		}
			
		/* Free temporary memory if nescessary */
		if (ap.ap_flags & A_FREE_CODE)
			free(ap.ap_code);
		if (ap.ap_flags & A_FREE_ECODE)
			free(ap.ap_ecode);
		if (ap.ap_flags & A_FREE_MSG)
			free(ap.ap_msg);

		if (ap.ap_flags & A_FLUSHADDR)
			pending_del_addr(sa, salen, queueid, acl->a_line);

		if (conf.c_debug || conf.c_acldebug) {
			iptostring(sa, salen, addrstr, sizeof(addrstr));
			mg_log(LOG_DEBUG, "Mail from=%s, rcpt=%s, addr=%s[%s] "
			    "is matched by entry %s", from, rcpt, 
			    hostname, addrstr, acl_entry(acl));
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
			    "address %s is whitelisted by DNSRBL", addrstr);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_URLCHECK) {
			iptostring(sa, salen, addrstr, sizeof(addrstr));
			snprintf(tmpstr, sizeof(tmpstr),
			    "URL check passed");
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
		if (retval & EXF_RCPT) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "recipient %s is whitelisted", rcpt);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_MACRO) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "macro rule is satisfied");
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_DEFAULT) {
			ADD_REASON(whystr, "this is the default action");
		}
		iptostring(sa, salen, addrstr, sizeof(addrstr));
		snprintf(tmpstr, sizeof(tmpstr),
		    "(from=%s, rcpt=%s, addr=%s[%s])", from, rcpt, hostname, addrstr);
		ADD_REASON(whystr, tmpstr);

		mg_log(LOG_INFO, "%s: skipping greylist because %s",
		    queueid, whystr);
	}
	ACL_UNLOCK;
	return retval;
}


int
domaincmp(host, domain)
	char *host;
	char *domain;
{
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

	while (!TAILQ_EMPTY(&acl_head)) {
		acl = TAILQ_FIRST(&acl_head);
		TAILQ_REMOVE(&acl_head, acl, a_list);

		if (acl->a_addr != NULL) {
			free(acl->a_addr);
			free(acl->a_mask);
		}
		if (acl->a_from != NULL)
			free(acl->a_from);
		if (acl->a_rcpt != NULL)
			free(acl->a_rcpt);
		if (acl->a_domain != NULL)
			free(acl->a_domain);
		if (acl->a_from_re != NULL)
			regfree(acl->a_from_re);
		if (acl->a_from_re_copy != NULL)
			free(acl->a_from_re_copy);
		if (acl->a_rcpt_re != NULL)
			regfree(acl->a_rcpt_re);
		if (acl->a_rcpt_re_copy != NULL)
			free(acl->a_rcpt_re_copy);
		if (acl->a_domain_re != NULL)
			regfree(acl->a_domain_re);
		if (acl->a_domain_re_copy != NULL)
			free(acl->a_domain_re_copy);
		if (acl->a_code != NULL)
			free(acl->a_code);
		if (acl->a_ecode != NULL)
			free(acl->a_ecode);
		if (acl->a_msg != NULL)
			free(acl->a_msg);
		free(acl);
	}

	TAILQ_INIT(&acl_head);
	acl_init_entry();

	return;
}

char *
acl_entry(acl)
	struct acl_entry *acl;
{
	static char entrystr[HDRLEN];
	char tempstr[HDRLEN];
	char addrstr[IPADDRSTRLEN];
	char maskstr[IPADDRSTRLEN];
	int def = 1;

	snprintf(entrystr, HDRLEN, "%cacl %d ", 
	(acl->a_stage == AS_RCPT) ? 'r' : 'd', acl->a_line);

	switch (acl->a_type) {
	case A_GREYLIST:
		mystrlcat(entrystr, "greylist ", sizeof(entrystr));
		break;
	case A_WHITELIST:
		mystrlcat(entrystr, "whitelist ", sizeof(entrystr));
		break;
	case A_BLACKLIST:
		mystrlcat(entrystr, "blacklist ", sizeof(entrystr));
		break;
	default:
		mg_log(LOG_ERR, "corrupted acl list");
		exit(EX_SOFTWARE);
		break;
	}

	if (acl->a_addrlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "addr list \"%s\" ", 
		    acl->a_addrlist->al_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_addr != NULL) {
		iptostring(acl->a_addr, acl->a_addrlen, addrstr,
		    sizeof(addrstr));
		inet_ntop(acl->a_addr->sa_family, acl->a_mask, maskstr,
		    sizeof(maskstr));
		snprintf(tempstr, sizeof(tempstr), "addr %s/%s ", addrstr, maskstr);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_fromlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "from list \"%s\" ", 
		    acl->a_fromlist->al_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_from != NULL) {
		snprintf(tempstr, sizeof(tempstr), "from %s ", acl->a_from);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_from_re != NULL) {
		snprintf(tempstr, sizeof(tempstr), "from /%s/ ",
		    acl->a_from_re_copy);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_rcptlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "rcpt list \"%s\" ", 
		    acl->a_rcptlist->al_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_rcpt != NULL) {
		snprintf(tempstr, sizeof(tempstr), "rcpt %s ", acl->a_rcpt);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_rcpt_re != NULL) {
		snprintf(tempstr, sizeof(tempstr), "rcpt /%s/ ",
		    acl->a_rcpt_re_copy);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_domainlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "domainlist \"%s\" ", 
		    acl->a_domainlist->al_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_domain != NULL) {
		snprintf(tempstr, sizeof(tempstr), "domain %s ", acl->a_domain);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_domain_re != NULL) {
		snprintf(tempstr, sizeof(tempstr), "domain /%s/ ",
		    acl->a_domain_re_copy);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
#if USE_DNSRBL
	if (acl->a_dnsrbllist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "dnsrbllist \"%s\" ", 
		    acl->a_dnsrbllist->al_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_dnsrbl != NULL) {
		snprintf(tempstr, sizeof(tempstr), "dnsrbl \"%s\" ",
		    acl->a_dnsrbl->d_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
#endif
#if USE_CURL
	if (acl->a_urlchecklist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "urlchecklist \"%s\" ", 
		    acl->a_urlchecklist->al_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_urlcheck != NULL) {
		snprintf(tempstr, sizeof(tempstr), "urlcheck \"%s\" ",
		    acl->a_urlcheck->u_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
#endif
	if (acl->a_macrolist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "sm_macrolist \"%s\" ", 
		    acl->a_macrolist->al_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_macro != NULL) {
		snprintf(tempstr, sizeof(tempstr), "sm_macro \"%s\" ",
		    acl->a_macro->m_name);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_delay != -1) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[delay %ld] ", (long)acl->a_delay);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
	}

	if (acl->a_autowhite != -1) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[aw %ld] ", (long)acl->a_autowhite);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
	}

	if (acl->a_flags & A_FLUSHADDR) {
		snprintf(tempstr, sizeof(tempstr), "[flushaddr] ");
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
	}

	if (acl->a_code) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[code \"%s\"] ", acl->a_code);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
	}

	if (acl->a_ecode) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[ecode \"%s\"] ", acl->a_ecode);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
	}

	if (acl->a_msg) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[msg \"%s\"] ", acl->a_msg);
		mystrlcat(entrystr, tempstr, sizeof(entrystr));
	}

	if (def)
		mystrlcat(entrystr, "default", sizeof(entrystr));
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
		entry = acl_entry(acl);
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
	if (gacl.a_delay != -1) {
		mg_log(LOG_ERR,
		    "delay specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	gacl.a_delay = delay;
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl delay %ld", (long)delay);

	return;
}

void
acl_add_autowhite(delay)
	time_t delay;
{
	if (gacl.a_autowhite != -1) {
		mg_log(LOG_ERR,
		    "autowhite specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	gacl.a_autowhite = delay;
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl delay %ld", (long)delay);

	return;
}

void
acl_add_list(list)
	char *list;
{
	struct all_list_entry *ale;

	if ((ale = all_list_byname(list)) == NULL) {
		mg_log(LOG_ERR, "inexistent list \"%s\" line %d",
		    list, conf_line);
		exit(EX_DATAERR);
	}

	switch (ale->al_type) {
	case LT_FROM:
		if (gacl.a_from != NULL || 
		    gacl.a_from_re != NULL ||
		    gacl.a_fromlist != NULL) {
			mg_log(LOG_ERR,
			    "muliple from statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_fromlist = ale;
		break;

	case LT_RCPT:
		if (gacl.a_rcpt != NULL ||
		    gacl.a_rcpt_re != NULL ||
		    gacl.a_rcptlist != NULL) {
			mg_log(LOG_ERR,
			    "muliple rcpt statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_rcptlist = ale;
		break;

	case LT_DOMAIN:
		if (gacl.a_domain != NULL ||
		    gacl.a_domain_re != NULL ||
		    gacl.a_domainlist != NULL) {
			mg_log(LOG_ERR,
			    "muliple domain statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_domainlist = ale;
		break;

#if USE_DNSRBL
	case LT_DNSRBL:
		if (gacl.a_dnsrbl != NULL ||
		    gacl.a_dnsrbllist != NULL) {
			mg_log(LOG_ERR,
			    "muliple dnsrbl statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_dnsrbllist = ale;
		break;
#endif
#if USE_CURL
	case LT_URLCHECK:
		if (gacl.a_urlcheck != NULL ||
		    gacl.a_urlchecklist != NULL) {
			mg_log(LOG_ERR,
			    "muliple urlcheck statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_urlchecklist = ale;
		break;
#endif
	case LT_MACRO:
		if (gacl.a_macro != NULL ||
		    gacl.a_macrolist != NULL) {
			mg_log(LOG_ERR,
			    "muliple sm_macro statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_macrolist = ale;
		break;

	case LT_ADDR:
		if (gacl.a_addr != NULL ||
		    gacl.a_addrlist != NULL) {
			mg_log(LOG_ERR,
			    "muliple addr statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_addrlist = ale;
		break;

	default:
		mg_log(LOG_ERR, "unexpected al_type %d line %d", 
		    ale->al_type, conf_line);
		exit(EX_DATAERR);
		break;
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl list \"%s\"", list);

	return;
}

void 
acl_add_code(code)
	char *code;
{
	if (gacl.a_code) {
		mg_log(LOG_ERR,
		    "code specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	if ((gacl.a_code = strdup(code)) == NULL) {
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
	if (gacl.a_ecode) {
		mg_log(LOG_ERR,
		    "ecode specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	if ((gacl.a_ecode = strdup(ecode)) == NULL) {
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
	if (gacl.a_msg) {
		mg_log(LOG_ERR,
		    "msg specified twice in ACL line %d", conf_line);
		exit(EX_DATAERR);
	}

	if ((gacl.a_msg = strdup(msg)) == NULL) {
		mg_log(LOG_ERR,
		    "malloc failed in ACL line %d", conf_line);
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load acl msg \"%s\"", msg);

	return;
}
