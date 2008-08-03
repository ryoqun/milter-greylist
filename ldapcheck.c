/* $Id: ldapcheck.c,v 1.1 2008/08/03 09:48:44 manu Exp $ */

/*
 * Copyright (c) 2008 Emmanuel Dreyfus
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

#ifdef USE_LDAP

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: ldapcheck.c,v 1.1 2008/08/03 09:48:44 manu Exp $");
#endif
#endif
#include <ctype.h>
#include <ldap.h>
#include <pthread.h>
#include <lber.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>

#include "conf.h"
#include "milter-greylist.h"
#include "spf.h"
#include "acl.h"
#include "prop.h"
#include "ldapcheck.h"

struct ldapconf {
	char lc_urls[QSTRLEN + 1];
	char *lc_dn;
	char *lc_pwd;
	LDAP *lc_ld;
};


LIST_HEAD(ldapcheck_list, ldapcheck_entry);

static int ldapcheck_reconnect(struct ldapconf *);
static int ldapcheck_connect(struct ldapconf *);
static int ldapcheck_disconnect(struct ldapconf *);
static char *url_encode_percent(char *);

static struct ldapcheck_list ldapcheck_list;
static struct ldapconf ldapconf;

int ldapcheck_gflags = 0;

void
ldapcheck_init(void) {
	LIST_INIT(&ldapcheck_list);

	ldapconf.lc_urls[0] = '\0';
	ldapconf.lc_ld = NULL;
	ldapconf.lc_dn = "";
	ldapconf.lc_pwd = "";

	ldapcheck_gflags = 0;
}

void
ldapcheck_conf_add(urls)
	char *urls;
{
	strncpy(ldapconf.lc_urls, urls, sizeof(ldapconf.lc_urls));
	ldapconf.lc_urls[sizeof(ldapconf.lc_urls) - 1 ] = '\0';

	return;
}

struct ldapcheck_entry *
ldapcheck_def_add(name, url, flags) 
	char *name;
	char *url;
	int flags;
{
	int error;

	struct ldapcheck_entry *lce;
	LDAPURLDesc *lud;
	char *eurl;

	/*
	 * Just check
	 */
	eurl = url_encode_percent(url);
	if ((error = ldap_url_parse(eurl, &lud)) != 0) {
		mg_log(LOG_ERR, "Bad LDAP URL \"%s\" at line %d", 
		       eurl, conf_line - 1);
		exit(EX_DATAERR);
	}
	free(eurl);
	ldap_free_urldesc(lud);

	if ((lce = malloc(sizeof(*lce))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	strncpy(lce->lce_name, name, sizeof(lce->lce_name));
	lce->lce_name[sizeof(lce->lce_name) - 1] = '\0';
	strncpy(lce->lce_url, url, sizeof(lce->lce_url));
	lce->lce_url[sizeof(lce->lce_url) - 1] = '\0';
	lce->lce_flags = flags;

	LIST_INSERT_HEAD(&ldapcheck_list, lce, lce_list);

	if (conf.c_debug || conf.c_acldebug) {
		mg_log(LOG_DEBUG, "load LDAP check \"%s\" \"%s\" %s", 
		    lce->lce_name, lce->lce_url, 
		    (lce->lce_flags & L_CLEARPROP) ? " clear" : "");
	}

	ldapcheck_gflags = 0;

	return lce;
}


static int
ldapcheck_reconnect(lc)
	struct ldapconf *lc;
{
	(void)ldapcheck_disconnect(lc);
	return ldapcheck_connect(lc);
}

static int
ldapcheck_connect(lc)
	struct ldapconf *lc;
{	
	int error;
	int option;
	int optval;

	/* 
	 * Already connected?
	 */
	if (lc->lc_ld != NULL)
		return 0;

	/*
	 * Initialize connexion
	 */
	if ((error = ldap_initialize(&lc->lc_ld, lc->lc_urls)) != 0) {
		mg_log(LOG_WARNING, 
		       "ldap_initialize failed for LDAP URL \"%s\": %s", 
		       lc->lc_urls, ldap_err2string(error));
		return -1;
	}

	option = LDAP_OPT_PROTOCOL_VERSION;
	optval = LDAP_VERSION3;
	if ((error = ldap_set_option(lc->lc_ld, option, &optval)) != 0) {
		mg_log(LOG_WARNING,
		       "ldap_set_option failed for LDAP URL \"%s\": %s", 
		       lc->lc_urls, ldap_err2string(error));
		goto bad;
	}

	error = ldap_simple_bind_s(lc->lc_ld, lc->lc_dn, lc->lc_pwd);
	if (error != 0) {
		mg_log(LOG_WARNING,
		       "ldap_simple_bind_s failed for LDAP URL \"%s\": %s",
		       lc->lc_urls, ldap_err2string(error));
		goto bad;
	}

	return 0;

bad:
	(void)ldapcheck_disconnect(lc);
	return -1;
}

static int
ldapcheck_disconnect(lc)
	struct ldapconf *lc;
{	
	int error = 0;

	if (lc->lc_ld == NULL)
		return 0;

	if ((error = ldap_unbind_s(lc->lc_ld)) != 0)
		mg_log(LOG_ERR, "ldap_unbind_s() failed: %s",
		       ldap_err2string(error));

	lc->lc_ld = NULL;

	return error;
}


int
ldapcheck_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct ldapconf *lc;
	char *rcpt;
	struct ldapcheck_entry *lce;
	LDAPURLDesc *lud = NULL;
	char *url = NULL;
	struct timeval tv1, tv2, tv3;
	LDAPMessage *res;
	int error;
	int retval = -1;
	int clearprop;

	lc = &ldapconf;
	rcpt = priv->priv_cur_rcpt;
	lce = ad->ldapcheck;
	url = fstring_expand(priv, rcpt, lce->lce_url);
	clearprop = lce->lce_flags & L_CLEARPROP;

	if (conf.c_debug) {
		mg_log(LOG_DEBUG, "checking \"%s\"\n", url);
		gettimeofday(&tv1, NULL);
	}

	if (lc->lc_ld == NULL)
		if (ldapcheck_connect(lc) != 0)
			goto bad;

	if ((error = ldap_url_parse(url, &lud)) != 0) {
		mg_log(LOG_ERR, "Bad expanded LDAP URL \"%s\"", url);
		goto bad;
	}

	/*
	 * Perform the search
	 */
retry:
	error = ldap_search_ext_s(lc->lc_ld, 
				  lud->lud_dn,
				  lud->lud_scope,
				  lud->lud_filter,
				  lud->lud_attrs,
				  0,		/* attrsonly */
				  NULL, 	/* serverctrls */
				  NULL, 	/* clientctrls */
				  NULL,		/* timeout */
				  0,		/* sizelimit */
				  &res);
	if (error != 0) {
		if ((error == LDAP_SERVER_DOWN) &&
		    (ldapcheck_reconnect(lc) != 0))
			goto retry;
			
		mg_log(LOG_ERR, "ldap_search_ext_s(\"%s\") failed: %s", 
		       url, ldap_err2string(error));
		goto bad;
	}
	
	/* 
	 * Extract results
	 */
	res = ldap_first_entry(lc->lc_ld, res);
	while (res != NULL) {
		BerElement *ber;
		char *attr;

		attr = ldap_first_attribute(lc->lc_ld, res, &ber);
		while (attr != NULL) {
			char **vals;
			char **val;
			
			vals = ldap_get_values(lc->lc_ld, res, attr);
			if (vals == NULL) {
				mg_log(LOG_ERR, "ldap_get_values for URL \"%s\""
						"returns vals = NULL", url);
				goto bad;
			}

			for (val = vals; *val; val++) 
				prop_push(attr, *val, clearprop, priv);

			ldap_value_free(vals);

			attr = ldap_next_attribute(lc->lc_ld, res, ber);
		}
		
		res = ldap_next_entry(lc->lc_ld, res);
	}

	retval = 0;
bad:
	if (lud)
		ldap_free_urldesc(lud);
	if (url)
		free(url);
	
        if (conf.c_debug) {
                gettimeofday(&tv2, NULL);
                timersub(&tv2, &tv1, &tv3);
                mg_log(LOG_DEBUG, "ldapcheck lookup performed in %ld.%06lds",
                    tv3.tv_sec, tv3.tv_usec);
        }

	return retval;
}

void
ldapcheck_clear(void)	/* acllist must be write locked */
{
	struct ldapcheck_entry *lce;
	struct ldapconf *lc;

	lc = &ldapconf;

	while(!LIST_EMPTY(&ldapcheck_list)) {
		lce = LIST_FIRST(&ldapcheck_list);
		LIST_REMOVE(lce, lce_list);
		free(lce);
	}
	
	(void)ldapcheck_disconnect(lc);

	ldapcheck_init();

	return;
}

struct ldapcheck_entry *
ldapcheck_byname(name)
	char *name;
{
	struct ldapcheck_entry *lce = NULL;

	LIST_FOREACH(lce, &ldapcheck_list, lce_list) {
		if (strcmp(name, lce->lce_name) == 0)
			break;
	}

	return lce;
}

static char *
url_encode_percent(url) 
	char *url;
{
	char *cp;
	size_t len;
	char *out;
	char *op;

	len = 0;
	for (cp = url; *cp; cp++) {
		if (*cp != '%')
			len++;
		else
			len += 3;
	}
	len++;

	if ((out = malloc(len + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed", 
		    len + 1, strerror(errno));
		exit(EX_OSERR);
	}
	out[0] = '\0';
	op = out;

	for (cp = url; *cp; cp++) {
		if (*cp != '%') {
			*op++ = *cp;
		} else {
			strcpy(op, "%25");
			op += 3;
		}
	}

	return out;
}

#if 0
static char *
url_encode(url)
	char *url;
{
	char *cp;
	size_t len;
	char *out;
	char *op;

	len = 0;
	for (cp = url; *cp; cp++) {
		if (isalnum((int)*cp) || 
		    (*cp == '.') || 
		    (*cp == '-') || 
		    (*cp == '_')) {
			len++;
		} else {
			len += 3;
		}
	}
	len++;

	if ((out = malloc(len + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed", 
		    len + 1, strerror(errno));
		exit(EX_OSERR);
	}
	out[0] = '\0';
	op = out;

	for (cp = url; *cp; cp++) {
		if (isalnum((int)*cp) || 
		    (*cp == '.') || 
		    (*cp == '-') || 
		    (*cp == ':') || 
		    (*cp == '_')) {
			*op++ = *cp;
		} else {
			int i;

			*op = '\0';
			(void)snprintf(op, 4, "%%%x", *cp);
			for (i = 0; i < 4; i++)
				op[i] = (char)toupper((int)op[i]);
			op += 3;
		}
	}

	return out;
}
#endif

#endif /* USE_LDAP */
