/* $Id: ldapcheck.c,v 1.8 2009/06/08 23:40:06 manu Exp $ */

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
__RCSID("$Id: ldapcheck.c,v 1.8 2009/06/08 23:40:06 manu Exp $");
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

struct ldapconf_entry {
	char *lc_url;
	char *lc_dn;
	char *lc_pwd;
	LDAP *lc_ld;
	int lc_refcount;
	pthread_mutex_t lc_lock;
	SIMPLEQ_ENTRY(ldapconf_entry) lc_list;
};

SIMPLEQ_HEAD(ldapconf_list, ldapconf_entry);
LIST_HEAD(ldapcheck_list, ldapcheck_entry);

static void ldapcheck_conf_addone(char *, char *, char *);
static int ldapcheck_connect(struct ldapconf_entry *);
static int ldapcheck_disconnect(struct ldapconf_entry *);
static char *url_encode_percent(char *);
static inline void ldapcheck_lock(struct ldapconf_entry *);
static inline void ldapcheck_unlock(struct ldapconf_entry *);

static struct ldapcheck_list ldapcheck_list;
static struct ldapconf_list ldapconf_list;
static struct timeval ldap_timeout;
static char *ldap_binddn;
static char *ldap_bindpw;

int ldapcheck_gflags = 0;

void
ldapcheck_init(void) {
	LIST_INIT(&ldapcheck_list);
	SIMPLEQ_INIT(&ldapconf_list);

	ldapcheck_gflags = 0;
	memset(&ldap_timeout, 0, sizeof(ldap_timeout));

	return;
}

static void
ldapcheck_conf_addone(url, binddn, bindpw)
	char *url;
	char *binddn;
	char *bindpw;
{
	struct ldapconf_entry *lc;

	if ((lc = malloc(sizeof(*lc))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((lc->lc_url = strdup(url)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	lc->lc_dn = NULL;
	lc->lc_pwd = NULL;
	if ((binddn != NULL) && (lc->lc_dn = strdup(binddn)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((bindpw != NULL) && (lc->lc_pwd = strdup(bindpw)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	lc->lc_ld = NULL;
	lc->lc_refcount = 0;
	if (pthread_mutex_init(&lc->lc_lock, NULL) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_init() failed: %s",
		    strerror(errno));
		exit(EX_OSERR);
	}

	SIMPLEQ_INSERT_TAIL(&ldapconf_list, lc, lc_list);

	return; 
}

void
ldapcheck_conf_add(urls, binddn, bindpw)
	char *urls;
	char *binddn;
	char *bindpw;
{
	char *lasts = NULL;
	char *p;
	char *sep = "\t ";
	if (conf.c_debug || conf.c_acldebug) {
		mg_log(LOG_DEBUG, "bind options dn =\"%s\", pwd = \"%s\"\n",
		       binddn, bindpw);
	}
	if ((p = strtok_r(urls, sep, &lasts)) != NULL) {
		ldapcheck_conf_addone(p, binddn, bindpw);

		while (p)
			if ((p = strtok_r(NULL, sep, &lasts)) != NULL)
				ldapcheck_conf_addone(p, binddn, bindpw);
	}

	return;
}

void
ldapcheck_timeout_set(timeout)
	int timeout;
{
	ldap_timeout.tv_sec = timeout;
	ldap_timeout.tv_usec = 0;

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


/* lc must be locked */
static int
ldapcheck_connect(lc)
	struct ldapconf_entry *lc;
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
	if ((error = ldap_initialize(&lc->lc_ld, lc->lc_url)) != 0) {
		mg_log(LOG_WARNING, 
		       "ldap_initialize failed for LDAP URL \"%s\": %s", 
		       lc->lc_url, ldap_err2string(error));
		return -1;
	}

	option = LDAP_OPT_PROTOCOL_VERSION;
	optval = LDAP_VERSION3;
	if ((error = ldap_set_option(lc->lc_ld, option, &optval)) != 0) {
		mg_log(LOG_WARNING,
		       "ldap_set_option failed for LDAP URL \"%s\": %s", 
		       lc->lc_url, ldap_err2string(error));
		goto bad;
	}

	
	if (ldap_timeout.tv_sec != 0) {
		option = LDAP_OPT_TIMEOUT;
		if ((error = ldap_set_option(lc->lc_ld, 
					     option, 
					     &ldap_timeout)) != 0) {
			mg_log(LOG_WARNING,
			       "ldap_set_option failed for "
			       "LDAP URL \"%s\": %s", 
			       lc->lc_url, ldap_err2string(error));
			goto bad;
		}

		option = LDAP_OPT_NETWORK_TIMEOUT;
		if ((error = ldap_set_option(lc->lc_ld, 
					     option, 
					     &ldap_timeout)) != 0) {
			mg_log(LOG_WARNING,
			       "ldap_set_option failed for "
			       "LDAP URL \"%s\": %s", 
			       lc->lc_url, ldap_err2string(error));
			goto bad;
		}
	}

	error = ldap_simple_bind_s(lc->lc_ld, lc->lc_dn, lc->lc_pwd);
	if (error != LDAP_SUCCESS) {
		mg_log(LOG_WARNING,
		       "ldap_simple_bind_s (%s/%s) failed for LDAP URL \"%s\": %s",
		       lc->lc_dn, lc->lc_pwd, lc->lc_url, ldap_err2string(error));
		goto bad;
	}

	if (conf.c_debug)
		mg_log(LOG_INFO, "LDAP URL \"%s\" connected", lc->lc_url);

	return 0;

bad:
	mg_log(LOG_WARNING, "LDAP URL \"%s\" unreachable", lc->lc_url);
	return -1;
}

/* lc must be locked */
static int
ldapcheck_disconnect(lc)
	struct ldapconf_entry *lc;
{	
	int error = 0;

	if (lc->lc_ld == NULL)
		return 0;

	/* Sanity check */
	if (lc->lc_refcount < 0) {
		mg_log(LOG_ERR, "bad refcount for LDAP URL \"%s\"", lc->lc_url);
		exit(EX_OSERR);
	}
	
	/* 
	 * Another thread is still using this connexion. We cannot dispose
	 * it immediatly, so we just return. If the fault is permanent, 
	 * the other threads will get more errors, and the last one will
	 * be able to disconnect. If the fault is transcient, other threads
	 * may have more success, so we do not need to disconnect.
	 */
	if (lc->lc_refcount > 0) {
		mg_log(LOG_DEBUG, "LDAP URL \"%s\" has refcount %d", 
		       lc->lc_url, lc->lc_refcount);
		return 0;
	}

	if ((error = ldap_unbind_s(lc->lc_ld)) != 0)
		mg_log(LOG_ERR, "ldap_unbind_s() failed: %s",
		       ldap_err2string(error));

	lc->lc_ld = NULL;

	if (conf.c_debug)
		mg_log(LOG_INFO, "LDAP URL \"%s\" disconnected", lc->lc_url);

	return error;
}


int
ldapcheck_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	struct ldapconf_entry *lc = NULL;
	char *rcpt;
	struct ldapcheck_entry *lce;
	LDAPURLDesc *lud = NULL;
	char *url = NULL;
	struct timeval tv1, tv2, tv3;
	LDAPMessage *res0 = NULL;
	LDAPMessage *res = NULL;
	int error,pushed = 0 ;
	int retval = -1;
	int clearprop;

	rcpt = priv->priv_cur_rcpt;
	lce = ad->ldapcheck;
	url = fstring_expand(priv, rcpt, lce->lce_url);
	clearprop = lce->lce_flags & L_CLEARPROP;

	if (conf.c_debug) {
		mg_log(LOG_DEBUG, "checking \"%s\"\n", url);
		gettimeofday(&tv1, NULL);
	}

	if ((error = ldap_url_parse(url, &lud)) != 0) {
		mg_log(LOG_ERR, "Bad expanded LDAP URL \"%s\"", url);
		goto bad;
	}

	SIMPLEQ_FOREACH(lc, &ldapconf_list, lc_list) {
		ldapcheck_lock(lc);
		lc->lc_refcount++;
		ldapcheck_unlock(lc);

		if (lc->lc_ld == NULL) {
			int error;

			ldapcheck_lock(lc);
			error = ldapcheck_connect(lc);
			if (error != 0) {
				lc->lc_refcount--;
				(void)ldapcheck_disconnect(lc);
			}
			ldapcheck_unlock(lc);
			if (error != 0)
				continue;
		}

		if (conf.c_debug)
			mg_log(LOG_DEBUG, 
			       "Querying \"%s\"", lc->lc_url);

		/*
		 * Perform the search
		 */
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
					  &res0);

		if (error == 0)
			break;

		ldapcheck_lock(lc);
		lc->lc_refcount--;
		(void)ldapcheck_disconnect(lc);
		ldapcheck_unlock(lc);

		mg_log(LOG_ERR, 
		       "LDAP URL \"%s\" unreachable: %s", 
		       url, ldap_err2string(error));
	}

	if ((lc == NULL) || (lc->lc_ld == NULL)) {
		mg_log(LOG_ERR, "No LDAP URL can be reached");
		goto bad;	
	}

	/* 
	 * Extract results
	 */
	for (res = ldap_first_entry(lc->lc_ld, res0);
	     res != NULL;
	     res = ldap_next_entry(lc->lc_ld, res)) {
		BerElement *ber = NULL;
		char *attr = NULL;

		for (attr = ldap_first_attribute(lc->lc_ld, res, &ber);
		     attr != NULL;
		     attr = ldap_next_attribute(lc->lc_ld, res, ber)) {
			char **vals = NULL;
			char **val = NULL;
			
			vals = ldap_get_values(lc->lc_ld, res, attr);
			if (vals == NULL) {
				mg_log(LOG_ERR, "ldap_get_values for URL \"%s\" attr %s "
						"returns vals = NULL", attr, url);
				ldap_value_free(vals);
				ldap_memfree(attr);
				continue;
			}

			for (val = vals; *val; val++)
			{
				acl_modify_by_prop(attr, *val, ap);
				prop_push(attr, *val, clearprop, priv);
				pushed++;
				if (conf.c_acldebug) mg_log(LOG_DEBUG,
					"acl debug: pushed prop %s: %s", attr,*val);
			}

			ldap_value_free(vals);
			ldap_memfree(attr);
		}

		if (ber != NULL)
			ber_free(ber, 0);
	}

	retval = pushed ? 1 : 0 ;
bad:
	if (res0)
		ldap_msgfree(res0);
	if (lud)
		ldap_free_urldesc(lud);

	if (lc != NULL) {
		ldapcheck_lock(lc);
		lc->lc_refcount--;
		ldapcheck_unlock(lc);
	}

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
	struct ldapconf_entry *lc;

	while(!LIST_EMPTY(&ldapcheck_list)) {
		lce = LIST_FIRST(&ldapcheck_list);
		LIST_REMOVE(lce, lce_list);
		free(lce);
	}
	
	while(!SIMPLEQ_EMPTY(&ldapconf_list)) {
		lc = SIMPLEQ_FIRST(&ldapconf_list);
		SIMPLEQ_REMOVE(&ldapconf_list, lc, ldapconf_entry, lc_list);

		ldapcheck_lock(lc);
		ldapcheck_disconnect(lc);
		ldapcheck_unlock(lc);

		if (lc->lc_url)
			free(lc->lc_url);

		if (lc->lc_dn)
			free(lc->lc_dn);

		if (lc->lc_pwd)
			free(lc->lc_pwd);

		free(lc);
	}

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


static inline void
ldapcheck_lock(lc)
	struct ldapconf_entry *lc;
{
	if (pthread_mutex_lock(&lc->lc_lock) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_lock failed "
		    "in urlcheck_clear: %s", strerror(errno));
		exit(EX_OSERR);
	}

	return;
}

static inline void
ldapcheck_unlock(lc)
	struct ldapconf_entry *lc;
{
	if (pthread_mutex_unlock(&lc->lc_lock) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_unlock failed "
		    "in urlcheck_clear: %s", strerror(errno));
		exit(EX_OSERR);
	}

	return;
}

#endif /* USE_LDAP */
