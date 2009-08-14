/* $Id: prop.c,v 1.3 2009/08/14 00:09:02 manu Exp $ */

/*
 * Copyright (c) 2006-2008 Emmanuel Dreyfus
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

#if defined(USE_CURL) || defined(USE_LDAP)

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: prop.c,v 1.3 2009/08/14 00:09:02 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sysexits.h>
#include <signal.h>

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif
#include <sys/types.h>

#include "milter-greylist.h"
#include "pending.h"
#include "spf.h"
#include "acl.h"
#include "conf.h"
#include "sync.h"
#include "prop.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

void
prop_push(linep, valp, clear, priv)
	char *linep;
	char *valp;
	int clear;
	struct mlfi_priv *priv;
{
	char *cp;
	struct prop *up;

	if ((up = malloc(sizeof(*up))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((up->up_name = strdup(linep)) == NULL) {
		mg_log(LOG_ERR, "strup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((up->up_value = strdup(valp)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	/*
	 * Convert everything to lower-case
	 */
	for (cp = up->up_name; *cp; cp++)
		*cp = (char)tolower((int)*cp);

	for (cp = up->up_value; *cp; cp++)
		*cp = (char)tolower((int)*cp);

	up->up_flags = UP_TMPPROP;
	if (clear)
		up->up_flags |= UP_CLEARPROP;

	LIST_INSERT_HEAD(&priv->priv_prop, up, up_list);

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "got prop $%s = \"%s\"", linep, valp);

	return;
}

void
prop_clear_all(priv)
	struct mlfi_priv *priv;
{
	struct prop *up;

	while ((up = LIST_FIRST(&priv->priv_prop)) != NULL) {
		free(up->up_name);
		free(up->up_value);
		LIST_REMOVE(up, up_list);
		free(up);
	}

	return;
}

int 
prop_string_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct prop *up;
	acl_data_t *upd;
	char *string;
	int retval = 0;

	upd = ad->prop->upd_data;
	string = fstring_expand(priv, NULL, upd->string);

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(ad->prop->upd_name, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs \"%s\"",
			    up->up_name, up->up_value, string);

		if (strcasecmp(up->up_value, string) == 0) {
			retval = 1;
			break;
		}
	}

	free(string);	
	return retval;
}

void
prop_clear(priv)
	struct mlfi_priv *priv; 
{
	struct prop *up;
	struct prop *nup;

	up = LIST_FIRST(&priv->priv_prop); 

	while (up != NULL) {
		nup = LIST_NEXT(up, up_list);
		if (up->up_flags & UP_CLEARPROP) {
			free(up->up_name);
			free(up->up_value);
			LIST_REMOVE(up, up_list);
			free(up);
		}
		up = nup;
	}
	return;
}

void
prop_clear_tmp(priv)
	struct mlfi_priv *priv; 
{
	struct prop *up;
	struct prop *nup;

	up = LIST_FIRST(&priv->priv_prop); 

	while (up != NULL) {
		nup = LIST_NEXT(up, up_list);
		if (up->up_flags & UP_TMPPROP) {
			free(up->up_name);
			free(up->up_value);
			LIST_REMOVE(up, up_list);
			free(up);
		}
		up = nup;
	}
	return;
}

void
prop_untmp(priv)
	struct mlfi_priv *priv; 
{
	struct prop *up;

	LIST_FOREACH(up, &priv->priv_prop, up_list)
		up->up_flags &= ~UP_TMPPROP;
	return;
}

int 
prop_regex_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct prop *up;
	acl_data_t *upd;
	int retval = 0;

	upd = ad->prop->upd_data;

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(ad->prop->upd_name, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs %s",
			    up->up_name, up->up_value, upd->regex.re_copy);

		if (myregexec(priv, upd, ap, up->up_value) == 0) {
			retval = 1;
			break;
		}
	}

	return retval;
}
#endif /* USE_CURL || USE_LDAP */
