/* $Id: macro.c,v 1.4 2006/12/29 18:32:44 manu Exp $ */

/*
 * Copyright (c) 2006 Emmanuel Dreyfus
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
__RCSID("$Id: macro.c,v 1.4 2006/12/29 18:32:44 manu Exp $");
#endif
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <regex.h>

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include "milter-greylist.h"
#include "pending.h"
#include "conf.h"
#include "macro.h"

/* 
 * locking is done through the same lock as acllist: both are static 
 * configuration, which are readen or changed at the same times.
 */
struct macrolist macro_head;

void
macro_init(void) {
	LIST_INIT(&macro_head);
	return;
}

int
macro_check(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	SMFICTX *ctx;
	struct macro_entry *me;
	char *value;
	int extended;
	int retval;

	ctx = priv->priv_ctx;
	me = ad->macro;

	value = smfi_getsymval(ctx, me->m_macro);
							 
	switch (me->m_type) {
	case M_UNSET:
		retval = (value == NULL) ? 0 : 1;
		break;
	case M_STRING:
		if (value == NULL)
			retval = -1;
		else
			retval = strcmp(value, me->m_string);
		break;
	case M_REGEX:
		if (value == NULL) {
			retval = -1;
		} else {
			extended = (conf.c_extendedregex ? REG_EXTENDED : 0);
			retval = regexec(me->m_regex, value, 0, NULL, 0);
		}
		break;
	default:
		mg_log(LOG_ERR, "unexpecte me->m_type = %d", me->m_type);
		exit(EX_SOFTWARE);
		break;
	}

	if (conf.c_debug) {
		mg_log(LOG_DEBUG, "sm_macro \"%s\" match", me->m_name);
		mg_log(LOG_DEBUG, "sm_macro \"%s\" %s=%s %s", me->m_name,
		    me->m_macro, value ? value : "(null)",
		    retval ? "nomatch" : "match");
	}

	return retval;
}


void
macro_add_unset(name, macro)
	char *name;
	char *macro;
{
	struct macro_entry *me;

	if (macro_byname(name) != NULL) {
		mg_log(LOG_ERR, "macro \"%s\" defined twice at line %d",
		    name, conf_line - 1);
		exit(EX_DATAERR);
	}

	if ((me = malloc(sizeof(*me))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	me->m_type = M_UNSET;
	if ((me->m_name = strdup(name)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((me->m_macro = strdup(macro)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	me->m_string = NULL;

	LIST_INSERT_HEAD(&macro_head, me, m_list);

	if (conf.c_debug || conf.c_acldebug) {
		mg_log(LOG_DEBUG, "load sm_macro \"%s\" \"%s\" unset",
		    me->m_name, me->m_macro);
	}

	return;
}

void
macro_add_string(name, macro, string)
	char *name;
	char *macro;
	char *string;
{
	struct macro_entry *me;

	if ((me = malloc(sizeof(*me))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	me->m_type = M_STRING;
	if ((me->m_name = strdup(name)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((me->m_macro = strdup(macro)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((me->m_string = strdup(string)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	LIST_INSERT_HEAD(&macro_head, me, m_list);

	if (conf.c_debug || conf.c_acldebug) {
		mg_log(LOG_DEBUG, "load sm_macro \"%s\" \"%s\" \"%s\"",
		    me->m_name, me->m_macro, me->m_string);
	}

	return;
}

#define ERRLEN 1024
void
macro_add_regex(name, macro, regex)
	char *name;
	char *macro;
	char *regex;
{
	struct macro_entry *me;
	char errstr[ERRLEN + 1];
	int error;
	size_t len;

	/* Strip slashes */
	len = strlen(regex);
	if (len > 0)
		regex[len - 1] = '\0';
	regex++;

	if ((me = malloc(sizeof(*me))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	me->m_type = M_REGEX;
	if ((me->m_name = strdup(name)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((me->m_macro = strdup(macro)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((me->m_regex = malloc(sizeof(*me->m_regex))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
        if ((error = regcomp(me->m_regex, regex,
	    (conf.c_extendedregex ? REG_EXTENDED : 0) | REG_ICASE)) != 0) {
		regerror(error, me->m_regex, errstr, ERRLEN);
		mg_log(LOG_ERR, "bad regular expression \"%s\": %s",
		    regex, errstr);
		exit(EX_OSERR);
	}

	LIST_INSERT_HEAD(&macro_head, me, m_list);

	if (conf.c_debug || conf.c_acldebug) {
		mg_log(LOG_DEBUG, "load sm_macro \"%s\" \"%s\" /%s/",
		    me->m_name, me->m_macro, regex);
	}
	return;
}

struct macro_entry *
macro_byname(macro)	/* acllist must be read locked */
	char *macro;
{
	struct macro_entry *me;	

	LIST_FOREACH(me, &macro_head, m_list) {
		if (strcmp(me->m_name, macro) == 0)
			break;
	}

	return me;
}

void
macro_clear(void)	/* acllist must be write locked */
{
	struct macro_entry *me;

	while(!LIST_EMPTY(&macro_head)) {
		me = LIST_FIRST(&macro_head);

		LIST_REMOVE(me, m_list);

		free(me->m_name);
		free(me->m_macro);

		switch (me->m_type) {
		case M_UNSET:
			break;
		case M_STRING:
			free(me->m_string);
			break;
		case M_REGEX:
			regfree(me->m_regex);
			free(me->m_regex);
			break;
		default:
			mg_log(LOG_ERR, 
			    "unexpecte me->m_type = %d", me->m_type);
			exit(EX_SOFTWARE);
		}
	}

	macro_init();
	return;
}

