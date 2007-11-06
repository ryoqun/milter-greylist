/* $Id: list.c,v 1.16 2007/11/06 11:39:33 manu Exp $ */

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
__RCSID("$Id: list.c,v 1.16 2007/11/06 11:39:33 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/types.h>
#include <regex.h>

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <netinet/in.h>

#include "milter-greylist.h"
#include "conf.h"
#include "spf.h"
#include "acl.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#ifdef USE_CURL
#include "urlcheck.h"
#endif
#include "macro.h"
#include "list.h"
#include "acl.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

struct all_list all_list_head;
struct all_list_entry *glist;

void
all_list_init(void)
{
	LIST_INIT(&all_list_head);

	glist_init();
	return;
}

void
all_list_clear(void)	/* acllist must be write locked */
{
	struct all_list_entry *ale;

	while(!LIST_EMPTY(&all_list_head)) {
		ale = LIST_FIRST(&all_list_head);
		LIST_REMOVE(ale, al_list);

		all_list_put(ale);	

		free(ale);
	}

	all_list_init();

	return;
}

struct all_list_entry *
all_list_get(type, name)
	acl_clause_t type;
	char *name;
{
	struct all_list_entry *ale;

	if ((ale = malloc(sizeof(*ale))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	ale->al_acr = get_acl_clause_rec(type);
	strncpy(ale->al_name, name, sizeof(ale->al_name));
	ale->al_name[sizeof(ale->al_name) - 1] = '\0';
	LIST_INIT(&ale->al_head);

	LIST_INSERT_HEAD(&all_list_head, ale, al_list);

	return ale;
}

void
all_list_put(ale)
	struct all_list_entry *ale;
{
	struct list_entry *le;

	while(!LIST_EMPTY(&ale->al_head)) {
		le = LIST_FIRST(&ale->al_head);
		LIST_REMOVE(le, l_list);

		if (le->l_acr->acr_free)
			(*le->l_acr->acr_free)(&le->l_data);

		free(le);
	}
	return;
}

void
list_add(ale, type, data)
	struct all_list_entry *ale;
	acl_clause_t type;
	void *data;
{
	struct list_entry *le;
	
	if ((le = malloc(sizeof(*le))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	le->l_acr = get_acl_clause_rec(type);
	(*le->l_acr->acr_add)(&le->l_data, data);

	LIST_INSERT_HEAD(&ale->al_head, le, l_list);

	if (conf.c_debug || conf.c_acldebug) {
		char buf[1024];

		mg_log(LOG_INFO, "load list item %s", 
		    (*le->l_acr->acr_print)(&le->l_data, buf, sizeof(buf)));
	}
}

void
all_list_settype(ale, l_type)
	struct all_list_entry *ale;
	acl_clause_t l_type;
{
	struct acl_clause_rec *list_acr;
	struct list_entry *le;
	acl_clause_t i_type;
	char *string;
	struct acl_clause_rec *new_item_acr;

	list_acr = get_acl_clause_rec(l_type);

	/* Fix each item type */
	LIST_FOREACH(le, &ale->al_head, l_list) {
		if (le->l_acr->acr_stage != AS_NONE) 
			continue;

		i_type = le->l_acr->acr_type;
		new_item_acr = acl_list_item_fixup(i_type, l_type);
		if (new_item_acr == NULL) {
			char b[1024];

			mg_log(LOG_ERR, 
			    "list has mismatching item %s at line %d",
			    (*le->l_acr->acr_print)(&le->l_data, b, sizeof(b)),
			    conf_line);
			exit(EX_DATAERR);	
		}

		if (conf.c_debug || conf.c_acldebug) {
			char b[1024];

			mg_log(LOG_DEBUG, "item %s changing type from %s to %s",
			    (*le->l_acr->acr_print)(&le->l_data, b, sizeof(b)),
			    le->l_acr->acr_name, new_item_acr->acr_name);
		}

		/* 
		 * Possible type changes:
		 * AC_EMAIL -> AC_FROM, AC_RCPT
		 * AC_REGEX -> AC_FROM_RE, AC_RCPT_RE, AC_DOMAIN_RE, ...
		 *    No need for data modification
		 * AC_STRING -> AC_DNSRBL, AC_URLCHECK, AC_MACRO, AC_BODY, ...
		 *    We get a string and we reinject it.
		 */
		if (le->l_acr->acr_type != new_item_acr->acr_type) {
			char b[1024];

			switch(le->l_acr->acr_type) {
			case AC_EMAIL:
			case AC_REGEX:
				le->l_acr = new_item_acr;
				break;
			case AC_STRING:
				string = strdup(le->l_data.string);
				if (string == NULL) {
					mg_log(LOG_ERR, "strdup failed: %s",
					    strerror(errno));
					exit(EX_DATAERR);
				}
				(*le->l_acr->acr_free)(&le->l_data);
				le->l_acr = new_item_acr;
				(*le->l_acr->acr_add)(&le->l_data, string);
				free(string);
				break;
			default:
				(void)(*le->l_acr->acr_print)
				    (&le->l_data, b, sizeof(b));

				mg_log(LOG_ERR, "cannot switch item %s "
				    "type from %s to %s", b,
				    le->l_acr->acr_name, 
				    new_item_acr->acr_name);
				exit(EX_DATAERR);
				break;
			}
		}

	}
	ale->al_acr = list_acr;

	if (conf.c_debug || conf.c_acldebug) 
		mg_log(LOG_INFO, "load list type %s, stage %s", 
		    ale->al_acr->acr_name, 
		    stage_string(ale->al_acr->acr_stage));

	return;
}

void
all_list_setname(ale, name)
	struct all_list_entry *ale;
	char *name;
{
	if (all_list_byname(name) != NULL) {
		mg_log(LOG_ERR, "list \"%s\" defined twice at line %d",
		    name, conf_line - 1);
		exit(EX_DATAERR);
	}

	if (conf.c_debug || conf.c_acldebug)
		mg_log(LOG_DEBUG, "load list name \"%s\"", name);

	strncpy(ale->al_name, name, sizeof(ale->al_name));
	ale->al_name[sizeof(ale->al_name) - 1] = '\0';
	return;
}

void
glist_init(void)
{
	glist = all_list_get(AC_LIST, "");
	return;
}


struct all_list_entry *
all_list_byname(name)
	char *name;
{
	struct all_list_entry *ale;

	LIST_FOREACH(ale, &all_list_head, al_list) {
		if (strcmp(ale->al_name, name) == 0)
			break;
	}

	return ale;
}

