/* $Id: list.c,v 1.1 2006/07/27 12:42:42 manu Exp $ */

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
__RCSID("$Id: list.c,v 1.1 2006/07/27 12:42:42 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <regex.h>

#include <sys/queue.h>
#include <sys/types.h>

#include "milter-greylist.h"
#include "conf.h"
#include "acl.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#include "list.h"

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
	int type;
	char *name;
{
	struct all_list_entry *ale;

	if (conf.c_debug || conf.c_acldebug) { 
		printf("all_list_get(%d, \"%s\") called from line %d\n", 
		    type, name, conf_line);
	}

	if ((ale = malloc(sizeof(*ale))) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	ale->al_type = type;
	strncpy(ale->al_name, name, sizeof(ale->al_name));
	ale->al_name[sizeof(ale->al_name) - 1] = '\0';
	LIST_INIT(&ale->al_head);

	LIST_INSERT_HEAD(&all_list_head, ale, al_list);

	if (conf.c_debug || conf.c_acldebug) { 
		printf("created type %d list \"%s\"\n", 
		    ale->al_type, ale->al_name);
	}

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

		switch(le->l_type) {
		case L_STRING:
			free(le->l_data.string);
			break;

		case L_REGEX:
			regfree(le->l_data.regex);
			break;

#ifdef USE_DNSRBL
		case L_DNSRBL:
			/* Nothing to do, it is free'ed with dnsrbl_list */
			break;
#endif

		case L_ADDR:
			free(le->l_data.netblock.nb_addr);
			free(le->l_data.netblock.nb_mask);
			break;
		default:
			syslog(LOG_ERR, "unexpected type %d", ale->al_type);
			exit(EX_SOFTWARE);
			break;
		}

		free(le);
	}

	return;
}

void
list_add(ale, type, data)
	struct all_list_entry *ale;
	enum item_type type;
	void *data;
{
	struct list_entry *le;

	if (conf.c_debug || conf.c_acldebug) { 
		printf("list_add(%p, %d, %p) called from line %d\n", 
		    ale, type, data, conf_line);
	}

	if ((le = malloc(sizeof(*le))) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	le->l_type = type;

	switch(type) {
	case L_STRING:
		if ((le->l_data.string = strdup(data)) == NULL) {
			syslog(LOG_ERR, "strdup failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
		break;

#define ERRLEN 1024
	case L_REGEX: {
		size_t len;
		char *str = (char *)data;
		regex_t *re;
		int error;
		int extended;
		char errstr[ERRLEN + 1];

		/* Strip leading and trailing slashes */
		len = strlen(str);
		if (len > 0)
			str[len - 1] = '\0';
		str++;

		if ((re = malloc(sizeof(*re))) == NULL) {
			syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		extended = (conf.c_extendedregex ? REG_EXTENDED : 0);
		if ((error = regcomp(re, str, extended | REG_ICASE)) != 0) {
			regerror(error, re, errstr, ERRLEN);
			syslog(LOG_ERR, "bad regular expression \"%s\": %s\n",
			    str, errstr);
			exit(EX_DATAERR);
		}

		le->l_data.regex = re;
		break;
	}
		
	case L_ADDR:
		/* Not done here */
		/* FALLTHROUGH */
	default:
		syslog(LOG_ERR, "unexpected l_type %d", type);
		exit(EX_OSERR);
	}

	LIST_INSERT_HEAD(&ale->al_head, le, l_list);

	if (conf.c_debug || conf.c_acldebug) { 
		printf("inserted list item of type %d in list \"%s\"\n", 
		    type, ale->al_name);
	}
}

/* Lot of code duplicate with acl_add_netblock() ... */
void
list_add_netblock(ale, sa, salen, cidr)
	struct all_list_entry *ale;
	struct sockaddr *sa;
	socklen_t salen;
	int cidr;
{
	struct list_entry *le;
	ipaddr mask;
	int maxcidr, masklen;
#ifdef AF_INET
	int i;
#endif

	if ((le = malloc(sizeof(*le))) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	le->l_type = L_ADDR;

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
		syslog(LOG_ERR, "bad address family line %d", conf_line);
		exit(EX_DATAERR);
		break;
	}

	if (cidr > maxcidr || cidr < 0) {
		syslog(LOG_ERR, "bad mask in acl list line %d", conf_line);
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
	default:
		break;
	}

	if (((le->l_data.netblock.nb_addr = malloc(salen)) == NULL) ||
	    ((le->l_data.netblock.nb_mask = malloc(masklen)) == NULL)) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	le->l_data.netblock.nb_addrlen = salen;
	memcpy(le->l_data.netblock.nb_addr, sa, salen);
	memcpy(le->l_data.netblock.nb_mask, &mask, masklen);

	LIST_INSERT_HEAD(&ale->al_head, le, l_list);

	if (conf.c_debug || conf.c_acldebug) { 
		printf("inserted list item of type netblock in list \"%s\"\n", 
		    ale->al_name);
	}

	return;
}

void
all_list_settype(ale, type)
	struct all_list_entry *ale;
	enum list_type type;
{
	ale->al_type = type;

#if USE_DNSRBL
	/* Lookup the DNSRBL */
	if (type == LT_DNSRBL) {
		struct list_entry *le;

		LIST_FOREACH(le, &ale->al_head, l_list) {
			struct dnsrbl_entry *de;

			if (le->l_type != L_STRING) {
				syslog(LOG_ERR, "inconsistent list line %d",
				    conf_line);
				exit(EX_SOFTWARE);
			}

			if ((de = dnsrbl_byname(le->l_data.string)) == NULL) {
				syslog(LOG_ERR, "Inexistent DNSRBL \"%s\" "
				    "at line %d", le->l_data.string, conf_line);
				exit(EX_DATAERR);
			}

			le->l_data.dnsrbl = de;
			le->l_type = L_DNSRBL;
		}

	}
#endif /* USE_DNSRBL */
	return;
}

void
all_list_setname(ale, name)
	struct all_list_entry *ale;
	char *name;
{
	strncpy(ale->al_name, name, sizeof(ale->al_name));
	ale->al_name[sizeof(ale->al_name) - 1] = '\0';
	return;
}

void
glist_init(void)
{
	glist = all_list_get(LT_UNKNOWN, "");
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

int
list_addr_filter(list, sa)
	struct all_list_entry *list;
	struct sockaddr *sa;
{
	struct list_entry *le;

	LIST_FOREACH(le, &list->al_head, l_list) {
		if (ip_match(sa, 
		    le->l_data.netblock.nb_addr, 
		    le->l_data.netblock.nb_mask))
			break;
	}

	return (le != NULL);
}

#if USE_DNSRBL
int
list_dnsrbl_filter(list, sa)
	struct all_list_entry *list;
	struct sockaddr *sa;
{
	struct list_entry *le;

	LIST_FOREACH(le, &list->al_head, l_list) {
		if (dnsrbl_check_source(sa, le->l_data.dnsrbl) != 0)
			break;
	}

	return (le != NULL);
}
#endif

int
list_from_filter(list, from)
	struct all_list_entry *list;
	char *from;
{
	struct list_entry *le;

	LIST_FOREACH(le, &list->al_head, l_list) {
		switch(le->l_type) {
		case L_STRING:
			if (emailcmp(from, le->l_data.string) == 0)
				goto from_out;
			break;
		case L_REGEX:
			if (regexec(le->l_data.regex, from, 0, NULL, 0) == 0)
				goto from_out;
			break;
		default:
			syslog(LOG_ERR, "corrupted list");
			exit(EX_SOFTWARE);
			break;
		}
	}
from_out:
	return (le != NULL);
}

int
list_rcpt_filter(list, rcpt)
	struct all_list_entry *list;
	char *rcpt;
{
	struct list_entry *le;

	LIST_FOREACH(le, &list->al_head, l_list) {
		switch(le->l_type) {
		case L_STRING:
			if (emailcmp(rcpt, le->l_data.string) == 0)
				goto rcpt_out;
			break;
		case L_REGEX:
			if (regexec(le->l_data.regex, rcpt, 0, NULL, 0) == 0)
				goto rcpt_out;
			break;
		default:
			syslog(LOG_ERR, "corrupted list");
			exit(EX_SOFTWARE);
			break;
		}
	}
rcpt_out:
	return (le != NULL);
}

int
list_domain_filter(list, domain)
	struct all_list_entry *list;
	char *domain;
{
	struct list_entry *le;

	LIST_FOREACH(le, &list->al_head, l_list) {
		switch(le->l_type) {
		case L_STRING:
			if (domaincmp(domain, le->l_data.string) == 0)
				goto domain_out;
			break;
		case L_REGEX:
			if (regexec(le->l_data.regex, domain, 0, NULL, 0) == 0)
				goto domain_out;
			break;
		default:
			syslog(LOG_ERR, "corrupted list");
			exit(EX_SOFTWARE);
			break;
		}
	}
domain_out:
	return (le != NULL);
}