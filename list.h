/* $Id: list.h,v 1.1 2006/07/27 12:42:42 manu Exp $ */

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

#ifndef _LIST_H_ 
#define _LIST_H_

LIST_HEAD(all_list, all_list_entry);
LIST_HEAD(list, list_entry);

extern struct all_list_entry *glist;

enum list_type { LT_UNKNOWN, LT_FROM, LT_RCPT, LT_DOMAIN, LT_ADDR, LT_DNSRBL };
enum item_type { L_STRING, L_ADDR, L_REGEX, L_DNSRBL };

struct list_entry {
	enum item_type l_type;
	union {
		struct {
			struct sockaddr *nb_addr;
			socklen_t nb_addrlen;
			ipaddr *nb_mask;
		} netblock;
		char *string;
		regex_t *regex;
#ifdef USE_DNSRBL
		struct dnsrbl_entry *dnsrbl;
#endif
	} l_data;
	LIST_ENTRY(list_entry) l_list;
};

struct all_list_entry {
	enum list_type al_type;
	char al_name[QSTRLEN + 1];
	LIST_ENTRY(all_list_entry) al_list;
	struct list al_head;
};

void all_list_init(void);
void all_list_clear(void);

struct all_list_entry *all_list_get(int, char *);
void all_list_put(struct all_list_entry *);
void list_add(struct all_list_entry *, enum item_type, void *);
void list_add_netblock(struct all_list_entry *, 
    struct sockaddr *, socklen_t, int);
void all_list_settype(struct all_list_entry *, enum list_type);
void all_list_setname(struct all_list_entry *, char *);
void glist_init(void);
struct all_list_entry *all_list_byname(char *);

int list_addr_filter(struct all_list_entry *, struct sockaddr *);
int list_dnsrbl_filter(struct all_list_entry *, struct sockaddr *);
int list_from_filter(struct all_list_entry *, char *);
int list_rcpt_filter(struct all_list_entry *, char *);
int list_domain_filter(struct all_list_entry *, char *);

#endif /* _LIST_H_ */
