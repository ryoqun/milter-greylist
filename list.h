/* $Id: list.h,v 1.7 2009/02/08 20:26:20 manu Exp $ */

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

extern struct all_list_entry *glist;

struct list_entry {
	struct acl_clause_rec *l_acr;
	acl_data_t l_data;
	STAILQ_ENTRY(list_entry) l_list;
};

struct all_list_entry {
	struct acl_clause_rec *al_acr;
	char al_name[QSTRLEN + 1];
	LIST_ENTRY(all_list_entry) al_list;
	STAILQ_HEAD(,list_entry) al_head;
};

void all_list_init(void);
void all_list_clear(void);

struct all_list_entry *all_list_get(acl_clause_t, char *);
void all_list_put(struct all_list_entry *);
void list_add(struct all_list_entry *, acl_clause_t, void *);
void list_add_netblock(struct all_list_entry *, 
    struct sockaddr *, socklen_t, int);
void all_list_settype(struct all_list_entry *, acl_clause_t);
void all_list_setname(struct all_list_entry *, char *);
void glist_init(void);
struct all_list_entry *all_list_byname(char *);

#endif /* _LIST_H_ */
