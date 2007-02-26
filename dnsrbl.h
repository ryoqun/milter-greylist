/* $Id: dnsrbl.h,v 1.9 2007/02/26 04:27:50 manu Exp $ */

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

#include "acl.h"

#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025 
#endif 

LIST_HEAD(dnsrbllist, dnsrbl_entry);

struct dnsrbl_entry {
	char d_name[QSTRLEN + 1];
	char d_domain[NS_MAXDNAME + 1];
	sockaddr_t d_blacklisted;
	ipaddr d_mask;
	LIST_ENTRY(dnsrbl_entry) d_list;
};

struct dnsrbl_list {
	struct dnsrbl_entry *dl_dnsrbl;
	LIST_ENTRY(dnsrbl_list) dl_list;
};

void dnsrbl_init(void);
int dnsrbl_check_source(acl_data_t *, acl_stage_t,
			struct acl_param *, struct mlfi_priv *);
void reverse_endian(struct sockaddr *, struct sockaddr *);
void dnsrbl_source_add(char *, char *, struct sockaddr *, int);
struct dnsrbl_entry *dnsrbl_byname(char *);
void dnsrbl_clear(void);
void dnsrbl_list_cleanup(struct mlfi_priv *);
char *dnsrbl_dump_matches(struct mlfi_priv *, char *, size_t);
