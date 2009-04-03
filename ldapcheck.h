/* $Id: ldapcheck.h,v 1.2 2009/04/03 04:15:27 manu Exp $ */

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

#ifndef _LDAPCHECK_H_
#define _LDAPCHECK_H_

#include "config.h"

#ifdef USE_LDAP

#include <ldap.h>

struct ldapcheck_entry {
	char lce_name[QSTRLEN + 1];
        char lce_url[QSTRLEN + 1];
	int lce_flags;
	LIST_ENTRY(ldapcheck_entry) lce_list;
};   

/* For lce_flags */
#define L_CLEARPROP     0x4
 
extern int ldapcheck_gflags;

void ldapcheck_init(void);
void ldapcheck_conf_add(char *);
void ldapcheck_timeout_set(int);
struct ldapcheck_entry *ldapcheck_def_add(char *, char *, int);
struct ldapcheck_entry *ldapcheck_byname(char *);
int ldapcheck_validate(acl_data_t *, acl_stage_t,
		       struct acl_param *, struct mlfi_priv *);
void ldapcheck_clear(void);
#endif

#endif /* _LDAPCHECK_H_ */
