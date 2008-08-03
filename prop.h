/* $Id: prop.h,v 1.1 2008/08/03 09:48:44 manu Exp $ */

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

#ifndef _PROP_H_
#define _PROP_H_

#include "config.h"

struct prop_data {
	char *upd_name;
	void *upd_data;
};

struct prop {
	char *up_name;
	char *up_value;
	int up_flags;
	LIST_ENTRY(prop) up_list;
};

#define UP_CLEARPROP	0x4
#define UP_TMPPROP	0x8

void prop_push(char *, char *, int, struct mlfi_priv *);
void prop_clear_tmp(struct mlfi_priv *);
void prop_untmp(struct mlfi_priv *);
char *prop_byname(struct mlfi_priv *, char *);
void prop_clear_all(struct mlfi_priv *);
void prop_clear(struct mlfi_priv *);
int prop_string_validate(acl_data_t *, acl_stage_t,
			 struct acl_param *, struct mlfi_priv *); 
int prop_regex_validate(acl_data_t *, acl_stage_t,
			struct acl_param *, struct mlfi_priv *); 

#endif /* _PROP_H_ */
