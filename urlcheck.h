/* $Id: urlcheck.h,v 1.10 2007/02/27 04:39:49 manu Exp $ */

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

#include <curl/curl.h>

struct urlcheck_cnx {
	CURL *uc_hdl;
	time_t uc_old;
	pthread_mutex_t uc_lock;
};

struct urlcheck_entry {
	char u_name[QSTRLEN + 1];
	char u_url[QSTRLEN + 1];
	int u_maxcnx;
	int u_flags;
	struct urlcheck_cnx *u_cnxpool;
	LIST_ENTRY(urlcheck_entry) u_list;
};

/* For u_flags */
#define U_POSTMSG	0x1
#define U_GETPROP	0x2
#define U_CLEARPROP	0x4

struct urlcheck_prop_data {
	char *upd_name;
	void *upd_data;
};

struct urlcheck_prop {
	char *up_name;
	char *up_value;
	int up_flags;
	LIST_ENTRY(urlcheck_prop) up_list;
};

extern int urlcheck_gflags;

struct urlcheck_entry *urlcheck_byname(char *);
void urlcheck_init(void);
void urlcheck_def_add(char *, char *, int, int);
void urlcheck_clear(void);
int urlcheck_validate(acl_data_t *, acl_stage_t,
		      struct acl_param *, struct mlfi_priv *);
char *urlcheck_prop_byname(struct mlfi_priv *, char *);
void urlcheck_prop_clear_all(struct mlfi_priv *);
void urlcheck_prop_clear(struct mlfi_priv *);
int urlcheck_prop_string_validate(acl_data_t *, acl_stage_t,
				  struct acl_param *, struct mlfi_priv *); 
int urlcheck_prop_regex_validate(acl_data_t *, acl_stage_t,
				 struct acl_param *, struct mlfi_priv *); 
