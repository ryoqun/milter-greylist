/* $Id: urlcheck.h,v 1.5 2007/01/01 08:08:41 manu Exp $ */

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

/* 
 * Max length for sendmail macro value and time. Of course that is not 
 * right but it should fit most usages.
 */
#define MACROMAXLEN	4096	/* Sendmail's default MACBUFSIZE */
#define TIMEMAXLEN	128	/* Arbitrary */

LIST_HEAD(urlchecklist, urlcheck_entry);

struct urlcheck_cnx {
	CURL *uc_hdl;
	time_t uc_old;
	pthread_mutex_t uc_lock;
};

struct urlcheck_entry {
	char u_name[QSTRLEN + 1];
	char u_url[QSTRLEN + 1];
	size_t u_urlmaxlen;
	int u_maxcnx;
	struct urlcheck_cnx *u_cnxpool;
	LIST_ENTRY(urlcheck_entry) u_list;
};

struct urlcheck_entry *urlcheck_byname(char *);
void urlcheck_init(void);
void urlcheck_def_add(char *, char *, int);
void urlcheck_clear(void);
int urlcheck_validate(acl_data_t *, acl_stage_t,
		      struct acl_param *, struct mlfi_priv *);