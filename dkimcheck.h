/* $Id: dkimcheck.h,v 1.1 2008/08/21 21:05:35 manu Exp $ */

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

#ifndef _DKIMCHECK_H_
#define _DKIMCHECK_H_

#include "config.h"

#ifdef USE_DKIM

#include <dkim.h>

void dkimcheck_init(void);
void dkimcheck_clear(void);
sfsistat dkimcheck_header(char *, char *, struct mlfi_priv *);
sfsistat dkimcheck_eoh(struct mlfi_priv *);
sfsistat dkimcheck_body(unsigned char *, size_t, struct mlfi_priv *);
sfsistat dkimcheck_eom(struct mlfi_priv *);
int dkimcheck_validate(acl_data_t *, acl_stage_t,
		       struct acl_param *, struct mlfi_priv *);
char *acl_print_dkim(acl_data_t *, char *, size_t);
void acl_add_dkim(acl_data_t *, void *);

#endif /* USE_DKIM */
#endif /* _DKIMCHECK_H_ */
