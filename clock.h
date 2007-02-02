/* $Id: clock.h,v 1.1 2007/02/02 02:10:23 manu Exp $ */

/*
 * Copyright (c) 2007 Emmanuel Dreyfus
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

#ifndef _CLOCK_H_
#define _CLOCK_H_

#define CS_MINUTE	0
#define CS_HOUR		1
#define CS_MONTHDAY	2
#define CS_MONTH	3
#define CS_WEEKDAY	4
#define CS_MAX		5

struct clockspec {
	LIST_HEAD(,clockspec_item) cs_items[CS_MAX];
};

struct clockspec_item {
	int ci_start;
	int ci_end;
	LIST_ENTRY(clockspec_item) ci_list;
};

void add_clock_item(int, int, int);
struct clockspec *register_clock(void);

struct clockspec *clockspec_byname(char *);
char *print_clockspec(acl_data_t *, char *, size_t);
void add_clockspec(acl_data_t *, void *);
int clockspec_filter(acl_data_t *, acl_stage_t, 
		     struct acl_param *, struct mlfi_priv *);
void next_clock_spec(void);
void clockspec_free(acl_data_t *);

#endif /* _CLOCK_H_ */
