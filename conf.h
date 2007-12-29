/* $Id: conf.h,v 1.41 2007/12/29 19:06:49 manu Exp $ */

/*
 * Copyright (c) 2004 Emmanuel Dreyfus
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

#ifndef _CONF_H_
#define _CONF_H_

#include "config.h"
#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pending.h"

#ifndef CONFFILE
#define CONFFILE "/etc/mail/greylist.conf"
#endif

#ifndef DRACDB
#define DRACDB "/usr/local/etc/dracdb.db"
#endif

TAILQ_HEAD(conf_list, conf_rec);
struct conf_rec {
	int c_refcount;
	time_t c_timestamp;
	TAILQ_ENTRY(conf_rec) c_chain;

	int c_forced;
	int c_debug;
	int c_acldebug;
	int c_quiet;
	int c_noauth;
	int c_noaccessdb;
	int c_nospf;
	int c_delayedreject;
	int c_testmode;
	int c_delay;
	int c_autowhite_validity;
	char *c_pidfile;
	char *c_dumpfile;
	int c_dumpfile_mode;
	struct in_addr c_match_mask;
#ifdef AF_INET6
	struct in6_addr c_match_mask6;
#endif
	char *c_socket;
	int c_socket_mode;
	char *c_user;
	char *c_syncaddr;
	char *c_syncport;
	char *c_syncsrcaddr;
	char *c_syncsrcport;
	int c_nodetach;
	int c_report;
	int c_lazyaw;
	int c_dumpfreq;
	int c_timeout;
	int c_extendedregex;
	char *c_dracdb;
	int c_nodrac;
	int c_dump_no_time_translation;
	int c_logexpired;
	char c_pidfile_storage[QSTRLEN + 1];
	char c_dumpfile_storage[QSTRLEN + 1];
	char c_socket_storage[QSTRLEN + 1];
	char c_user_storage[QSTRLEN + 1];
	char c_syncaddr_storage[IPADDRSTRLEN + 1];
	char c_syncport_storage[NUMLEN + 1];
	char c_syncsrcaddr_storage[IPADDRSTRLEN + 1];
	char c_syncsrcport_storage[NUMLEN + 1];
	char c_dracdb_storage[QSTRLEN + 1];
	size_t c_maxpeek;
};

/* c_forced flags */
#define C_GLNONE	0x00000
#define C_DEBUG		0x00001
#define C_QUIET		0x00002
#define C_NOAUTH	0x00004
#define C_NOSPF		0x00008 
#define C_TESTMODE	0x00010
#define C_DELAY		0x00020
#define C_AUTOWHITE	0x00040
#define C_PIDFILE	0x00080
#define C_DUMPFILE	0x00100
#define C_MATCHMASK	0x00200
#define C_SOCKET	0x00400
#define C_USER		0x00800
#define C_NODETACH	0x01000
#define C_LAZYAW	0x02000
#define C_MATCHMASK6	0x04000
#define C_ACLDEBUG	0x08000
#define C_NOTFORCED(x) 	((conf.c_forced & (x)) == 0) 

/* c_report */
#define C_NOTHING	0x0
#define C_DELAYS	0x1
#define C_NODELAYS	0x2
#define C_ALL		0x3

extern struct conf_rec defconf;
extern pthread_key_t conf_key;
#define GET_CONF() ((struct conf_rec *)pthread_getspecific(conf_key))
#define conf (*GET_CONF())
extern char *conffile;
extern int conf_cold;

void conf_init(void);
void conf_load(void);
void conf_update(void);
void conf_retain(void);
void conf_release(void);

extern FILE *conf_in;
extern int conf_line;
extern int conf_acl_end;
extern int conf_racl_end;
extern int conf_dacl_end;

int conf_parse(void);
void conf_dispose_input_file(void);
char *quotepath(char *, char *, size_t);
char *quotepath_alloc(const char *);
void conf_defaults(struct conf_rec *);

#endif /* _CONF_H_ */
