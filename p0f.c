/* $Id: p0f.c,v 1.3 2008/09/07 13:37:03 manu Exp $ */

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

#include "config.h"

#ifdef USE_P0F

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: p0f.c,v 1.3 2008/09/07 13:37:03 manu Exp $");
#endif
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <arpa/inet.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <syslog.h>


#include "conf.h"
#include "spf.h"
#include "acl.h"
#include "milter-greylist.h"
#include "p0f.h"

#ifdef P0F_QUERY_FROM_P0F_DIST
#include <p0f-query.h>
#else /* P0F_QUERY_FROM_P0F_DIST */
/* This is from p0f/p0f-query.h */
#define QUERY_MAGIC		0x0defaced
#define QTYPE_FINGERPRINT	1
#define RESP_BADQUERY		1
#define RESP_NOMATCH		2

struct p0f_query {
	u_int32_t	magic;
	u_int8_t	type;
	u_int32_t	id;
	u_int32_t	src_ad,dst_ad;
	u_int16_t	src_port,dst_port;
};
struct p0f_response {
	u_int32_t	magic;
	u_int32_t	id;
	u_int8_t 	type;
	u_int8_t	genre[20];
	u_int8_t	detail[40];
	int8_t		dist;
	u_int8_t	link[30];
	u_int8_t	tos[30];
	u_int8_t	fw,nat;
	u_int8_t	real;
	int16_t		score;
	u_int16_t	mflags;
	int32_t		uptime;
};
/* End of stuff borrowed from p0f/p0f-query.h */
#endif /* P0F_QUERY_FROM_P0F_DIST */

static int p0f_reconnect(void);

static int p0fsock = -1;

void
p0f_init(void)
{
	return;
}

void
p0f_clear(void)
{
	if (p0fsock != -1) {
		(void)shutdown(p0fsock, SHUT_RDWR);
		(void)close(p0fsock);
		p0fsock = -1;
	}
	p0f_init();
	return;
}

int
p0f_cmp(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *data;

       if (priv->priv_p0f == NULL)
               return 0;

	data = (char *)ad->string;
	if (strcasestr(priv->priv_p0f, data) != NULL)
		return 1;
	return 0;
}

int
p0f_regexec(ad, stage, ap, priv)
	acl_data_t *ad; 
	acl_stage_t stage; 
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
       if (priv->priv_p0f == NULL)
               return 0;

	if (myregexec(priv, ad, ap, priv->priv_helo) == 0)
		return 1;
	return 0;
}

int
p0f_lookup(priv)
	struct mlfi_priv *priv;
{
	struct p0f_query req;
	struct p0f_response rep;
	struct timeval tv;
	char *daddr;
	char *dport;
	size_t len;

	/*
	 * The p0f query interface semms to only support IPv4
	 */
	if (SA(&priv->priv_addr)->sa_family != AF_INET)
		return -1;

	if ((daddr = smfi_getsymval(priv->priv_ctx, "{daemon_addr}")) == NULL) {
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {daemon_addr}");
		return -1;
	}
	if ((dport = smfi_getsymval(priv->priv_ctx, "{daemon_port}")) == NULL) {
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {daemon_port}");
		return -1;
	}

	if (p0f_reconnect() != 0)
		return -1;

	memset(&req, 0, sizeof(req));
	memset(&rep, 0, sizeof(rep));
	(void)gettimeofday(&tv, NULL);

	req.magic = QUERY_MAGIC;
	req.id = tv.tv_usec;
	req.type = QTYPE_FINGERPRINT;
	req.src_ad = SADDR4(&priv->priv_addr)->s_addr;
	req.src_port = SA4(&priv->priv_addr)->sin_port;
	req.dst_ad = inet_addr(daddr);
	req.dst_port = atoi(dport);

	if (write(p0fsock, &req ,sizeof(req)) != sizeof(req)) {
		mg_log(LOG_ERR, "writing to \"%s\" failed", conf.c_p0fsock);
		p0f_clear();
		return -1;
	}

	if (read(p0fsock, &rep, sizeof(rep)) != sizeof(rep)) {
		mg_log(LOG_ERR, "writing to \"%s\" failed", conf.c_p0fsock);
		p0f_clear();
		return -1;
	}

	p0f_clear();

	if (rep.magic != QUERY_MAGIC) {
		mg_log(LOG_ERR, "Unexpected p0f magic = %d", rep.magic);
		return -1;
	}

	switch(rep.type) {
	case RESP_BADQUERY:
		mg_log(LOG_INFO, "p0f rejected query");
		return -1;
		
		break;
	case RESP_NOMATCH:
		mg_log(LOG_INFO, "p0f cache miss");
		return -1; /* XXX This causes a tempfail */
		break;
	default:
		break;
	}

	/* +2 for space and trailing \0 */
	len = strlen((char *)rep.genre) + strlen((char *)rep.detail) + 2;
	if ((priv->priv_p0f = malloc(len)) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed: %s", len, strerror(errno));
		exit(EX_OSERR);
	}

	(void)sprintf(priv->priv_p0f, "%s %s", rep.genre, rep.detail);
	if (conf.c_debug)
		mg_log(LOG_DEBUG, "p0f identified \"%s\"", priv->priv_p0f);
	
	return 0;
}


void
p0f_sock_set(sock)
	char *sock;
{
	(void)strncpy(conf.c_p0fsock, sock, sizeof(conf.c_p0fsock));
	return;
}

static int
p0f_reconnect(void)
{
	struct sockaddr_un sun;

	if (p0fsock != -1)
		return 0;

	if ((p0fsock = socket(PF_UNIX,SOCK_STREAM,0)) == -1) {
		mg_log(LOG_ERR, "socket(PF_UNIX, SOCK_STREAM, 0) failed");
		exit(EX_OSERR);
	}

	if (p0fsock == -1) {
		mg_log(LOG_ERR, "p0f socket not initialized");
		exit(EX_SOFTWARE);
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "using p0f socket \"%s\"", conf.c_p0fsock);		
	(void)memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, conf.c_p0fsock, sizeof(sun.sun_path));

	if (connect(p0fsock, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
		mg_log(LOG_ERR, "Cannot connect to p0f socket \"%s\"",
		      conf.c_p0fsock);	
		close(p0fsock);
		p0fsock = -1;
		return -1;
	}

	return 0;	
}

#endif /* USE_P0F */
