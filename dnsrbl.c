/* $Id: dnsrbl.c,v 1.15.2.2 2006/10/26 21:01:08 manu Exp $ */

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

#include "config.h"

#ifdef USE_DNSRBL

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: dnsrbl.c,v 1.15.2.2 2006/10/26 21:01:08 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#ifndef NS_MAXMSG
#define NS_MAXMSG	65535
#endif

#ifdef res_ninit
#define HAVE_RESN	1
#ifndef res_ndestroy
#define res_ndestroy(res)	res_nclose(res)
#endif
#else
#define	res_ninit(res) \
	((_res.options & RES_INIT) == 0 && res_init())
#define res_nquery(res, req, class, type, ans, anslen)	\
	res_query(req, class, type, ans, anslen)
#define res_ndestroy(res)
#endif

#include "milter-greylist.h"
#include "pending.h"
#include "conf.h"
#include "dnsrbl.h"

/* 
 * locking is done through the same lock as acllist: both are static 
 * configuration, which are readen or changed at the same times.
 */
struct dnsrbllist dnsrbl_head;

void
dnsrbl_init(void) {
	LIST_INIT(&dnsrbl_head);
	return;
}

int
dnsrbl_check_source(sa, salen, source)
	struct sockaddr *sa;
	socklen_t salen;
        struct dnsrbl_entry *source;
{
#ifdef HAVE_RESN
	struct __res_state res;
#endif
	sockaddr_t ss;
	char req[NS_MAXDNAME + 1];
	char *ans = NULL;
	int anslen;
	ns_msg handle;
	ns_rr rr;
	int qtype, i;
	char *dnsrbl = source->d_domain;
	struct sockaddr *blacklisted;
	int retval = 0;
	char *addr;
	size_t len;

	/* No IPv6 DNSRBL exists right now */
	if (sa->sa_family != AF_INET)
		return 0;

	blacklisted = SA(&source->d_blacklisted);

	switch (blacklisted->sa_family) {
	case AF_INET:
		qtype = T_A;
		addr = (char *)SADDR4(blacklisted);
		len = sizeof(*SADDR4(blacklisted));
		break;
#ifdef AF_INET6
	case AF_INET6:
		qtype = T_AAAA;
		addr = (char *)SADDR6(blacklisted);
		len = sizeof(*SADDR6(blacklisted));
		break;
#endif
	default:
		mg_log(LOG_ERR, "unexpected address family %d",
		    blacklisted->sa_family);
		exit(EX_SOFTWARE);
		break;
	}

#ifdef HAVE_RESN
	bzero(&res, sizeof(res));
#endif
	if (res_ninit(&res) != 0) {
		mg_log(LOG_ERR, "res_ninit failed: %s", strerror(errno));
		return -1;
	}

	reverse_endian(SA(&ss), sa);

	if ((iptostring(SA(&ss), salen, req, NS_MAXDNAME)) == NULL){
		mg_log(LOG_ERR, "iptostring failed: %s", strerror(errno));
		retval = -1;
		goto end;
	}

	(void)mystrlcat(req, ".", NS_MAXDNAME);
	(void)mystrlcat(req, dnsrbl, NS_MAXDNAME);

	if ((ans = malloc(NS_MAXMSG + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		goto end;
	}
	anslen = res_nquery(&res, req, C_IN, qtype, ans, NS_MAXMSG + 1);
	if (anslen == -1)
		goto end;

	if (ns_initparse(ans, anslen, &handle) < 0) {
		mg_log(LOG_ERR, "ns_initparse failed: %s", strerror(errno));
		retval = -1;
		goto end;
	}

	for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
		if ((ns_parserr(&handle, ns_s_an, i, &rr)) != 0) {
			mg_log(LOG_ERR, "ns_parserr failed: %s", 
			    strerror(errno));
			retval = -1;
			goto end;
		}

		switch (blacklisted->sa_family) {
		case AF_INET:
			if (rr.type != T_A)
				continue;
			break;
#ifdef AF_INET6
		case AF_INET6:
			if (rr.type != T_AAAA)
				continue;
			break;
#endif
		default:
			mg_log(LOG_ERR, "unexpected sa_family");
			exit(EX_OSERR);
			break;
		}

		if (rr.rdlength != len)
			continue;

		if (memcmp(addr, rr.rdata, len) == 0) {
			retval = 1;
			goto end;
		}
	}

end:
	if (retval == 1 && conf.c_debug) {
		char addrstr[NS_MAXDNAME + 1];

		iptostring(sa, salen, addrstr, sizeof(addrstr));
		mg_log(LOG_DEBUG, "Host %s exists in DNSRBL \"%s\"", 
				addrstr, source->d_name);
	}
	free(ans);
	res_ndestroy(&res);
	return retval;
}


/* XXX this code is probably broken with IPv6 */
void
reverse_endian(dst, src)
	struct sockaddr *src;
	struct sockaddr *dst;
{
	int i, len;
	char *src_start;
	char *dst_start;

	switch (src->sa_family) {
	case AF_INET:
		src_start = (char *)SADDR4(src);
		dst_start = (char *)SADDR4(dst);
		len = sizeof(*SADDR4(src));
		break;
#ifdef AF_INET6
	case AF_INET6:
		src_start = (char *)SADDR6(src);
		dst_start = (char *)SADDR6(dst);
		len = sizeof(*SADDR6(src));
		break;
#endif
	default:
		mg_log(LOG_ERR, "invalid address family %d", src->sa_family);
		exit(EX_SOFTWARE);
		break;
	}

	dst->sa_family = src->sa_family;
#ifdef HAVE_SA_LEN
	dst->sa_len = src->sa_len;
#endif

	for (i = 0; i < len; i++)
		dst_start[len - 1 - i] = src_start[i];

	return;
}

void
dnsrbl_source_add(name, domain, blacklisted) /* acllist must be write locked */
	char *name;
	char *domain;
	struct sockaddr *blacklisted;
{
	struct dnsrbl_entry *de;
	socklen_t salen;
	char addrstr[IPADDRSTRLEN];

	if ((de = malloc(sizeof(*de))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	switch(blacklisted->sa_family) {
	case AF_INET:
		salen = sizeof(struct sockaddr_in);
		break;
#ifdef AF_INET6
	case AF_INET6:
		salen = sizeof(struct sockaddr_in6);
		break;
#endif
	default:
		mg_log(LOG_ERR, "invalid address family %d",
		    blacklisted->sa_family);
		exit(EX_SOFTWARE);
		break;
	}
		

	strncpy(de->d_name, name, sizeof(de->d_name));
	de->d_name[sizeof(de->d_name) - 1] = '\0';
	strncpy(de->d_domain, domain, sizeof(de->d_domain));
	de->d_domain[sizeof(de->d_domain) - 1] = '\0';
	memcpy(&de->d_blacklisted, blacklisted, salen);

	LIST_INSERT_HEAD(&dnsrbl_head, de, d_list);

	if (conf.c_debug || conf.c_acldebug) {
		if ((iptostring(SA(&de->d_blacklisted), salen, addrstr,
		    sizeof(addrstr))) == NULL) {
			mg_log(LOG_ERR, "iptostring failed: %s",
			    strerror(errno));
			exit(EX_SOFTWARE);
		}
		mg_log(LOG_DEBUG, "load DNSRBL \"%s\" \"%s\" %s", 
		    de->d_name, de->d_domain, addrstr);
	}

	return;
}

struct dnsrbl_entry *
dnsrbl_byname(dnsrbl)	/* acllist must be read locked */
	char *dnsrbl;
{
	struct dnsrbl_entry *de;	

	LIST_FOREACH(de, &dnsrbl_head, d_list) {
		if (strcmp(de->d_name, dnsrbl) == 0)
			break;
	}

	return de;
}

void
dnsrbl_clear(void)	/* acllist must be write locked */
{
	struct dnsrbl_entry *de;

	while(!LIST_EMPTY(&dnsrbl_head)) {
		de = LIST_FIRST(&dnsrbl_head);
		LIST_REMOVE(de, d_list);
		free(de);
	}

	dnsrbl_init();

	return;
}

#endif /* USE_DNSRBL */
