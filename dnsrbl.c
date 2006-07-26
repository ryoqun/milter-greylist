/* $Id: dnsrbl.c,v 1.2 2006/07/26 08:38:16 manu Exp $ */

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
__RCSID("$Id: dnsrbl.c,v 1.2 2006/07/26 08:38:16 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>

#include <sys/queue.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "milter-greylist.h"
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
dnsrbl_check_source(sa, source)
	struct sockaddr *sa;
        struct dnsrbl_entry *source;
{
	struct __res_state res;
	struct sockaddr_storage ss;
	char req[NS_MAXDNAME + 1];
	char ans[NS_MAXMSG + 1];
	int anslen;
	void *addr;
	ns_msg handle;
	ns_rr rr;
	int i;
	char *dnsrbl = source->de_domain;
	struct sockaddr *blacklisted;

	blacklisted = (struct sockaddr *)&source->de_blacklisted;

	res_ninit(&res);

	reverse_endian((struct sockaddr *)&ss, sa);

	switch (ss.ss_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *)&ss)->sin_addr;
		break;
#ifdef AF_INET6
	case AF_INET6:
		addr = &((struct sockaddr_in6 *)&ss)->sin6_addr;
		break;
#endif
	default:
		syslog(LOG_ERR, "unexpected address family %d", ss.ss_family);
		exit(EX_SOFTWARE);
		break;
	}

	if ((inet_ntop(ss.ss_family, addr, req, NS_MAXDNAME)) == NULL){
		syslog(LOG_ERR, "inet_ntop failed: %s", strerror(errno));
		return -1;
	}

	(void)strncat(req, ".", NS_MAXDNAME);
	(void)strncat(req, dnsrbl, NS_MAXDNAME);

	anslen = res_nquery(&res, req, C_IN, T_A, ans, sizeof(ans));
	if (anslen == -1)
		return 0;

	if (ns_initparse(ans, anslen, &handle) < 0) {
		syslog(LOG_ERR, "ns_initparse failed: %s", strerror(errno));
		return -1;
	}
	
	for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
		char *addr;
		size_t len;

		if ((ns_parserr(&handle, ns_s_an, i, &rr)) != 0) {
			syslog(LOG_ERR, "ns_parserr failed: %s", 
			    strerror(errno));
			return -1;
		}

		switch (blacklisted->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin;

			if (rr.type != T_A)
				continue;

			sin = (struct sockaddr_in *)blacklisted;
			addr = (char *)&sin->sin_addr;
			len = sizeof(sin->sin_addr);
			break;
		}
#ifdef AF_INET6
		case AF_INET6: {
			struct sockaddr_in6 *sin6;

			if (rr.type != T_AAAA)
				continue;

			sin6 = (struct sockaddr_in6 *)blacklisted;
			addr = (char *)&sin6->sin6_addr;
			len = sizeof(sin6->sin6_addr);
			break;
		}
#endif
		default:
			syslog(LOG_ERR, "unexpected address family %d", 
			    blacklisted->sa_family);
			exit(EX_SOFTWARE);
			break;
		}

		if (memcmp(addr, rr.rdata, len) == 0)
			return 1;
	}

	return 0;
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
		src_start = (char *)&((struct sockaddr_in *)src)->sin_addr;
		dst_start = (char *)&((struct sockaddr_in *)dst)->sin_addr;
		len = sizeof(((struct sockaddr_in *)src)->sin_addr);
		break;
#ifdef AF_INET6
	case AF_INET6:
		src_start = (char *)&((struct sockaddr_in6 *)src)->sin6_addr;
		dst_start = (char *)&((struct sockaddr_in6 *)dst)->sin6_addr;
		len = sizeof(((struct sockaddr_in6 *)src)->sin6_addr);
		break;
#endif
	default:
		syslog(LOG_ERR, "invalid address family %d", src->sa_family);
		exit(EX_SOFTWARE);
		break;
	}

	dst->sa_family = src->sa_family;
	dst->sa_len = src->sa_len;

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

	if ((de = malloc(sizeof(*de))) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	strncpy(de->de_name, name, sizeof(de->de_name));
	de->de_name[sizeof(de->de_name) - 1] = '\0';
	strncpy(de->de_domain, domain, sizeof(de->de_domain));
	de->de_domain[sizeof(de->de_domain) - 1] = '\0';
	memcpy(&de->de_blacklisted, blacklisted, blacklisted->sa_len);

	LIST_INSERT_HEAD(&dnsrbl_head, de, de_list);

	return;
}

struct dnsrbl_entry *
dnsrbl_byname(dnsrbl)	/* acllist must be read locked */
	char *dnsrbl;
{
	struct dnsrbl_entry *de;	

	LIST_FOREACH(de, &dnsrbl_head, de_list) {
		if (strcmp(de->de_name, dnsrbl) == 0)
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
		LIST_REMOVE(de, de_list);
		free(de);
	}

	dnsrbl_init();

	return;
}

#endif /* USE_DNSRBL */
