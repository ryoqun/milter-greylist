/* $Id: spf.c,v 1.15 2004/12/08 17:49:48 manu Exp $ */

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

#include "config.h"

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: spf.c,v 1.15 2004/12/08 17:49:48 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "conf.h"
#include "spf.h"
#include "except.h"


#ifdef HAVE_SPF
#include <spf.h>
int
spf_check(sa, salen, helo, from)
	struct sockaddr *sa;
	socklen_t salen;
	char *helo;
	char *from;
{
	peer_info_t *p = NULL;
	char addr[IPADDRSTRLEN];
	int result = EXF_NONE;
	struct timeval tv1, tv2, tv3;

	if (conf.c_debug)
		gettimeofday(&tv1, NULL);

	if (sa->sa_family != AF_INET)	/* libspf doesn't support IPv6 */
		return result;
	if (!iptostring(sa, salen, addr, sizeof(addr)))
		return result;

	if ((p = SPF_init("milter-greylist", addr, 
	    NULL, NULL, NULL, FALSE, FALSE)) == NULL) {
		syslog(LOG_ERR, "SPF_Init failed");
		goto out1;
	}
	SPF_smtp_helo(p, helo);
	SPF_smtp_from(p, from);
	p->RES = SPF_policy_main(p);

	if (conf.c_debug)
		syslog(LOG_DEBUG, "SPF return code %d", p->RES);

	if (p->RES == SPF_PASS)
		result = EXF_SPF;

	SPF_close(p);

out1:
	if (conf.c_debug) {
		gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		syslog(LOG_DEBUG, "SPF lookup performed in %ld.%06lds",  
		    tv3.tv_sec, tv3.tv_usec);
	}
	
	return result;
}
#endif /* HAVE_SPF */


#ifdef HAVE_SPF_ALT
#include <spf_alt/spf.h>
#include <spf_alt/spf_dns_resolv.h>
#include <spf_alt/spf_lib_version.h>
#endif

#ifdef HAVE_SPF2
#include <spf2/spf.h>
#include <spf2/spf_dns_resolv.h>
#include <spf2/spf_lib_version.h>
#endif

#if defined(HAVE_SPF_ALT) || defined(HAVE_SPF2)
/* SMTP needs at least 64 chars for local part and 255 for doamin... */
#define NS_MAXDNAME 1025 
int
spf_alt_check(sa, salen, helo, fromp)
	struct sockaddr *sa;
	socklen_t salen;
	char *helo;
	char *fromp;
{
	SPF_config_t spfconf;
	SPF_dns_config_t dnsconf;
	char addr[IPADDRSTRLEN];
	char from[NS_MAXDNAME + 1];
	SPF_output_t out;
	int result = EXF_NONE;
	struct timeval tv1, tv2, tv3;
	size_t len;

	if (conf.c_debug)
		gettimeofday(&tv1, NULL);

	if ((spfconf = SPF_create_config()) == NULL) {
		syslog(LOG_ERR, "SPF_create_config failed");
		goto out1;
	}

	if ((dnsconf = SPF_dns_create_config_resolv(NULL, 0)) == NULL) {
		syslog(LOG_ERR, "SPF_dns_create_config_resolv faile");
		goto out2;
	}

	/* 
	 * Get the IP address
	 */
	if (!iptostring(sa, salen, addr, sizeof(addr))) {
		syslog(LOG_ERR, "SPF_set_ip_str failed");
		goto out3;
	}
	if (SPF_set_ip_str(spfconf, addr) != 0) {
		syslog(LOG_ERR, "SPF_set_ip_str failed");
		goto out3;
	}

	/* HELO string */
	if (SPF_set_helo_dom(spfconf, helo) != 0) {
		syslog(LOG_ERR, "SPF_set_helo failed");
		goto out3;
	}

	/* 
	 * And the enveloppe source e-mail
	 */
	if (fromp[0] == '<')
		fromp++; /* strip leading < */
	strncpy(from, fromp, NS_MAXDNAME);
	from[NS_MAXDNAME] = '\0';
	len = strlen(from);
	if (fromp[len - 1] == '>')
		from[len - 1] = '\0'; /* strip trailing > */

	if (SPF_set_env_from(spfconf, from) != 0) {
		syslog(LOG_ERR, "SPF_set_env_from failed");
		goto out3;
	}

	/*
	 * Get the SPF result
	 */
	SPF_init_output(&out);
#if ((SPF_LIB_VERSION_MAJOR == 0) && (SPF_LIB_VERSION_MINOR <= 3))
	out = SPF_result(spfconf, dnsconf, NULL);
#else
	out = SPF_result(spfconf, dnsconf);
#endif
	if (out.result == SPF_RESULT_PASS) 
		result = EXF_SPF;

	if (conf.c_debug)
		syslog(LOG_DEBUG, "SPF return code %d", out.result);

	SPF_free_output(&out);
out3:
	SPF_dns_destroy_config_resolv(dnsconf);
out2:
	SPF_destroy_config(spfconf);
out1:
	if (conf.c_debug) {
		gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		syslog(LOG_DEBUG, "SPF lookup performed in %ld.%06lds",  
		    tv3.tv_sec, tv3.tv_usec);
	}

	return result;
}

#endif /* HAVE_SPF_ALT */
