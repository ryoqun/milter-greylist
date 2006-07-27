/* $Id: acl.c,v 1.22 2006/07/27 20:08:32 manu Exp $ */

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
__RCSID("$Id: acl.c,v 1.22 2006/07/27 20:08:32 manu Exp $");
#endif
#endif

#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <pthread.h>
#include <sysexits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex.h>

#include "acl.h"
#include "conf.h"
#include "sync.h"
#include "list.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#include "milter-greylist.h"

struct acllist acl_head;
pthread_rwlock_t acl_lock;

static struct acl_entry gacl;

static void
acl_init_entry (void) {
	memset (&gacl, 0, sizeof (gacl));
	gacl.a_delay = -1;
	gacl.a_autowhite = -1;
}

void
acl_init(void) {
	int error;

	TAILQ_INIT(&acl_head);
	if ((error = pthread_rwlock_init(&acl_lock, NULL)) != 0) {
		syslog(LOG_ERR, "pthread_rwlock_init failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}
	acl_init_entry();

	return;
}

void
acl_add_netblock(sa, salen, cidr)
	struct sockaddr *sa;
	socklen_t salen;
	int cidr;
{
	ipaddr mask;
	char addrstr[IPADDRSTRLEN];
	char maskstr[IPADDRSTRLEN];
	int maxcidr, masklen;
#ifdef AF_INET6
	int i;
#endif

	if (gacl.a_addr != NULL) {
		fprintf (stderr,
		    "addr specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	switch (sa->sa_family) {
	case AF_INET:
		maxcidr = 32;
		masklen = sizeof(mask.in4);
		break;
#ifdef AF_INET6
	case AF_INET6:
		maxcidr = 128;
		masklen = sizeof(mask.in6);
		break;
#endif
	default:
		fprintf(stderr,
		    "bad address family in acl list line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	if (cidr > maxcidr || cidr < 0) {
		fprintf(stderr, "bad mask in acl list line %d\n", 
		    conf_line);
		exit(EX_DATAERR);
	}

	switch (sa->sa_family) {
	case AF_INET:
		prefix2mask4(cidr, &mask.in4);
		SADDR4(sa)->s_addr &= mask.in4.s_addr;
		break;
#ifdef AF_INET6
	case AF_INET6:
		prefix2mask6(cidr, &mask.in6);
		for (i = 0; i < 16; i += 4)
			*(uint32_t *)&SADDR6(sa)->s6_addr[i] &=
			    *(uint32_t *)&mask.in6.s6_addr[i];
		break;
#endif
	}

	if ((gacl.a_addr = malloc(salen)) == NULL ||
	    (gacl.a_mask = malloc(masklen)) == NULL) {
		syslog(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	gacl.a_addrlen = salen;
	memcpy(gacl.a_addr, sa, salen);
	memcpy(gacl.a_mask, &mask, masklen);

	if (conf.c_debug || conf.c_acldebug) {
		iptostring(gacl.a_addr, gacl.a_addrlen, addrstr,
		    sizeof(addrstr));
		inet_ntop(gacl.a_addr->sa_family, gacl.a_mask, maskstr,
		    sizeof(maskstr));
		printf("load acl net %s/%s\n", addrstr, maskstr);
	}

	return;
}

void
acl_add_from(email)
	char *email;
{
	if (gacl.a_from != NULL || 
	    gacl.a_from_re != NULL ||
	    gacl.a_fromlist != NULL ) {
		fprintf (stderr,
		    "from specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_from = strdup(email)) == NULL) {
		syslog(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		printf("load acl from %s\n", email);

	return;
}

#ifdef USE_DNSRBL
void
acl_add_dnsrbl(dnsrbl)
	char *dnsrbl;
{
	if (gacl.a_dnsrbl != NULL ||
	    gacl.a_dnsrbllist != NULL) {
		fprintf (stderr,
		    "dnsrbl specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_dnsrbl = dnsrbl_byname(dnsrbl)) == NULL) {
		syslog(LOG_ERR, "unknown DNSRBL \"%s\"", dnsrbl);
		exit(EX_DATAERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		printf("load acl dnsrbl %s\n", dnsrbl);

	return;
}
#endif

void
acl_add_rcpt(email)
	char *email;
{
	if (gacl.a_rcpt != NULL || 
	    gacl.a_rcpt_re != NULL ||
	    gacl.a_rcptlist != NULL) {
		fprintf (stderr,
		    "rcpt specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_rcpt = strdup(email)) == NULL) {
		syslog(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		printf("load acl rcpt %s\n", email);

	return;
}

void
acl_add_domain(domain)
	char *domain;
{
	if (gacl.a_domain != NULL || 
	    gacl.a_domain_re != NULL ||
	    gacl.a_domainlist != NULL) {
		fprintf (stderr,
		    "domain specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	if ((gacl.a_domain = strdup(domain)) == NULL) {
		syslog(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
		
	if (conf.c_debug || conf.c_acldebug)
		printf("load acl domain %s\n", domain);

	return;
}

#define ERRLEN 1024
void
acl_add_from_regex(regexstr)
	char *regexstr;
{
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	if (gacl.a_from != NULL || 
	    gacl.a_from_re != NULL ||
	    gacl.a_fromlist != NULL) {
		fprintf (stderr,
		    "from specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((gacl.a_from_re = malloc(sizeof(*gacl.a_from_re))) == NULL) {
		syslog(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((error = regcomp(gacl.a_from_re, regexstr, 
	    (conf.c_extendedregex ? REG_EXTENDED : 0) | REG_ICASE)) != 0) {
		regerror(error, gacl.a_from_re, errstr, ERRLEN);
		fprintf(stderr, "bad regular expression \"%s\": %s\n", 
		    regexstr, errstr);
		exit(EX_OSERR);
	}

	if ((gacl.a_from_re_copy = strdup(regexstr)) == NULL) {
		syslog(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug || conf.c_acldebug)
		printf("load acl from regex %s\n", regexstr);

	return;
}

void
acl_add_rcpt_regex(regexstr)
	char *regexstr;
{
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	if (gacl.a_rcpt != NULL || 
	    gacl.a_rcpt_re != NULL ||
	    gacl.a_rcptlist != NULL) {
		fprintf (stderr,
		    "rcpt specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((gacl.a_rcpt_re = malloc(sizeof(*gacl.a_rcpt_re))) == NULL) {
		syslog(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((error = regcomp(gacl.a_rcpt_re, regexstr,
	    (conf.c_extendedregex ? REG_EXTENDED : 0) | REG_ICASE)) != 0) {
		regerror(error, gacl.a_rcpt_re, errstr, ERRLEN);
		fprintf(stderr, "bad regular expression \"%s\": %s\n", 
		    regexstr, errstr);
		exit(EX_OSERR);
	}

	if ((gacl.a_rcpt_re_copy = strdup(regexstr)) == NULL) {
		syslog(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug || conf.c_acldebug)
		printf("load acl rcpt regex %s\n", regexstr);

	return;
}

void
acl_add_domain_regex(regexstr)
	char *regexstr;
{
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	if (gacl.a_domain != NULL || 
	    gacl.a_domain_re != NULL ||
	    gacl.a_domainlist != NULL) {
		fprintf (stderr,
		    "domain specified twice in ACL line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((gacl.a_domain_re = malloc(sizeof(*gacl.a_domain_re))) == NULL) {
		syslog(LOG_ERR, "acl malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	if ((error = regcomp(gacl.a_domain_re, regexstr,
	    (conf.c_extendedregex ? REG_EXTENDED : 0) | REG_ICASE)) != 0) {
		regerror(error, gacl.a_domain_re, errstr, ERRLEN);
		fprintf(stderr, "bad regular expression \"%s\": %s\n", 
		    regexstr, errstr);
		exit(EX_OSERR);
	}

	if ((gacl.a_domain_re_copy = strdup(regexstr)) == NULL) {
		syslog(LOG_ERR, "acl strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug || conf.c_acldebug)
		printf("load acl domain regex %s\n", regexstr);

	return;
}

struct acl_entry *
acl_register_entry_first(acl_type)	/* acllist must be write-locked */
	acl_type_t acl_type;
{
	struct acl_entry *acl;

	if ((acl = malloc(sizeof(*acl))) == NULL) {
		syslog(LOG_ERR, "ACL malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	*acl = gacl;
	acl->a_type = acl_type;
	acl->a_line = conf_line - 1;
	TAILQ_INSERT_HEAD(&acl_head, acl, a_list);
	acl_init_entry ();

	if (conf.c_debug || conf.c_acldebug) {
		switch(acl_type) {
		case A_GREYLIST:
			printf("register acl first GREYLIST\n");
			break;
		case A_WHITELIST:
			printf("register acl first WHITELIST\n");
			break;
		case A_BLACKLIST:
			printf("register acl first BLACKLIST\n");
			break;
		default:
			syslog(LOG_ERR, "unecpected acl_type %d", acl_type);
			exit(EX_SOFTWARE);
			break;
		}
	}

	return acl;
}

struct acl_entry *
acl_register_entry_last(acl_type)	/* acllist must be write-locked */
	acl_type_t acl_type;
{
	struct acl_entry *acl;

	if ((acl = malloc(sizeof(*acl))) == NULL) {
		syslog(LOG_ERR, "ACL malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	*acl = gacl;
	acl->a_type = acl_type;
	acl->a_line = conf_line - 1;
	TAILQ_INSERT_TAIL(&acl_head, acl, a_list);
	acl_init_entry ();

	if (conf.c_debug || conf.c_acldebug) {
		switch(acl_type) {
		case A_GREYLIST:
			printf("register acl last GREYLIST\n");
			break;
		case A_WHITELIST:
			printf("register acl last WHITELIST\n");
			break;
		case A_BLACKLIST:
			printf("register acl last BLACKLIST\n");
			break;
		default:
			syslog(LOG_ERR, "unecpected acl_type %d", acl_type);
			exit(EX_SOFTWARE);
			break;
		}
	}

	return acl;
}

int 
acl_filter(sa, salen, hostname, from, rcpt, queueid, delay, autowhite, line)
	struct sockaddr *sa;
	socklen_t salen;
	char *hostname;
	char *from;
	char *rcpt;
	char *queueid;
	time_t *delay;
	time_t *autowhite;
	int *line;
{
	struct acl_entry *acl;
	char addrstr[IPADDRSTRLEN];
	char whystr[HDRLEN];
	char tmpstr[HDRLEN];
	int retval;
	int testmode = conf.c_testmode;

	ACL_RDLOCK;

	TAILQ_FOREACH(acl, &acl_head, a_list) {
		retval = 0;

		if (acl->a_addrlist != NULL) {
			if (list_addr_filter(acl->a_addrlist, sa)) {
				retval |= EXF_ADDR;
			} else {
				continue;
			}
		}

		if (acl->a_addr != NULL) {
			if (ip_match(sa, acl->a_addr, acl->a_mask)) {
				retval |= EXF_ADDR;
			} else  {
				continue;
			}
		}

		if (acl->a_domainlist != NULL) {
			if (list_domain_filter(acl->a_domainlist, hostname)) {
				retval |= EXF_DOMAIN;
			} else {
				continue;
			}
		}

		if (acl->a_domain != NULL) {
			if (domaincmp(hostname, acl->a_domain)) {
				retval |= EXF_DOMAIN;
			} else {
				continue;
			}
		}

		if (acl->a_domain_re != NULL) {
			if (regexec(acl->a_domain_re,
			    hostname, 0, NULL, 0) == 0) {
				retval |= EXF_DOMAIN;
			} else {
				continue;
			}
		}

		if (acl->a_fromlist != NULL) {
			if (list_from_filter(acl->a_fromlist, from)) {
				retval |= EXF_FROM;
			} else {
				continue;
			}
		}

		if (acl->a_from != NULL) {
			if (emailcmp(from, acl->a_from) == 0) {
				retval |= EXF_FROM;
			} else {
				continue;
			}
		}

		if (acl->a_from_re != NULL) {
			if (regexec(acl->a_from_re, from, 0, NULL, 0) == 0) {
				retval |= EXF_FROM;
			} else {
				continue;
			}
		}

		if (acl->a_rcptlist != NULL) {
			if (list_rcpt_filter(acl->a_rcptlist, rcpt)) {
				retval |= EXF_RCPT;
			} else {
				continue;
			}
		}

		if (acl->a_rcpt != NULL) {
			if (emailcmp(rcpt, acl->a_rcpt) == 0) {
			retval |= EXF_RCPT;
			} else {
				continue;
			}
		}

		if (acl->a_rcpt_re != NULL) {
			if (regexec(acl->a_rcpt_re, rcpt, 0, NULL, 0) == 0) {
				retval |= EXF_RCPT;
			} else {
				continue;
			}
		}
#ifdef USE_DNSRBL
		if (acl->a_dnsrbllist != NULL) {
			if (list_dnsrbl_filter(acl->a_dnsrbllist, sa)) {
				retval |= EXF_DNSRBL;
				if (conf.c_debug) {
					iptostring(sa, salen, 
					    addrstr, sizeof(addrstr));
					syslog(LOG_DEBUG, 
					    "Mail from addr=%s[%s] exists in "
					    "DNSRBL \"%s\"", 
			    		    hostname, addrstr, 
					    acl->a_dnsrbl->d_name);
				}
			} else {
				continue;
			}
		}

		if (acl->a_dnsrbl != NULL) {
			if (dnsrbl_check_source(sa, acl->a_dnsrbl) != 0) {
				retval |= EXF_DNSRBL;
				if (conf.c_debug) {
					iptostring(sa, salen, 
					    addrstr, sizeof(addrstr));
					syslog(LOG_DEBUG, 
					    "Mail from addr=%s[%s] exists in "
					    "DNSRBL \"%s\"", 
			    		    hostname, addrstr, 
					    acl->a_dnsrbl->d_name);
				}
			} else {
				continue;
			}
		}
#endif
		/*
		 * We found an entry that matches, exit the evaluation
		 * loop
		 */
		break;
	}

	if (acl) {
		if (retval == 0)
			retval = EXF_DEFAULT;
		switch (acl->a_type) {
		case A_GREYLIST:
			retval |= EXF_GREYLIST;
			break;
		case A_WHITELIST:
			retval |= EXF_WHITELIST;
			break;
		case A_BLACKLIST:
			retval |= EXF_BLACKLIST;
			break;
		default:
			syslog(LOG_ERR, "corrupted acl list");
			exit(EX_SOFTWARE);
			break;
		}

		*line = acl->a_line;

		*delay =
		    (acl->a_delay != -1) ? acl->a_delay : conf.c_delay;
		*autowhite = 
		    (acl->a_autowhite != -1) ? 
		    acl->a_autowhite : conf.c_autowhite_validity;

		if (conf.c_debug || conf.c_acldebug) {
			iptostring(sa, salen, addrstr, sizeof(addrstr));
			syslog(LOG_DEBUG, "Mail from=%s, rcpt=%s, addr=%s[%s] "
			    "is matched by entry %s", from, rcpt, 
			    hostname, addrstr, acl_entry(acl));
		}
	} else {
		/*
		 * No match: use the default action
		 */
		if (testmode)
			retval = EXF_WHITELIST;
		else
			retval = EXF_GREYLIST;
		retval |= EXF_DEFAULT;

		*delay = conf.c_delay;
		*autowhite = conf.c_autowhite_validity;
	}

	if (retval & EXF_WHITELIST) {
		whystr[0] = '\0';
		if (retval & EXF_ADDR) {
			iptostring(sa, salen, addrstr, sizeof(addrstr));
			snprintf(tmpstr, sizeof(tmpstr),
			     "address %s is whitelisted", addrstr);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_DOMAIN) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "sender DNS name %s is whitelisted", hostname);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_FROM) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "sender %s is whitelisted", from);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_RCPT) {
			snprintf(tmpstr, sizeof(tmpstr),
			     "recipient %s is whitelisted", rcpt);
			ADD_REASON(whystr, tmpstr);
		}
		if (retval & EXF_DEFAULT) {
			ADD_REASON(whystr, "this is the default action");
		}
		iptostring(sa, salen, addrstr, sizeof(addrstr));
		snprintf(tmpstr, sizeof(tmpstr),
		    "(from=%s, rcpt=%s, addr=%s[%s])", from, rcpt, hostname, addrstr);
		ADD_REASON(whystr, tmpstr);

		syslog(LOG_INFO, "%s: skipping greylist because %s",
		    queueid, whystr);
	}
	ACL_UNLOCK;
	return retval;
}


int
domaincmp(host, domain)
	char *host;
	char *domain;
{
	int hidx, didx;

	if ((host[0] == '\0') && domain[0] == '\0')
		return 1;

	if ((host[0] == '\0') || domain[0] == '\0') 
		return 0;

	hidx = strlen(host) - 1;
	didx = strlen(domain) - 1;

	while ((hidx >= 0) && (didx >= 0)) {
		if (tolower((int)host[hidx]) != tolower((int)domain[didx])) {
			return (0);
		}
		hidx--;
		didx--;
	}

	if (didx >= 0)
		return (0);

	return (1);
}

int 
emailcmp(big, little)
	char *big;
	char *little;
{
	int i;
	int retval = -1;
	char *cbig;
	char *clittle;
	char *ocbig;
	char *oclittle;

	if ((cbig = malloc(strlen(big) + 1)) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	ocbig = cbig;
	strcpy(cbig, big);

	if ((clittle = malloc(strlen(little) + 1)) == NULL) {
		syslog(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	oclittle = clittle;
	strcpy(clittle, little);

	/* Strip leading <, tabs and spaces */
	while (strchr("< \t", cbig[0]) != NULL)
		cbig++;
	while (strchr("< \t", clittle[0]) != NULL)
		clittle++;

	/* Strip trailing >, tabs and spaces */
	i = strlen(cbig) - 1;
	while ((i >= 0) && (strchr("> \t", cbig[i]) != NULL))
		cbig[i--] = '\0';
	i = strlen(clittle) - 1;
	while ((i >= 0) && (strchr("> \t", clittle[i]) != NULL))
		clittle[i--] = '\0';

	while (cbig[0] && clittle[0]) {
		if (tolower((int)cbig[0]) != tolower((int)clittle[0]))
			break;
		cbig++;
		clittle++;
	}
		
	if (cbig[0] || clittle[0])
		retval = -1;
	else
		retval = 0;

	free(ocbig);
	free(oclittle);

	return retval;
}

void
acl_clear(void) {	/* acllist must be write locked */
	struct acl_entry *acl;

	while (!TAILQ_EMPTY(&acl_head)) {
		acl = TAILQ_FIRST(&acl_head);
		TAILQ_REMOVE(&acl_head, acl, a_list);

		if (acl->a_addr != NULL) {
			free(acl->a_addr);
			free(acl->a_mask);
		}
		if (acl->a_from != NULL)
			free(acl->a_from);
		if (acl->a_rcpt != NULL)
			free(acl->a_rcpt);
		if (acl->a_domain != NULL)
			free(acl->a_domain);
		if (acl->a_from_re != NULL)
			regfree(acl->a_from_re);
		if (acl->a_from_re_copy != NULL)
			free(acl->a_from_re_copy);
		if (acl->a_rcpt_re != NULL)
			regfree(acl->a_rcpt_re);
		if (acl->a_rcpt_re_copy != NULL)
			free(acl->a_rcpt_re_copy);
		if (acl->a_domain_re != NULL)
			regfree(acl->a_domain_re);
		if (acl->a_domain_re_copy != NULL)
			free(acl->a_domain_re_copy);
		free(acl);
	}

	TAILQ_INIT(&acl_head);
	acl_init_entry();

	return;
}

char *
acl_entry(acl)
	struct acl_entry *acl;
{
	static char entrystr[HDRLEN];
	char tempstr[HDRLEN];
	char addrstr[IPADDRSTRLEN];
	char maskstr[IPADDRSTRLEN];
	int def = 1;

	strcpy(entrystr, "acl ");

	switch (acl->a_type) {
	case A_GREYLIST:
		strncat(entrystr, "greylist ", sizeof(entrystr));
		break;
	case A_WHITELIST:
		strncat(entrystr, "whitelist ", sizeof(entrystr));
		break;
	case A_BLACKLIST:
		strncat(entrystr, "blacklist ", sizeof(entrystr));
		break;
	default:
		syslog(LOG_ERR, "corrupted acl list");
		exit(EX_SOFTWARE);
		break;
	}

	if (acl->a_addrlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "addr list \"%s\" ", 
		    acl->a_addrlist->al_name);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_addr != NULL) {
		iptostring(acl->a_addr, acl->a_addrlen, addrstr,
		    sizeof(addrstr));
		inet_ntop(acl->a_addr->sa_family, acl->a_mask, maskstr,
		    sizeof(maskstr));
		snprintf(tempstr, sizeof(tempstr), "addr %s/%s ", addrstr, maskstr);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_fromlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "from list \"%s\" ", 
		    acl->a_fromlist->al_name);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_from != NULL) {
		snprintf(tempstr, sizeof(tempstr), "from %s ", acl->a_from);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_from_re != NULL) {
		snprintf(tempstr, sizeof(tempstr), "from /%s/ ",
		    acl->a_from_re_copy);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_rcptlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "rcpt list \"%s\" ", 
		    acl->a_rcptlist->al_name);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_rcpt != NULL) {
		snprintf(tempstr, sizeof(tempstr), "rcpt %s ", acl->a_rcpt);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_rcpt_re != NULL) {
		snprintf(tempstr, sizeof(tempstr), "rcpt /%s/ ",
		    acl->a_rcpt_re_copy);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_domainlist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "domainlist \"%s\" ", 
		    acl->a_domainlist->al_name);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_domain != NULL) {
		snprintf(tempstr, sizeof(tempstr), "domain %s ", acl->a_domain);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_domain_re != NULL) {
		snprintf(tempstr, sizeof(tempstr), "domain /%s/ ",
		    acl->a_domain_re_copy);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
#if USE_DNSRBL
	if (acl->a_dnsrbllist != NULL) {
		snprintf(tempstr, sizeof(tempstr), "dnsrbllist \"%s\" ", 
		    acl->a_dnsrbllist->al_name);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
	if (acl->a_dnsrbl != NULL) {
		snprintf(tempstr, sizeof(tempstr), "dnsrbl \"%s\" ",
		    acl->a_dnsrbl->d_name);
		strncat(entrystr, tempstr, sizeof(entrystr));
		def = 0;
	}
#endif
	if (acl->a_delay != -1) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[delay %ld] ", acl->a_delay);
		strncat(entrystr, tempstr, sizeof(entrystr));
	}

	if (acl->a_autowhite != -1) {
		snprintf(tempstr, sizeof(tempstr), 
		    "[aw %ld] ", acl->a_autowhite);
		strncat(entrystr, tempstr, sizeof(entrystr));
	}

	if (def)
		strncat(entrystr, "default", sizeof(entrystr));
	return entrystr;
}

void
acl_dump (void) {	/* acllist must be write locked */
	struct acl_entry *acl;
	char *entry;
	FILE *debug;

	/*
	 * We log the ACL to syslogd
	 * We also write the ACL in a file because syslogd seems to lose
	 * some debugging messages on FreeBSD 4.10 :-(
	 */
	debug = fopen("/tmp/access-list.debug", "w");
	ACL_RDLOCK;
	syslog(LOG_INFO, "Access list dump:\n");
	TAILQ_FOREACH(acl, &acl_head, a_list) {
		entry = acl_entry(acl);
		syslog(LOG_INFO, "%s\n", entry);
		if (debug != NULL)
			fprintf (debug, "%s\n", entry);
	}
	ACL_UNLOCK;
	if (debug != NULL)
		fclose(debug);
}

void 
acl_add_delay(delay)
	time_t delay;
{
	if (gacl.a_delay != -1) {
		fprintf (stderr,
		    "delay specified twice in ACL line %d\n", conf_line);
		exit(EX_DATAERR);
	}

	gacl.a_delay = delay;
		
	if (conf.c_debug || conf.c_acldebug)
		printf("load acl delay %ld\n", delay);

	return;
}

void
acl_add_autowhite(delay)
	time_t delay;
{
	if (gacl.a_autowhite != -1) {
		fprintf (stderr,
		    "autowhite specified twice in ACL line %d\n", conf_line);
		exit(EX_DATAERR);
	}

	gacl.a_autowhite = delay;
		
	if (conf.c_debug || conf.c_acldebug)
		printf("load acl delay %ld\n", delay);

	return;
}

void
acl_add_list(list)
	char *list;
{
	struct all_list_entry *ale;

	if ((ale = all_list_byname(list)) == NULL) {
		syslog(LOG_ERR, "inexistent list \"%s\" line %d",
		    list, conf_line);
		exit(EX_DATAERR);
	}

	switch (ale->al_type) {
	case LT_FROM:
		if (gacl.a_from != NULL || 
		    gacl.a_from_re != NULL ||
		    gacl.a_fromlist != NULL) {
			fprintf (stderr,
			    "muliple from statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_fromlist = ale;
		break;

	case LT_RCPT:
		if (gacl.a_rcpt != NULL ||
		    gacl.a_rcpt_re != NULL ||
		    gacl.a_rcptlist != NULL) {
			fprintf (stderr,
			    "muliple rcpt statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_rcptlist = ale;
		break;

	case LT_DOMAIN:
		if (gacl.a_domain != NULL ||
		    gacl.a_domain_re != NULL ||
		    gacl.a_domainlist != NULL) {
			fprintf (stderr,
			    "muliple domain statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_domainlist = ale;
		break;

#if USE_DNSRBL
	case LT_DNSRBL:
		if (gacl.a_dnsrbl != NULL ||
		    gacl.a_dnsrbllist != NULL) {
			fprintf (stderr,
			    "muliple dnsrbl statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_dnsrbllist = ale;
		break;
#endif

	case LT_ADDR:
		if (gacl.a_addr != NULL ||
		    gacl.a_addrlist != NULL) {
			fprintf (stderr,
			    "muliple addr statement (list \"%s\", line %d)",
			    list, conf_line);
			exit(EX_DATAERR);
		}
		gacl.a_addrlist = ale;
		break;

	default:
		syslog(LOG_ERR, "unexpected al_type %d line %d", 
		    ale->al_type, conf_line);
		exit(EX_DATAERR);
		break;
	}
		
	if (conf.c_debug || conf.c_acldebug)
		printf("load acl list \"%s\"\n", list);

	return;
}
