/* $Id: except.c,v 1.47 2004/08/02 20:17:38 manu Exp $ */

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
__RCSID("$Id: except.c,v 1.47 2004/08/02 20:17:38 manu Exp $");
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

#include "except.h"
#include "conf.h"
#include "sync.h"
#include "milter-greylist.h"

struct exceptlist except_head;
pthread_rwlock_t except_lock;

static int emailcmp(char *, char *);

void
except_init(void) {
	int error;

	LIST_INIT(&except_head);
	if ((error = pthread_rwlock_init(&except_lock, NULL)) != 0) {
		syslog(LOG_ERR, "pthread_rwlock_init failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void
except_add_netblock(sa, salen, cidr)	/* exceptlist must be write-locked */
	struct sockaddr *sa;
	socklen_t salen;
	int cidr;
{
	ipaddr mask;
	struct except *except;
	char addrstr[IPADDRSTRLEN];
	char maskstr[IPADDRSTRLEN];
	int maxcidr, masklen;
#ifdef AF_INET6
	int i;
#endif

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
		    "bad address family in exception list line %d\n",
		    conf_line);
		exit(EX_DATAERR);
	}
	if (cidr > maxcidr || cidr < 0) {
		fprintf(stderr, "bad mask in exception list line %d\n", 
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

	if ((except = malloc(sizeof(*except))) == NULL ||
	    (except->e_addr = malloc(salen)) == NULL ||
	    (except->e_mask = malloc(masklen)) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_NETBLOCK;
	except->e_addrlen = salen;
	memcpy(except->e_addr, sa, salen);
	memcpy(except->e_mask, &mask, masklen);
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug) {
		iptostring(except->e_addr, except->e_addrlen, addrstr,
		    sizeof(addrstr));
		inet_ntop(except->e_addr->sa_family, except->e_mask, maskstr,
		    sizeof(maskstr));
		printf("load exception net %s/%s\n", addrstr, maskstr);
	}

	return;
}

void
except_add_from(email)	/* exceptlist must be write-locked */
	char *email;
{
	struct except *except;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_FROM;
	strncpy(except->e_from, email, ADDRLEN);
	except->e_from[ADDRLEN] = '\0';
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug)
		printf("load exception from %s\n", email);

	return;
}

void
except_add_rcpt(email)	/* exceptlist must be write-locked */
	char *email;
{
	struct except *except;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_RCPT;
	strncpy(except->e_rcpt, email, ADDRLEN);
	except->e_rcpt[ADDRLEN] = '\0';
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug)
		printf("load exception rcpt %s\n", email);

	return;
}

void
except_add_domain(domain)	/* exceptlist must be write-locked */
	char *domain;
{
	struct except *except;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_DOMAIN;
	strncpy(except->e_domain, domain, ADDRLEN);
	except->e_domain[ADDRLEN] = '\0';
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug)
		printf("load exception domain %s\n", domain);

	return;
}

#define ERRLEN 1024
void
except_add_from_regex(regexstr)	/* exceptlist must be write-locked */
	char *regexstr;
{
	struct except *except;
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	if ((error = regcomp(&except->e_from_re, regexstr, REG_ICASE)) != 0) {
		regerror(error, &except->e_from_re, errstr, ERRLEN);
		fprintf(stderr, "bad regular expression \"%s\": %s\n", 
		    regexstr, errstr);
		free(except);
		exit(EX_OSERR);
	}

	except->e_type = E_FROM_RE;
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug)
		printf("load exception from regex %s\n", regexstr);

	return;
}

void
except_add_rcpt_regex(regexstr)	/* exceptlist must be write-locked */
	char *regexstr;
{
	struct except *except;
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	if ((error = regcomp(&except->e_rcpt_re, regexstr, REG_ICASE)) != 0) {
		regerror(error, &except->e_rcpt_re, errstr, ERRLEN);
		fprintf(stderr, "bad regular expression \"%s\": %s\n", 
		    regexstr, errstr);
		free(except);
		exit(EX_OSERR);
	}

	except->e_type = E_RCPT_RE;
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug)
		printf("load exception rcpt regex %s\n", regexstr);

	return;
}

void
except_add_domain_regex(regexstr)	/* exceptlist must be write-locked */
	char *regexstr;
{
	struct except *except;
	size_t len;
	int error;
	char errstr[ERRLEN + 1];

	/* 
	 * Strip leading and trailing slashes
	 */
	len = strlen(regexstr);
	if (len > 0)
		regexstr[len - 1] = '\0';
	regexstr++;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	if ((error = regcomp(&except->e_domain_re, regexstr, REG_ICASE)) != 0) {
		regerror(error, &except->e_domain_re, errstr, ERRLEN);
		fprintf(stderr, "bad regular expression \"%s\": %s\n", 
		    regexstr, errstr);
		free(except);
		exit(EX_OSERR);
	}

	except->e_type = E_DOMAIN_RE;
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug)
		printf("load exception domain regex %s\n", regexstr);

	return;
}


int 
except_rcpt_filter(rcpt, queueid)
	char *rcpt;
	char *queueid;
{
	struct except *ex;
	int testmode = conf.c_testmode;
	int retval;

	EXCEPT_RDLOCK;


	/*
	 * Default if we do not find the recipient in the list
	 * for testmode: the recipient is whitelisted
	 * for normal mode: the recipient is not whitelisted.
	 */
	if (testmode)
		retval = EXF_RCPT;
	else
		retval = EXF_NONE;

	LIST_FOREACH(ex, &except_head, e_list) {
		/*
		 * If we find it in the list this means:
		 * for testmode: that it is not whitelisted
		 * for normal mode: that it is whitelisted
		 */
		if ((ex->e_type == E_RCPT) &&
		    (emailcmp(rcpt, ex->e_rcpt) == 0)) {
			if (testmode)
				retval = EXF_NONE;
			else
				retval = EXF_RCPT;
			break;
		}

		if ((ex->e_type == E_RCPT_RE) &&
		    (regexec(&ex->e_rcpt_re, rcpt, 0, NULL, 0) == 0)) {
			if (testmode)
				retval = EXF_NONE;
			else
				retval = EXF_RCPT;
			break;
		}
	}

	if (testmode && (retval == EXF_RCPT)) {
		syslog(LOG_INFO, "%s: testmode: skipping greylist "
		    "for recipient \"%s\"", queueid, rcpt);
	}
	
	EXCEPT_UNLOCK;
	return retval;
}

int 
except_sender_filter(sa, salen, hostname, from, queueid)
	struct sockaddr *sa;
	socklen_t salen;
	char *hostname;
	char *from;
	char *queueid;
{
	struct except *ex;
	char addrstr[IPADDRSTRLEN];
	int retval;

	EXCEPT_RDLOCK;

	LIST_FOREACH(ex, &except_head, e_list) {
		switch (ex->e_type) {
		case E_RCPT:
		case E_RCPT_RE:
			break;

		case E_NETBLOCK: {
			if (ip_match(sa, ex->e_addr, ex->e_mask)) {
				iptostring(sa, salen, addrstr,
				    sizeof(addrstr));
				syslog(LOG_INFO, "%s: address %s is in "
				    "exception list", queueid, addrstr);
				retval = EXF_ADDR;
				goto out;
			}
			break;
		}

		case E_DOMAIN: {
			/* Use emailcmp even if it's not an e-mail */
			if (emailcmp(hostname, ex->e_domain) == 0) {
				syslog(LOG_INFO, "%s: sender DNS name %s is in "
				    "exception list", queueid, hostname);
				retval = EXF_DOMAIN;
				goto out;
			}
			break;
		}

		case E_DOMAIN_RE: {
			if (regexec(&ex->e_domain_re, 
			    hostname, 0, NULL, 0) == 0) {
				syslog(LOG_INFO, "%s: sender DNS name %s is in "
				    "exception list", queueid, hostname);
				retval = EXF_DOMAIN;
				goto out;
			}
			break;
		}

		case E_FROM:
			if (emailcmp(from, ex->e_from) == 0) {
				syslog(LOG_INFO, "%s: sender %s is in "
				    "exception list", queueid, from);
				retval = EXF_FROM;
				goto out;
			}
			break;

		case E_FROM_RE:
			if (regexec(&ex->e_from_re, from, 0, NULL, 0) == 0) {
				syslog(LOG_INFO, "%s: sender %s is in "
				    "exception list", queueid, from);
				retval = EXF_FROM;
				goto out;
			}
			break;

		default:
			syslog(LOG_ERR, "corrupted exception list");
			exit(EX_SOFTWARE);
			break;
		}
	}

	retval = EXF_NONE;
out:
	EXCEPT_UNLOCK;
	return retval;
}

static int 
emailcmp(big, little)
	char *big;
	char *little;
{
	int i;

	while (big[0]) {
		if (tolower(big[0]) != tolower(little[0]))
			big++;

		for (i = 0; big[0] && little[i] && (i < ADDRLEN); i++) {
			if (tolower(big[0]) != tolower(little[i]))
				break;
			big++;
		}
		
		if (little[i] == 0)
			return 0;
	}

	return 1;
}

void
except_clear(void) {	/* exceptlist must be write locked */
	struct except *except;

	while(!LIST_EMPTY(&except_head)) {
		except = LIST_FIRST(&except_head);
		LIST_REMOVE(except, e_list);

		if (except->e_type == E_NETBLOCK) {
			free(except->e_addr);
			free(except->e_mask);
		}

		if (except->e_type == E_FROM_RE)
			regfree(&except->e_from_re);

		if (except->e_type == E_RCPT_RE)
			regfree(&except->e_rcpt_re);

		if (except->e_type == E_DOMAIN_RE)
			regfree(&except->e_domain_re);

		free(except);
	}

	return;
}
