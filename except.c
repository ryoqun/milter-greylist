/* $Id: except.c,v 1.32 2004/03/31 10:07:17 manu Exp $ */

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
__RCSID("$Id: except.c,v 1.32 2004/03/31 10:07:17 manu Exp $");
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "except.h"
#include "conf.h"
#include "sync.h"
#include "milter-greylist.h"

struct exceptlist except_head;
pthread_rwlock_t except_lock;

static int emailcmp(char *, char *);

int
except_init(void) {
	int error;

	LIST_INIT(&except_head);
	if ((error = pthread_rwlock_init(&except_lock, NULL)) == 0)
		return error;

	return 0;
}

void
except_add_netblock(in, cidr)	/* exceptlist must be write-locked */
	struct in_addr *in;
	int cidr;
{
	struct in_addr mask;
	struct except *except;
	char addrstr[IPADDRLEN + 1];
	char maskstr[IPADDRLEN + 1];

	if ((cidr > 32) || (cidr < 0)) {
		fprintf(stderr, "bad mask in exception list line %d\n", 
		    conf_line);
		exit(EX_DATAERR);
	}

	cidr2mask(cidr, &mask);
	in->s_addr &= mask.s_addr;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_NETBLOCK;
	memcpy(&except->e_addr, in, sizeof(*in));
	memcpy(&except->e_mask, &mask, sizeof(mask));
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (conf.c_debug)
		printf("load exception net %s/%s\n", 
		    (char *)inet_ntop(AF_INET, 
		    &except->e_addr, addrstr, IPADDRLEN),
		    (char *)inet_ntop(AF_INET, 
		    &except->e_mask, maskstr, IPADDRLEN));

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

int 
except_filter(in, from, rcpt, queueid)
	struct in_addr *in;
	char *from;
	char *rcpt;
	char *queueid;
{
	struct except *ex;
	char addrstr[IPADDRLEN + 1];
	int testmode = conf.c_testmode;
	int retval;

	EXCEPT_RDLOCK;

	/*
	 * Testmode: check if the recipient is in the exception list.
	 * If not, then avoid grey listing.
	 */
	if (testmode) {
		int found = 0;

		LIST_FOREACH(ex, &except_head, e_list) {
			if (ex->e_type != E_RCPT)
				continue;

			if (emailcmp(rcpt, ex->e_rcpt) == 0) {
				found = 1;
				break;
			}
		}

		if (!found) {
			syslog(LOG_INFO, "%s: testmode: skipping greylist "
			    "for recipient \"%s\"", queueid, rcpt);
			retval = EXF_RCPT;
			goto out;
		}
	}
	
	LIST_FOREACH(ex, &except_head, e_list) {
		switch (ex->e_type) {
		case E_NETBLOCK: {
			if ((in->s_addr & ex->e_mask.s_addr) == 
			    ex->e_addr.s_addr) {
				syslog(LOG_INFO, "%s: address %s is in "
				    "exception list", queueid,
				    inet_ntop(AF_INET, in, addrstr, IPADDRLEN));
				retval = EXF_ADDR;
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

		case E_RCPT:
			if (testmode != 0)
				break;

			if (emailcmp(rcpt, ex->e_rcpt) == 0) {
				syslog(LOG_INFO, "%s: recipient %s is in "
				    "exception list", queueid, rcpt);
				retval = EXF_RCPT;
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
		free(except);
	}

	return;
}
