/* $Id: except.c,v 1.8 2004/03/02 10:34:37 manu Exp $ */

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

#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sysexits.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "except.h"

extern int debug;
int testmode = 0;
char *exceptfile = EXCEPTFILE;
struct exceptlist except_head;

static int emailcmp(char *, char *);

int
except_init(void) {
	LIST_INIT(&except_head);
	return 0;
}

void
except_load(void)
{
	FILE *stream;

	if ((stream = fopen(exceptfile, "r")) == NULL) {
		fprintf(stderr, "cannot open exception file %s: %s\n", 
		    exceptfile, strerror(errno));
		fprintf(stderr, "continuing with no exception list\n");
		return;
	}

	except_in = stream;
	except_parse();
	fclose(stream);

	return;
}

void
except_add_netblock(in, cidr)
	struct in_addr *in;
	int cidr;
{
	struct in_addr mask;
	struct except *except;

	if ((cidr > 32) || (cidr < 0)) {
		fprintf(stderr, "bad mask in exception list line %d\n", 
		    except_line);
		exit(EX_DATAERR);
	}

	if (cidr == 0)
		bzero(&mask, sizeof(mask));
	else
		cidr = 32 - cidr;
	mask = inet_makeaddr(~((1UL << cidr) - 1), 0L);

	in->s_addr &= mask.s_addr;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_NETBLOCK;
	memcpy(&except->e_addr, in, sizeof(*in));
	memcpy(&except->e_mask, &mask, sizeof(mask));
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (debug) {
		/*
		 * inet_ntoa result is a static char[], so we cannot use
		 * inet_ntoa two times in the same function call, else we 
		 * get the same result twice.
		 */
		printf("load exception net %s", inet_ntoa(except->e_addr));
		printf("/%s\n", inet_ntoa(except->e_mask));
	}

	return;
}

void
except_add_from(email)
	char *email;
{
	struct except *except;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_FROM;
	strncpy(except->e_from, email, ADDRLEN);
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (debug)
		printf("load exception from %s\n", email);

	return;
}

void
except_add_rcpt(email)
	char *email;
{
	struct except *except;

	if ((except = malloc(sizeof(*except))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}
		
	except->e_type = E_RCPT;
	strncpy(except->e_rcpt, email, ADDRLEN);
	LIST_INSERT_HEAD(&except_head, except, e_list);

	if (debug)
		printf("load exception rcpt %s\n", email);

	return;
}

int 
except_filter(in, from, rcpt)
	struct in_addr *in;
	char *from;
	char *rcpt;
{
	struct except *ex;

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
			syslog(LOG_INFO, "testmode: skipping greylist "
			    "for recipient \"%s\"\n", rcpt);
			return 1;
		}
	}
	
	LIST_FOREACH(ex, &except_head, e_list) {
		switch (ex->e_type) {
		case E_NETBLOCK: {
			if ((in->s_addr & ex->e_mask.s_addr) == 
			    ex->e_addr.s_addr) {
				syslog(LOG_INFO, "address %s is in "
				    "exception list\n", inet_ntoa(*in));
				return 1;
			}
			break;
		}

		case E_FROM:
			if (emailcmp(from, ex->e_from) == 0) {
				syslog(LOG_INFO, "sender %s is in "
				    "exception list\n", from);
				return 1;
			}
			break;

		case E_RCPT:
			if (testmode != 0)
				break;

			if (emailcmp(rcpt, ex->e_rcpt) == 0) {
				syslog(LOG_INFO, "recipient %s is in "
				    "exception list\n", rcpt);
				return 1;
			}
			break;

		default:
			syslog(LOG_ERR, "corrupted exception list\n");
			exit(EX_SOFTWARE);
			break;
		}
	}
	return 0;
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
