/* $Id: except.c,v 1.1.1.1 2004/02/21 00:01:17 manu Exp $ */

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
char *exceptfile = EXCEPTFILE;
struct exceptlist except_head;

int
except_init(void) {
	LIST_INIT(&except_head);
	return 0;
}

void
except_load(void)
{
	FILE *stream;
	char *format = "%15[0-9.]/%d\n";
	char addr[IPADDRLEN + 1];
	int cidr;
	struct in_addr in;
	struct in_addr mask;
	int readen;
	int line = 0;
	struct except *except;
	int error;

	if ((stream = fopen(exceptfile, "r")) == NULL) {
		fprintf(stderr, "cannot open exception file %s: %s\n", 
		    exceptfile, strerror(errno));
		fprintf(stderr, "continuing with no exception list\n");
		return;
	}

	while(feof(stream) == 0) {
		line++;
		readen = fscanf(stream, format, &addr, &cidr);
		switch (readen) {
		case 0: 
			goto end;
			break;

		case 1:
			mask = inet_makeaddr(~0UL, 0L);
			break;

		case 2:
			if ((cidr > 32) || (cidr < 0)) {
				fprintf(stderr, "bad mask in exception list "
				    "line %d\n", line);
				exit(EX_DATAERR);
			}

			if (cidr == 0)
				bzero(&mask, sizeof(mask));
			else
				cidr = 32 - cidr;
				mask = inet_makeaddr(~((1UL << cidr) - 1), 0L);
			break;

		default:
			fprintf(stderr, "syntax error in exception list "
			    "line %d\n", line);
			exit(EX_DATAERR);
			break;
		}

		if ((error = inet_aton(addr, &in)) != 1) {
			fprintf(stderr, "bad address in exception list "
			    "line %d: %s\n", line, strerror(errno));
			exit(EX_DATAERR);
		}
		in.s_addr &= mask.s_addr;

		if ((except = malloc(sizeof(*except))) == NULL) {
			perror("cannot allocate memory");
			exit(EX_OSERR);
		}
		
		memcpy(&except->e_addr, &in, sizeof(in));
		memcpy(&except->e_mask, &mask, sizeof(mask));
		LIST_INSERT_HEAD(&except_head, except, e_list);

		if (debug) {
			printf("load exception %s", inet_ntoa(except->e_addr));
			printf("/%s\n", inet_ntoa(except->e_mask));
		}

	}

end:
	fclose(stream);

	return;
}

int 
except_check(in)
	struct in_addr *in;
{
	struct except *ex;
	
	LIST_FOREACH(ex, &except_head, e_list) {
		if ((in->s_addr & ex->e_mask.s_addr) == ex->e_addr.s_addr) {
			syslog(LOG_INFO, "address %s is in exception list\n", 
			    inet_ntoa(*in));
			return 1;
		}
	}
	return 0;
}
