/* $Id: conf.c,v 1.3 2004/03/18 09:55:14 manu Exp $ */

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

#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: conf.c,v 1.3 2004/03/18 09:55:14 manu Exp $");
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

#ifndef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include "conf.h"
#include "except.h"
#include "sync.h"
#include "milter-greylist.h"

char *conffile = CONFFILE;
struct timeval conffile_modified;

void
conf_load(void) 	/* exceptlist must be write-locked */
{
	FILE *stream;

	if ((stream = fopen(conffile, "r")) == NULL) {
		fprintf(stderr, "cannot open config file %s: %s\n", 
		    conffile, strerror(errno));
		fprintf(stderr, "continuing with no exception list\n");
		return;
	}

	conf_in = stream;
	conf_parse();
	fclose(stream);

	(void)gettimeofday(&conffile_modified, NULL);

	return;
}

void
conf_update(void) {
	struct stat st;
	struct timeval tv1, tv2, tv3;
	
	if (stat(conffile, &st) != 0) {
		syslog(LOG_DEBUG, "config file \"%s\" unavailable", 
		    conffile);
		return;
	}

	/* 
	 * conffile_modified is updated in conf_load()
	 */
	if (st.st_mtime < conffile_modified.tv_sec) 
		return;

	syslog(LOG_INFO, "reloading \"%s\"", conffile);
	if (debug)
		(void)gettimeofday(&tv1, NULL);

	peer_clear();
	EXCEPT_WRLOCK;
	except_clear();
	conf_load();
	EXCEPT_UNLOCK;

	if (debug) {
		(void)gettimeofday(&tv2, NULL);
		timersub(&tv2, &tv1, &tv3);
		syslog(LOG_DEBUG, "reloaded config file in %ld.%06lds", 
		    tv3.tv_sec, tv3.tv_usec);
	}

	return;
}
