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

#define _BSD_SOURCE

#include <stdio.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sysexits.h>
#include <sys/param.h>

#include "pending.h"
#include "syncer.h"

extern int debug;

int dumpfreq = DUMPFREQ;
char *dumpfile = DUMPFILE;

void
syncer_thread(dontcare)
	void *dontcare;
{
	FILE *dump;
	int dumpfd;
	struct timeval tv1, tv2;
	char newdumpfile[MAXPATHLEN + 1];

	syslog(LOG_DEBUG, "syncer_thread started\n");

	/* 
	 * Re-import a saved greylist
	 */
	if ((dump = fopen(dumpfile, "r")) == NULL) {
		syslog(LOG_ERR, "cannot read dumpfile \"%s\"\n", dumpfile);
		syslog(LOG_ERR, "starting with an empty greylist\n");
	} else {
		pending_import(dump);
		fclose(dump);
	}

	sleep(dumpfreq);

	while (1) {
		if (debug) {
			(void)gettimeofday(&tv1, NULL);
			syslog(LOG_DEBUG, "dumping\n");
		}

		/* 
		 * Dump the database in a temporary file and 
		 * then replace the old one by the new one.
		 * On decent systems, rename(2) garantees that 
		 * even if the machine crashes, we will not 
		 * loose both files.
		 */
		snprintf(newdumpfile, MAXPATHLEN, "%s-XXXXXXXX", dumpfile);

		if ((dumpfd = mkstemp(newdumpfile)) == -1) {
			syslog(LOG_ERR, "mkstemp(\"%s\") failed: %s\n", 
			    newdumpfile, strerror(errno));
			exit(EX_OSERR);
		}

		if ((dump = fdopen(dumpfd, "w")) == NULL) {
			syslog(LOG_ERR, "cannot write dumpfile \"%s\": %s\n", 
			    newdumpfile, strerror(errno));
			exit(EX_OSERR);
		}

		pending_textdump(dump);
		fclose(dump);
		rename(newdumpfile, dumpfile);

		if (debug) {
			(void)gettimeofday(&tv2, NULL);
			syslog(LOG_DEBUG, "dumping done in %ld.%06lds\n",
			tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec);
		}

		sleep(dumpfreq);
	}
		
}
