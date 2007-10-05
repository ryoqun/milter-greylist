/* $Id: stat.c,v 1.5 2007/10/05 23:12:47 manu Exp $ */

/*
 * Copyright (c) 2007 Emmanuel Dreyfus
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
__RCSID("$Id: stat.c,v 1.5 2007/10/05 23:12:47 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sysexits.h>

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include <libmilter/mfapi.h>

#include "milter-greylist.h"
#include "conf.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

static FILE *outfp = NULL;
static int (*outfp_close)(FILE *) = NULL;
static char *format = NULL;
static pthread_mutex_t *outlock = NULL;

void
mg_stat_def(output, fstring)
	char *output;
	char *fstring;
{
	/* 
	 * If we reconfigure, we might want to close a 
	 * previously open output and free a fstring string
	 */
	if ((outfp != NULL) && (outfp_close != NULL))
		(void)(*outfp_close)(outfp);
	if (format != NULL)
		free(format);

	/*
	 * For first use, initialize the lock.
	 */
	if (outlock == NULL) {
		if ((outlock = malloc(sizeof(*outlock))) == NULL) {
			mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
		if (pthread_mutex_init(outlock, NULL) != 0) {
			 mg_log(LOG_ERR, "pthread_mutex_init() failed: %s",
			      strerror(errno));
			exit(EX_OSERR);
		}
	}

	switch (output[0]) {
	case '>':	/* file */
		errno = 0;
		if (output[1] == '>')
			outfp = Fopen(output + 2, "a");
		else
			outfp = Fopen(output + 1, "w");
#ifdef USE_FD_POOL
		outfp_close = fclose_ext;
#else
		outfp_close = fclose;
#endif
		break;
	case '|':	/* pipe */
		outfp = popen(output + 1, "w");
		outfp_close = pclose;
		break;
	default:
		mg_log(LOG_WARNING, "ignored \"%s\" stat output line %d", 
		    output, conf_line - 1);
		return;
		break;
	}

	if (outfp == NULL) {
		mg_log(LOG_WARNING, "cannot open \"%s\" at line %d: %s",
		    output, conf_line -1, 
		    (errno == 0) ? "out of stdio streams" : strerror(errno));
		return;
	}

	if ((format = fstring_escape(strdup(fstring))) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "using output \"%s\", format \"%s\"",
		    output, fstring);

	return;
}

sfsistat
mg_stat(priv, stat)
	struct mlfi_priv *priv;
	sfsistat stat;
{
	struct rcpt *rcpt;
	char *statlog;

	if (outfp == NULL)
		return stat;

	/* 
	 * Wipe out the header if the message was not accepted
	 */
	if ((stat != SMFIS_CONTINUE) && (priv->priv_sr.sr_report)) {
		free(priv->priv_sr.sr_report);
		priv->priv_sr.sr_report = NULL;
	}


	if (pthread_mutex_lock(outlock) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_lock failed "
		    "in mg_stat: %s", strerror(errno));
		exit(EX_OSERR);
	}

	/* 
	 * Keep track of it in fstring_expand 
	 */
	priv->priv_sr.sr_retcode = stat; 

	if (priv->priv_cur_rcpt == NULL) {
		LIST_FOREACH(rcpt, &priv->priv_rcpt, r_list) {
			statlog = fstring_expand(priv, rcpt->r_addr, format);
			fprintf(outfp, "%s", statlog);
			free(statlog);
		}
	} else {
		statlog = fstring_expand(priv, priv->priv_cur_rcpt, format);
		fprintf(outfp, "%s", statlog);
		free(statlog);
	}

	fflush(outfp);

	if (pthread_mutex_unlock(outlock) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_unlock failed "
		    "in mg_stat: %s", strerror(errno));
		exit(EX_OSERR);
	}

	return stat;
}
