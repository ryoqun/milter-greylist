/* $Id: milter-greylist.c,v 1.1 2004/02/21 00:01:17 manu Exp $ */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/types.h>

#include <libmilter/mfapi.h>

#include "except.h"
#include "pending.h"
#include "syncer.h"
#include "milter-greylist.h"

int debug = 0;
struct smfiDesc smfilter =
{
	"greylist",	/* filter name */
	SMFI_VERSION,	/* version code */
	0,		/* flags */
	mlfi_connect,	/* connection info filter */
	NULL,		/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	NULL,		/* header filter */
	NULL,		/* end of header */
	NULL,		/* body block filter */
	NULL,		/* end of message */
	NULL,		/* message aborted */
	mlfi_close,	/* connection cleanup */
};

sfsistat 
mlfi_connect(ctx, hostname, addr)
	SMFICTX *ctx;
	char *hostname;
	_SOCK_ADDR *addr;
{
	struct mlfi_priv *priv;
	struct sockaddr_in *sin;

	if ((priv = malloc(sizeof(*priv))) == NULL)
		return SMFIS_TEMPFAIL;	

	smfi_setpriv(ctx, priv);
	bzero(priv, sizeof(*priv));

	sin = (struct sockaddr_in *)addr;
	if ((sin != NULL) && (sin->sin_family == AF_INET))
		priv->priv_addr.s_addr = sin->sin_addr.s_addr;

	if (debug)
		syslog(LOG_DEBUG, "addr = %s\n", inet_ntoa(priv->priv_addr));


	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);
	strncpy(priv->priv_from, *envfrom, ADDRLEN);

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if (debug)
		syslog(LOG_DEBUG, "addr = %s, from = %s, rcpt = %s\n", 
		    inet_ntoa(priv->priv_addr), 
		    priv->priv_from, *envrcpt);

	if (except_check(&priv->priv_addr) == 1)
		return SMFIS_CONTINUE;

	if (pending_check(&priv->priv_addr, priv->priv_from, *envrcpt) == 0)
		return SMFIS_CONTINUE;
	else
		(void)smfi_setreply(ctx, "451", "4.7.1", 
		    "Greylisting in action, please come back later");

	return SMFIS_TEMPFAIL;
}

sfsistat
mlfi_close(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) != NULL) {
		free(priv);
		smfi_setpriv(ctx, NULL);
	}

	return SMFIS_CONTINUE;
}



int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch;
	pthread_t tid;

	/* Process command line options */
	while ((ch = getopt(argc, argv, "vd:w:f:hp:")) != -1) {
		switch (ch) {
		case 'v':
			debug = 1;
			break;

		case 'w':
			if ((optarg == NULL) || ((delay = atoi(optarg)) == 0)) {
				fprintf(stderr, 
				    "%s: -w needs a positive argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			break;

		case 'f':
			if (optarg == NULL) {
				fprintf(stderr, "%s: -f needs an argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			exceptfile = optarg;
			break;

		case 'd':
			if (optarg == NULL) {
				fprintf(stderr, "%s: -d needs an argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			dumpfile = optarg;
			break;
				
		case 'p':
			if (optarg == NULL) {
				fprintf(stderr, "%s: -p needs an argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			(void) smfi_setconn(optarg);
			break;

		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}
	
	/* 
	 * Register our callbacks 
	 */
	if (smfi_register(smfilter) == MI_FAILURE) {
		fprintf(stderr, "%s: smfi_register failed\n", argv[0]);
		exit(EX_UNAVAILABLE);
	}

	/*
	 * Various init
	 */
	if (except_init() != 0) {
		fprintf(stderr, "%s: list init failed\n", argv[0]);
		exit(EX_SOFTWARE);
	}

	if (pending_init() != 0) {
		fprintf(stderr, "%s: list init failed\n", argv[0]);
		exit(EX_SOFTWARE);
	}

	openlog("milter-greylist", 0, LOG_MAIL);

	/*
	 * Load exception list
	 */
	except_load();
	
	/*
	 * Spawn syncer thread
	 */
	if (pthread_create(&tid, NULL, (void *)syncer_thread, NULL) != 0) {
		fprintf(stderr, "%s: cannot spawn syncer thread: %s\n", 
		    argv[0], strerror(errno));
		exit(EX_OSERR);
	}

	/*
	 * Here we go!
	 */
	return smfi_main();
}

void
usage(progname)
	char *progname;
{
	fprintf(stderr, "usage: %s [-v] [-d dumpfile] [-f exceptionfile] "
	    "[-w delay] -p socket\n", progname);
	exit(EX_USAGE);
}
