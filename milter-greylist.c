/* $Id: milter-greylist.c,v 1.36 2004/03/20 06:35:35 manu Exp $ */

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
__RCSID("$Id: milter-greylist.c,v 1.36 2004/03/20 06:35:35 manu Exp $");
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sysexits.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <libmilter/mfapi.h>

#include "config.h"
#include "dump.h"
#include "except.h"
#include "conf.h"
#include "pending.h"
#include "sync.h"
#include "autowhite.h"
#include "milter-greylist.h"

int debug = 0;
int dont_fork = 0;
int quiet = 0;

static char *strncpy_rmsp(char *, char *, size_t);

struct smfiDesc smfilter =
{
	"greylist",	/* filter name */
	SMFI_VERSION,	/* version code */
	SMFIF_ADDHDRS,	/* flags */
	mlfi_connect,	/* connection info filter */
	NULL,		/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	NULL,		/* header filter */
	NULL,		/* end of header */
	NULL,		/* body block filter */
	mlfi_eom,	/* end of message */
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
	struct sockaddr_in *addr_in;

	if ((priv = malloc(sizeof(*priv))) == NULL)
		return SMFIS_TEMPFAIL;	

	smfi_setpriv(ctx, priv);
	bzero(priv, sizeof(*priv));

	addr_in = (struct sockaddr_in *)addr;
	if ((addr_in != NULL) && (addr_in->sin_family == AF_INET))
		priv->priv_addr.s_addr = addr_in->sin_addr.s_addr;

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	/*
	 * Strip spaces from the source address
	 */
	strncpy_rmsp(priv->priv_from, *envfrom, ADDRLEN);
	priv->priv_from[ADDRLEN] = '\0';

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	struct mlfi_priv *priv;
	long remaining;
	char hdr[HDRLEN + 1];
	char addrstr[IPADDRLEN + 1];
	char rcpt[ADDRLEN + 1];
	char *queue_id;
	int h, mn, s;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if (debug)
		syslog(LOG_DEBUG, "addr = %s, from = %s, rcpt = %s", 
		    inet_ntoa(priv->priv_addr), 
		    priv->priv_from, *envrcpt);

	/*
	 * Strip spaces from the recipient address
	 */
	strncpy_rmsp(rcpt, *envrcpt, ADDRLEN);
	rcpt[ADDRLEN] = '\0';

	/* 
	 * Reload the config file if it has been touched
	 * Restart the sync master thread if nescessary
	 */
	conf_update();
	sync_master_restart();

	if ((priv->priv_whitelist = except_filter(&priv->priv_addr, 
	    priv->priv_from, rcpt)) != EXF_NONE) {
		priv->priv_elapsed = 0;
		return SMFIS_CONTINUE;
	}

	if ((priv->priv_whitelist = autowhite_check(&priv->priv_addr,
	    priv->priv_from, rcpt)) != EXF_NONE) {
		priv->priv_elapsed = 0;
		return SMFIS_CONTINUE;
	}

	if (pending_check(&priv->priv_addr, priv->priv_from, 
	    rcpt, &remaining, &priv->priv_elapsed) != 0) 
		return SMFIS_CONTINUE;

	h = remaining / 3600;
	remaining = remaining % 3600;
	mn = (remaining / 60);
	remaining = remaining % 60;
	s = remaining;

	if ((queue_id = smfi_getsymval(ctx, "{i}") == NULL) {
		syslog(LOG_ERR, "Option \"O Milter.macros.connect="
		    "i,j,{if_addr}\" missing in sendmail.cf");
		queue_id = "(unknown)";
	}
	   
	syslog(LOG_INFO, "%s: addr %s from %s to %s delayed for %02d:%02d:%02d",
	    queue_id, inet_ntop(AF_INET, &priv->priv_addr, addrstr, IPADDRLEN),
	    priv->priv_from, *envrcpt, h, mn, s);

	if (quiet) {
		(void)smfi_setreply(ctx, "451", "4.7.1", 
		    "Greylisting in action, please come back later");
	} else {
		snprintf(hdr, HDRLEN, 
		    "Greylisting in action, please come "
		    "back in %02d:%02d:%02d", h, mn, s);
		(void)smfi_setreply(ctx, "451", "4.7.1", hdr);
	}

	return SMFIS_TEMPFAIL;
}

sfsistat
mlfi_eom(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;
	char hdr[HDRLEN + 1];
	int h, mn, s;
	char *fqdn = NULL;
	char *ip = NULL;
	char timestr[HDRLEN + 1];
	struct timeval tv;
	char *whystr = NULL;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if (((fqdn = smfi_getsymval(ctx, "{j}")) == NULL) ||
	    ((ip = smfi_getsymval(ctx, "{if_addr}")) == NULL))
		syslog(LOG_ERR, "Option \"O Milter.macros.connect="
		    "i,j,{if_addr}\" missing in sendmail.cf");

	(void)gettimeofday(&tv, NULL);
	strftime(timestr, HDRLEN, 
	    "%a, %d %b %Y %T %z", localtime((time_t *)&tv.tv_sec));

	if (priv->priv_elapsed == 0) {
		switch (priv->priv_whitelist) {
		case EXF_ADDR:
			whystr = "Sender IP whitelisted";
			break;

		case EXF_FROM:
			whystr = "Sender e-mail whitelisted";
			break;

		case EXF_RCPT:
			whystr = "Recipient e-mail whitelisted";
			break;

		case EXF_AUTO:
			whystr = "IP, sender and recipient auto-whitelisted";
			break;

		default:
			syslog(LOG_ERR, "unexpected priv_whitelist = %d", 	
			    priv->priv_whitelist);
			whystr = "Internal error";
			break;
		}

		snprintf(hdr, HDRLEN, "%s, not delayed by "
		    "milter-greylist-%s (%s [%s]); %s",
		    whystr, PACKAGE_VERSION, fqdn, ip, timestr);

		smfi_addheader(ctx, HEADERNAME, hdr);

		return SMFIS_CONTINUE;
	}

	h = priv->priv_elapsed / 3600;
	priv->priv_elapsed = priv->priv_elapsed % 3600;
	mn = (priv->priv_elapsed / 60);
	priv->priv_elapsed = priv->priv_elapsed % 60;
	s = priv->priv_elapsed;

	snprintf(hdr, HDRLEN,
	    "Delayed for %02d:%02d:%02d by milter-greylist-%s (%s [%s]); %s", 
	    h, mn, s, PACKAGE_VERSION, fqdn, ip, timestr);
	smfi_addheader(ctx, HEADERNAME, hdr);

	return SMFIS_CONTINUE;
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
	int gotsocket = 0;
	struct passwd *pw = NULL;

	/* Process command line options */
	while ((ch = getopt(argc, argv, "a:vDd:qw:f:hp:Tu:")) != -1) {
		switch (ch) {
		case 'a':
			autowhite_validity = (time_t)atoi(optarg);
			break;

		case 'D':
			dont_fork = 1;
			break;

		case 'q':
			quiet = 1;
			break;

		case 'u': {
			if (geteuid() != 0) {
				fprintf(stderr, "%s: only root can use -u\n", 
				    argv[0]);
				exit(EX_USAGE);
			}

			if ((optarg == NULL) || 
			    ((pw = getpwnam(optarg)) == NULL)) {
				fprintf(stderr, 
				    "%s: -u needs a valid user as argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			break;
		}
			
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
			conffile = optarg;
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
			cleanup_sock(optarg);
			(void)smfi_setconn(optarg);
			gotsocket = 1;
			break;

		case 'T':
			testmode = 1;	
			break;

		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}
	
	if (gotsocket == 0) {
		fprintf(stderr, "%s: -p is a mandatory option\n",
		    argv[0]);
		usage(argv[0]);
	}

	/*
	 * Drop root privs
	 */
	if (pw != NULL) {
		if ((setuid(pw->pw_uid) != 0) ||
		    (seteuid(pw->pw_uid) != 0)) {
			fprintf(stderr, "%s: cannot change UID: %s\n",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
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
	if ((except_init() != 0) ||
	    (pending_init() != 0) ||
	    (peer_init() != 0) ||
	    (autowhite_init() != 0) ||
	    (dump_init() != 0)) {
		fprintf(stderr, "%s: list init failed\n", argv[0]);
		exit(EX_SOFTWARE);
	}

	if (dont_fork != 0)
		openlog("milter-greylist", LOG_PERROR, LOG_MAIL);
	else
		openlog("milter-greylist", 0, LOG_MAIL);

	/*
	 * Load config file
	 * We can do this without locking exceptlist, as
	 * normal operation has not started: no other thread
	 * can access the list yet.
	 */
	conf_load();
	
	/*
	 * Reload a saved greylist
	 * No lock needed here either.
	 */
	dump_reload();

	/*
	 * Turn into a daemon
	 */
	if (dont_fork == 0) {

		(void)close(0);
		(void)open("/dev/null", O_RDONLY, 0);
		(void)close(1);
		(void)open("/dev/null", O_RDONLY, 0);
		(void)close(2);
		(void)open("/dev/null", O_RDONLY, 0);

		if (chdir("/") != 0) {
			fprintf(stderr, "%s: cannot chdir to root: %s\n",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}

		switch (fork()) {
		case -1:
			fprintf(stderr, "%s: cannot fork: %s\n",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
			break;

		case 0:
			break;

		default:
			exit(EX_OK);	
			break;
		}
	}

	/*
	 * Start the dumper thread
	 */
	dumper_start();

	/*
	 * Run the peer MX greylist sync threads
	 */
	sync_master_restart();
	sync_sender_start();

	/*
	 * Here we go!
	 */
	return smfi_main();
}

void
usage(progname)
	char *progname;
{
	fprintf(stderr, 
	    "usage: %s [-DvqT] [-a autowhite] [-d dumpfile] [-f configfile]\n"
	    "       [-w delay] [-u username] -p socket\n", progname);
	exit(EX_USAGE);
}

void
cleanup_sock(path)
	char *path;
{
	struct stat st;

	/* Does it exists? Get information on it if it does */
	if (stat(path, &st) != 0)
		return;

	/* Is it a socket? */
	if ((st.st_mode & S_IFSOCK) == 0)
		return;

	/* Remove the beast */
	(void)unlink(path);
	return;
}

static char *
strncpy_rmsp(dst, src, len)
	char *dst;
	char *src;
	size_t len;
{
	unsigned int i;

	for (i = 0; src[i] && (i < len); i++) {
		if (isgraph(src[i]))
			dst[i] = src[i];
		else
			dst[i] = '_';
	}

	return dst;
}
