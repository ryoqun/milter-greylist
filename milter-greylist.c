/* $Id: milter-greylist.c,v 1.82 2004/05/20 19:34:19 manu Exp $ */

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
__RCSID("$Id: milter-greylist.c,v 1.82 2004/05/20 19:34:19 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>

/* On IRIX, <unistd.h> defines a EX_OK that clashes with <sysexits.h> */
#ifdef EX_OK
#undef EX_OK
#endif
#include <sysexits.h>

#if HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <libmilter/mfapi.h>

#include "dump.h"
#include "except.h"
#include "conf.h"
#include "pending.h"
#include "sync.h"
#include "spf.h"
#include "autowhite.h"
#include "milter-greylist.h"

static char *strncpy_rmsp(char *, char *, size_t);
static char *gmtoffset(time_t *, char *, size_t);
static void writepid(char *);
static void check_lockfile(void);
void rmlockfile(void);

struct smfiDesc smfilter =
{
	"greylist",	/* filter name */
	SMFI_VERSION,	/* version code */
	SMFIF_ADDHDRS,	/* flags */
	mlfi_connect,	/* connection info filter */
	MLFI_HELO,	/* SMTP HELO command filter */
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
	bzero((void *)priv, sizeof(*priv));
	priv->priv_whitelist = EXF_UNSET;

	addr_in = (struct sockaddr_in *)addr;

	if ((addr_in != NULL) && (addr_in->sin_family == AF_INET)) {
		priv->priv_addr.s_addr = addr_in->sin_addr.s_addr;
	} else {
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_NONIPV4;
	}

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_helo(ctx, helostr)
	SMFICTX *ctx;
	char *helostr;
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT)) 
	strncpy_rmsp(priv->priv_helo, helostr, ADDRLEN);
	priv->priv_helo[ADDRLEN] = '\0';
#endif

	return SMFIS_CONTINUE;
}


sfsistat
mlfi_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	struct mlfi_priv *priv;
	char *auth_authen;
	char *verify;
	char *cert_subject;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if ((priv->priv_queueid = smfi_getsymval(ctx, "{i}")) == NULL) {
		syslog(LOG_DEBUG, "smfi_getsymval failed for {i}");
		priv->priv_queueid = "(unknown id)";
	}

	/*
	 * Strip spaces from the source address
	 */
	strncpy_rmsp(priv->priv_from, *envfrom, ADDRLEN);
	priv->priv_from[ADDRLEN] = '\0';

	/*
	 * Reload the config file if it has been touched
	 */
	conf_update();

	/*
	 * Is the sender non-IPv4?
	 */
	if (priv->priv_whitelist == EXF_NONIPV4)
		return SMFIS_CONTINUE;

	/*
	 * Is the user authenticated?
	 */
	if ((conf.c_noauth == 0) &&
	    ((auth_authen = smfi_getsymval(ctx, "{auth_authen}")) != NULL)) {
		syslog(LOG_DEBUG, 
		    "User %s authenticated, bypassing greylisting", 
		    auth_authen);
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_AUTH;

		return SMFIS_CONTINUE;
	} 

	/* 
	 * STARTTLS authentication?
	 */
	if ((conf.c_noauth == 0) &&
	    ((verify = smfi_getsymval(ctx, "{verify}")) != NULL) &&
	    (strcmp(verify, "OK") == 0) &&
	    ((cert_subject = smfi_getsymval(ctx, "{cert_subject}")) != NULL)) {
		syslog(LOG_DEBUG, 
		    "STARTTLS succeeded for DN=\"%s\", bypassing greylisting", 
		    cert_subject);
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_STARTTLS;

		return SMFIS_CONTINUE;
	}

	/*
	 * Is the sender IP or its e-mail address in the
	 * permanent whitelist? We do this before SPF as
	 * a lookup in the whitelist is less expensive
	 * than a DNS lookup.
	 */
	if ((priv->priv_whitelist = except_sender_filter(&priv->priv_addr, 
	    priv->priv_from, priv->priv_queueid)) != EXF_NONE) {
		priv->priv_elapsed = 0;

		return SMFIS_CONTINUE;
	}

	/*
	 * Is the sender address SPF-compliant?
	 */
	if ((conf.c_nospf == 0) && 
	    (SPF_CHECK(&priv->priv_addr, 
	    priv->priv_helo, *envfrom) != EXF_NONE)) {
		char ipstr[IPADDRLEN + 1];

		inet_ntop(AF_INET, &priv->priv_addr, ipstr, IPADDRLEN);
		syslog(LOG_DEBUG, 
		    "Sender IP %s and address %s are SPF-compliant, "
		    "bypassing greylist", ipstr, *envfrom);
		priv->priv_elapsed = 0;
		priv->priv_whitelist = EXF_SPF;

		return SMFIS_CONTINUE;
	}

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	struct mlfi_priv *priv;
	time_t remaining;
	char hdr[HDRLEN + 1];
	char addrstr[IPADDRLEN + 1];
	char rcpt[ADDRLEN + 1];
	int h, mn, s;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if (conf.c_debug)
		syslog(LOG_DEBUG, "%s: addr = %s, from = %s, rcpt = %s", 
		    priv->priv_queueid, inet_ntoa(priv->priv_addr), 
		    priv->priv_from, *envrcpt);

	/*
	 * For multiple-recipients messages, if the sender IP or the
	 * sender e-mail address is whitelisted, authenticated, or
	 * SPF compliant, then there is no need to check again, 
	 * it is whitelisted for all the recipients.
	 * 
	 * Moreover, this will prevent a wrong X-Greylist header display
	 * if the {IP, sender e-mail} address was whitelisted and the
	 * last recipient was also whitelisted. If we would set priv_whitelist
	 * on the last recipient, all recipient would have a X-Greylist
	 * header explaining that they were whitelisted, whereas some
	 * of them would not.
	 */
	if ((priv->priv_whitelist == EXF_ADDR) ||
	    (priv->priv_whitelist == EXF_FROM) ||
	    (priv->priv_whitelist == EXF_AUTH) ||
	    (priv->priv_whitelist == EXF_SPF) ||
	    (priv->priv_whitelist == EXF_NONIPV4) ||
	    (priv->priv_whitelist == EXF_STARTTLS))
		return SMFIS_CONTINUE;

	/* 
	 * Restart the sync master thread if nescessary
	 */
	sync_master_restart();

	/*
	 * Strip spaces from the recipient address
	 */
	strncpy_rmsp(rcpt, *envrcpt, ADDRLEN);
	rcpt[ADDRLEN] = '\0';

	/*
	 * Check if the recipient e-mail is in the permanent whitelist.
	 */
	if ((priv->priv_whitelist = except_rcpt_filter(rcpt,
	    priv->priv_queueid)) != EXF_NONE) {
		priv->priv_elapsed = 0;
		return SMFIS_CONTINUE;
	}

	/* 
	 * Check if the tuple {sender IP, sender e-mail, recipient e-mail}
	 * was autowhitelisted
	 */
	if ((priv->priv_whitelist = autowhite_check(&priv->priv_addr,
	    priv->priv_from, rcpt, priv->priv_queueid)) != EXF_NONE) {
		priv->priv_elapsed = 0;
		return SMFIS_CONTINUE;
	}

	/*
	 * On a multi-recipient message, one message can be whitelisted,
	 * and the next ones be greylisted. The first one would
	 * pass through immediatly (priv->priv_delay = 0) with a 
	 * priv->priv_whitelist = EXF_NONE. This would cause improper
	 * X-Greylist header display in mlfi_eom()
	 *
	 * The fix: if we make it to mlfi_eom() with priv_elapsed = 0, this
	 * means that some recipients were whitelisted. 
	 * We can set priv_whitelist now, because if the message is greylisted
	 * for everyone, it will not go to mlfi_eom(), and priv_whitelist 
	 * will not be used.
	 */
	priv->priv_whitelist = EXF_RCPT;

	/*
	 * Check if the tuple {sender IP, sender e-mail, recipient e-mail}
	 * is in the greylist and if it ca now be accepted. If it is not
	 * in the greylist, it will be added.
	 */
	if (pending_check(&priv->priv_addr, priv->priv_from, 
	    rcpt, &remaining, &priv->priv_elapsed, priv->priv_queueid) != 0) 
		return SMFIS_CONTINUE;

	/*
	 * The message has been added to the greylist and will be delayed.
	 * Log this and report to the client.
	 */
	h = remaining / 3600;
	remaining = remaining % 3600;
	mn = (remaining / 60);
	remaining = remaining % 60;
	s = remaining;

	syslog(LOG_INFO, "%s: addr %s from %s to %s delayed for %02d:%02d:%02d",
	    priv->priv_queueid,
	    inet_ntop(AF_INET, &priv->priv_addr, addrstr, IPADDRLEN),
	    priv->priv_from, *envrcpt, h, mn, s);

	if (conf.c_quiet) {
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
	char tzstr[HDRLEN + 1];
	char tznamestr[HDRLEN + 1];
	char *whystr = NULL;
	char host[ADDRLEN + 1];
	time_t t;
	struct tm ltm;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if ((fqdn = smfi_getsymval(ctx, "{j}")) == NULL) {
		syslog(LOG_DEBUG, "smfi_getsymval failed for {j}");
		gethostname(host, ADDRLEN);
		fqdn = host;
	}

	if ((ip = smfi_getsymval(ctx, "{if_addr}")) == NULL) {
		syslog(LOG_DEBUG, "smfi_getsymval failed for {if_addr}");
		ip = "0.0.0.0";
	}

	t = time(NULL);
	localtime_r(&t, &ltm);
	strftime(timestr, HDRLEN, "%a, %d %b %Y %T", &ltm);
	gmtoffset(&t, tzstr, HDRLEN);
	strftime(tznamestr, HDRLEN, "%Z", &ltm);

	if (priv->priv_elapsed == 0) {
		if ((conf.c_report & C_NODELAYS) == 0)
			return SMFIS_CONTINUE;
			
		switch (priv->priv_whitelist) {
		case EXF_ADDR:
			whystr = "Sender IP whitelisted";
			break;

		case EXF_FROM:
			whystr = "Sender e-mail whitelisted";
			break;

		case EXF_AUTH:
			whystr = "Sender succeded SMTP AUTH authentication";
			break;

		case EXF_SPF:
			whystr = "Sender is SPF-compliant";
			break;

		case EXF_NONIPV4:
			whystr = "Message not sent from an IPv4 address";
			break;

		case EXF_STARTTLS:
			whystr = "Sender succeeded STARTTLS authentication";
			break;

		case EXF_RCPT:
			whystr = "Recipient e-mail whitelisted";
			break;

		case EXF_AUTO:
			whystr = "IP, sender and recipient auto-whitelisted";
			break;

		default:
			syslog(LOG_ERR, "%s: unexpected priv_whitelist = %d", 	
			    priv->priv_queueid, priv->priv_whitelist);
			whystr = "Internal error";
			break;
		}

		snprintf(hdr, HDRLEN, "%s, not delayed by "
		    "milter-greylist-%s (%s [%s]); %s %s (%s)",
		    whystr, PACKAGE_VERSION, fqdn, 
		    ip, timestr, tzstr, tznamestr);

		smfi_addheader(ctx, HEADERNAME, hdr);

		return SMFIS_CONTINUE;
	}

	h = priv->priv_elapsed / 3600;
	priv->priv_elapsed = priv->priv_elapsed % 3600;
	mn = (priv->priv_elapsed / 60);
	priv->priv_elapsed = priv->priv_elapsed % 60;
	s = priv->priv_elapsed;

	snprintf(hdr, HDRLEN,
	    "Delayed for %02d:%02d:%02d by milter-greylist-%s "
	    "(%s [%s]); %s %s (%s)", 
	    h, mn, s, PACKAGE_VERSION, fqdn, ip, timestr, tzstr, tznamestr);

	if (conf.c_report & C_DELAYS)
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

	/*
	 * Load configuration defaults
	 */
	conf_defaults(&defconf);

	/* 
	 * Process command line options 
	 */
	while ((ch = getopt(argc, argv, "Aa:vDd:qw:f:hp:P:Tu:rSL:")) != -1) {
		switch (ch) {
		case 'A':
			defconf.c_noauth = 1;
			defconf.c_forced |= C_NOAUTH;
			break;

		case 'a':
			if (optarg == NULL) {
				fprintf(stderr, "%s: -a needs an argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_autowhite_validity = 
			    (time_t)humanized_atoi(optarg);
			defconf.c_forced |= C_AUTOWHITE;
			break;

		case 'D':
			defconf.c_nodetach = 1;
			defconf.c_forced |= C_NODETACH;
			break;

		case 'q':
			defconf.c_quiet = 1;
			defconf.c_forced |= C_QUIET;
			break;

		case 'r':
			printf("milter-greylist-%s %s\n", 
			    PACKAGE_VERSION, BUILD_ENV);
			exit(EX_OK);
			break;

		case 'S':
			defconf.c_nospf = 1;
			defconf.c_forced |= C_NOSPF;
			break;

		case 'u': {
			if (geteuid() != 0) {
				fprintf(stderr, "%s: only root can use -u\n", 
				    argv[0]);
				exit(EX_USAGE);
			}

			if (optarg == NULL) {
				fprintf(stderr, 
				    "%s: -u needs a valid user as argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_user = optarg;
			defconf.c_forced |= C_USER;
			break;
		}
			
		case 'v':
			defconf.c_debug = 1;
			defconf.c_forced |= C_DEBUG;
			break;

		case 'w':
			if ((optarg == NULL) || 
			    ((defconf.c_delay = humanized_atoi(optarg)) == 0)) {
				fprintf(stderr, 
				    "%s: -w needs a positive argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_forced |= C_DELAY;
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
			defconf.c_dumpfile = optarg;
			defconf.c_forced |= C_DUMPFILE;
			break;
				
		case 'P':
			if (optarg == NULL) {
				fprintf(stderr, "%s: -P needs an argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_pidfile = optarg;
			defconf.c_forced |= C_PIDFILE;
			break;

		case 'p':
			if (optarg == NULL) {
				fprintf(stderr, "%s: -p needs an argument\n",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_socket = optarg;
			defconf.c_forced |= C_SOCKET;
			break;

		case 'L': {
			int cidr;
			char maskstr[IPADDRLEN + 1];

		  	if (optarg == NULL) {
				fprintf(stderr, 
				    "%s: -L requires a CIDR mask\n", argv[0]);
				usage(argv[0]);
			}

			cidr = atoi(optarg);
			if ((cidr > 32) || (cidr < 0)) {
				fprintf(stderr, 
				    "%s: -L requires a CIDR mask\n", argv[0]);
				usage(argv[0]);
			}
			cidr2mask(cidr, &defconf.c_match_mask);
			defconf.c_forced |= C_MATCHMASK;

			if (defconf.c_debug)
				printf("match mask: %s\n", inet_ntop(AF_INET, 
				    &defconf.c_match_mask, maskstr, IPADDRLEN));

			break;
		}

		case 'T':
			defconf.c_testmode = 1;	
			defconf.c_forced |= C_TESTMODE;
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
	 * Load config file
	 */
	conf_load();

	if (conf.c_nodetach != 0)
		openlog("milter-greylist", LOG_PERROR, LOG_MAIL);
	else
		openlog("milter-greylist", 0, LOG_MAIL);

	/*
	 * Various init
	 * pending_init and autowhite_init are called in check_lockfile
	 */
	except_init();
	peer_init();
	dump_init();

	/*
	 * Check the lockfile. This is used to detect unproper shutdown,
	 * which is a synonym of DB corruption. Also used to prevent
	 * multiple launch of milter-greylist.
	 * On improper shutdwn, we reload from the text dump.
	 */
	check_lockfile();

	/*
	 * Handle the socket
	 */
	if (conf.c_socket == NULL) {
		fprintf(stderr, "%s: No socket provided, exitting\n", argv[0]);
		usage(argv[0]);
	}
	cleanup_sock(conf.c_socket);
	(void)smfi_setconn(conf.c_socket);

	/*
	 * Turn into a daemon
	 */
	if (conf.c_nodetach == 0) {

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

		if (setsid() == -1) {
			syslog(LOG_ERR, "%s: setsid failed: %s\n",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
	}

	/* 
	 * Write down our PID to a file
	 */
	if (conf.c_pidfile != NULL)
		writepid(conf.c_pidfile);

	/*
	 * Drop root privs
	 */
	if (conf.c_user != NULL) {
		struct passwd *pw = NULL;

		if ((pw = getpwnam(conf.c_user)) == NULL) {
			syslog(LOG_ERR, "%s: Cannot get user %s data: %s\n",
			    argv[0], conf.c_user, strerror(errno));
			exit(EX_OSERR);
		}

		if ((setuid(pw->pw_uid) != 0) ||
		    (seteuid(pw->pw_uid) != 0)) {
			syslog(LOG_ERR, "%s: cannot change UID: %s\n",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
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
	    "usage: %s [-ADvqST] [-a autowhite] [-d dumpfile] [-f configfile]\n"
	    "       [-w delay] [-u username] [-L cidrmask] -p socket\n", 
	    progname);
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
		if (isgraph((int)src[i]))
			dst[i] = src[i];
		else
			dst[i] = '_';
	}

	if (i < len)
		dst[i] = '\0';

	return dst;
}

int
humanized_atoi(str)	/* *str is modified */
	char *str;
{
	unsigned int unit;
	size_t len;
	char numstr[NUMLEN + 1];

	if (((len = strlen(str)) || (len > NUMLEN)) == 0)
		return 0;

	switch(str[len - 1]) {
	case 's':
		unit = 1;
		break;

	case 'm':
		unit = 60;
		break;

	case 'h':
		unit = 60 * 60;
		break;

	case 'd':
		unit = 24 * 60 * 60;
		break;

	case 'w':
		unit = 7 * 24 * 60 * 60;
		break;

	default:
		return atoi(str);
		break;
	}

	strncpy(numstr, str, NUMLEN);
	numstr[len - 1] = '\0';

	return (atoi(numstr) * unit);
}

static char *
gmtoffset(date, buf, size)
	time_t *date;
	char *buf;
	size_t size;
{
	struct tm gmt;
	struct tm local;
	int offset;
	char *sign;
	int h, mn;

	gmtime_r(date, &gmt);
	localtime_r(date, &local);

	offset = local.tm_min - gmt.tm_min;
	offset += (local.tm_hour - gmt.tm_hour) * 60;

	/* Offset cannot be greater than a day */
	if (local.tm_year <  gmt.tm_year)
		offset -= 24 * 60;
	else
		offset += (local.tm_yday - gmt.tm_yday) * 60 * 24;

	if (offset >= 0) {
		sign = "+";
	} else {
		sign = "-";
		offset = -offset;
	}
	 
	h = offset / 60;
	mn = offset % 60;

	snprintf(buf, size, "%s%02d%02d", sign, h, mn);
	return buf;
}

static void
writepid(pidfile)
	char *pidfile;
{
	FILE *stream;

	if ((stream = fopen(pidfile, "w")) == NULL) {
		syslog(LOG_ERR, "Cannot open pidfile \"%s\" for writing: %s", 
		    pidfile, strerror(errno));
		return;
	}

	fprintf(stream, "%ld\n", (long)getpid());
	fclose(stream);

	return;
}


struct in_addr *
cidr2mask(cidr, mask)
	int cidr;
	struct in_addr *mask;
{

	if ((cidr == 0) || (cidr > 32)) {
		bzero((void *)mask, sizeof(*mask));
	} else {
		cidr = 32 - cidr;
		*mask = inet_makeaddr(~((1UL << cidr) - 1), 0L);
	}
	
	return mask;
}

static void
check_lockfile(void)
{
	FILE *lockfile;
	pid_t pid;

	/* Does it exists? */
	if (access(conf.c_lockfile, F_OK) == 0) {
		if ((lockfile = fopen(conf.c_lockfile, "r+")) == NULL) {
			syslog(LOG_ERR, "Cannot open lockfile \"%s\": %s", 
			    conf.c_lockfile, strerror(errno));
			exit(EX_OSERR);
		}

		if (fscanf(lockfile, "%d\n", &pid) != 1) {
			syslog(LOG_ERR, "Corrupted lockfile \"%s\"", 
			    conf.c_lockfile);
			exit(EX_OSERR);
		}

		/* 
		 * Is milter-greylist already running?
		 */
		if (kill(pid, 0) == 0) {
			syslog(LOG_ERR, "milter-greylist already running "
			    "(pid %d)", pid);
			exit(EX_USAGE);
		}

		/* 
		 * Stale lockfile, assume the database are corrupted
		 * Remove the DB databases
		 * Reload from the text dump.
		 * Register atexit callback
		 * Create a lockfile
		 */

		syslog(LOG_ERR, "Database is not clean, reloading text dump");

		if ((access(conf.c_greylistdb, F_OK) == 0) &&
		    (unlink(conf.c_greylistdb) != 0)) {
			syslog(LOG_ERR, "unlink \"%s\" failed",
			    conf.c_greylistdb);
			exit(EX_USAGE);
		}

		if ((access(conf.c_autowhitedb, F_OK) == 0) &&
		    (unlink(conf.c_autowhitedb) != 0)) {
			syslog(LOG_ERR, "unlink \"%s\" failed",
			    conf.c_autowhitedb);
			exit(EX_USAGE);
		}

		pending_init();
		autowhite_init();
		
		dump_reload();

		if (atexit(*rmlockfile) != 0) {
			syslog(LOG_ERR, "atexit failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
			
		fseek(lockfile, 0, SEEK_SET);
		ftruncate(fileno(lockfile), 0);
		fprintf(lockfile, "%d\n", getpid());
		fclose(lockfile);

		return;
	}
			
	/* 
	 * No lockfile, shutdown was done properly
	 * Register the exit callback
	 * Create the lockfile
	 */
	if (atexit(*rmlockfile) != 0) {
		syslog(LOG_ERR, "atexit failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((lockfile = fopen(conf.c_lockfile, "w")) == NULL) {
		syslog(LOG_ERR, "Cannot open lockfile \"%s\": %s", 
		    conf.c_lockfile, strerror(errno));
		exit(EX_OSERR);
	}
	fprintf(lockfile, "%d\n", getpid());
	fclose(lockfile);

	pending_init();
	autowhite_init();

	return;
}

void
rmlockfile(void) {

	syslog(LOG_INFO, "shutting down");

	if (aw_db != NULL)
		aw_db->close(aw_db);

	if (pending_db != NULL)
		pending_db->close(pending_db);

	if (unlink(conf.c_lockfile) != 0) 
		syslog(LOG_ERR, "Cannot unlink lockfile \"%s\": %s", 
		    conf.c_lockfile, strerror(errno));;

	return;
}
