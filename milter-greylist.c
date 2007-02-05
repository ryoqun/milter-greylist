/* $Id: milter-greylist.c,v 1.165 2007/02/05 06:06:26 manu Exp $ */

/*
 * Copyright (c) 2004-2007 Emmanuel Dreyfus
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
__RCSID("$Id: milter-greylist.c,v 1.165 2007/02/05 06:06:26 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>

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

#ifdef USE_DRAC
#ifdef USE_DB185_EMULATION
#include <db_185.h>
#else
#include <db.h>
#endif
static int check_drac(char *dotted_ip);
#endif

#include <libmilter/mfapi.h>

#include "dump.h"
#include "acl.h"
#include "list.h"
#include "conf.h"
#include "pending.h"
#include "sync.h"
#include "spf.h"
#include "autowhite.h"
#include "stat.h"
#include "milter-greylist.h"
#ifdef USE_DNSRBL
#include "dnsrbl.h"
#endif
#ifdef USE_CURL
#include "urlcheck.h"
#endif
#ifdef USE_GEOIP
#include "geoip.h"
#endif
#include "macro.h"

static char *gmtoffset(time_t *, char *, size_t);
static void writepid(char *);
static void log_and_report_greylisting(SMFICTX *, struct mlfi_priv *, char *);
static void reset_acl_values(struct mlfi_priv *);
static void add_recipient(struct mlfi_priv *, char *);
#ifndef USE_POSTFIX
static char *local_ipstr(struct mlfi_priv *);
#endif

static sfsistat real_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat real_helo(SMFICTX *, char *);
static sfsistat real_envfrom(SMFICTX *, char **);
static sfsistat real_envrcpt(SMFICTX *, char **);
static sfsistat real_header(SMFICTX *, char *, char *);
static sfsistat real_body(SMFICTX *, unsigned char *, size_t);
static sfsistat real_eom(SMFICTX *);
static sfsistat real_close(SMFICTX *);

struct smfiDesc smfilter =
{
	"greylist",	/* filter name */
	SMFI_VERSION,	/* version code */
	SMFIF_ADDHDRS,	/* flags */
	mlfi_connect,	/* connection info filter */
	MLFI_HELO,	/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	mlfi_header,	/* header filter */
	NULL,		/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	NULL,		/* message aborted */
	mlfi_close,	/* connection cleanup */
};

static int nodetach = 0;

sfsistat
mlfi_connect(ctx, hostname, addr)
	SMFICTX *ctx;
	char *hostname;
	_SOCK_ADDR *addr;
{
	sfsistat r;

	conf_retain();
	r = real_connect(ctx, hostname, addr);
	conf_release();
	return r;
}

sfsistat
mlfi_helo(ctx, helostr)
	SMFICTX *ctx;
	char *helostr;
{
	sfsistat r;

	conf_retain();
	r = real_helo(ctx, helostr);
	conf_release();
	return r;
}

sfsistat
mlfi_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	sfsistat r;

	/*
	 * Reload the config file if it has been touched
	 */
	conf_update();
	conf_retain();
	r = real_envfrom(ctx, envfrom);
	conf_release();
	return r;
}

sfsistat
mlfi_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	sfsistat r;

	conf_retain();
	r = real_envrcpt(ctx, envrcpt);
	conf_release();
	return r;
}

sfsistat
mlfi_header(ctx, header, value)
	SMFICTX *ctx;
	char *header;
	char *value;
{
	sfsistat r;

	conf_retain();
	r = real_header(ctx, header, value);
	conf_release();
	return r;
}

sfsistat
mlfi_body(ctx, chunk, size)
	SMFICTX *ctx;
	unsigned char *chunk;
	size_t size;
{
	sfsistat r;

	conf_retain();
	r = real_body(ctx, chunk, size);
	conf_release();
	return r;
}

sfsistat
mlfi_eom(ctx)
	SMFICTX *ctx;
{
	sfsistat r;

	conf_retain();
	r = real_eom(ctx);
	conf_release();
	return r;
}

sfsistat
mlfi_close(ctx)
	SMFICTX *ctx;
{
	sfsistat r;

	conf_retain();
	r = real_close(ctx);
	conf_release();
	return r;
}

static sfsistat
real_connect(ctx, hostname, addr)
	SMFICTX *ctx;
	char *hostname;
	_SOCK_ADDR *addr;
{
	struct mlfi_priv *priv;

	if ((priv = malloc(sizeof(*priv))) == NULL)
		return SMFIS_TEMPFAIL;	

	smfi_setpriv(ctx, priv);
	bzero((void *)priv, sizeof(*priv));
	priv->priv_ctx = ctx;
	priv->priv_sr.sr_whitelist = EXF_UNSET;
	priv->priv_sr.sr_retcode = -1;
	priv->priv_sr.sr_nmatch = 0;
	priv->priv_sr.sr_pmatch = NULL;
	LIST_INIT(&priv->priv_rcpt);
	priv->priv_cur_rcpt = NULL;
	priv->priv_rcptcount = 0;
	TAILQ_INIT(&priv->priv_header);
	TAILQ_INIT(&priv->priv_body);
	priv->priv_msgcount = 0;
	priv->priv_buf = NULL;
	priv->priv_buflen = 0;

	strncpy(priv->priv_hostname, hostname, ADDRLEN);
	priv->priv_hostname[ADDRLEN] = '\0';

	if (addr != NULL) {
		switch (addr->sa_family) {
		case AF_INET:
			priv->priv_addrlen = sizeof(struct sockaddr_in);
			memcpy(&priv->priv_addr, addr, priv->priv_addrlen);
#ifdef HAVE_SA_LEN
			/* XXX: sendmail doesn't set sa_len */
			SA4(&priv->priv_addr)->sin_len = priv->priv_addrlen;
#endif
			break;
#ifdef AF_INET6
		case AF_INET6:
			priv->priv_addrlen = sizeof(struct sockaddr_in6);
			memcpy(&priv->priv_addr, addr, priv->priv_addrlen);
#ifdef SIN6_LEN
			/* XXX: sendmail doesn't set sa_len */
			SA6(&priv->priv_addr)->sin6_len = priv->priv_addrlen;
#endif
			unmappedaddr(SA(&priv->priv_addr),
			    &priv->priv_addrlen);
			break;
#endif
		default:
			priv->priv_sr.sr_elapsed = 0;
			priv->priv_sr.sr_whitelist = 
			    EXF_WHITELIST | EXF_NONIP;
			break;
		}
	} else {
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_NONIP;
	}

#ifdef USE_GEOIP
	geoip_set_ccode(priv);
#endif
	return SMFIS_CONTINUE;
}

static sfsistat
real_helo(ctx, helostr)
	SMFICTX *ctx;
	char *helostr;
{
	struct mlfi_priv *priv;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

#if (defined(HAVE_SPF) || defined(HAVE_SPF_ALT) || \
     defined(HAVE_SPF2_10) || defined(HAVE_SPF2)) 
	strncpy_rmsp(priv->priv_helo, helostr, ADDRLEN);
	priv->priv_helo[ADDRLEN] = '\0';
#endif

	return SMFIS_CONTINUE;
}


static sfsistat
real_envfrom(ctx, envfrom)
	SMFICTX *ctx;
	char **envfrom;
{
	char tmpfrom[ADDRLEN + 1];
	char *idx;
	struct mlfi_priv *priv;
	char *auth_authen;
	char *verify;
	char *cert_subject;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if ((priv->priv_queueid = smfi_getsymval(ctx, "{i}")) == NULL) {
#ifndef USE_POSTFIX
		/* 
		 * Postfix does not choose a queue file name 
		 * until after it accepts the first valid RCPT TO 
		 * command, so don't log the failure 
		 */
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {i}");
#endif
		priv->priv_queueid = "(unknown id)";
	}

	/*
	 * Strip spaces from the source address
	 */
	strncpy_rmsp(tmpfrom, *envfrom, ADDRLEN);
	tmpfrom[ADDRLEN] = '\0';

	/* 
	 * Strip anything before the last '=' in the
	 * source address. This avoid problems with
	 * mailing lists using a unique sender address
	 * for each retry.
	 */
	if ((idx = rindex(tmpfrom, '=')) == NULL)
		idx = tmpfrom;

	strncpy(priv->priv_from, idx, ADDRLEN);
	priv->priv_from[ADDRLEN] = '\0';

	/*
	 * Is the sender non-IP?
	 */
	if (priv->priv_sr.sr_whitelist & EXF_NONIP)
		return SMFIS_CONTINUE;

	/*
	 * Is the user authenticated?
	 */
	if ((conf.c_noauth == 0) &&
	    ((auth_authen = smfi_getsymval(ctx, "{auth_authen}")) != NULL)) {
		mg_log(LOG_DEBUG, 
		    "User %s authenticated, bypassing greylisting", 
		    auth_authen);
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_AUTH;

		return SMFIS_CONTINUE;
	} 

	/* 
	 * STARTTLS authentication?
	 */
	if ((conf.c_noauth == 0) &&
	    ((verify = smfi_getsymval(ctx, "{verify}")) != NULL) &&
	    (strcmp(verify, "OK") == 0) &&
	    ((cert_subject = smfi_getsymval(ctx, "{cert_subject}")) != NULL)) {
		mg_log(LOG_DEBUG, 
		    "STARTTLS succeeded for DN=\"%s\", bypassing greylisting", 
		    cert_subject);
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_STARTTLS;

		return SMFIS_CONTINUE;
	}

	/*
	 * Is the sender address SPF-compliant?
	 */
	if ((conf.c_nospf == 0) && (SPF_CHECK(priv) != EXF_NONE)) {
		char ipstr[IPADDRSTRLEN];

		if (iptostring(SA(&priv->priv_addr),
		    priv->priv_addrlen, ipstr, sizeof(ipstr))) {

			mg_log(LOG_DEBUG, 
			    "Sender IP %s and address %s are SPF-compliant, "
			    "bypassing greylist", ipstr, *envfrom);
		}

		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_SPF;

		return SMFIS_CONTINUE;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
real_envrcpt(ctx, envrcpt)
	SMFICTX *ctx;
	char **envrcpt;
{
	struct mlfi_priv *priv;
	time_t remaining;
	char *greylist;
	char addrstr[IPADDRSTRLEN];
	char rcpt[ADDRLEN + 1];

	/*
	 * Strip spaces from the recipient address
	 */
	strncpy_rmsp(rcpt, *envrcpt, ADDRLEN);
	rcpt[ADDRLEN] = '\0';

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	if (!iptostring(SA(&priv->priv_addr), priv->priv_addrlen, addrstr,
	    sizeof(addrstr)))
		goto exit_accept;

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: addr = %s[%s], from = %s, rcpt = %s", 
		    priv->priv_queueid, priv->priv_hostname, 
		    addrstr, priv->priv_from, *envrcpt);

	/*
	 * For multiple-recipients messages, if the sender IP or the
	 * sender e-mail address is whitelisted, authenticated, or
	 * SPF compliant, then there is no need to check again, 
	 * it is whitelisted for all the recipients.
	 * 
	 * Moreover, this will prevent a wrong X-Greylist header display
	 * if the {IP, sender e-mail} address was whitelisted and the
	 * last recipient was also whitelisted. If we would set 
	 * priv_sr.sr_whitelist on the last recipient, all recipient 
	 * would have a X-Greylist header explaining that they were 
	 * whitelisted, whereas some of them would not.
	 */
	if ((priv->priv_sr.sr_whitelist & EXF_ADDR) ||
	    (priv->priv_sr.sr_whitelist & EXF_DOMAIN) ||
	    (priv->priv_sr.sr_whitelist & EXF_FROM) ||
	    (priv->priv_sr.sr_whitelist & EXF_AUTH) ||
	    (priv->priv_sr.sr_whitelist & EXF_SPF) ||
	    (priv->priv_sr.sr_whitelist & EXF_NONIP) ||
	    (priv->priv_sr.sr_whitelist & EXF_DRAC) ||
	    (priv->priv_sr.sr_whitelist & EXF_ACCESSDB) ||
	    (priv->priv_sr.sr_whitelist & EXF_MACRO) ||
	    (priv->priv_sr.sr_whitelist & EXF_STARTTLS))
		goto exit_accept;

#ifdef USE_DRAC
	if ((SA(&priv->priv_addr)->sa_family == AF_INET) && 
	    (conf.c_nodrac == 0) &&
	    check_drac(addrstr)) {
		mg_log(LOG_DEBUG, "whitelisted by DRAC");
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_DRAC;

		goto exit_accept;
	}
#endif

	 /*
	  * If sendmail rules have defined a ${greylist} macro
	  * with value WHITE, then it is whitelisted
	  */
	if ((conf.c_noaccessdb == 0) &&
	    ((greylist = smfi_getsymval(ctx, "{greylist}")) != NULL) &&
	    (strcmp(greylist, "WHITE") == 0)) {
		mg_log(LOG_DEBUG, 
		    "whitelisted by {greylist}");
		priv->priv_sr.sr_elapsed = 0;
		priv->priv_sr.sr_whitelist = EXF_ACCESSDB;
 
		goto exit_accept;
	}

	/* 
	 * Restart the sync master thread if nescessary
	 */
	sync_master_restart();

	/*
	 * Check the ACL
	 */
	reset_acl_values(priv);
	priv->priv_cur_rcpt = rcpt;
	acl_filter(AS_RCPT, ctx, priv);
	if (priv->priv_sr.sr_whitelist & EXF_WHITELIST) {
		priv->priv_sr.sr_elapsed = 0;
		goto exit_accept;
	}

	/* 
	 * Blacklist overrides autowhitelisting...
	 */
	if (priv->priv_sr.sr_whitelist & EXF_BLACKLIST) {
		char aclstr[16];
		char *code = "551";
		char *ecode = "5.7.1";
		char *msg;

		if (priv->priv_sr.sr_acl_line != 0)
			snprintf(aclstr, sizeof(aclstr), " (ACL %d)", 
			    priv->priv_sr.sr_acl_line);

		mg_log(LOG_INFO, 
		    "%s: addr %s[%s] from %s to %s blacklisted%s",
		    priv->priv_queueid, priv->priv_hostname, addrstr, 
		    priv->priv_from, rcpt, aclstr);

		code = (priv->priv_sr.sr_code) ? 
		    priv->priv_sr.sr_code : code;
		ecode = (priv->priv_sr.sr_ecode) ? 
		    priv->priv_sr.sr_ecode : ecode;
		msg =  (priv->priv_sr.sr_msg) ?
		    priv->priv_sr.sr_msg : "Go away!";

		msg = fstring_expand(priv, rcpt, msg);

		(void)smfi_setreply(ctx, code, ecode, msg);

		free(msg);

		return mg_stat(priv,
		    *code == '4' ? SMFIS_TEMPFAIL : SMFIS_REJECT);
	}

	/* 
	 * Check if the tuple {sender IP, sender e-mail, recipient e-mail}
	 * was autowhitelisted
	 */
	priv->priv_sr.sr_whitelist = autowhite_check(SA(&priv->priv_addr),
	    priv->priv_addrlen, priv->priv_from, rcpt, priv->priv_queueid,
	    priv->priv_sr.sr_delay, priv->priv_sr.sr_autowhite);

	if (priv->priv_sr.sr_whitelist != EXF_NONE) {
		priv->priv_sr.sr_elapsed = 0;
		goto exit_accept;
	}

	/*
	 * On a multi-recipient message, one message can be whitelisted,
	 * and the next ones be greylisted. The first one would
	 * pass through immediatly (priv->priv_sr.sr_delay = 0) with a 
	 * priv->priv_sr.sr_whitelist = EXF_NONE. This would cause improper
	 * X-Greylist header display in mlfi_eom()
	 *
	 * The fix: if we make it to mlfi_eom() with priv_sr.sr_elapsed = 0
	 * this means that some recipients were whitelisted. 
	 * We can set priv_sr.sr_whitelist now, because if the message 
	 * is greylisted for everyone, it will not go to mlfi_eom(), 
	 * and priv_sr.sr_whitelist will not be used.
	 */
	priv->priv_sr.sr_whitelist = EXF_WHITELIST | EXF_RCPT;

	/*
	 * Check if the tuple {sender IP, sender e-mail, recipient e-mail}
	 * is in the greylist and if it ca now be accepted. If it is not
	 * in the greylist, it will be added.
	 */
	if (pending_check(SA(&priv->priv_addr), priv->priv_addrlen,
	    priv->priv_from, rcpt, &remaining, &priv->priv_sr.sr_elapsed,
	    priv->priv_queueid, priv->priv_sr.sr_delay, 
	    priv->priv_sr.sr_autowhite) != 0)
		goto exit_accept;

	priv->priv_sr.sr_remaining = remaining;

	/*
	 * The message has been added to the greylist and will be delayed.
	 * If the sender address is null, this will be done after the DATA
	 * phase, otherwise immediately.
	 * Delayed reject with per-recipient delays or messages 
	 * will use the last match.
	 */
	if ((conf.c_delayedreject == 1) && 
	    (strcmp(priv->priv_from, "<>") == 0)) {
		priv->priv_delayed_reject = 1;
		add_recipient(priv, rcpt);
		goto exit_accept;
	}

	/*
	 * Log temporary failure and report to the client.
	 */
	log_and_report_greylisting(ctx, priv, *envrcpt);
	return mg_stat(priv, SMFIS_TEMPFAIL);

exit_accept:
	add_recipient(priv, rcpt);
	return SMFIS_CONTINUE;
}

static sfsistat
real_header(ctx, name, value)
	SMFICTX *ctx;
	char *name;
	char *value;
{
	struct header *h;
	struct mlfi_priv *priv;
	const char sep[] = ": ";
	const char crlf[] = "\r\n";
	size_t len;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	len = strlen(name) + strlen(sep) + strlen(value) + strlen(crlf);
	priv->priv_msgcount += len;

	if (priv->priv_msgcount > conf.c_maxpeek) {
		mg_log(LOG_DEBUG, "ignoring message beyond maxpeek = %d", 
		    conf.c_maxpeek);
		return SMFIS_CONTINUE;
	}

	if ((h = malloc(sizeof(*h))) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	len = strlen(name) + strlen(sep) + strlen(value) + strlen(crlf);
	if ((h->h_line = malloc(len + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	h->h_line[0] = '\0';
	strcat(h->h_line, name);
	strcat(h->h_line, sep);
	strcat(h->h_line, value);
	strcat(h->h_line, crlf);

	TAILQ_INSERT_TAIL(&priv->priv_header, h, h_list);

	return SMFIS_CONTINUE;
}


static sfsistat
real_body(ctx, chunk, size)
	SMFICTX *ctx;
	unsigned char *chunk;
	size_t size;
{
	struct mlfi_priv *priv;
	struct body *b;
	size_t linelen;
	int i;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);

	/* Avoid copying the whole message to save CPU */
	if ((priv->priv_msgcount > conf.c_maxpeek) || 
	    (priv->priv_buflen > conf.c_maxpeek)) {
		priv->priv_msgcount += size;
		mg_log(LOG_DEBUG, "ignoring message beyond maxpeek = %d", 
		    conf.c_maxpeek);
		return SMFIS_CONTINUE;
	}

	/* First time: add \r\n between headers and body */
	if (TAILQ_EMPTY(&priv->priv_body) && (priv->priv_buflen == 0)) {
		const char crlf[] = "\r\n";

		if ((b = malloc(sizeof(*b))) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		if ((b->b_lines = strdup(crlf)) == NULL) {
			mg_log(LOG_ERR, "strdup() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		TAILQ_INSERT_TAIL(&priv->priv_body, b, b_list);

		priv->priv_msgcount += strlen(crlf);
	}


	for (i = size - 1; i >= 0; i--) {
		if (chunk[i] == '\n')
			break;
	}

	if (chunk[i] == '\n') { /* We have a newline */
		if ((b = malloc(sizeof(*b))) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
	
		i++; /* Include the \n in this chunk */
		linelen = priv->priv_buflen + i;

		if ((b->b_lines = malloc(linelen + 1)) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		/* Gather data saved from a previous call */
		if (priv->priv_buf) {
			memcpy(b->b_lines, priv->priv_buf, priv->priv_buflen);
			free(priv->priv_buf);
			priv->priv_buf = NULL;
		}
		memcpy(b->b_lines + priv->priv_buflen, chunk, i + 1);
		b->b_lines[linelen] = '\0';
		priv->priv_buflen = 0;

		TAILQ_INSERT_TAIL(&priv->priv_body, b, b_list);

		priv->priv_msgcount += linelen;
	} else { /* No newline in chunk, keep it for later */
		if ((priv->priv_buf = realloc(priv->priv_buf, 
		    priv->priv_buflen + size)) == NULL) {
			mg_log(LOG_ERR, 
			    "realloc() failed: %s", 
			    strerror(errno));
			exit(EX_OSERR);
		}
		memcpy(&priv->priv_buf[priv->priv_buflen], chunk, size);
		priv->priv_buflen += size;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
real_eom(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;
	char *hdrstr;
	char whystr [HDRLEN + 1];
	struct smtp_reply rcpt_sr;
	struct rcpt *rcpt;

	priv = (struct mlfi_priv *) smfi_getpriv(ctx);
	priv->priv_cur_rcpt = NULL; /* There is no current recipient */

	/* 
	 * If we got no newline at all, at least 
	 * we can save the current buffer 
	 */
	if (TAILQ_EMPTY(&priv->priv_body) && (priv->priv_buflen > 0)) {
		struct body *b;

		if ((b = malloc(sizeof(*b))) == NULL) {
			mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		b->b_lines = priv->priv_buf;
		b->b_lines[priv->priv_buflen - 1] = '\0';

		priv->priv_buf = NULL;
		priv->priv_buflen = 0;

		TAILQ_INSERT_TAIL(&priv->priv_body, b, b_list);
	}

	if (priv->priv_delayed_reject) {
		LIST_FOREACH(rcpt, &priv->priv_rcpt, r_list) 
			log_and_report_greylisting(ctx, priv, rcpt->r_addr);
		return mg_stat(priv, SMFIS_TEMPFAIL);
	}

	/* 
	 * Check DATA-stage ACL. This can only cause blacklist or whitelist
	 * action. 
	 * We save data obtained from RCPT and we will restore it afterward
	 */
	memcpy(&rcpt_sr, &priv->priv_sr, sizeof(rcpt_sr));
	acl_filter(AS_DATA, ctx, priv);
	if (priv->priv_sr.sr_whitelist & EXF_BLACKLIST) {
		char aclstr[16];
		char addrstr[IPADDRSTRLEN];
		char *code = "551";
		char *ecode = "5.7.1";
		char *msg;

		if (priv->priv_sr.sr_acl_line != 0)
			snprintf(aclstr, sizeof(aclstr), " (ACL %d)", 
			    priv->priv_sr.sr_acl_line);

		mg_log(LOG_INFO, 
		    "%s: addr %s[%s] from %s blacklisted%s",
		    priv->priv_queueid, priv->priv_hostname, addrstr, 
		    priv->priv_from, aclstr);

		code = (priv->priv_sr.sr_code) ? 
		    priv->priv_sr.sr_code : code;
		ecode = (priv->priv_sr.sr_ecode) ? 
		    priv->priv_sr.sr_ecode : ecode;
		msg =  (priv->priv_sr.sr_msg) ?
		    priv->priv_sr.sr_msg : "Go away!";

		msg = fstring_expand(priv, NULL, msg);

		(void)smfi_setreply(ctx, code, ecode, msg);

		free(msg);

		return mg_stat(priv, 
		    *code == '4' ? SMFIS_TEMPFAIL : SMFIS_REJECT);
	}

	/* Restore the info collected from RCPT stage */
	memcpy(&priv->priv_sr, &rcpt_sr, sizeof(rcpt_sr));

	if (priv->priv_sr.sr_elapsed == 0) {
		if ((conf.c_report & C_NODELAYS) == 0)
			goto out;
			

		if (priv->priv_sr.sr_report) {
			hdrstr = fstring_expand(priv, 
			    NULL, priv->priv_sr.sr_report);
		} else {
			whystr[0] = '\0';
			if (priv->priv_sr.sr_whitelist & EXF_DOMAIN) {
				ADD_REASON(whystr, 
				    "Sender DNS name whitelisted");
				priv->priv_sr.sr_whitelist &= ~EXF_DOMAIN;
			}
			if (priv->priv_sr.sr_whitelist & EXF_ADDR) {
				ADD_REASON(whystr, 
				    "Sender IP whitelisted");
				priv->priv_sr.sr_whitelist &= ~EXF_ADDR;
			}
			if (priv->priv_sr.sr_whitelist & EXF_FROM) {
				ADD_REASON(whystr, 
				    "Sender e-mail whitelisted");
				priv->priv_sr.sr_whitelist &= ~EXF_FROM;
			}
			if (priv->priv_sr.sr_whitelist & EXF_AUTH) {
				ADD_REASON(whystr, 
				    "Sender succeeded SMTP AUTH");
				priv->priv_sr.sr_whitelist &= ~EXF_AUTH;
			}
			if (priv->priv_sr.sr_whitelist & EXF_ACCESSDB) {
				ADD_REASON(whystr, 
				    "Message whitelisted by Sendmail "
				    "access database");
				priv->priv_sr.sr_whitelist &= ~EXF_ACCESSDB;
			}
			if (priv->priv_sr.sr_whitelist & EXF_DRAC) {
				ADD_REASON(whystr, 
				    "Message whitelisted by DRAC "
				    "access database");
				priv->priv_sr.sr_whitelist &= ~EXF_DRAC;
			}
			if (priv->priv_sr.sr_whitelist & EXF_SPF) {
				ADD_REASON(whystr, "Sender is SPF-compliant");
				priv->priv_sr.sr_whitelist &= ~EXF_SPF;
			}
			if (priv->priv_sr.sr_whitelist & EXF_NONIP) {
#ifdef AF_INET6
				ADD_REASON(whystr, 
				    "Message not sent from an IPv4 "
				    "neither IPv6 address");
#else
				ADD_REASON(whystr, 
				    "Message not sent from an IPv4 address");
#endif
				priv->priv_sr.sr_whitelist &= ~EXF_NONIP;
			}
			if (priv->priv_sr.sr_whitelist & EXF_STARTTLS) {
				ADD_REASON(whystr, 
				    "Sender succeeded STARTTLS authentication");
				priv->priv_sr.sr_whitelist &= ~EXF_STARTTLS;
			}
			if (priv->priv_sr.sr_whitelist & EXF_RCPT) {
				ADD_REASON(whystr, 
				    "Recipient e-mail whitelisted");
				priv->priv_sr.sr_whitelist &= ~EXF_RCPT;
			}
			if (priv->priv_sr.sr_whitelist & EXF_AUTO) {
				ADD_REASON(whystr, 
				    "IP, sender and "
				    "recipient auto-whitelisted");
				priv->priv_sr.sr_whitelist &= ~EXF_AUTO;
			}
			if (priv->priv_sr.sr_whitelist & EXF_DNSRBL) {
				ADD_REASON(whystr, 
				    "Sender IP whitelisted by DNSRBL");
				priv->priv_sr.sr_whitelist &= ~EXF_DNSRBL;
			}
			if (priv->priv_sr.sr_whitelist & EXF_URLCHECK) {
				ADD_REASON(whystr, "URL check passed");
				priv->priv_sr.sr_whitelist &= ~EXF_URLCHECK;
			}
			if (priv->priv_sr.sr_whitelist & EXF_DEFAULT) {
				ADD_REASON(whystr, 
				    "Default is to whitelist mail");
				priv->priv_sr.sr_whitelist &= ~EXF_DEFAULT;
			}
			priv->priv_sr.sr_whitelist &= 
			    ~(EXF_GREYLIST | EXF_WHITELIST);
			if (priv->priv_sr.sr_whitelist != 0) {
				mg_log(LOG_ERR, 
				    "%s: unexpected priv_sr.sr_whitelist = %d",
				    priv->priv_queueid, 
				    priv->priv_sr.sr_whitelist);
				mystrlcat (whystr, "Internal error ", HDRLEN);
			}

			mystrlcat (whystr, ", not delayed by %V", HDRLEN);
			hdrstr = fstring_expand(priv, NULL, whystr);
		}

		smfi_addheader(ctx, HEADERNAME, hdrstr);

		free(hdrstr);

		goto out;
	}


	if (conf.c_report & C_DELAYS) {
		char *hdrstr;

		if (priv->priv_sr.sr_report)
			hdrstr = fstring_expand(priv, 
			    NULL, priv->priv_sr.sr_report);
		else
			hdrstr = fstring_expand(priv, 
			    NULL, "Delayed for %E by %V");

		smfi_addheader(ctx, HEADERNAME, hdrstr);

		free(hdrstr);
	}

out:
	return mg_stat(priv, SMFIS_CONTINUE);
}

static sfsistat
real_close(ctx)
	SMFICTX *ctx;
{
	struct mlfi_priv *priv;
	struct rcpt *r;
	struct header *h;
	struct body *b;

	if ((priv = (struct mlfi_priv *) smfi_getpriv(ctx)) != NULL) {
		if (priv->priv_sr.sr_code)
			free(priv->priv_sr.sr_code);
		if (priv->priv_sr.sr_ecode)
			free(priv->priv_sr.sr_ecode);
		if (priv->priv_sr.sr_msg)
			free(priv->priv_sr.sr_msg);
		if (priv->priv_sr.sr_report)
			free(priv->priv_sr.sr_report);

		if (priv->priv_sr.sr_pmatch) {
			int i;		

			for (i = 0; i < priv->priv_sr.sr_nmatch; i++)
				if (priv->priv_sr.sr_pmatch[i] != NULL)
					free(priv->priv_sr.sr_pmatch[i]);
			free(priv->priv_sr.sr_pmatch);
		}

		while ((r = LIST_FIRST(&priv->priv_rcpt)) != NULL) {
			LIST_REMOVE(r, r_list);
			free(r);
		}
		while ((h = TAILQ_FIRST(&priv->priv_header)) != NULL) {
			free(h->h_line);
			TAILQ_REMOVE(&priv->priv_header, h,  h_list);
			free(h);
		}
		while ((b = TAILQ_FIRST(&priv->priv_body)) != NULL) {
			free(b->b_lines);
			TAILQ_REMOVE(&priv->priv_body, b, b_list);
			free(b);
		}
		if (priv->priv_buf)
			free(priv->priv_buf);
		free(priv);
		smfi_setpriv(ctx, NULL);
	}

	/*
	 * If we need to dump on each change and something changed, dump
	 */
	dump_flush();

	return SMFIS_CONTINUE;
}



int
main(argc, argv)
	int argc;
	char *argv[];
{
	int ch;
	int checkonly = 0;
	int exitval;
	sigset_t set;

	/*
	 * Load configuration defaults
	 */
	conf_defaults(&defconf);

	/* 
	 * Process command line options 
	 */
	while ((ch = getopt(argc, argv, "Aa:cvDd:qw:f:hp:P:Tu:rSL:M:l")) != -1) {
		switch (ch) {
		case 'A':
			defconf.c_noauth = 1;
			defconf.c_forced |= C_NOAUTH;
			break;

		case 'a':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -a needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_autowhite_validity = 
			    (time_t)humanized_atoi(optarg);
			defconf.c_forced |= C_AUTOWHITE;
			break;
		case 'c':
		        checkonly = 1;
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
			mg_log(LOG_INFO, "milter-greylist-%s %s", 
			    PACKAGE_VERSION, BUILD_ENV);
			exit(EX_OK);
			break;

		case 'S':
			defconf.c_nospf = 1;
			defconf.c_forced |= C_NOSPF;
			break;

		case 'u': {
			if (geteuid() != 0) {
				mg_log(LOG_ERR, "%s: only root can use -u", 
				    argv[0]);
				exit(EX_USAGE);
			}

			if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -u needs a valid user as argument",
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
				mg_log(LOG_ERR,
				    "%s: -w needs a positive argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_forced |= C_DELAY;
			break;

		case 'f':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -f needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			conffile = optarg;
			break;

		case 'd':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -d needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_dumpfile = optarg;
			defconf.c_forced |= C_DUMPFILE;
			break;
				
		case 'P':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -P needs an argument",
				    argv[0]);
				usage(argv[0]);
			}
			defconf.c_pidfile = optarg;
			defconf.c_forced |= C_PIDFILE;
			break;

		case 'p':
			if (optarg == NULL) {
				mg_log(LOG_ERR, "%s: -p needs an argument",
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
				mg_log(LOG_ERR,
				    "%s: -L requires a CIDR mask", argv[0]);
				usage(argv[0]);
			}

			cidr = atoi(optarg);
			if ((cidr > 32) || (cidr < 0)) {
				mg_log(LOG_ERR,
				    "%s: -L requires a CIDR mask", argv[0]);
				usage(argv[0]);
			}
			prefix2mask4(cidr, &defconf.c_match_mask);
			defconf.c_forced |= C_MATCHMASK;

			if (defconf.c_debug)
				mg_log(LOG_DEBUG, "match mask: %s", 
				    inet_ntop(AF_INET, &defconf.c_match_mask, 
				    maskstr, IPADDRLEN));

			break;
		}

		case 'M': {
			int plen;
#ifdef AF_INET6
			char maskstr[INET6_ADDRSTRLEN + 1];
#endif

		  	if (optarg == NULL) {
				mg_log(LOG_ERR,
				    "%s: -M requires a prefix length",
				    argv[0]);
				usage(argv[0]);
			}

			plen = atoi(optarg);
			if ((plen > 128) || (plen < 0)) {
				mg_log(LOG_ERR,
				    "%s: -M requires a prefix length",
				    argv[0]);
				usage(argv[0]);
			}
#ifdef AF_INET6
			prefix2mask6(plen, &defconf.c_match_mask6);
			defconf.c_forced |= C_MATCHMASK6;

			if (defconf.c_debug)
				mg_log(LOG_DEBUG, "match mask: %s", 
				    inet_ntop(AF_INET6, &defconf.c_match_mask6,
				    maskstr, INET6_ADDRSTRLEN));

#endif
			break;
		}

		case 'T':
			defconf.c_testmode = 1;	
			defconf.c_forced |= C_TESTMODE;
			break;

		case 'l':
			defconf.c_acldebug = 1;
			defconf.c_forced |= C_ACLDEBUG;
			break;

		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}
	
	/*
	 * Various init
	 */
	tzset();
	conf_init();
	all_list_init();
	acl_init ();
	pending_init();
	peer_init();
	autowhite_init();
	dump_init();
#ifdef USE_DNSRBL
	dnsrbl_init();
#endif
#ifdef USE_CURL
	urlcheck_init();
#endif
	macro_init();

	/*
	 * Load config file
	 * We can do this without locking exceptlist, as
	 * normal operation has not started: no other thread
	 * can access the list yet.
	 */
	conf_load();
	if (checkonly) {
		mg_log(LOG_INFO, "config file \"%s\" is okay", conffile);
		exit(EX_OK);
	}
	conf_retain();
	nodetach = conf.c_nodetach;

	openlog("milter-greylist", 0, LOG_MAIL);
	conf_cold = 0;
	
	if (conf.c_socket == NULL) {
		mg_log(LOG_ERR, "%s: No socket provided, exiting", argv[0]);
		usage(argv[0]);
	}
	cleanup_sock(conf.c_socket);
	(void)smfi_setconn(conf.c_socket);

	/*
	 * Reload a saved greylist
	 * No lock needed here either.
	 */
	dump_reload();

	/*
	 * If no body/header search exists, don't install the hooks,
	 * it will improve performance a lot.
	 */
	if (conf.c_maxpeek == 0) {
		smfilter.xxfi_header = NULL;
		smfilter.xxfi_body = NULL;
	}

	/* 
	 * Register our callbacks 
	 */
	if (smfi_register(smfilter) == MI_FAILURE) {
		mg_log(LOG_ERR, "%s: smfi_register failed", argv[0]);
		exit(EX_UNAVAILABLE);
	}

	/*
	 * Turn into a daemon
	 */
	if (conf.c_nodetach == 0) {

		(void)close(0);
		(void)open("/dev/null", O_RDONLY, 0);
		(void)close(1);
		(void)open("/dev/null", O_WRONLY, 0);
		(void)close(2);
		(void)open("/dev/null", O_WRONLY, 0);

		if (chdir("/") != 0) {
			mg_log(LOG_ERR, "%s: cannot chdir to root: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}

		switch (fork()) {
		case -1:
			mg_log(LOG_ERR, "%s: cannot fork: %s",
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
			mg_log(LOG_ERR, "%s: setsid failed: %s",
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
		struct group *gr = NULL;
		char *c_group = NULL;

		if ((c_group = strchr(conf.c_user, ':')) != NULL)
			*c_group++ = '\0';

		if ((pw = getpwnam(conf.c_user)) == NULL) {
			mg_log(LOG_ERR, "%s: cannot get user %s data: %s",
			    argv[0], conf.c_user, strerror(errno));
			exit(EX_OSERR);
		}

		if (c_group != NULL) {
			if ((gr = getgrnam(c_group)) == NULL) {
				mg_log(LOG_ERR, "%s: cannot get group %s data: %s",
			    	argv[0], c_group, strerror(errno));
				exit(EX_OSERR);
			}
			pw->pw_gid = gr->gr_gid;
		}

#ifdef HAVE_INITGROUPS
		if (initgroups(conf.c_user, pw->pw_gid) != 0) {
		        mg_log(LOG_ERR, "%s: cannot change "
			    "supplementary groups: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
#endif

		if (setgid(pw->pw_gid) != 0 ||
		    setegid(pw->pw_gid) != 0) {
			mg_log(LOG_ERR, "%s: cannot change GID: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}


		if ((setuid(pw->pw_uid) != 0) ||
		    (seteuid(pw->pw_uid) != 0)) {
			mg_log(LOG_ERR, "%s: cannot change UID: %s",
			    argv[0], strerror(errno));
			exit(EX_OSERR);
		}
	}

	/*
	 * Block signals before all other threads start.
	 * The libmilter watches them and returns from smfi_main() if got.
	 */
	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

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
	conf_release();
	exitval = smfi_main();
	mg_log(LOG_ERR, "smfi_main() returned %d", exitval);
	
#ifdef WORKAROUND_LIBMILTER_RACE_CONDITION
	signal(SIGSEGV, SIG_IGN);
	signal(SIGBUS, SIG_IGN);
	signal(SIGABRT, SIG_IGN);
	conf_retain();
	dump_perform(1);
	conf_release();
#else
	dumper_stop();
#endif
	return exitval;
}

void
usage(progname)
	char *progname;
{
	mg_log(LOG_ERR,
	    "usage: %s [-A] [-a autowhite_delay] [-c] [-D] [-d dumpfile]",
	    progname);
	mg_log(LOG_ERR,
	    "       [-f configfile] [-h] [-l] [-q] [-r] [-S] [-T]");
	mg_log(LOG_ERR,
	    "       [-u username[:groupname]] [-v] [-w greylist_delay] [-L cidrmask]");
	mg_log(LOG_ERR,
	    "       [-M prefixlen] [-P pidfile] -p socket");
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

char *
strncpy_rmsp(dst, src, len)
	char *dst;
	char *src;
	size_t len;
{
	unsigned int i;

	for (i = 0; src[i] && (i < len); i++) {
		if (isgraph((int)(unsigned char)src[i]))
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

	/* For msgsize clauses */
	case 'k':
		unit = 1024;
		break;

	case 'M':
		unit = 1024 * 1024;
		break;

	/* Giga and beyond is probably useless... */

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
		mg_log(LOG_ERR, "Cannot open pidfile \"%s\" for writing: %s", 
		    pidfile, strerror(errno));
		return;
	}

	fprintf(stream, "%ld\n", (long)getpid());
	fclose(stream);

	return;
}


struct in_addr *
prefix2mask4(cidr, mask)
	int cidr;
	struct in_addr *mask;
{

	if ((cidr == 0) || (cidr > 32)) {
		bzero((void *)mask, sizeof(*mask));
	} else {
		cidr = 32 - cidr;
		mask->s_addr = htonl(~((1UL << cidr) - 1));
	}
	
	return mask;
}

#ifdef AF_INET6
struct in6_addr *
prefix2mask6(plen, mask)
	int plen;
	struct in6_addr *mask;
{
	int i;
	uint32_t m;

	if (plen == 0 || plen > 128)
		bzero((void *)mask, sizeof(*mask));
	else {
		for (i = 0; i < 16; i += 4) {
			if (plen < 32)
				m = ~(0xffffffff >> plen);
			else
				m = 0xffffffff;
			*(uint32_t *)&mask->s6_addr[i] = htonl(m);
			plen -= 32;
			if (plen < 0)
				plen = 0;
		}
	}

	return mask;
}
#endif

void
unmappedaddr(sa, salen)
	struct sockaddr *sa;
	socklen_t *salen;
{
#ifdef AF_INET6
	struct in_addr addr4;
	int port;       
			
	if (SA6(sa)->sin6_family != AF_INET6 ||
	    !IN6_IS_ADDR_V4MAPPED(SADDR6(sa)))
		return;
	addr4.s_addr = *(uint32_t *)&SADDR6(sa)->s6_addr[12];
	port = SA6(sa)->sin6_port;
	bzero(sa, sizeof(struct sockaddr_in));
	SADDR4(sa)->s_addr = addr4.s_addr;
	SA4(sa)->sin_port = port;
	SA4(sa)->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	SA4(sa)->sin_len = sizeof(struct sockaddr_in);
#endif
	*salen = sizeof(struct sockaddr_in);
#endif
	return;
}

void
log_and_report_greylisting(ctx, priv, rcpt)
	SMFICTX *ctx;
	struct mlfi_priv *priv;
	char *rcpt;
{
	int h, mn, s;
	char addrstr[IPADDRSTRLEN];
	time_t remaining;
	char *delayed_rj;
	char aclstr[16];
	char *code = "451";
	char *ecode = "4.7.1";
	char *msg = "Greylisting in action, please come back later";

	/*
	 * The message has been added to the greylist and will be delayed.
	 * Log this and report to the client.
	 */
	iptostring(SA(&priv->priv_addr), priv->priv_addrlen, addrstr,
	    sizeof(addrstr));

	remaining = priv->priv_sr.sr_remaining;
	h = remaining / 3600;
	remaining = remaining % 3600;
	mn = (remaining / 60);
	remaining = remaining % 60;
	s = remaining;

	if (priv->priv_delayed_reject)
		delayed_rj = " after DATA phase";
	else
		delayed_rj = "";

	if (priv->priv_sr.sr_acl_line != 0)
		snprintf(aclstr, sizeof(aclstr), " (ACL %d)", 
		    priv->priv_sr.sr_acl_line);
	else
		aclstr[0] = '\0';

	mg_log(LOG_INFO, 
	    "%s: addr %s[%s] from %s to %s delayed%s for %02d:%02d:%02d%s",
	    priv->priv_queueid, priv->priv_hostname, addrstr, 
	    priv->priv_from, rcpt, delayed_rj, h, mn, s, aclstr);

	code = (priv->priv_sr.sr_code) ? priv->priv_sr.sr_code : code;
	ecode = (priv->priv_sr.sr_ecode) ? 
	    priv->priv_sr.sr_ecode : ecode;

	if (priv->priv_sr.sr_msg)
		msg = priv->priv_sr.sr_msg;
	else if (conf.c_quiet)
		msg = "Greylisting in action, please come back later";
	else
		msg = "Greylisting in action, please come back in %R";

	msg = fstring_expand(priv, rcpt, msg);

	(void)smfi_setreply(ctx, code, ecode, msg);

	free(msg);

	return;
}

#ifdef	USE_DRAC
static int
check_drac(dotted_ip)
	char *dotted_ip;
{
	DB *ddb;
	DBT key, data;
	char ipkey[16];
	int rc;

	ddb = dbopen(conf.c_dracdb, O_RDONLY | O_SHLOCK, 0666, DB_BTREE, NULL);
	if (ddb == NULL) {
		mg_log(LOG_DEBUG, "dbopen \"%s\" failed", conf.c_dracdb);
		return 0;
	}

	key.data = strncpy(ipkey, dotted_ip, sizeof(ipkey));
	key.size = strlen(ipkey);
	rc = ddb->get(ddb, &key, &data, 0);
	ddb->close(ddb);

	switch (rc) {
	case 0:
#ifdef TEST
		mg_log(LOG_DEBUG, "key.data=%.*s (len=%d) "
		    "data.data=%.*s (len=%d)",
		    key.size, key.data, key.size,
		    data.size, data.data, data.size);
#endif /* TEST */
		return 1;
		break;

	case 1:
		return 0;
		break;

	default:
		mg_log(LOG_ERR, "check_drack: errno=%d", errno);
		break;
	}

	return 0;
}
#endif	/* USE_DRAC */

static void 
reset_acl_values(priv)
	struct mlfi_priv *priv;
{
	priv->priv_sr.sr_delay = conf.c_delay;
	priv->priv_sr.sr_autowhite = conf.c_autowhite_validity;

	if (priv->priv_sr.sr_code != NULL) {
		free(priv->priv_sr.sr_code);
		priv->priv_sr.sr_code = NULL;
	}
	if (priv->priv_sr.sr_ecode != NULL) {
		free(priv->priv_sr.sr_ecode);
		priv->priv_sr.sr_ecode = NULL;
	}
	if (priv->priv_sr.sr_msg != NULL) {
		free(priv->priv_sr.sr_msg);
		priv->priv_sr.sr_msg = NULL;
	}
	if (priv->priv_sr.sr_report != NULL) {
		free(priv->priv_sr.sr_report);
		priv->priv_sr.sr_report = NULL;
	}

	return;
}


#ifndef HAVE_STRLCAT
size_t
mystrlcat(dst, src, len)
	char *dst;
	const char *src;
	size_t len;
{
	size_t srclen = strlen(src);
	size_t dstlen;

	for (dstlen = 0; dstlen != len && dst[dstlen]; ++dstlen)
		;
	if (dstlen == len) {
#if 0
		/* BSD's strlcat leaves the string not NUL-terminated. */
		return dstlen + srclen;
#else
		/* This situation is a bug. We make core dump. */
		abort();
#endif
	}
	strncpy(dst + dstlen, src, len - dstlen - 1);
	dst[len - 1] = '\0';
	return dstlen + srclen;
}
#endif

#ifndef HAVE_VSYSLOG
#ifndef LINE_MAX
#define LINE_MAX 1024
#endif /* LINE_MAX */
void
vsyslog(level, fmt, ap)
	int level;
	char *fmt;
	va_list ap;
{
	char messagebuf[LINE_MAX];

	vsnprintf(messagebuf, sizeof(messagebuf), fmt, ap);
	messagebuf[sizeof(messagebuf) - 1] = '\0';
	syslog(level, "%s", messagebuf);

	return;
}
#endif /* HAVE_VSYSLOG */

/* VARARGS */
void
mg_log(int level, char *fmt, ...) {
	va_list ap;

	if (conf_cold || nodetach) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		va_end(ap);
	}

	if (!conf_cold) {
		va_start(ap, fmt);
		vsyslog(level, fmt, ap);
		va_end(ap);
	}

	return;
}

static void
add_recipient(priv, rcpt)
	struct mlfi_priv *priv;
	char *rcpt;
{
	struct rcpt *nr;

	if ((nr = malloc(sizeof(*nr))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	strncpy(nr->r_addr, rcpt, sizeof(nr->r_addr));
	nr->r_addr[ADDRLEN] = '\0';

	LIST_INSERT_HEAD(&priv->priv_rcpt, nr, r_list);
	priv->priv_rcptcount++;
	return;
}

static void
mystrncat(s, append, slenmax)
	char **s;
	char *append;
	size_t *slenmax;
{
	char *str = *s;
	size_t alen;
	size_t slen;

	slen = strlen(*s);
	alen = strlen(append);

	if (slen + alen > *slenmax) {
		if (conf.c_debug)
			mg_log(LOG_DEBUG, "resize url buffer %d -> %d",
			    *slenmax, slen + alen);

		if ((str = realloc(str, slen + alen + 1)) == NULL) {
			mg_log(LOG_ERR, "malloc(%d) failed",
			    slen + alen + 1, strerror(errno));
			exit(EX_OSERR);
		}
		*slenmax = slen + alen;
		*s = str;
	}

	memcpy(str + slen, append, alen);
	str[slen + alen] = '\0';

	return;
}

static char *
strip_brackets(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	size_t outlen;

	/* Strip leading and trailing <> */
	(void)strncpy(out, in, len);
	out[len] = '\0';

	outp = out;
	if (outp[0] == '<')
		outp++;

	outlen = strlen(outp);
	if ((outlen > 0) && 
	    (outp[outlen - 1] == '>'))
		outp[outlen - 1] = '\0';

	return outp;
}

static char *
mbox_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'@')) != NULL)
		*ap = '\0';

	return outp;
}

static char *
site_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'@')) != NULL)
		outp = ap + 1;

	return outp;
}

static char *
machine_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'.')) != NULL)
		*ap = '\0';

	return outp;
}

static char *
domain_only(out, in, len)
	char *out;
	char *in;
	size_t len;
{
	char *outp;
	char *ap;

	outp = strip_brackets(out, in, len);
	if ((ap = index(outp, (int)'.')) != NULL)
		outp = ap + 1;

	return outp;
}

char *
fstring_expand(priv, rcpt, fstring)
	struct mlfi_priv *priv;
	char *rcpt;
	const char *fstring;
{
	size_t offset;
	char *outstr;
	size_t outmaxlen = URLMAXLEN;
	char *tmpstr;
	char *tmpstrp;
	char *last;
	char *ptok;
	int fstr_len;	/* format string length, minus the % (eg: %mr -> 2) */
	int skip_until_brace_close = 0;

	/* 
	 * Shortcut if there is nothing to substitute 
	 */
	if (strchr(fstring, '%') == NULL) {
		if ((outstr = strdup(fstring)) == NULL) {
			mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
		return outstr;
	}
		
	if ((outstr = malloc(outmaxlen + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	outstr[0] = '\0';

	if ((tmpstr = strdup(fstring)) == NULL) {
		mg_log(LOG_ERR, "strdup() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	tmpstrp = tmpstr;
	fstr_len = 0;

	while ((ptok = strtok_r(tmpstrp, "%", &last)) != NULL) {
		char tmpaddr[ADDRLEN + 1];

		if (skip_until_brace_close) {
			char *cp;

			for (cp = ptok; *cp; cp++)
				if (*cp == '}') 
					break;

			if (*cp == '\0')
				continue;

			skip_until_brace_close = 0;
			ptok = cp + 1;
			mystrncat(&outstr, ptok, &outmaxlen);
			continue;
		}

		/* 
		 * If first time, check if the first char was a '%'
		 */
		if (tmpstrp != NULL) {
			tmpstrp = NULL;
			if (fstring[0] != '%') {
				mystrncat(&outstr, ptok, &outmaxlen);
				continue;
			}
		}

		/* 
		 * On second time and later, ptok points on the 
		 * character following '%'
		 * Check if it could be a format string
		 */
		fstr_len = 1;

		switch (*ptok) {
		case 'h':	/* Hello string */
			mystrncat(&outstr, priv->priv_helo, &outmaxlen);
			break;
		case 'd':	/* Sender machine DNS name */
			mystrncat(&outstr, priv->priv_hostname, &outmaxlen);
			break;
		case 'f':	/* Sender e-mail */
			mystrncat(&outstr, 
			    strip_brackets(tmpaddr, priv->priv_from, ADDRLEN), 
			    &outmaxlen);
			break;
		case 'r':	/* Recipient e-mail */
			if (rcpt != NULL)
				mystrncat(&outstr, 
					strip_brackets(tmpaddr, rcpt, ADDRLEN), 
					&outmaxlen);
			break;
		case 'm': 	/* mailbox part of sender or receiver e-mail */
				/* Or machine part of DNS address */
			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'r':	/* Recipient */
				mystrncat(&outstr, 
					mbox_only(tmpaddr, 
					      rcpt, 
					      ADDRLEN), 
					&outmaxlen);
				break;
			case 'f':	/* Sender */
				mystrncat(&outstr, 
				    	mbox_only(tmpaddr, 
					      priv->priv_from, 
					      ADDRLEN), 
					&outmaxlen);
				break;
			case 'd':	/* DNS name */
				mystrncat(&outstr, 
				    	machine_only(tmpaddr, 
					      priv->priv_hostname, 
					      ADDRLEN), 
					&outmaxlen);
				break;
			default:
				fstr_len = 0;
				break;
			}
			break;
		case 's':	/* site part of sender or reciever e-mail */
				/* Or domain part of DNS address */
			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'r':	/* Recipient */
				mystrncat(&outstr, 
					site_only(tmpaddr, 
					      rcpt, 
					      ADDRLEN), 
					&outmaxlen);
				break;
			case 'f':	/* Sender */
				mystrncat(&outstr, 
				    	site_only(tmpaddr, 
					      priv->priv_from, 
					      ADDRLEN), 
					&outmaxlen);
				break;
			case 'd':	/* DNS name */
				mystrncat(&outstr, 
				    	domain_only(tmpaddr, 
					      priv->priv_hostname, 
					      ADDRLEN), 
					&outmaxlen);
				break;
			default:
				fstr_len = 0;
				break;
			}
			break;
		case 'i': {	/* Sender machine IP address */
			char ipstr[IPADDRSTRLEN + 1];

			iptostring(SA(&priv->priv_addr),
			    priv->priv_addrlen, ipstr, sizeof(ipstr));
			mystrncat(&outstr, ipstr, &outmaxlen);
			break;
		}

		case 'I': {	/* Sender machine / cidr, eg: %I{/24} */
			char ipstr[IPADDRSTRLEN + 1];
			struct sockaddr_storage addr;
			socklen_t salen;
			int cidr = 0;
			ipaddr mask;
			int i;

			fstr_len = 0;

			if ((ptok[1] != '{') || (ptok[1] == '\0'))
				break;

			if ((ptok[2] != '/') || (ptok[2] == '\0'))
				break;

			for (i = 3; ptok[i] != '\0'; i++) {
				if (ptok[i] == '}') {
					fstr_len = i + 1;
					break;
				}

				if (!isdigit((int)(ptok[i])))
					break;

				cidr = (10 * cidr) + (ptok[i] - '0');
			}

			if (fstr_len == 0)
				break;

			if (cidr < 0)
				break;

			switch (SA(&priv->priv_addr)->sa_family) {
			case AF_INET:
				salen = sizeof(struct sockaddr_in);

				if (cidr > 32)
					break;

				memcpy(&addr, &priv->priv_addr, 
				    sizeof(struct sockaddr_in));
				prefix2mask4(cidr, &mask.in4);
				SADDR4(&addr)->s_addr &= mask.in4.s_addr;

				break;
#ifdef AF_INET6
			case AF_INET6:
				salen = sizeof(struct sockaddr_in6);

				if (cidr > 128)
					break;

				memcpy(&addr, &priv->priv_addr, 
				    sizeof(struct sockaddr_in6));
				prefix2mask6(cidr, &mask.in6);
				for (i = 0; i < 16; i += 4)
					*(uint32_t *)&SADDR6(&addr)->s6_addr[i] 
					&= *(uint32_t *)&mask.in6.s6_addr[i];

				break;
#endif
			default:
				mg_log(LOG_ERR, "unepxected sa_family");
				exit(EX_SOFTWARE);
				break;
			}

			iptostring(SA(&addr), salen, ipstr, sizeof(ipstr));
			mystrncat(&outstr, ipstr, &outmaxlen);
			break;
		}

		case 'v':	/* milter-greylist version */
			mystrncat(&outstr, PACKAGE_VERSION, &outmaxlen);
			break;

		case 'G': {	/* GMT offset (e.g.: -0100) */
			char tzstr[HDRLEN + 1];
			time_t t;

			t = time(NULL);
			gmtoffset(&t, tzstr, HDRLEN);
			mystrncat(&outstr, tzstr, &outmaxlen);
			break;
		}
		
		case 'C': {	/* Country code from GeoIP */
#ifdef USE_GEOIP
			mystrncat(&outstr, priv->priv_ccode, &outmaxlen);
#else
			fstr_len =  0;
#endif
			break;
		}
		case 'E': {	/* elapsed time */
			int h, mn, s;
			char num[16];

			s = priv->priv_sr.sr_elapsed;	
			h = s / 3600;
			s = s % 3600;
			mn = s / 60;
			s = s % 60;

			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'h':	/* hours */
				snprintf(num, sizeof(num), "%d", h);
				break;
			case 'm':	/* minutes */
				snprintf(num, sizeof(num), "%d", mn);
				break;
			case 's':	/* seconds */
				snprintf(num, sizeof(num), "%d", s);
				break;
			case 't':	/* total in seconds */
				snprintf(num, sizeof(num), "%d",
				    (int)priv->priv_sr.sr_elapsed);
				break;
			default:	/* hh:mm:ss */
				fstr_len = 1;
				snprintf(num, sizeof(num), 
				    "%02d:%02d:%02d", h, mn, s);
				break;
			}
				
			mystrncat(&outstr, num, &outmaxlen);
			break;
		}

		case 'R': {	/* remaining time */
			int h, mn, s;
			char num[16];

			s = priv->priv_sr.sr_remaining;
			h = s / 3600;
			s = s % 3600;
			mn = s / 60;
			s = s % 60;

			fstr_len = 2;

			switch(*(ptok + 1)) {
			case 'h':	/* hours */
				snprintf(num, sizeof(num), "%d", h);
				break;
			case 'm':	/* minutes */
				snprintf(num, sizeof(num), "%d", mn);
				break;
			case 's':	/* seconds */
				snprintf(num, sizeof(num), "%d", s);
				break;
			case 't':	/* total in seconds */
				snprintf(num, sizeof(num), "%d",
				    (int)priv->priv_sr.sr_remaining);
				break;
			default:	/* hh:mm:ss */
				fstr_len = 1;
				snprintf(num, sizeof(num), 
				    "%02d:%02d:%02d", h, mn, s);
				break;
			}

			mystrncat(&outstr, num, &outmaxlen);
			break;
		}

		case 'V': {	/* milter-greylist-<version> <complete date> */
			char host[ADDRLEN + 1];
			char timestr[HDRLEN + 1];
			char tzstr[HDRLEN + 1];
			char tznamestr[HDRLEN + 1];
			char output[HDRLEN + 1];
			char *fqdn;
			time_t t;
			struct tm ltm;
			
			t = time(NULL);
			localtime_r(&t, &ltm);
			strftime(timestr, HDRLEN, "%a, %d %b %Y %T", &ltm);
			gmtoffset(&t, tzstr, HDRLEN);
			strftime(tznamestr, HDRLEN, "%Z", &ltm);

			fqdn = smfi_getsymval(priv->priv_ctx, "{j}");
			if (fqdn == NULL) {
				mg_log(LOG_DEBUG, 
				    "smfi_getsymval failed for {j}");
				gethostname(host, ADDRLEN);
				fqdn = host;
			}

			snprintf(output, HDRLEN, 
#ifndef USE_POSTFIX
			    "milter-greylist-%s (%s [%s]); %s %s (%s)",
#else
			    "milter-greylist-%s (%s); %s %s (%s)",
#endif
			    PACKAGE_VERSION, fqdn,
#ifndef USE_POSTFIX
			    local_ipstr(priv),
#endif
			    timestr, tzstr, tznamestr);
			mystrncat(&outstr, output, &outmaxlen);
			break;
		}

		case 'g': {	/* regex match %g{\1} */
			int i;
			int nmatch = 0;

			fstr_len = 0;

			if ((ptok[1] != '{') || (ptok[1] == '\0'))
				break;

			if ((ptok[2] != '\\') || (ptok[2] == '\0'))
				break;

			for (i = 3; ptok[i] != '\0'; i++) {
				if (ptok[i] == '}') {
					fstr_len = i + 1;
					break;
				}

				if (!isdigit((int)(ptok[i])))
					break;

				nmatch = (10 * nmatch) + (ptok[i] - '0');
			}

			if (fstr_len == 0)
				break;

			if (nmatch == 0)
				break;

			if (nmatch > priv->priv_sr.sr_nmatch)
				break;

			if (priv->priv_sr.sr_pmatch[nmatch - 1] != NULL)
				mystrncat(&outstr, 
				    priv->priv_sr.sr_pmatch[nmatch - 1],
				    &outmaxlen);

			break;
		}

		case 'T': {	/* current time %T{strftime_string} */
			const char *cp;
			time_t now;
			struct tm tm;
			char *format;

			if (*(ptok + 1) != '{')
				break;

			fstr_len = 2;

			/* 
			 * Lookup in the original string and not in tmpstr
			 * since strtok removed the next *
			 */
			offset = ((u_long)ptok + 2) - (u_long)tmpstr;
			for (cp = fstring + offset; *cp; cp++) {
				fstr_len++;
				if (*cp == '}')
					break;
			}

			/* No match, no substitution */
			if (*cp == '\0') {
				fstr_len = 0;
				break;
			}

			format = malloc(fstr_len + 1);
			if (format == NULL) {
				mg_log(LOG_ERR, "malloc failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}

			/* -3 to remove T{ after the % and trailing } */
			memcpy(format, fstring + offset, fstr_len - 3);
			format[fstr_len - 3] = '\0';

			now = time(NULL);
			(void)localtime_r(&now, &tm);
			(void)strftime(outstr + strlen(outstr), 
			    outmaxlen - strlen(outstr), format, &tm);
			
			free(format);

			/* We need to skip inside of %T{} */
			skip_until_brace_close = 1;
			break;
		}
		case 'M': { 	/* sendmail macro (maybe %Mj or %M{foo}) */
			char *cp;
			char *symval;
			char *symname;

			switch(*(ptok + 1)) {
			case '{':
				fstr_len = 2;
				/* Find the trailing } */
				for (cp = ptok + 2; *cp; cp++) {
					fstr_len++;
					if (*cp == '}')
						break;
				}

				/* No match, no substitution */
				if (*cp == '\0')
					fstr_len = 0;

				break;
			default:
				fstr_len = 2;
				break;
			}

			if (fstr_len == 0)
				break;

			symname = malloc(fstr_len + 1);
			if (symname == NULL) {
				mg_log(LOG_ERR, "malloc failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}
			/* +1/-1 to skip the M after the % */
			memcpy(symname, ptok + 1, fstr_len - 1);
			symname[fstr_len - 1] = '\0';

			symval = smfi_getsymval(priv->priv_ctx, symname);

#if 0
			if (conf.c_debug) 
				mg_log(LOG_DEBUG, 
				    "macro %s value = \"%s\"",
				    symname, 
				    (symval == NULL) ? "(null)" : symval);
#endif

			if (symval == NULL)
				symval = "";

			mystrncat(&outstr, symval, &outmaxlen);

			free(symname);
			break;
		}
		case 'S': 	/* status returned to sendmail */
			switch (priv->priv_sr.sr_retcode) {
			case SMFIS_CONTINUE:
				mystrncat(&outstr, "accept", &outmaxlen);
				break;
			case SMFIS_TEMPFAIL:
				mystrncat(&outstr, "tempfail", &outmaxlen);
				break;
			case SMFIS_REJECT:
				mystrncat(&outstr, "reject", &outmaxlen);
				break;
			case -1: /* Not known */
				break;
			default:
				mg_log(LOG_ERR, "unexpected sr_retcode = %d",
				    priv->priv_sr.sr_retcode);
				exit(EX_SOFTWARE);
				break;
			}
			break;
		case 'A': {	/* Line number for matching ACL */
			char buf[16];

			snprintf(buf, sizeof(buf), "%d", 
			   priv->priv_sr.sr_acl_line); 
			mystrncat(&outstr, buf, &outmaxlen);
			break;
		}	
			
		default:
			fstr_len = 0;
			break;
		}

		/* 
		 * Special case for %T{}: no need to copy the 
		 * next chars until a %, as we want to skip until a }
		 */
		if (skip_until_brace_close)
			continue;

		/* 
		 * If no substitution was made, then keep the '%' 
		 * Otherwise, skip the format string
		 */
		if (fstr_len == 0)
			mystrncat(&outstr, "%", &outmaxlen);
		else
			ptok += fstr_len;

		mystrncat(&outstr, ptok, &outmaxlen);
	}

	free(tmpstr);

	return outstr;
}

char *
fstring_escape(fstring)
	char *fstring;
{
	char *cp;

	for (cp = fstring; *cp != '\0'; cp++) {
		int slen;

		if (*cp != '\\')
			continue;

		slen = 0;
		switch(*(cp + 1)) {
		case '\0':
			return fstring;
			break;
		case 'a':	/* bell */
			*cp = '\a';
			slen = 1;
			break;
		case 'b':	/* backspace */
			*cp = '\f';
			slen = 1;
			break;
		case 'f':	/* formfeed */
			*cp = '\f';
			slen = 1;
			break;
		case 'n':	/* newline */
			*cp = '\n';
			slen = 1;
			break;
		case 'r':	/* carriage return */
			*cp = '\r';
			slen = 1;
			break;
		case 't':	/* horizontal tab */
			*cp = '\t';
			slen = 1;
			break;
		case 'v':	/* vertical tab */
			*cp = '\v';
			slen = 1;
			break;
		case '\\':	/* backslash */
			*cp = '\\';
			slen = 1;
			break;
		case '\?':	/* question mark */
			*cp = '\?';
			slen = 1;
			break;
		case '\'':	/* single quote */
			*cp = '\'';
			slen = 1;
			break;
		case '\"':	/* double quote */
			*cp = '\"';
			slen = 1;
			break;
		case '0': {	/* octal value */
			char c1, c2;
			
			if (*(cp + 2) == '\0')
				break;
			c1 = *(cp + 2);
			if (*(cp + 3) == '\0')
				break;
			c2 = *(cp + 2);

			if (isdigit((int)c1) && isdigit((int)c2)) {
				int d1, d2;

				d1 = c1 - '0';
				d2 = c2 - '0';
				*cp = (8 * d1) + d2;
				slen = 3;
			} 
			/* And we'll ignore \0 alone */
			break;
		}
		case 'x': {	/* hexadecimal value */
			char c1, c2;
			
			if (*(cp + 2) == '\0')
				break;
			c1 = *(cp + 2);
			if (*(cp + 3) == '\0')
				break;
			c2 = *(cp + 2);

			if (isxdigit((int)c1) && isxdigit((int)c2)) {
				int d1, d2;

				if (isdigit((int)c1))
					d1 = c1 - '0';
				else if (islower((int)c1))
					d1 = c1 - 'a';
				else
					d1 = c1 - 'A';

				if (isdigit((int)c2))
					d2 = c2 - '0';
				else if (islower((int)c2))
					d2 = c2 - 'a';
				else
					d2 = c2 - 'A';

				*cp = (16 * d1) + d2;
				slen = 3;
			} 
			break;
		}
		default: /* Unknown sequence, discard */
			slen = -1;
			break;
		}

		if (slen == -1)
			bcopy(cp + 1, cp, strlen(cp + 1) + 1);
		if (slen != 0)
			bcopy(cp + 1 + slen, cp + 1, strlen(cp + 1 + slen) + 1);
		slen = 0;
	}

	return fstring;
}

#ifndef USE_POSTFIX
static char *
local_ipstr(priv)
	struct mlfi_priv *priv;
{
	char *ip;

	/* 
	 * Macro {if_addr} does not exist in Postfix 
	 */
	ip = smfi_getsymval(priv->priv_ctx, "{if_addr}");
#ifdef AF_INET6
	/*
	 * XXX: sendmail doesn't return {if_addr} when connection is
	 * from ::1
	 */
	if (ip == NULL && SA(&priv->priv_addr)->sa_family == AF_INET6) {
		char buf[IPADDRSTRLEN];

		if (iptostring(SA(&priv->priv_addr), priv->priv_addrlen, buf,
		    sizeof(buf)) != NULL &&
		    strcmp(buf, "::1") == 0)
			ip = "IPv6:::1";
	}
#endif /* AF_INET6 */
	if (ip == NULL) {
		mg_log(LOG_DEBUG, "smfi_getsymval failed for {if_addr}");
		ip = "0.0.0.0";
	}

	return ip;
}
#endif /* !USE_POSTFIX */
