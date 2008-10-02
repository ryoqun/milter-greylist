/* $Id: spamd.c,v 1.5 2008/10/02 19:09:39 manu Exp $ */

/*
 * Copyright (c) 2008 Manuel Badzong, Emmanuel Dreyfus
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
 *        This product includes software developed by Manuel Badzong
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
 
#ifdef USE_SPAMD

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: spamd.c,v 1.5 2008/10/02 19:09:39 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sysexits.h>
#include <syslog.h>

#include "acl.h"
#include "conf.h"
#include "queue.h"
#include "milter-greylist.h"

#include "spamd.h"

/* For priv->priv_spamd_flags */
#define SPAMD_HAS_STATUS 1
#define SPAMD_IS_SPAM 2

#define SPAMD_PORT "783"
#define SPAMD_BUFLEN 1024

#define SPAMD_SPAMD_SPAMD "SPAMD/"
#define SPAMD_SPAMD_VERSION "1.1"
#define SPAMD_SPAMD_OK "EX_OK"
#define SPAMD_SPAMD_SPAM "Spam: "
#define SPAMD_SPAMD_TRUE "True"
#define SPAMD_SPAMD_FALSE "False"

#define SPAMD_ERR_PROTO "spamd protocol error"
#define SPAMD_ERR_VERSION "spamd protocol version mismatch"
#define SPAMD_ERR_STATUS "spamd returned non-ok"

static int spamd_check(acl_data_t *, acl_stage_t, 
		       struct acl_param *, struct mlfi_priv *);
static void spamd_rcvhdr(struct mlfi_priv *, char *, int);
static char *spamd_trim(char *);
static int spamd_read(int, char *, size_t);
static int spamd_write(int, char *, size_t);
static int spamd_socket(char *, char *);
static int spamd_unix_socket(char *);
static int spamd_inet_socket(char *, char *);


void
spamd_sock_set(type, sock)
	char *type;
	char *sock;
{
	(void)strncpy(conf.c_spamdsock, sock, sizeof(conf.c_spamdsock));
	(void)strncpy(conf.c_spamdsocktype, 
		      type, sizeof(conf.c_spamdsocktype));
	return;
}

int
spamd_isspam(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (stage != AS_DATA) {
		mg_log(LOG_ERR, 
		       "spamassassin filter called at non DATA stage");
		exit(EX_SOFTWARE);
	}

	if (!(priv->priv_spamd_flags & SPAMD_HAS_STATUS))
		if (spamd_check(ad, stage, ap, priv) == -1)
			return -1;

	if (priv->priv_spamd_flags & SPAMD_IS_SPAM)
		return 1;

	return 0;
}

int
spamd_score(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	if (stage != AS_DATA) {
		mg_log(LOG_ERR, 
		       "spamassassin filter called at non DATA stage");
		exit(EX_SOFTWARE);
	}

	if (!(priv->priv_spamd_flags & SPAMD_HAS_STATUS))
		if (spamd_check(ad, stage, ap, priv) == -1)
			return -1;

	if (acl_opnum_cmp(priv->priv_spamd_score10, 
			  ad->opnum.op,
			  ad->opnum.num * 10))
		return 1;

	return 0;
}

static int
spamd_check(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	int sock;
	struct header *h;
	struct body *b;
	char buffer[SPAMD_BUFLEN];
	char rcvhdr[SPAMD_BUFLEN];
	char *p, *q;

	if (priv->priv_spamd_flags & SPAMD_HAS_STATUS)
		return 0;

	spamd_rcvhdr(priv, rcvhdr, SPAMD_BUFLEN);

	snprintf(buffer, SPAMD_BUFLEN,
	  "CHECK SPAMC/1.2\r\nContent-length: %d\r\n\r\n",
	  priv->priv_msgcount + strlen(rcvhdr));

	if ((sock = spamd_socket(conf.c_spamdsocktype, 
				 conf.c_spamdsock)) == -1)
		return -1;
	 
	if (spamd_write(sock, buffer, strlen(buffer)) == -1)
		return -1;

	TAILQ_FOREACH(h, &priv->priv_header, h_list) {
		/*
		 * Insert received header before other received headers.
		 */
		if (rcvhdr[0] && !strncasecmp(h->h_line, "Received", 8)) {
			if (spamd_write(sock, rcvhdr, strlen(rcvhdr)) == -1)
				return -1;
			rcvhdr[0] = 0;
		}
		if (spamd_write(sock, h->h_line, strlen(h->h_line)) == -1)
			return -1;
	}

	/*
	 * No received header found.
	 */
	if (rcvhdr[0]) {
		if (spamd_write(sock, rcvhdr, strlen(rcvhdr)) == -1)
			return -1;
		rcvhdr[0] = 0;
	}
			
	TAILQ_FOREACH(b, &priv->priv_body, b_list)
		if (spamd_write(sock, b->b_lines, strlen(b->b_lines)) == -1)
			return -1;

	if (spamd_read(sock, buffer, SPAMD_BUFLEN) == -1)
		return -1;

	/*
	 * Check status line.
	 */
	p = buffer;
	if (strncmp(p, SPAMD_SPAMD_SPAMD, strlen(SPAMD_SPAMD_SPAMD))) {
		mg_log(LOG_ERR, SPAMD_ERR_PROTO);
		return -1;
	}

	p += strlen(SPAMD_SPAMD_SPAMD);
	if (strncmp(p, SPAMD_SPAMD_VERSION, strlen(SPAMD_SPAMD_VERSION)))
		mg_log(LOG_WARNING, SPAMD_ERR_VERSION);

	p += strlen(SPAMD_SPAMD_VERSION);
	if ((p = strstr(p, SPAMD_SPAMD_OK)) == NULL) {
		mg_log(LOG_ERR, SPAMD_ERR_STATUS);
		mg_log(LOG_ERR, buffer);
		return -1;
	}

	/*
	 * Spamd returns 2 lines. Read 2nd line if neccessary.
	 */
	p += strlen(SPAMD_SPAMD_OK);
	if (strlen(p) <= 2) {  /* '\r\n' (2 chars) follow SPAMD_SPAMD_OK */
		if (spamd_read(sock, buffer, SPAMD_BUFLEN) == -1)
			return -1;
		p = buffer;
	}

	close(sock);
	p = spamd_trim(p);

	/*
	 * Check score line.
	 */
	if (strncmp(p, SPAMD_SPAMD_SPAM, strlen(SPAMD_SPAMD_SPAM))) {
		mg_log(LOG_ERR, SPAMD_ERR_PROTO);
		return -1;
	}

	p += strlen(SPAMD_SPAMD_SPAM);
	if (!strncmp(p, SPAMD_SPAMD_TRUE, strlen(SPAMD_SPAMD_TRUE))) {
		priv->priv_spamd_flags &= SPAMD_IS_SPAM;
	} else if (!strncmp(p, SPAMD_SPAMD_FALSE, strlen(SPAMD_SPAMD_FALSE))) {
		priv->priv_spamd_flags |= ~SPAMD_IS_SPAM;
	} else {
		mg_log(LOG_ERR, SPAMD_ERR_PROTO);
		return -1;
	}

	/*
	 * Cut score.
	 */
	if ((q = strchr(p, '/')) == NULL) {
		mg_log(LOG_ERR, SPAMD_ERR_PROTO);
		return -1;
	}
	*q = '\0';

	if ((p = strchr(p, ';')) == NULL) {
		mg_log(LOG_ERR, SPAMD_ERR_PROTO);
		return -1;
	}
	p = spamd_trim(++p);

	priv->priv_spamd_score10 = (int) (atof(p) * 10);
	priv->priv_spamd_flags = SPAMD_HAS_STATUS;

	return 0;
}

static void
spamd_rcvhdr(priv, str, len)
	struct mlfi_priv *priv;
	char *str;
	int len;
{
	struct rcpt rcpt;
	char ipstr[IPADDRSTRLEN];
	char myhostname[ADDRLEN + 1];
	char now[SPAMD_BUFLEN];
	time_t t;
	struct tm *tm;
	struct tm tm_buffer;

	iptostring(SA(&priv->priv_addr), 
		   priv->priv_addrlen, 
		   ipstr, sizeof(ipstr));

	if (gethostname(myhostname, SPAMD_BUFLEN)) {
		mg_log(LOG_WARNING, "spamd gethostname failed");
		strcpy(myhostname, "unknown");
	}

	/* strftime format specifier for timezone offset %z is not 
	 * generally available (GNU only). For portability we force timezone
	 * GMT (offset +0), the timestamp remains correct anyhow.
	 * This does not harm SA processing of Received lines.
	 * Especially this line will neither flow back to the MTA nor
	 * show up at the recipient ...
	 */
	t = time(NULL);
	tm = gmtime_r(&t, &tm_buffer);
	if (strftime(now, len, "%a, %d %b %Y %H:%M:%S +0000", tm) == 0) {
		mg_log(LOG_WARNING, "spamd strftime failed");
		now[0] = '\0';
	}

	if (priv->priv_rcptcount == 1) {
		memcpy(&rcpt, LIST_FIRST(&priv->priv_rcpt), sizeof(rcpt));

		snprintf(str, len,
	  		 "Received: from %s (%s [%s])\r\n\tby %s (%s) "
			 "with SMTP id %s\r\n\tfor %s; %s\r\n",
			  priv->priv_helo, priv->priv_hostname, 
			  ipstr, myhostname, "milter-greylist", 
			  priv->priv_queueid, rcpt.r_addr, now);
	} else {
		snprintf(str, len,
	  		 "Received: from %s (%s [%s])\r\n\tby %s (%s) "
			 "with SMTP id %s;\r\n\t%s\r\n",
			 priv->priv_helo, priv->priv_hostname, 
			 ipstr, myhostname, "milter-greylist", 
			 priv->priv_queueid, now);
	}

	return;
}

static char *
spamd_trim(char *s)
{
	char *p;

	p = s + strlen(s);

	for (;strchr(" \t\n\r", *s); ++s);
	for (;strchr(" \t\n\r", *(p - 1)); --p);
	*p = '\0';

	return s;
}

static int
spamd_read(fd, buf, count)
	int fd;
	char *buf;
	size_t count;
{
	int n;

	if ((n = read(fd, buf, count)) == -1) {
		mg_log(LOG_ERR, "spamd read failed: %s", strerror(errno));
		return -1;
	}

	if (n == count)
		if (buf[--n] != '\0')
			mg_log(LOG_WARNING, "spamd read buffer exhausted");

	buf[n] = '\0';

	return n;
}

static int
spamd_write(fd, buf, count)
	int fd;
	char *buf;
	size_t count;
{
	int n, written = 0;

	do {
		if ((n = write(fd, buf, count)) == -1) {
			mg_log(LOG_ERR, 
			       "spamd write failed: %s", 
			       strerror(errno));
			return -1;
		}
		written += n;
	} while (written < count);

	return written;
}

static int
spamd_socket(type, path)
	char *type;
	char *path;
{
	char *host, *port;
	int sock;

	if (!strncmp(type, "unix", 4))
		return spamd_unix_socket(path);

	if (strncmp(type, "inet", 4))
		return -1;

	if ((host = malloc(strlen(path) + 1)) == NULL) {
		mg_log(LOG_ERR, "spamd malloc failed: %s", strerror(errno));
		return -1;
	}
	strcpy(host, path);
	
	if ((port = strrchr(host, ':')) == NULL)
		port = SPAMD_PORT;
	else
		*port++ = '\0';

	sock = spamd_inet_socket(host, port);
	free(host);

	return sock;
}

static int
spamd_unix_socket(path)
	char *path;
{
	struct sockaddr_un sun;
	int sock;
	
	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof(sun.sun_path) - 1);

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		mg_log(LOG_ERR, "spamd socket failed: %s", strerror(errno));
		return -1;
	}

	if (connect(sock, (struct sockaddr*) &sun, sizeof(sun))) {
		mg_log(LOG_ERR, "spamd connect failed: %s", strerror(errno));
		return -1;
	}

	return sock;
}

static int
spamd_inet_socket(host, port)
	char *host;
	char *port;
{
	struct addrinfo *ai, *res;
	struct addrinfo hints;
	int e;
	int sock = -1;

	bzero(&hints, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
	hints.ai_flags = AI_ADDRCONFIG;
#endif

	if ((e = getaddrinfo(host, port, &hints, &ai))) {
		mg_log(LOG_ERR, 
		       "spamd getaddrinfo failed: %s", 
		       gai_strerror(e));
		return -1;
	}

	for (res = ai; res != NULL; res = res->ai_next) {
		sock = socket(res->ai_family, 
			      res->ai_socktype, 
			      res->ai_protocol);
		if (sock == -1)
			continue;

		if (connect(sock, res->ai_addr, res->ai_addrlen) == 0)
			break;

		close(sock);
		sock = -1;
	}

	freeaddrinfo(ai);
	if (sock == -1) {
		mg_log(LOG_ERR, 
		       "spamd connection to %s:%s failed: %s", 
		       host, port, strerror(errno));
		return -1;
	}

	return sock;
}

#endif /* USE_SPAMD */
