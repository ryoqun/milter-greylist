/* $Id: urlcheck.c,v 1.21 2007/03/15 05:33:00 manu Exp $ */

/*
 * Copyright (c) 2006 Emmanuel Dreyfus
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

#ifdef USE_CURL

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: urlcheck.c,v 1.21 2007/03/15 05:33:00 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <ctype.h>
#include <sysexits.h>
#include <signal.h>

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else 
#include <sys/queue.h>
#endif
#include <sys/types.h>

#include "milter-greylist.h"
#include "pending.h"
#include "acl.h"
#include "conf.h"
#include "urlcheck.h"

#define BOUNDARY_LEN	4
struct post_data {
	struct mlfi_priv *pd_priv;
	struct header *pd_curhdr;
	struct body *pd_curbody;
	char *pd_curptr;
	int pd_done;
	char pd_boundary[BOUNDARY_LEN + 1];
};

/* Header and trailer for POST requests */
char post_header_templ[] = 
    "--%s\r\n"
    "Content-Disposition: form-data; name=\"msg\"; filename=\"msg.txt\"\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Transfer-Encoding: binary\r\n"
    "\r\n";
char post_trailer_templ[] = 
    "\r\n"
    "--%s--\r\n";
char post_header[sizeof(post_header_templ) - 2 + BOUNDARY_LEN];
char post_trailer[sizeof(post_trailer_templ) - 2 + BOUNDARY_LEN];

int urlcheck_gflags = 0;


/* 
 * locking is done through the same lock as acllist: both are static 
 * configuration, which are readen or changed at the same times.
 */
struct urlchecklist urlcheck_head;

static size_t curl_outlet(void *, size_t, size_t, void *);
static int find_boundary(struct mlfi_priv *, char *);
static size_t curl_post(void *, size_t, size_t, void *);
static int answer_parse(struct iovec *, struct acl_param *, int, 
			struct mlfi_priv *);
static int answer_getline(char *, char *, struct acl_param *);
static struct urlcheck_cnx *get_cnx(struct urlcheck_entry *);
static void urlcheck_prop_push(char *, char *, int, struct mlfi_priv *);
static void urlcheck_prop_clear_tmp(struct mlfi_priv *);
static void urlcheck_prop_untmp(struct mlfi_priv *);

static void urlcheck_validate_pipe(struct iovec *, struct urlcheck_entry *, 
				   struct urlcheck_cnx *, char *);
static void urlcheck_validate_internal(struct iovec *, struct urlcheck_entry *, 
				       struct urlcheck_cnx *, char *, 
				       acl_stage_t, struct mlfi_priv *);
static void urlcheck_validate_helper(struct urlcheck_entry *, 
				     struct urlcheck_cnx *);
static void urlcheck_cleanup_pipe(struct urlcheck_cnx *);
void urlcheck_helper_timeout(int);

#define URLCHECK_ANSWER_MAX	4096

void
urlcheck_init(void) {
	LIST_INIT(&urlcheck_head);
	curl_global_init(CURL_GLOBAL_ALL);
	return;
}


void
urlcheck_def_add(name, url, max_cnx, flags) /* acllist must be write locked */
	char *name;
	char *url;
	int max_cnx;
	int flags;
{
	struct urlcheck_entry *ue;
	struct urlcheck_cnx *uc;
	int postmsg;
	int getprop;

	postmsg = flags & U_POSTMSG;
	getprop = flags & U_GETPROP;

	if (urlcheck_byname(name) != NULL) {
		mg_log(LOG_ERR, "urlcheck \"%s\" defined twice at line %d",
		    name, conf_line - 1);
		exit(EX_DATAERR);
	}

	if ((ue = malloc(sizeof(*ue))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	strncpy(ue->u_name, name, sizeof(ue->u_name));
	ue->u_name[sizeof(ue->u_name) - 1] = '\0';

	strncpy(ue->u_url, url, sizeof(ue->u_url));
	ue->u_url[sizeof(ue->u_url) - 1] = '\0';

	ue->u_maxcnx = max_cnx;
	ue->u_flags = flags;

	if (postmsg && conf.c_maxpeek == 0)
		conf.c_maxpeek = -1;

	if ((uc = malloc(max_cnx * sizeof(*uc))) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed for URL check cnx pool: %s",
		    max_cnx * sizeof(*uc), strerror(errno));
		exit(EX_OSERR);
	}
	ue->u_cnxpool = uc;

	while (max_cnx > 0) {
		uc->uc_hdl = NULL;
		uc->uc_old = 0;
		uc->uc_pipe_req[0] = -1;
		uc->uc_pipe_req[1] = -1;
		uc->uc_pipe_rep[0] = -1;
		uc->uc_pipe_rep[1] = -1;
		uc->uc_pid = -1;
		if (pthread_mutex_init(&uc->uc_lock, NULL) != 0) {
			mg_log(LOG_ERR, "pthread_mutex_init() failed: %s",
			    strerror(errno));
			exit(EX_OSERR);
		}

		uc++;
		max_cnx--;
	}

	LIST_INSERT_HEAD(&urlcheck_head, ue, u_list);

	if (conf.c_debug || conf.c_acldebug) {
		mg_log(LOG_DEBUG, "load URL check \"%s\" \"%s\" %d%s%s%s%s", 
		    ue->u_name, ue->u_url, ue->u_maxcnx,
		    getprop ? " getprop" : "", 
		    (ue->u_flags & U_CLEARPROP) ? " clear" : "", 
		    (ue->u_flags & U_FORK) ? " fork" : "", 
		    postmsg ? " postmsg" : "");
	}

	urlcheck_gflags = 0;
	return;
}

struct urlcheck_entry *
urlcheck_byname(urlcheck)	/* acllist must be read locked */
	char *urlcheck;
{
	struct urlcheck_entry *ue;	

	LIST_FOREACH(ue, &urlcheck_head, u_list) {
		if (strcasecmp(ue->u_name, urlcheck) == 0)
			break;
	}

	return ue;
}

void
urlcheck_clear(void)	/* acllist must be write locked */
{
	struct urlcheck_entry *ue;
	struct urlcheck_cnx *uc;

	while(!LIST_EMPTY(&urlcheck_head)) {
		ue = LIST_FIRST(&urlcheck_head);
		LIST_REMOVE(ue, u_list);

		uc = ue->u_cnxpool;
		while (ue->u_maxcnx > 0) {
			/* 
			 * Drain the lock. No other thread should be
			 * able to acquire it now since we removed 
			 * ue from the list. XXX is that right?
			 */

			if (pthread_mutex_lock(&uc->uc_lock) != 0) {
				mg_log(LOG_ERR, "pthread_mutex_lock failed "
				    "in urlcheck_clear: %s", strerror(errno));
				exit(EX_OSERR);
			}

			if (pthread_mutex_unlock(&uc->uc_lock) != 0) {
				mg_log(LOG_ERR, "pthread_mutex_unlock failed "
				    "in urlcheck_clear: %s", strerror(errno));
				exit(EX_OSERR);
			}

			if (uc->uc_hdl != NULL)
				curl_easy_cleanup(uc->uc_hdl);

			urlcheck_cleanup_pipe(uc);

			pthread_mutex_destroy(&uc->uc_lock);

			uc++;
			ue->u_maxcnx--;
		}
		free(ue->u_cnxpool);
		free(ue);
	}

	curl_global_cleanup();

	urlcheck_init();

	return;
}


#if 0
static char *
url_encode(url)
	char *url;
{
	char *cp;
	size_t len;
	char *out;
	char *op;

	len = 0;
	for (cp = url; *cp; cp++) {
		if (isalnum((int)*cp) || 
		    (*cp == '.') || 
		    (*cp == '-') || 
		    (*cp == '_')) {
			len++;
		} else {
			len += 3;
		}
	}
	len++;

	if ((out = malloc(len + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed", 
		    len + 1, strerror(errno));
		exit(EX_OSERR);
	}
	out[0] = '\0';
	op = out;

	for (cp = url; *cp; cp++) {
		if (isalnum((int)*cp) || 
		    (*cp == '.') || 
		    (*cp == '-') || 
		    (*cp == ':') || 
		    (*cp == '_')) {
			*op++ = *cp;
		} else {
			int i;

			*op = '\0';
			(void)snprintf(op, 4, "%%%x", *cp);
			for (i = 0; i < 4; i++)
				op[i] = (char)toupper((int)op[i]);
			op += 3;
		}
	}

	return out;
}
#endif

static int
find_boundary(priv, boundary)
	struct mlfi_priv *priv;
	char *boundary;
{
	int i;
	struct body *b;
	struct header *h;

	for (i = 0; i < BOUNDARY_LEN; i++)
		boundary[i] = 'a';
	boundary[BOUNDARY_LEN] = '\0';

	do {
		TAILQ_FOREACH(h, &priv->priv_header, h_list)
			if (strstr(h->h_line, boundary) != NULL)
				goto next;
			
		TAILQ_FOREACH(b, &priv->priv_body, b_list)
			if (strstr(b->b_lines, boundary) != NULL)
				goto next;

		return 0;
next:
		for (i = 0; i < BOUNDARY_LEN; i++) {
			if (boundary[i] == 'z') {
				boundary[i] = 'a';
			} else {
				boundary[i]++;
				break;
			}
		}

		/* Failure to find a proper boundary */
		if (i == BOUNDARY_LEN)
			return -1;

	} while (/*CONSTCOND*/ 1);
}

static size_t
curl_post(buffer, size, nmemb, userp)
	void  *buffer;
	size_t size;
	size_t nmemb;
	void *userp;
{
	struct post_data *pd;
	size_t len = 0;

	pd = (struct post_data *)userp;

	/* First time */
	if ((pd->pd_curhdr != NULL) && (pd->pd_curptr == NULL)) {
		len = sizeof(post_header) - 1;
		if (size * nmemb < len) {
			mg_log(LOG_ERR, "libcurl frag too small");
			exit(EX_OSERR);
		}
		snprintf(buffer, len, post_header_templ, pd->pd_boundary);
		pd->pd_curptr = pd->pd_curhdr->h_line;
		goto finish;
	}

	/* We are currently doing headers */
	if (pd->pd_curhdr != NULL) {
		len = strlen(pd->pd_curptr);
		if (len <= size * nmemb) {
			/*
			 * we copy everything we need and move
			 * to the next header line.
			 */
			if (len > 0)
				memcpy(buffer, pd->pd_curptr, len);

			pd->pd_curhdr = TAILQ_NEXT(pd->pd_curhdr, h_list);

			/* 
			 * If there are no more headers, we will move to
			 * the body on next time we are called.
			 */
			if (pd->pd_curhdr == NULL) 
				pd->pd_curptr = pd->pd_curbody->b_lines;
			else
				pd->pd_curptr = pd->pd_curhdr->h_line;

		} else { /* (len > size * nmemb) */
			/* 
			 * More data to write than buffer size,
			 * copy everything we can
			 */
			len = (size * nmemb);
			memcpy(buffer, pd->pd_curptr, len);
			pd->pd_curptr += len;
		}
		goto finish;
	}

	/* We are currently processing body */
	if (pd->pd_curbody != NULL) {
		len = strlen(pd->pd_curptr);

		if (len <= size * nmemb) {
			/* Copy the whole chunk */
			memcpy(buffer, pd->pd_curptr, len);

			/* Move to the next one */
			pd->pd_curbody = 
			    TAILQ_NEXT(pd->pd_curbody, b_list);

			/* If it's not the last one... */
			if (pd->pd_curbody != NULL)
				pd->pd_curptr = pd->pd_curbody->b_lines;
			else
				pd->pd_curptr = NULL;
		} else {
			/* 
			 * Copy everything we have 
			 * strncpy is used without adding the \0 on purpose
			 */
			strncpy(buffer, pd->pd_curptr, len);

			pd->pd_curptr += len;
		}
		goto finish;
	}

	/* Body is done, do trailer */
	if ((pd->pd_curbody == NULL) && (!pd->pd_done)) {
		len = sizeof(post_trailer) - 1;
		if (size * nmemb < len) {
			mg_log(LOG_ERR, "libcurl frag too small");
			exit(EX_OSERR);
		}
		snprintf(buffer, len, post_trailer_templ, pd->pd_boundary);

		pd->pd_done = 1;

		goto finish;
	}

	/* Job completed */
	if (pd->pd_done)
		len = 0;
finish:
	return len;
}

static size_t
curl_outlet(buffer, size, nmemb, userp)
	void  *buffer;
	size_t size;
	size_t nmemb;
	void *userp;
{
	struct iovec *iov;
	void *newbuf;
	size_t newlen;

	iov = (struct iovec *)userp;

	newlen = iov->iov_len + (size * nmemb);

	if (newlen > URLCHECK_ANSWER_MAX) {
		mg_log(LOG_WARNING, "urlcheck answer too big, abort");
		if (iov->iov_base != NULL)
			free(iov->iov_base);
		iov->iov_base = NULL;
		iov->iov_len = 0;
		return 0;
	}

	if ((newbuf = realloc(iov->iov_base, newlen)) == NULL) {
		mg_log(LOG_ERR, "realloc() failed");
		exit(EX_OSERR);
	}
	iov->iov_base = newbuf;
	
	memcpy(iov->iov_base + iov->iov_len, buffer, size * nmemb);
	iov->iov_len = newlen;

	return (size * nmemb);
}

/* Return a locked connexion */
static struct urlcheck_cnx *
get_cnx(ue) 
	struct urlcheck_entry *ue;
{
	struct urlcheck_cnx *uc = ue->u_cnxpool;
	int i;
	int error;
	time_t oldest_date;
	int oldest_cnx;
	struct urlcheck_cnx *cnx = NULL;

	oldest_date = uc[0].uc_old;
	oldest_cnx = 0;

	/* First, try to find a free one */
	for (i = 0; i < ue->u_maxcnx; i++) {
		error = pthread_mutex_trylock(&uc[i].uc_lock);
		if (error == EBUSY) {
			if (uc[i].uc_old < oldest_date) {
				oldest_date = uc[i].uc_old;
				oldest_cnx = i;
			}
			continue;
		}
		if (error != 0) {
			mg_log(LOG_ERR, "pthread_mutex_trylock failed in "
			    "get_cnx: %s", strerror(errno));
			exit(EX_OSERR);
		}

		/* We got a lock */
		cnx = &uc[i];
		break;
	}

	/* 
	 * Nothing was free, we have to wait for a connexion.  
	 * Use the one that was locked for the longest time
	 */
	if (cnx == NULL) {
		mg_log(LOG_WARNING, "pool too small for URL check \"%s\"",
		    ue->u_name);
		cnx = &uc[oldest_cnx];
		if (pthread_mutex_lock(&cnx->uc_lock) != 0) {
			mg_log(LOG_ERR, "pthread_mutex_lock failed in "
			    "get_cnx: %s", strerror(errno));
			exit(EX_OSERR);
		}
	}

	/* 
	 * We now have a lock on a connexion 
	 * Record the time 
	 */
	cnx->uc_old = time(NULL);

	return cnx;
}


int
urlcheck_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *rcpt;
	struct urlcheck_entry *ue;
	char *url;
	int retval = 0;
	struct iovec data;
	struct urlcheck_cnx *cnx;

	rcpt = priv->priv_cur_rcpt;
	ue = ad->urlcheck;
	url = fstring_expand(priv, rcpt, ue->u_url);

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "checking \"%s\"\n", url);

	cnx = get_cnx(ue);

	data.iov_base = NULL;
	data.iov_len = 0;

	if (ue->u_flags & U_FORK)
		urlcheck_validate_pipe(&data, ue, cnx, url);
	else
		urlcheck_validate_internal(&data, ue, cnx, url, stage, priv);

	if (data.iov_base == NULL) {
		mg_log(LOG_WARNING, "urlcheck failed: no answer");
		goto out;
	}

out:
	free(url);

	if (pthread_mutex_unlock(&cnx->uc_lock) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_unlock failed: %s",
		    strerror(errno));
		exit(EX_OSERR);
	}

	if (data.iov_base) {
		retval = answer_parse(&data, ap, ue->u_flags, 
		    (ue->u_flags & U_GETPROP) ? priv : NULL);
		free(data.iov_base);
	}

	return retval;
}

static void
urlcheck_validate_pipe(data, ue, cnx, url)
	struct iovec *data;
	struct urlcheck_entry *ue;
	struct urlcheck_cnx *cnx;
	char *url;
{
	ssize_t size;

	if (cnx->uc_pid == -1) {
		/* Fork a new helper */

		if (pipe(cnx->uc_pipe_req) == -1) {
			mg_log(LOG_ERR, "pipe() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}
		if (pipe(cnx->uc_pipe_rep) == -1) {
			mg_log(LOG_ERR, "pipe() failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		switch(cnx->uc_pid = fork()) {
		case -1:
			mg_log(LOG_ERR, "fork() failed: %s", strerror(errno));
			exit(EX_OSERR);
			break;
		case 0:
			if (signal(SIGALRM, 
			    *urlcheck_helper_timeout) == SIG_ERR)
				mg_log(LOG_ERR, 
				    "signal(SIGALRM) failed: %s",
				    strerror(errno));

			if (conf.c_debug)
				mg_log(LOG_DEBUG,
				    "started urlcheck helper (pid %d)",
				    getpid());
			while (1)
				urlcheck_validate_helper(ue, cnx);
			/* NOTREACHED */
			break;
		default:
			break;
		}
	}

	size = strlen(url) + 1;

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: %d bytes to write", __func__, size);

	if ((write(cnx->uc_pipe_req[1], &size, sizeof(size)) != sizeof(size))) {
		urlcheck_cleanup_pipe(cnx);
		goto out;
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: write \"%s\"", __func__, url);

	if (write(cnx->uc_pipe_req[1], url, size) != size) {
		urlcheck_cleanup_pipe(cnx);
		goto out;
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: awaiting reply", __func__);

	if (read(cnx->uc_pipe_rep[0], &size, sizeof(size)) != sizeof(size)) {
		urlcheck_cleanup_pipe(cnx);
		goto out;
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: %d bytes to read", __func__, size);

	data->iov_len = size;
	if ((data->iov_base = malloc(size)) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (read(cnx->uc_pipe_rep[0], data->iov_base, size) != size) {
		urlcheck_cleanup_pipe(cnx);
		goto out;
	}
out:
	return;
}

void
urlcheck_helper_timeout(sig)
	int sig;
{
	if (conf.c_debug)
		mg_log(LOG_DEBUG, "urlcheck_helper_timeout");

	if (getppid() == 1) {
		mg_log(LOG_INFO, 
		    "parent died, urlcheck helper exit (pid %d)",
		    getpid());
		exit(EX_OK);
	}

	(void)alarm(URLCHECK_HELPER_TIMEOUT);

	return;
}

static void
urlcheck_validate_helper(ue, cnx)
	struct urlcheck_entry *ue;
	struct urlcheck_cnx *cnx;
{
	ssize_t size;
	char *url;
	struct iovec data;

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s", __func__);

	(void)alarm(URLCHECK_HELPER_TIMEOUT);

	if (read(cnx->uc_pipe_req[0], &size, sizeof(size)) != sizeof(size)) {
		mg_log(LOG_ERR, "urlcheck helper I/O error");
		exit(EX_OSERR);
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: %d bytes to read", __func__, size);

	if ((url = malloc(size)) == NULL) {
		mg_log(LOG_ERR, "malloc() failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if (read(cnx->uc_pipe_req[0], url, size) != size) {
		mg_log(LOG_ERR, "urlcheck helper I/O error");
		exit(EX_OSERR);
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "%s: url = \"%s\"", __func__, url);

	data.iov_base = NULL;
	data.iov_len = 0;

	/*
	 * stage and priv are used for the postmsg option. For now 
	 * it is not compatible with the fork option, so we just lie
	 * about it being AS_RCPT/NULL so that they are not used.
	 */
	urlcheck_validate_internal(&data, ue, cnx, url, AS_RCPT, NULL);

	size = data.iov_len;
	if (write(cnx->uc_pipe_rep[1], &size, sizeof(size)) != sizeof(size)) {
		mg_log(LOG_ERR, "urlcheck helper I/O error");
		exit(EX_OSERR);
	}

	if (write(cnx->uc_pipe_rep[1], data.iov_base, size) != size) {
		mg_log(LOG_ERR, "urlcheck helper I/O error");
		exit(EX_OSERR);
	}

	if (data.iov_base != NULL)
		free(data.iov_base);
	free(url);
	return;
}

static void
urlcheck_cleanup_pipe(cnx)
	struct urlcheck_cnx *cnx;
{
	if (cnx->uc_pid == -1)
		return;

	mg_log(LOG_ERR, "urlcheck I/O failed: %s", strerror(errno));

	close(cnx->uc_pipe_req[0]);
	close(cnx->uc_pipe_req[1]);
	close(cnx->uc_pipe_rep[0]);
	close(cnx->uc_pipe_rep[1]);

	mg_log(LOG_ERR, "killing helper at pid = %d", cnx->uc_pid);

	kill(cnx->uc_pid, SIGKILL);
	cnx->uc_pid = -1;

	return;
}


static void
urlcheck_validate_internal(data, ue, cnx, url, stage, priv)
	struct iovec *data;
	struct urlcheck_entry *ue;
	struct urlcheck_cnx *cnx;
	char *url;
	acl_stage_t stage;
	struct mlfi_priv *priv;
{
	CURL *ch;
	CURLcode cerr;
	struct curl_slist *headers = NULL;

	if (cnx->uc_hdl == NULL) {
		if ((cnx->uc_hdl = curl_easy_init()) == NULL) {
			mg_log(LOG_ERR, "curl_easy_init() failed");
			exit(EX_SOFTWARE);
		}
	}

	ch = cnx->uc_hdl;

	if ((cerr = curl_easy_setopt(ch, CURLOPT_URL, url)) != CURLE_OK) {
		mg_log(LOG_WARNING, "curl_easy_setopt(CURLOPT_URL) failed; %s",
		    curl_easy_strerror(cerr));
		goto out;
	}

	if ((cerr = curl_easy_setopt(ch, 
	    CURLOPT_WRITEFUNCTION, curl_outlet)) != CURLE_OK) {
		mg_log(LOG_WARNING, "curl_easy_setopt(CURLOPT_WRITEFUNCTION) "
		    "failed; %s", curl_easy_strerror(cerr));
		goto out;
	}

	if ((cerr = curl_easy_setopt(ch, 
	    CURLOPT_WRITEDATA, (void *)data)) != CURLE_OK) {
		mg_log(LOG_WARNING, "curl_easy_setopt(CURLOPT_WRITEDATA) "
		    "failed; %s", curl_easy_strerror(cerr));
		goto out;
	}

	if ((stage == AS_DATA) &&
	    (ue->u_flags & U_POSTMSG) && 
	    !TAILQ_EMPTY(&priv->priv_header)) {
		struct post_data pd;
		size_t len;
		char head_templ[] = 
		    "Content-Type: multipart/form-data; boundary=%s";
		char head[sizeof(head_templ) - 2 + BOUNDARY_LEN];

		if (find_boundary(priv, pd.pd_boundary) == -1) {
			mg_log(LOG_WARNING, 
			    "Unable to create a MIME boundary, "
			    "not posting message");
			goto out;
		}

		sprintf(head, head_templ, pd.pd_boundary);

		if (headers == NULL)
			headers = curl_slist_append(headers, head);
		
		if ((cerr = curl_easy_setopt(ch, 
		    CURLOPT_HTTPHEADER, headers)) != CURLE_OK) {
			mg_log(LOG_WARNING, 
			    "curl_easy_setopt(CURLOPT_HTTPHEADERS) "
			    "failed; %s", curl_easy_strerror(cerr));
			goto out;
		}

		if ((cerr = curl_easy_setopt(ch, 
		    CURLOPT_POST, 1)) != CURLE_OK) {
			mg_log(LOG_WARNING, 
			    "curl_easy_setopt(CURLOPT_POST) "
			    "failed; %s", curl_easy_strerror(cerr));
			goto out;
		}

		len = sizeof(post_header) - 1 
		    + priv->priv_msgcount
		    + sizeof(post_trailer) - 1;
		if ((cerr = curl_easy_setopt(ch, 
		    CURLOPT_POSTFIELDSIZE, len)) != CURLE_OK) {
			mg_log(LOG_WARNING, 
			    "curl_easy_setopt(CURLOPT_POSTFIELDSIZE) "
			    "failed; %s", curl_easy_strerror(cerr));
			goto out;
		}

		if ((cerr = curl_easy_setopt(ch, 
		    CURLOPT_READFUNCTION, curl_post)) != CURLE_OK) {
			mg_log(LOG_WARNING, 
			    "curl_easy_setopt(CURLOPT_READFUNCTION) "
			    "failed; %s", curl_easy_strerror(cerr));
			goto out;
		}

		pd.pd_priv = priv;
		pd.pd_curhdr = TAILQ_FIRST(&priv->priv_header);
		pd.pd_curbody = TAILQ_FIRST(&priv->priv_body);
		pd.pd_curptr = NULL;
		pd.pd_done = 0;

		if ((cerr = curl_easy_setopt(ch, 
		    CURLOPT_READDATA, (void *)&pd)) != CURLE_OK) {
			mg_log(LOG_WARNING, 
			    "curl_easy_setopt(CURLOPT_READDATA) "
			    "failed; %s", curl_easy_strerror(cerr));
			goto out;
		}
	}

	if ((cerr = curl_easy_perform(ch)) != CURLE_OK) {
		mg_log(LOG_WARNING, "curl_easy_perform() failed; %s",
		    curl_easy_strerror(cerr));
		goto out;
	}

	if (data->iov_base == NULL) {
		mg_log(LOG_WARNING, "urlcheck failed: no answer");
		goto out;
	}

out:
	if (headers != NULL)
		curl_slist_free_all(headers);

	if (cnx->uc_hdl)
		curl_easy_cleanup(cnx->uc_hdl);
	cnx->uc_hdl = NULL;

	return;
}

static int
answer_parse(data, ap, flags, priv)
	struct iovec *data;
	struct acl_param *ap;
	int flags;
	struct mlfi_priv *priv;
{
	int idx;
	char *buf;
	size_t len;
	char *linep;
	char *valp;
	int retval = 0;

	buf = data->iov_base;
	len = data->iov_len;
	idx = 0;

	if (len == 0) {
		mg_log(LOG_DEBUG, "ignoring blank reply");
		return -1;
	}
	buf[len - 1] = '\0';	/* Prevent run-away printf */
	len--;			/* Stop before trailing 0 */

	while (idx < len) {
		/* strip spaces */
		while ((idx < len) && isspace((int)buf[idx]))
			idx++;
		linep = buf + idx;

		if (idx == len)
			break;

		if (buf[idx] == '\n') {
			idx++;
			continue;
		}

		/* find the : */
		while ((idx < len) && 
		       (buf[idx] != '\n') && 
		       (buf[idx] != ':')) 
			idx++;

		if (idx == len) 
			break;

		if (buf[idx] == '\n') {
			buf[idx] = '\0';
			mg_log(LOG_DEBUG, 
			    "ignoring unexpected line with no value \"%s\"", 
			    linep);
			idx++;
			continue;
		}

		/* Cut linep */
		buf[idx] = '\0';
		idx++;

		/* Strip spaces in valp */
		while ((idx < len) && isspace((int)buf[idx]))
			idx++;
		valp = buf + idx;

		if (idx == len)
			break;

		if (buf[idx] == '\n') {
			buf[idx] = '\0';
			mg_log(LOG_DEBUG, "ignoring line \"%s: %s\"", 
			    linep, valp);
			idx++;
			continue;
		}

		/* Look for end of line */
		while ((idx < len) && 
		       (buf[idx] != '\n'))
			idx++;

		if (idx == len) {
			buf[idx] = '\0';
			mg_log(LOG_DEBUG, 
			    "ignoring unexpected line \"%s: %s\"", 
			    linep, valp);
			break;
		}

		/* cut valp */
		buf[idx] = '\0';
		idx++;

		if (answer_getline(linep, valp, ap) == -1) {
			if (!(flags & U_GETPROP))
				mg_log(LOG_DEBUG, 
				    "ignoring unepxected \"%s\" => \"%s\"",
				    linep, valp);
		} else {
			/* We have a match! */
			retval = 1;
		}

		if (flags & U_GETPROP)
			urlcheck_prop_push(linep, valp, flags, priv);
	}

	/* 
	 * If we did not match, toss the gathered properties
	 * otherwise clear the tmp flag
	 */
	if (flags & U_GETPROP) {
		if (retval == 0)
			urlcheck_prop_clear_tmp(priv);
		else
			urlcheck_prop_untmp(priv);
	}

	return retval;
}

static int
answer_getline(key, value, ap)
	char *key;
	char *value;
	struct acl_param *ap;
{
#ifdef URLCHECK_DEBUG
	if (conf.c_debug)
		mg_log(LOG_DEBUG, "urlcheck got \"%s\" => \"%s\"",
		    key, value);
#endif
	if (strcasecmp(key, "milterGreylistStatus") == 0) {
		if ((strcasecmp(value, "Ok") == 0) ||
		    (strcasecmp(value, "TRUE") == 0))
		goto out;
	}

	if (strcasecmp(key, "milterGreylistAction") == 0) {
		if (strcasecmp(value, "greylist") == 0)
			ap->ap_type = A_GREYLIST;
		else if (strcasecmp(value, "blacklist") == 0)
			ap->ap_type = A_BLACKLIST;
		else if (strcasecmp(value, "whitelist") == 0)
			ap->ap_type = A_WHITELIST;
		else 
			mg_log(LOG_WARNING, "ignored greylist-type \"%s\"",
			    value);
		goto out;
	}

	if (strcasecmp(key, "milterGreylistDelay") == 0) {
		ap->ap_delay = humanized_atoi(value);
		goto out;
	}

	if (strcasecmp(key, "milterGreylistAutowhite") == 0) {
		ap->ap_autowhite = humanized_atoi(value);
		goto out;
	}

	if (strcasecmp(key, "milterGreylistFlushAddr") == 0) {
		ap->ap_flags |= A_FLUSHADDR;
		goto out;
	}

	if (strcasecmp(key, "milterGreylistCode") == 0) {
		if ((ap->ap_code = strdup(value)) == NULL) {
			mg_log(LOG_ERR, "strdup(\"%s\") failed: %s",
			    key, strerror(errno));
			exit(EX_OSERR);
		}
		ap->ap_flags |= A_FREE_CODE;
		goto out;
	}

	if (strcasecmp(key, "milterGreylistEcode") == 0) {
		if ((ap->ap_ecode = strdup(value)) == NULL) {
			mg_log(LOG_ERR, "strdup(\"%s\") failed: %s",
			    key, strerror(errno));
			exit(EX_OSERR);
		}
		ap->ap_flags |= A_FREE_ECODE;
		goto out;
	}

	if (strcasecmp(key, "milterGreylistMsg") == 0) {
		if ((ap->ap_msg = strdup(value)) == NULL) {
			mg_log(LOG_ERR, "strdup(\"%s\") failed: %s",
			    key, strerror(errno));
			exit(EX_OSERR);
		}
		ap->ap_flags |= A_FREE_MSG;
		goto out;
	}

	if (strcasecmp(key, "milterGreylistReport") == 0) {
		if ((ap->ap_report = strdup(value)) == NULL) {
			mg_log(LOG_ERR, "strdup(\"%s\") failed: %s",
			    key, strerror(errno));
			exit(EX_OSERR);
		}
		ap->ap_flags |= A_FREE_REPORT;
		goto out;
	}

	return -1;
out:
	return 0;
}

static void
urlcheck_prop_push(linep, valp, flags, priv)
	char *linep;
	char *valp;
	int flags;
	struct mlfi_priv *priv;
{
	char *cp;
	struct urlcheck_prop *up;

	if ((up = malloc(sizeof(*up))) == NULL) {
		mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((up->up_name = strdup(linep)) == NULL) {
		mg_log(LOG_ERR, "strup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	if ((up->up_value = strdup(valp)) == NULL) {
		mg_log(LOG_ERR, "strdup failed: %s", strerror(errno));
		exit(EX_OSERR);
	}

	/*
	 * Convert everything to lower-case
	 */
	for (cp = up->up_name; *cp; cp++)
		*cp = (char)tolower((int)*cp);

	for (cp = up->up_value; *cp; cp++)
		*cp = (char)tolower((int)*cp);

	up->up_flags = UP_TMPPROP;
	if (flags & U_CLEARPROP);
		up->up_flags |= UP_CLEARPROP;

	LIST_INSERT_HEAD(&priv->priv_prop, up, up_list);

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "got prop $%s = \"%s\"", linep, valp);

	return;
}

void
urlcheck_prop_clear_all(priv)
	struct mlfi_priv *priv;
{
	struct urlcheck_prop *up;

	while ((up = LIST_FIRST(&priv->priv_prop)) != NULL) {
		free(up->up_name);
		free(up->up_value);
		LIST_REMOVE(up, up_list);
		free(up);
	}

	return;
}

int 
urlcheck_prop_string_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct urlcheck_prop *up;
	acl_data_t *upd;
	char *string;
	int retval = 0;

	upd = (acl_data_t *)&ad->prop->upd_data;
	string = fstring_expand(priv, NULL, upd->string);

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(ad->prop->upd_name, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs \"%s\"",
			    up->up_name, up->up_value, string);

		if (strcasecmp(up->up_value, string) == 0) {
			retval = 1;
			break;
		}
	}

	free(string);	
	return retval;
}

void
urlcheck_prop_clear(priv)
	struct mlfi_priv *priv; 
{
	struct urlcheck_prop *up;
	struct urlcheck_prop *nup;

	up = LIST_FIRST(&priv->priv_prop); 

	while (up != NULL) {
		nup = LIST_NEXT(up, up_list);
		if (up->up_flags & UP_CLEARPROP) {
			free(up->up_name);
			free(up->up_value);
			LIST_REMOVE(up, up_list);
			free(up);
		}
		up = nup;
	}
	return;
}

static void
urlcheck_prop_clear_tmp(priv)
	struct mlfi_priv *priv; 
{
	struct urlcheck_prop *up;
	struct urlcheck_prop *nup;

	up = LIST_FIRST(&priv->priv_prop); 

	while (up != NULL) {
		nup = LIST_NEXT(up, up_list);
		if (up->up_flags & UP_TMPPROP) {
			free(up->up_name);
			free(up->up_value);
			LIST_REMOVE(up, up_list);
			free(up);
		}
		up = nup;
	}
	return;
}

static void
urlcheck_prop_untmp(priv)
	struct mlfi_priv *priv; 
{
	struct urlcheck_prop *up;

	LIST_FOREACH(up, &priv->priv_prop, up_list)
		up->up_flags &= ~UP_TMPPROP;
	return;
}

int 
urlcheck_prop_regex_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv; 
{
	struct urlcheck_prop *up;
	acl_data_t *upd;
	int retval = 0;

	upd = (acl_data_t *)&ad->prop->upd_data;

	LIST_FOREACH(up, &priv->priv_prop, up_list) {
		if (strcasecmp(ad->prop->upd_name, up->up_name) != 0)
			continue;

		if (conf.c_debug)
			mg_log(LOG_DEBUG, "test $%s = \"%s\" vs %s",
			    up->up_name, up->up_value, upd->regex.re_copy);

		if (myregexec(priv, upd, ap, up->up_value) == 0) {
			retval = 1;
			break;
		}
	}

	return retval;
}
#endif /* USE_CURL */
