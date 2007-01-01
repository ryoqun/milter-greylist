/* $Id: urlcheck.c,v 1.7 2007/01/01 10:57:13 manu Exp $ */

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
__RCSID("$Id: urlcheck.c,v 1.7 2007/01/01 10:57:13 manu Exp $");
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
#include <sys/types.h>

#include "milter-greylist.h"
#include "pending.h"
#include "acl.h"
#include "conf.h"
#include "urlcheck.h"

/* 
 * locking is done through the same lock as acllist: both are static 
 * configuration, which are readen or changed at the same times.
 */
struct urlchecklist urlcheck_head;

static char *fstring_expand(struct mlfi_priv *, 
    char *, char *);
static size_t curl_outlet(void *, size_t, size_t, void *);
static int answer_parse(struct iovec *, struct acl_param *);
static int answer_getline(char *, char *, struct acl_param *);
static struct urlcheck_cnx *get_cnx(struct urlcheck_entry *);
static char *strip_brackets(char *, char *, size_t);
static char *mbox_only(char *, char *, size_t);
static char *site_only(char *, char *, size_t);
static char *machine_only(char *, char *, size_t);
static char *domain_only(char *, char *, size_t);

#define URLCHECK_ANSWER_MAX	4096

void
urlcheck_init(void) {
	LIST_INIT(&urlcheck_head);
	curl_global_init(CURL_GLOBAL_ALL);
	return;
}


void
urlcheck_def_add(name, url, max_cnx) /* acllist must be write locked */
	char *name;
	char *url;
	int max_cnx;
{
	struct urlcheck_entry *ue;
	struct urlcheck_cnx *uc;

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

	if ((uc = malloc(max_cnx * sizeof(*uc))) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed for URL check cnx pool: %s",
		    max_cnx * sizeof(*uc), strerror(errno));
		exit(EX_OSERR);
	}
	ue->u_cnxpool = uc;

	while (max_cnx > 0) {
		uc->uc_hdl = NULL;
		uc->uc_old = 0;
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
		mg_log(LOG_DEBUG, "load URL check \"%s\" \"%s\" %d", 
		    ue->u_name, ue->u_url, ue->u_maxcnx);
	}

	return;
}

struct urlcheck_entry *
urlcheck_byname(urlcheck)	/* acllist must be read locked */
	char *urlcheck;
{
	struct urlcheck_entry *ue;	

	LIST_FOREACH(ue, &urlcheck_head, u_list) {
		if (strcmp(ue->u_name, urlcheck) == 0)
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
fstring_expand(priv, rcpt, fstring)
	struct mlfi_priv *priv;
	char *rcpt;
	char *fstring;
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
		 * If first time, there is no '%' to substitue yet 
		 * (no URL starts by '%')
		 */
		if (tmpstrp != NULL) {
			tmpstrp = NULL;
			mystrncat(&outstr, ptok, &outmaxlen);
			continue;
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
			char ipstr[IPADDRSTRLEN];

			iptostring(SA(&priv->priv_addr),
			    priv->priv_addrlen, ipstr, sizeof(ipstr));
			mystrncat(&outstr, ipstr, &outmaxlen);
			break;
		}
		case 'T': {	/* current time %T{strftime_string} */
			char *cp;
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
	 * Record the time and initialize it if needed
	 */
	cnx->uc_old = time(NULL);

	if (cnx->uc_hdl == NULL) {
		if ((cnx->uc_hdl = curl_easy_init()) == NULL) {
			mg_log(LOG_ERR, "curl_easy_init() failed");
			exit(EX_SOFTWARE);
		}
	}

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
	CURL *ch;
	CURLcode cerr;
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

	data.iov_base = NULL;
	data.iov_len = 0;
	if ((cerr = curl_easy_setopt(ch, 
	    CURLOPT_WRITEDATA, (void *)&data)) != CURLE_OK) {
		mg_log(LOG_WARNING, "curl_easy_setopt(CURLOPT_WRITEDATA) "
		    "failed; %s", curl_easy_strerror(cerr));
		goto out;
	}

	if ((cerr = curl_easy_perform(ch)) != CURLE_OK) {
		mg_log(LOG_WARNING, "curl_easy_perform() failed; %s",
		    curl_easy_strerror(cerr));
		goto out;
	}

	if (data.iov_base == NULL) {
		mg_log(LOG_WARNING, "urlcheck failed: no answer");
		goto out;
	}

	retval = answer_parse(&data, ap);
out:
	if (pthread_mutex_unlock(&cnx->uc_lock) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_unlock failed: %s",
		    strerror(errno));
		exit(EX_OSERR);
	}

	free(url);
	return retval;
}

static int
answer_parse(data, ap)
struct iovec *data;
	struct acl_param *ap;
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

	linep = buf;

	/* strip spaces */
	while (isspace((int)*linep))
		linep++;

	valp = NULL;
	while (idx < len) {
		if (buf[idx] == ':') {
			buf[idx] = '\0';
			valp = buf + idx + 1;

			/* Strip spaces */
			while (isspace((int)*valp))
				valp++;
		}

		if (buf[idx] == '\n') {
			buf[idx] = '\0';

			if (valp == NULL) {
				mg_log(LOG_DEBUG, 
				    "ignoring unepxected line \"%s\"", linep);
			} else if (answer_getline(linep, valp, ap) == -1) {
				mg_log(LOG_DEBUG, 
				    "ignoring unepxected \"%s\" => \"%s\"",
				    linep, valp);
			} else {
				/* We have a match! */
				retval = 1;
			}
			linep = buf + idx + 1;
			while (isspace((int)*linep))
				linep++;
		}

		idx++;
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

	return -1;
out:
	return 0;
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
#endif /* USE_URLCHECK */
