/* $Id: dkimcheck.c,v 1.4 2008/10/30 04:39:39 manu Exp $ */

/*
 * Copyright (c) 2008 Emmanuel Dreyfus
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

#ifdef USE_DKIM

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID  
__RCSID("$Id: dkimcheck.c,v 1.4 2008/10/30 04:39:39 manu Exp $");
#endif
#endif
#include <ctype.h>
#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#endif
#include <dkim.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <stdlib.h>
#include <syslog.h>

#include "conf.h"
#include "spf.h"
#include "acl.h"
#include "milter-greylist.h"
#include "dkimcheck.h"

static DKIM_LIB *dkim_ptr = NULL;
static sfsistat dkimcheck_error(struct mlfi_priv *);

static sfsistat
dkimcheck_error(priv)
	struct mlfi_priv *priv;
{
	sfsistat retval;

	switch (priv->priv_dkimstat) {
	case DKIM_STAT_OK:
		retval = SMFIS_CONTINUE;
		break;

	case DKIM_STAT_NOSIG: 
		mg_log(LOG_DEBUG, "DKIM failed: %s",
		       dkim_getresultstr(priv->priv_dkimstat));

		retval = SMFIS_CONTINUE;
		break;

	case DKIM_STAT_KEYFAIL:
	case DKIM_STAT_CBTRYAGAIN:
		mg_log(LOG_WARNING, "DKIM failed: %s",
		       dkim_getresultstr(priv->priv_dkimstat));

		retval = SMFIS_TEMPFAIL;
		break;

	case DKIM_STAT_INTERNAL:
		mg_log(LOG_WARNING, "DKIM failed: %s",
		       dkim_getresultstr(priv->priv_dkimstat));

		exit(EX_OSERR);
		break;

	default:
		mg_log(LOG_ERR, "DKIM failed: %s",
		       dkim_getresultstr(priv->priv_dkimstat));

		retval = SMFIS_CONTINUE;
		break;
	}

	if (priv->priv_dkim != DKIM_STAT_OK) {
		(void)dkim_free(priv->priv_dkim);
		priv->priv_dkim = NULL;
	}

	return retval;
}

void
dkimcheck_init(void)
{
	if ((dkim_ptr = dkim_init(NULL, NULL)) == NULL) {
		mg_log(LOG_ERR, "dkim_init() failed");
		exit(EX_OSERR);
	}

	return;
}

void
dkimcheck_clear(void)
{
	/*
	 * XXX This probably leaves stale handles for messages being processed
	 */
	if (dkim_ptr != NULL)
		dkim_close(dkim_ptr);
	dkim_ptr = NULL;

	dkimcheck_init();
	return;
}

sfsistat
dkimcheck_header(name, value, priv)
	char *name;
	char *value;
	struct mlfi_priv *priv;
{
	unsigned char *header;
	size_t len;

	if (priv->priv_dkim == NULL) {
		/* 
		 * priv->priv_dkim may be NULL because we never 
		 * handled a header, or because we encountered an
		 * error. In the latter case, priv->priv_dkimstat
		 * is set to an error value different than DKIM_STAT_OK
		 * and we do not try to run DKIM again.
		 */
		if (priv->priv_dkimstat != DKIM_STAT_OK)
			return SMFIS_CONTINUE;

		priv->priv_dkim = dkim_verify(dkim_ptr, priv->priv_queueid,
					      NULL, &priv->priv_dkimstat);
		if (priv->priv_dkim == NULL) {
			mg_log(LOG_ERR, "dkim_verify() failed: %s",
			       dkim_getresultstr(priv->priv_dkimstat));
			return SMFIS_CONTINUE;
		}
	}

	/* 2 for ": " */
	len = strlen(name) + strlen(value) + 2;
	if ((header = malloc(len + 1)) == NULL) {
		mg_log(LOG_ERR, "malloc(%d) failed: %s",
				 len, strerror(errno));
		exit (EX_OSERR);
	}

	(void)snprintf((char *)header, len, "%s: %s", name, value);
	priv->priv_dkimstat = dkim_header(priv->priv_dkim, header, len);

	free(header);

	return dkimcheck_error(priv);
}

sfsistat
dkimcheck_eoh(priv)
	struct mlfi_priv *priv;
{
	if (priv->priv_dkim == NULL)
		return SMFIS_CONTINUE;

	priv->priv_dkimstat = dkim_eoh(priv->priv_dkim);
	return dkimcheck_error(priv);
}

sfsistat
dkimcheck_body(chunk, size, priv)
	unsigned char *chunk;
	size_t size;
	struct mlfi_priv *priv;
{
	if (priv->priv_dkim == NULL)
		return SMFIS_CONTINUE;

	priv->priv_dkimstat = dkim_body(priv->priv_dkim, chunk, size);
	return dkimcheck_error(priv);
}

sfsistat
dkimcheck_eom(priv)
	struct mlfi_priv *priv;
{
	bool testkey;

	if (priv->priv_dkim == NULL)
		return SMFIS_CONTINUE;

	priv->priv_dkimstat = dkim_eom(priv->priv_dkim, &testkey);
	return dkimcheck_error(priv);
}

int
dkimcheck_validate(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	enum spf_status stat;
	int result;

	if (stage != AS_DATA) {
		mg_log(LOG_ERR, "dkim clause called at non DATA stage");
		exit(EX_SOFTWARE);
	}

	stat = ad ? *(enum spf_status *)ad : MGSPF_PASS;

	switch (stat) {
	case MGSPF_PASS:
		result = (priv->priv_dkimstat == DKIM_STAT_OK);
		break;

	case MGSPF_FAIL:
		switch (priv->priv_dkimstat) {
		case DKIM_STAT_BADSIG:
		case DKIM_STAT_NOKEY:
		case DKIM_STAT_REVOKED:
		case DKIM_STAT_CBREJECT:
			result = 1;
			break;
		default:
			result = 0;
		}
		break;

	case MGSPF_ERROR:
		switch (priv->priv_dkimstat) {
		case DKIM_STAT_SYNTAX:
		case DKIM_STAT_INVALID:
		case DKIM_STAT_NOTIMPLEMENT:
		case DKIM_STAT_CBERROR:
		case DKIM_STAT_MULTIDNSREPLY:
			result = 1;
			break;
		default:
			result = 0;
		}
		break;

	case MGSPF_NONE:
		result = (priv->priv_dkimstat == DKIM_STAT_NOSIG);
		break;

	case MGSPF_UNKNOWN:
		result = (priv->priv_dkimstat == DKIM_STAT_CANTVRFY);
		break;

	default:
		mg_log(LOG_ERR, "Internal error: unexpected dkim_status");
		exit(EX_SOFTWARE);
		break;
	}
	
	return result;
}

char *
acl_print_dkim(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	char *tmpstr;
	enum spf_status status;

	status = ad ? *(enum spf_status *)ad : MGSPF_PASS;
	switch (status) {
	case MGSPF_PASS:
		tmpstr = "pass";
		break;
	case MGSPF_FAIL:
		tmpstr = "fail";
		break;
	case MGSPF_UNKNOWN:
		tmpstr = "unknown";
		break;
	case MGSPF_ERROR:
		tmpstr = "error";
		break;
	case MGSPF_NONE:
		tmpstr = "none";
		break;
	default:
		mg_log(LOG_ERR, "Internal error: unexpected dkim_status");
		exit(EX_SOFTWARE);
		break;
	}
	snprintf(buf, len, "%s", tmpstr);
	return buf;
}

void
acl_add_dkim(ad, data)
	acl_data_t *ad;
	void *data;
{
	enum spf_status status;
	char buf[QSTRLEN + 1];

	status = *(enum spf_status *)data;

	switch (status) {
	case MGSPF_PASS:
	case MGSPF_FAIL:
	case MGSPF_UNKNOWN:
	case MGSPF_ERROR:
	case MGSPF_NONE:
		ad->dkim_status = *(enum spf_status *)data;
		break;
	default:
		acl_print_dkim((acl_data_t *)&status, buf, QSTRLEN);
		mg_log(LOG_ERR, "bad DKIM status %s", buf);
		exit(EX_USAGE);
		break;
	}

	return;
}

void
dkimcheck_free(priv)
	struct mlfi_priv *priv;
{
	if (priv->priv_dkim != NULL) {
		dkim_free(priv->priv_dkim);
		priv->priv_dkim = NULL;
	}
	return;
}

#endif /* USE_DKIM */
