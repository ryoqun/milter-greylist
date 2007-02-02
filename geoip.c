/* $Id: geoip.c,v 1.1 2007/02/02 07:00:06 manu Exp $ */

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

#ifdef USE_GEOIP

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id");
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include <sys/param.h>

#include <GeoIP.h>

#include "milter-greylist.h"
#include "conf.h"
#include "geoip.h"

static GeoIP *geoip_handle = NULL;
static char geoip_database[MAXPATHLEN + 1];

void
geoip_set_db(name)
	char *name;
{
	if (geoip_handle != NULL) {
		GeoIP_delete(geoip_handle);
		geoip_handle = NULL;
	}
	
	strncpy(geoip_database, name, MAXPATHLEN);
	geoip_database[MAXPATHLEN] = '\0';

	geoip_handle = GeoIP_open(geoip_database, GEOIP_STANDARD);
	if (geoip_handle == NULL) {
		mg_log(LOG_WARNING, 
		    "GeoIP databade \"%s\" cannot be used",
		    geoip_database);
		return;
	}
}

int
geoip_filter(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;
	struct mlfi_priv *priv;
{
	char *ccode = ad->string;

	if (priv->priv_ccode == NULL)
		return 0;

	if (strcmp(ccode, priv->priv_ccode) == 0)
		return 1;
	else
		return 0;
}

void
geoip_set_ccode(priv)
	struct mlfi_priv *priv;
{
	char ipstr[IPADDRSTRLEN];
	int cid;

	if (geoip_handle == NULL) {
		mg_log(LOG_WARNING, "GeoIP is not available");
		priv->priv_ccode = NULL;
		return;
	}

	if (iptostring(SA(&priv->priv_addr),
	    priv->priv_addrlen, ipstr, sizeof(ipstr)) == NULL) {
		mg_log(LOG_DEBUG, "GeoIP iptostring failed");
		priv->priv_ccode = NULL;
		return;
	}

	cid = GeoIP_id_by_name(geoip_handle, priv->priv_hostname);

	priv->priv_ccode = GeoIP_country_code[cid];	

	return;
}

#endif /* USE_GEOIP */
