/* $Id: clock.c,v 1.2 2007/04/20 02:36:50 manu Exp $ */

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
__RCSID("$Id: clock.c,v 1.2 2007/04/20 02:36:50 manu Exp $");
#endif
#endif

#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <sysexits.h>
#include <time.h>
#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else 
#include <sys/queue.h>
#endif

#include "conf.h"
#include "acl.h"
#include "milter-greylist.h"
#include "clock.h"

static int clock_validate(int *, int *, int);
static int clock_dump(char *, size_t, struct clockspec *, int);

static struct clockspec *gcs = NULL; 
static int current_cs = -1;

void
add_clock_item(start, end, repeat)
	int start;
	int end;
	int repeat;
{
	int i;
	int count;

	if (gcs == NULL) {
		if ((gcs = malloc(sizeof(*gcs))) == NULL) {
			mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		for (i = 0; i < CS_MAX; i++)
			LIST_INIT(&gcs->cs_items[i]);

		current_cs = CS_MINUTE;
	}

#if 0
	if (conf.c_debug)
		mg_log(LOG_DEBUG, "add_clock_item: %d-%d/%d @ %d",
		    start, end, repeat, current_cs);
#endif

	if (current_cs == CS_MAX) {
		mg_log(LOG_ERR, 
		    "too many field in time specification at %d",
		    conf_line);
		return;
	}

	if (clock_validate(&start, &end, current_cs) != 0) {
		if (conf.c_debug)
			mg_log(LOG_DEBUG, 
			    "start = %d, end = %d\n", 
			    start, end);
		return;
	}

	if (repeat == 0)
		count = 1;
	else
		count = (1 + end - start) / repeat;

	for (i = 0; i < count; i++) {
		struct clockspec_item *ci;

		if ((ci = malloc(sizeof(*ci))) == NULL) {
			mg_log(LOG_ERR, "malloc failed: %s", strerror(errno));
			exit(EX_OSERR);
		}

		ci->ci_start = start + (i * repeat);
		if (repeat == 0)
			ci->ci_end = end;
		else
			ci->ci_end = ci->ci_start;

		LIST_INSERT_HEAD(&gcs->cs_items[current_cs], ci, ci_list);
	}

}

struct clockspec *
register_clock(void)
{
	struct clockspec *cs;

	if (conf.c_debug) {
		int i;
		char buf[CS_MAX][QSTRLEN + 1];

		for (i = 0; i < CS_MAX; i++)
			clock_dump(buf[i], QSTRLEN, gcs, i);

		mg_log(LOG_DEBUG, "load time \"%s %s %s %s %s\"", 
		    buf[0], buf[1], buf[2], buf[3], buf[4]);
	}

	cs = gcs;
	gcs = NULL;

	return cs;
}


int
clock_validate(sp, ep, cs)
	int *sp;
	int *ep;
	int cs;
{
	if (*sp > *ep) {
		mg_log(LOG_WARNING, 
		    "invalid time specification: %d > %d at %d",
		    *sp, *ep, conf_line);
		    return -1;
	}
		
	switch (cs) {
	case CS_MINUTE:
		if ((*ep == -1) && (*sp == -1)) {
			*ep = 59;
			*sp = 0;
		}

		if (*ep > 59) {
			mg_log(LOG_WARNING, 
			    "invalid time specification: greater than 59 at %d",
			    conf_line);
			return -1;
		}
		break;
	case CS_HOUR:
		if ((*ep == -1) && (*sp == -1)) {
			*ep = 23;
			*sp = 0;
		}

		if (*ep > 23) {
			mg_log(LOG_WARNING, 
			    "invalid time specification: greater than 23 at %d",
			    conf_line);
			return -1;
		}
		break;
	case CS_MONTHDAY:
		if ((*ep == -1) && (*sp == -1)) {
			*ep = 31;
			*sp = 1;
		}

		if (*ep > 31) {
			mg_log(LOG_WARNING, 
			    "invalid time specification: greater than 31 at %d",
			    conf_line);
			return -1;
		}
		break;
	case CS_MONTH:
		if ((*ep == -1) && (*sp == -1)) {
			*ep = 12;
			*sp = 1;
		}

		if (*ep > 12) {
			mg_log(LOG_WARNING, 
			    "invalid time specification: greater than 12 at %d",
			    conf_line);
			return -1;
		}
		break;
	case CS_WEEKDAY:
		if ((*ep == -1) && (*sp == -1)) {
			*ep = 6;
			*sp = 0;
		}

		if (*ep == 7)
			*ep = 0;
		if (*sp == 7)
			*sp = 0;
			
		if (*ep > 7) {
			mg_log(LOG_WARNING, 
			    "invalid time specification: greater than 7 at %d",
			    conf_line);
			return -1;
		}
		break;

	default:
		mg_log(LOG_ERR, "unexpected current_cs");
		exit(EX_OSERR);
		break;
	}

	return 0;
}


void
add_clockspec(ad, cs)
	acl_data_t *ad;
	void *cs;
{
	ad->clockspec = (struct clockspec *)cs;
	return;
}

int
clockspec_filter(ad, stage, ap, priv)
	acl_data_t *ad;
	acl_stage_t stage;
	struct acl_param *ap;  
	struct mlfi_priv *priv; 
{
	time_t now;
	struct tm tm;
	struct clockspec *cs;
	struct clockspec_item *ci;
	int match[CS_MAX] = { 0, 0, 0, 0, 0 };

	cs = ad->clockspec;

	now = time(NULL);
	(void)localtime_r(&now, &tm);

	if (conf.c_debug)
		mg_log(LOG_DEBUG, 
		    "current time %d %d %d %d %d",
		    tm.tm_min, tm.tm_hour, tm.tm_mday, 
		    tm.tm_mon + 1, tm.tm_wday);

	LIST_FOREACH(ci, &cs->cs_items[CS_MINUTE], ci_list)
		if ((tm.tm_min >= ci->ci_start) && (tm.tm_min <= ci->ci_end))
			break;
	if (ci == NULL)
		goto fail;
	match[CS_MINUTE] = 1;

	LIST_FOREACH(ci, &cs->cs_items[CS_HOUR], ci_list)
		if ((tm.tm_hour >= ci->ci_start) && (tm.tm_hour <= ci->ci_end))
			break;
	if (ci == NULL)
		goto fail;
	match[CS_HOUR] = 1;

	LIST_FOREACH(ci, &cs->cs_items[CS_MONTHDAY], ci_list)
		if ((tm.tm_mday >= ci->ci_start) && (tm.tm_mday <= ci->ci_end))
			break;
	if (ci == NULL)
		goto fail;
	match[CS_MONTHDAY] = 1;

	LIST_FOREACH(ci, &cs->cs_items[CS_MONTH], ci_list)
		if ((tm.tm_mon + 1 >= ci->ci_start) && 
		    (tm.tm_mon + 1 <= ci->ci_end))
			break;
	if (ci == NULL)
		goto fail;
	match[CS_MONTH] = 1;

	LIST_FOREACH(ci, &cs->cs_items[CS_WEEKDAY], ci_list)
		if ((tm.tm_wday >= ci->ci_start) && (tm.tm_wday <= ci->ci_end))
			break;
	if (ci == NULL)
		goto fail;
	match[CS_WEEKDAY] = 1;

	if (conf.c_debug) {
		char buf[QSTRLEN + 1];

		mg_log(LOG_DEBUG, "time match %s", 
		    print_clockspec(ad, buf, QSTRLEN));
	}

	return 1;
fail:
	if (conf.c_debug) {
		mg_log(LOG_DEBUG, "%s%s%s%s%smatched",
		    match[CS_MINUTE] ? "minutes " : "",
		    match[CS_HOUR] ? "hours " : "",
		    match[CS_MONTHDAY] ? "mday " : "",
		    match[CS_MONTH] ? "month " : "",
		    match[CS_WEEKDAY] ? "wday " : "");
	}
	return 0;
}

void
next_clock_spec(void)
{
	current_cs++;
}

static int
clock_dump(buf, len, cs, ccs)
	char *buf;
	size_t len;
	struct clockspec *cs;
	int ccs; 
{
	struct clockspec_item *ci;
	int written = 0;
	int first = 1;

	LIST_FOREACH(ci, &cs->cs_items[ccs], ci_list) {
		written += snprintf(buf + written, len - written, "%s%d-%d", 
		    first ? "" : ",", ci->ci_start, ci->ci_end);
		first = 0;
	}

	return written;
}

char *
print_clockspec(ad, buf, len)
	acl_data_t *ad;
	char *buf;
	size_t len;
{
	struct clockspec *cs = ad->clockspec;
	int written = 0;
	int first = 1;
	int i;

	written = snprintf(buf + written, len - written, "\"");

	for (i = 0; i < CS_MAX; i++) {
		if (first)
			first = 0;
		else
			written += snprintf(buf + written, len - written, " ");
		written += clock_dump(buf + written, len - written, cs, i);
	}


	written = snprintf(buf + written, len - written, "\"");

	return buf;
}

void
clockspec_free(ad)
	acl_data_t *ad;
{
	struct clockspec *cs = ad->clockspec;
	struct clockspec_item *ci;
	int i;

	for (i = 0; i < CS_MAX; i++) {
		while ((ci = LIST_FIRST(&cs->cs_items[i])) != NULL) {
			LIST_REMOVE(ci, ci_list);
			free(ci);
		}
	}
	free(cs);
}
