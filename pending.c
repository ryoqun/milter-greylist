/* $Id: pending.c,v 1.52 2004/05/21 10:22:08 manu Exp $ */

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
__RCSID("$Id: pending.c,v 1.52 2004/05/21 10:22:08 manu Exp $");
#endif
#endif

#ifdef HAVE_OLD_QUEUE_H 
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sysexits.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>

#ifdef HAVE_DB_185_H
#include <db_185.h>
#else 
#include <db.h>
#endif
 
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef O_EXLOCK
#define O_EXLOCK 0
#endif

#include "sync.h"
#include "dump.h"
#include "conf.h"
#include "pending.h"
#include "autowhite.h"
#include "milter-greylist.h"

DB *pending_db = NULL;
pthread_rwlock_t pending_lock; 	/* protects pending_head and dump_dirty */

void
pending_init(void) {

	pthread_rwlock_init(&pending_lock, NULL);

	if ((pending_db = dbopen(conf.c_greylistdb,
	    O_RDWR|O_EXLOCK|O_CREAT, 0644, DB_BTREE, NULL)) == NULL) {
		syslog(LOG_ERR, "dbopen \"%s\" failed: %s",
		    conf.c_greylistdb, strerror(errno));
		exit(EX_OSERR);
	}

	/* 
	 * Create or update the option record
	 */
	pending_db_options();

	return;
}


void
pending_get(in, from, rcpt, date, pp)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t date;
	struct pending *pp;
{
	struct pending pending;
	int delay = conf.c_delay;
	time_t now;
	DBT key;
	DBT rec;
	char keystr[KEYLEN + 1];

	if (pp == NULL)
		pp = &pending;

	bzero(pp, sizeof(*pp));
	now = time(NULL);

	if (date == 0) {
		pp->p_accepted = now + delay;
	} else {
		pp->p_accepted = date;
	}

	pp->p_addr.s_addr = in->s_addr;
	strncpy(pp->p_from, from, ADDRLEN);
	pp->p_from[ADDRLEN] = '\0';
	strncpy(pp->p_rcpt, rcpt, ADDRLEN);
	pp->p_rcpt[ADDRLEN] = '\0';

	key.data = pending_makekey(keystr, KEYLEN, in, from, rcpt);	
	key.size = strlen(keystr) + 1;
	rec.data = pp;
	rec.size = sizeof(*pp);

	PENDING_WRLOCK;
	if (pending_db->put(pending_db, &key, &rec, 0) != 0)
		syslog(LOG_ERR, "db->put failed: %s", strerror(errno));
	dump_dirty++;
	PENDING_UNLOCK;

	if (conf.c_debug) {
		char addr[IPADDRLEN + 1];

		inet_ntop(AF_INET, in, addr, IPADDRLEN);
		syslog(LOG_DEBUG, "created: %s from %s to %s delayed for %lds",
		    addr, pp->p_from, pp->p_rcpt, pp->p_accepted - now);
	}

	return;
}

void
pending_put(keystr)
	char *keystr;
{
	DBT key;

	if (conf.c_debug) 
		syslog(LOG_DEBUG, "removing key \"%s\" from greylist", keystr);

	key.data = keystr;
	key.size = strlen(keystr) + 1;

	PENDING_WRLOCK;
	if (pending_db->del(pending_db, &key, 0) != 0)
	    syslog(LOG_ERR, "db->del failed: %s", strerror(errno));
	dump_dirty++;
	PENDING_UNLOCK;

	return;
}

void
pending_del(in, from, rcpt, date)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t date;
{
	char addr[IPADDRLEN + 1];
	char keystr[KEYLEN + 1];
	time_t now;

	now = time(NULL);
	(void)inet_ntop(AF_INET, in, addr, IPADDRLEN);
	pending_put(pending_makekey(keystr, KEYLEN, in, from, rcpt));

	/* Sync the database to disk */
	PENDING_RDLOCK;
	pending_db->sync(pending_db, 0);
	PENDING_UNLOCK;

	return;
}

int
pending_check(in, from, rcpt, remaining, elapsed, queueid)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t *remaining;
	time_t *elapsed;
	char *queueid;
{
	char addr[IPADDRLEN + 1];
	struct pending *pending;
	struct pending pending_rec;
	DBT key;
	DBT rec;
	char keystr[KEYLEN + 1];
	int found;
	time_t now;
	time_t rest = -1;
	time_t accepted = -1;
	int delay = conf.c_delay;

	now = time(NULL);
	(void)inet_ntop(AF_INET, in, addr, IPADDRLEN);

	/*
	 * Look for our entry.
	 */
	key.data = pending_makekey(keystr, KEYLEN, in, from, rcpt);
	key.size = strlen(keystr) + 1;

	PENDING_RDLOCK;
	found = pending_db->get(pending_db, &key, &rec, 0);
	PENDING_UNLOCK;

	switch(found) {
	case 0: /* Tuple found */
		pending = (struct pending *)rec.data;	
		accepted = pending->p_accepted;
		rest = accepted - now; 

		/*
		 * Is it acceptable now?
		 */
		if (rest < 0) {
			autowhite_add(in, from, rcpt, NULL, queueid);
			peer_delete(pending);
			pending_put(keystr);
			rest = 0;
		}

		/*
		 * Is it obsolete?
		 */
		if (now - accepted > TIMEOUT) {
			if (conf.c_debug) {
				syslog(LOG_DEBUG, 
				    "check: %s from %s to %s timed out", 
				    addr, from, rcpt);
			}
			/*
			 * No need to peer_delete() as the peers
			 * will get a timeout too.
			 */
			pending_put(keystr);
		}
		break;

	case 1: /* Not found, add it */
		accepted = now + delay;
		pending_get(in, from, rcpt, accepted, &pending_rec);
		peer_create(&pending_rec);
		rest = delay;

		break;

	default:
		syslog(LOG_ERR, "db->get failed: %s", strerror(errno));
		rest = 0;
		accepted = now;
		break;
	}

	/*
	 * Sync the database to disk 
	 */
	PENDING_RDLOCK;
	pending_db->sync(pending_db, 0);
	PENDING_UNLOCK;

	if (remaining != NULL)
		*remaining = rest; 

	if (elapsed != NULL)
		*elapsed = now - (accepted - delay);

	if (rest == 0)
		return 1;
	else
		return 0;
}

char *
pending_makekey(data, len, in, from, rcpt)
	char *data;
	size_t len;
	struct in_addr *in;
	char *from;
	char *rcpt;
{
	char addr[IPADDRLEN + 1];
	struct in_addr masked_addr;
	char fromcase[ADDRLEN + 1];
	char rcptcase[ADDRLEN + 1];
	unsigned int i;

	masked_addr.s_addr = in->s_addr & conf.c_match_mask.s_addr;
	inet_ntop(AF_INET, &masked_addr, addr, IPADDRLEN);

	for (i = 0; (i < ADDRLEN) && (from[i] != '\0'); i++)
		fromcase[i] = tolower(from[i]);
	fromcase[i] = '\0';

	for (i = 0; (i < ADDRLEN) && (rcpt[i] != '\0'); i++)
		rcptcase[i] = tolower(rcpt[i]);
	rcptcase[i] = '\0';

	snprintf(data, len, "%s\t%s\t%s", addr, fromcase, rcptcase);
	data[len] = '\0';

	return data;
}

int
pending_update(new_db, stream) /* pending_db must be write-locked */
	DB *new_db;
	FILE *stream;
{
	int finished = 0;
	DBT key;
	char keystr[KEYLEN + 1];
	DBT rec;
	struct pending *pending;
	int res;
	int flag = R_FIRST;
	struct timeval begin;
	time_t now;
	int count = 0;
	int deleted = 0;
	int dirty = dump_dirty;
	char textdate[DATELEN + 1];
	char addr[IPADDRLEN + 1];
	struct tm tm;

	gettimeofday(&begin, NULL);
	now = (time_t)begin.tv_sec;

	if (new_db)
		syslog(LOG_INFO, "Rebuilding pending database keys");

	if (stream != NULL) {
		fprintf(stream, "\n\n#\n# greylisted tuples\n#\n");
		fprintf(stream, "# Sender IP	%32s	%32s	"
		    "Time accepted\n", "Sender e-mail", "Recipient e-mail");
	}

	while (!finished) {
		res = pending_db->seq(pending_db, &key, &rec, flag);
		flag = R_NEXT;

		switch (res) {
		case 0:
			/* Skip the DB option record */
			if (strcmp(key.data, DB_OPTIONS) == 0) {
				break;
			}

			count++;
			pending = (struct pending *)rec.data;

			/* 
			 * Handle timeouts 
			 */
			if (now - pending->p_accepted > TIMEOUT) {
				deleted++;

				if (conf.c_debug) {
					char addr[IPADDRLEN + 1];

					inet_ntop(AF_INET, &pending->p_addr,
					    addr, IPADDRLEN);
					syslog(LOG_DEBUG,
					    "del: %s from %s to %s timed out",
					    addr, pending->p_from, 
					    pending->p_rcpt);
				}

				if (pending_db->del(pending_db, &key, 0) != 0)
					syslog(LOG_ERR, "db->del failed: %s",
					    strerror(errno));
				dump_dirty++;

				/* 
				 * Break: we don't want to update this key
				 * as it just gone away
				 */
				break;
			}

			/*
			 * Update the keys by overwriting the current record
			 */
			if (new_db) {
				key.data = pending_makekey(keystr, KEYLEN, 
				    &pending->p_addr,
				    pending->p_from, pending->p_rcpt);
				key.size = strlen(keystr) + 1;

				if (new_db->put(new_db, 
				    &key, &rec, R_CURSOR) != 0) {
					syslog(LOG_ERR, "db->put failed: %s",
					    strerror(errno));
				}
				dump_dirty++;
			}

			/*
			 * Output the data to a text dumpfile
			 */
			if (stream == NULL)
				break;

			localtime_r(&pending->p_accepted, &tm);
			strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);

			inet_ntop(AF_INET, &pending->p_addr, addr, IPADDRLEN);

			fprintf(stream, "%s	%32s	%32s	%ld # %s\n", 
			    addr, pending->p_from, pending->p_rcpt, 
			    (unsigned long)pending->p_accepted, textdate);

			break;
		case 1:
			finished = 1;
			break;

		case -1:
			/* FALLTHROUGH */
		default:
			syslog(LOG_ERR, "db->seq failed (%d): %s",
			    res, strerror(errno));
			finished = 1;
			break;
		}
	}

	if (dump_dirty != dirty)
		pending_db->sync(pending_db, 0);	

	if (conf.c_debug) {
		struct timeval end;
		struct timeval duration;

		gettimeofday(&end, NULL);
		timersub(&end, &begin, &duration);

		syslog(LOG_DEBUG, 
		    "pending_update done in %ld.%06lds, deleted %d over %d",
		    duration.tv_sec, duration.tv_usec, deleted, count);
	}

	return count;
}

void
pending_db_options(void) {
	DBT key;
	DBT rec;
	struct db_options *dbo;
	struct db_options dborec;
	int found;
	DB *new_db;
	char new_db_name[MAXPATHLEN + 1];

	key.data = DB_OPTIONS;
	key.size = strlen(DB_OPTIONS) + 1;

	PENDING_RDLOCK;
	found = pending_db->get(pending_db, &key, &rec, 0);
	PENDING_UNLOCK;

	switch(found) {
	case 0:	/* found */
		dbo = rec.data;
		if ((dbo->dbo_match_mask.s_addr == conf.c_match_mask.s_addr) &&
		    (dbo->dbo_lazyaw == conf.c_lazyaw))
			break;

		/* 
		 * We need to update the database keys.
		 *
		 * It seems Berkeley DB API limitation makes impossible
		 * to walk the database updating the keys. We therefore
		 * create a new database, copy the records with updated 
		 * keys in it, and replace the older database.
		 */
		snprintf(new_db_name, MAXPATHLEN, 
		    "%s.%s", conf.c_greylistdb, "new");

		if ((new_db = dbopen(new_db_name, 
		    O_TRUNC|O_RDWR|O_EXLOCK|O_CREAT, 
		    0644, DB_BTREE, NULL)) == NULL) {
			syslog(LOG_ERR, "dbopen \"%s\" failed: %s",
			    new_db_name, strerror(errno));
			exit(EX_OSERR);
		}

		/*
		 * Remove outdated records, and save everything
		 * else to the new database, with updated keys.
		 * The database remain locked until we replace
		 * the old one.
		 */
		PENDING_WRLOCK;
		pending_update(new_db, NULL);

		/*
		 * At that stage we don't need the older database
		 * anymore, close it.
		 */
		pending_db->close(pending_db);

		/* 
		 * Replace the older database
		 */
		if (rename(new_db_name, conf.c_greylistdb) != 0) {
			syslog(LOG_ERR, "cannot replace \"%s\" by \"%s\": %s",
			    conf.c_greylistdb, new_db_name, strerror(errno));
			exit(EX_OSERR);
		}

		/*
		 * The newer database can now be used 
		 */
		pending_db = new_db;	
		PENDING_UNLOCK;
		/* FALLTRHOUGH */

	/*
	 * If the options changed (the case above), or if
	 * the option record was not found (brand new database)
	 * then we put a new option record.
	 */
	case 1: /* not found */
		dborec.dbo_match_mask = conf.c_match_mask;
		dborec.dbo_lazyaw = conf.c_lazyaw;

		rec.data = &dborec;
		rec.size = sizeof(dborec);

		PENDING_WRLOCK;
		if (pending_db->put(pending_db, &key, &rec, 0) != 0)
			syslog(LOG_ERR, "option record could not be saved: "
			    "db->put failed: %s", strerror(errno));
		dump_dirty++;
		PENDING_UNLOCK;

		break;

	default: /* error */
		syslog(LOG_ERR, "option record could not be found: "
		    "db->get failed: %s", strerror(errno));
		break;
	}

	PENDING_RDLOCK;
	pending_db->sync(pending_db, 0);
	PENDING_UNLOCK;

	return;
}
