/* $Id: pending.c,v 1.54 2004/05/23 19:40:45 manu Exp $ */

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
__RCSID("$Id: pending.c,v 1.54 2004/05/23 19:40:45 manu Exp $");
#endif
#endif

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <ctype.h>
#include <signal.h>
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

int
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
	 * Check if we need to reload from the text dump
	 */
	return pending_db_options(PS_COLD);
}

void
pending_destroy(void) {
	pending_db->close(pending_db);

	if (unlink(conf.c_greylistdb) != 0) {
		syslog(LOG_ERR, "Cannot delete \"%s\": %s",
		    conf.c_greylistdb, strerror(errno));
		exit(EX_OSERR);
	}

	pending_init();

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

	snprintf(data, len, "G\t%s\t%s\t%s", addr, fromcase, rcptcase);
	data[len] = '\0';

	return data;
}

int
pending_update(update, stream) /* pending_db must be write-locked */
	int update;
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
	DB *new_db = NULL;
	char new_db_name[MAXPATHLEN + 1];

	gettimeofday(&begin, NULL);
	now = (time_t)begin.tv_sec;

	if (update) {
		syslog(LOG_INFO, "Rebuilding pending database keys");

		snprintf(new_db_name, MAXPATHLEN, "%s.new", conf.c_greylistdb);
		if ((new_db = dbopen(new_db_name, 
		    O_TRUNC|O_RDWR|O_EXLOCK|O_CREAT, 
		    0644, DB_BTREE, NULL)) == NULL) {
			syslog(LOG_ERR, "dbopen \"%s\" failed: %s",
			    new_db_name, strerror(errno));
			exit(EX_OSERR);
		}
	}

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
			if (update) {
				key.data = pending_makekey(keystr, KEYLEN, 
				    &pending->p_addr,
				    pending->p_from, pending->p_rcpt);
				key.size = strlen(keystr) + 1;

				if (new_db->put(new_db, 
				    &key, &rec, R_CURSOR) != 0) {
					syslog(LOG_ERR, "db->put failed: %s",
					    strerror(errno));
				}
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

	if (update) {
		if (pending_db->close(pending_db) != 0)
			syslog(LOG_ERR, "cannot close greylist db: %s",
			    strerror(errno));

		if (rename(new_db_name, conf.c_greylistdb) != 0) {
			syslog(LOG_ERR, "rename \"%s\" to  \"%s\" failed: %s",
			    new_db_name, conf.c_greylistdb, strerror(errno));
			exit(EX_OSERR);
		}

		pending_db = new_db;
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

int
pending_db_options(ps) 
	pending_startup_t ps;
{
	DBT key;
	DBT rec;
	struct db_options *dbo;
	struct db_options dborec;
	int found;

	key.data = DB_OPTIONS;
	key.size = strlen(DB_OPTIONS) + 1;

	PENDING_RDLOCK;
	found = pending_db->get(pending_db, &key, &rec, 0);
	PENDING_UNLOCK;

	switch(found) {
	case 0:	/* found */
		dbo = rec.data;

		/* 
		 * If this is a cold reload, check for improper shutdown
		 */
		if ((ps == PS_COLD) && (dbo->dbo_busy != 0)) {
			if (kill(dbo->dbo_busy, 0) == 0) {
				syslog(LOG_ERR, 
				    "milter-greylist already running (pid %d)",
				    dbo->dbo_busy);
				exit(EX_USAGE);
			}

			/* 
			 * Bad shutdown: Cause a reload from test dump 
			 * No need to update the dbo_busy field as the
			 * database will be destroyed and recreated.
			 */
			return -1;
		}

		/*
		 * Update the dbo_busy record with our PID
		 */
		if (ps == PS_COLD) {
			if (atexit(*pending_shutdown) != 0) {
				syslog(LOG_ERR, "atexit failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}

			dbo->dbo_busy = getpid();

			PENDING_WRLOCK;
			if (pending_db->put(pending_db, &key, &rec, 0) != 0) {
				syslog(LOG_ERR, "option record could "
				    "not be saved: db->put failed: %s", 
				    strerror(errno));
				exit(EX_OSERR);
			}
			PENDING_UNLOCK;
		}

		/* 
		 * If the database does not need a key fixup, get away now
		 */
		if ((dbo->dbo_match_mask.s_addr == conf.c_match_mask.s_addr) &&
		    (dbo->dbo_lazyaw == conf.c_lazyaw))
			break;

		pending_update(1, NULL);
		/* FALLTRHOUGH */

	/*
	 * If the options changed (the case above), or if
	 * the option record was not found (brand new database)
	 * then we put a new option record.
	 */
	case 1: /* not found */
		dborec.dbo_match_mask = conf.c_match_mask;
		dborec.dbo_lazyaw = conf.c_lazyaw;
		dborec.dbo_busy = getpid();

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

	return 0;
}

void
pending_shutdown(void) { /* Access with no lock: exitting is monothread */
	DBT key;
	DBT rec;
	struct db_options *dbo;
	int found;

	syslog(LOG_INFO, "shuting down greylist database");

	key.data = DB_OPTIONS;
	key.size = strlen(DB_OPTIONS) + 1;

	found = pending_db->get(pending_db, &key, &rec, 0);

	if (found != 0) {
		syslog(LOG_ERR, "No %s record in greylist database",
		    DB_OPTIONS);

		if (pending_db->close(pending_db) != 0)
			syslog(LOG_ERR, "closing greylist database failed: %s",
			    strerror(errno));

		return;
	}

	dbo = rec.data;
	
	if (pending_db->sync(pending_db, 0) != 0) {
		syslog(LOG_ERR, "sync failed on greylist database: %s",
		    strerror(errno));
		return;
	}

	dbo->dbo_busy = 0;

	if (pending_db->put(pending_db, &key, &rec, 0) != 0) {
		syslog(LOG_ERR, "put %s record failed for greylist db: %s",
		    DB_OPTIONS, strerror(errno));
		return;
	}

	if (pending_db->close(pending_db) != 0) {
		syslog(LOG_ERR, "close failed on greylist database: %s",
		    strerror(errno));
		return;
	}

	return;
}
