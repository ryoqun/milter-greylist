/* $Id: autowhite.c,v 1.24 2004/05/21 10:22:08 manu Exp $ */

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

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: autowhite.c,v 1.24 2004/05/21 10:22:08 manu Exp $");
#endif
#endif

#include "config.h"
#ifdef HAVE_OLD_QUEUE_H
#include "queue.h"
#else
#include <sys/queue.h>
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <sysexits.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

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

#include "conf.h"
#include "except.h"
#include "pending.h"
#include "dump.h"
#include "autowhite.h"

DB *aw_db = NULL;
pthread_rwlock_t autowhite_lock;

void
autowhite_init(void) {

	pthread_rwlock_init(&autowhite_lock, NULL);

	if ((aw_db = dbopen(conf.c_autowhitedb, 
	    O_RDWR|O_EXLOCK|O_CREAT, 0644, DB_BTREE, NULL)) == NULL) {
		syslog(LOG_ERR, "dbopen \"%s\" failed: %s",
		    conf.c_autowhitedb, strerror(errno));
		exit(EX_OSERR);
	}

	/*
	 * Create or update the option record 
	 */
	autowhite_db_options();

	return;
}

void
autowhite_add(in, from, rcpt, date, queueid)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t *date;
	char *queueid;
{
	struct autowhite *aw;
	struct autowhite awrec;
	time_t now;
	char addr[IPADDRLEN + 1];
	time_t autowhite_validity;
	int h, mn, s;
	DBT key;
	DBT rec;
	char keystr[KEYLEN + 1];
	int found;

	if ((autowhite_validity = conf.c_autowhite_validity) == 0)
		return;

	now = time(NULL);

	h = autowhite_validity / 3600;
	mn = ((autowhite_validity % 3600) / 60);
	s = (autowhite_validity % 3600) % 60;

	inet_ntop(AF_INET, in, addr, IPADDRLEN);

	key.data = autowhite_makekey(keystr, KEYLEN, in, from, rcpt);
	key.size = strlen(keystr) + 1;

	AUTOWHITE_RDLOCK;
	found = aw_db->get(aw_db, &key, &rec, 0);
	AUTOWHITE_UNLOCK;

	switch(found) {
	case 0: /* Tuple found */
		aw = (struct autowhite *)rec.data;

		/*
		 * Renew the autowhitelisting expiration delay
		 */
		aw->a_expire = now + autowhite_validity;

		AUTOWHITE_WRLOCK;
		if ((aw_db->put(aw_db, &key, &rec, 0)) != 0)
			syslog(LOG_ERR, "db->put failed: %s", strerror(errno));
		dump_dirty++;
		AUTOWHITE_UNLOCK;

		syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
		    "autowhitelisted for more %02d:%02d:%02d", 
		    queueid, addr, from, rcpt, h, mn, s);

		break;

	case 1: /* Not found, create it */
		autowhite_get(in, from, rcpt, date, &awrec);
		break;

	default:
		syslog(LOG_ERR, "db->get failed: %s", strerror(errno));
		break;
	}

	/* Flush changes to disk */
	AUTOWHITE_RDLOCK;
	aw_db->sync(aw_db, 0);
	AUTOWHITE_UNLOCK;

	return;
}

int
autowhite_check(in, from, rcpt, queueid)
	struct in_addr *in;
	char *from;
	char *rcpt;
	char *queueid;
{
	struct autowhite *aw;
	time_t now;
	char addr[IPADDRLEN + 1];
	time_t autowhite_validity = conf.c_autowhite_validity;
	int h, mn, s;
	DBT key;
	DBT rec;
	char keystr[KEYLEN + 1];
	int found;
	int retval;

	if (autowhite_validity == 0)
		return EXF_NONE;

	now = time(NULL);

	h = autowhite_validity / 3600;
	mn = ((autowhite_validity % 3600) / 60);
	s = (autowhite_validity % 3600) % 60;

	inet_ntop(AF_INET, in, addr, IPADDRLEN);

	key.data = autowhite_makekey(keystr, KEYLEN, in, from, rcpt);
	key.size = strlen(keystr) + 1;

	AUTOWHITE_RDLOCK;
	found = aw_db->get(aw_db, &key, &rec, 0);
	AUTOWHITE_UNLOCK;

	switch(found) {
	case 0: /* Tuple found */
		aw = (struct autowhite *)rec.data;

		/* 
		 * Is it expired?
		 */
		if (aw->a_expire < now) {
			syslog(LOG_INFO, "addr %s from %s rcpt %s: "
			    "autowhitelisted entry expired",
			    addr, from, rcpt);
			autowhite_put(keystr);
			retval = EXF_NONE;
			break;
		}

		/*
		 * Renew the autowhitelisting expiration delay
		 */
		aw->a_expire = now + autowhite_validity;

		AUTOWHITE_WRLOCK;
		if ((aw_db->put(aw_db, &key, &rec, 0)) != 0)
			syslog(LOG_ERR, "db->put failed: %s", strerror(errno));
		dump_dirty++;
		aw_db->sync(aw_db, 0); /* Flush changes to disk */
		AUTOWHITE_UNLOCK;

		syslog(LOG_INFO, "%s: addr %s from %s rcpt %s: "
		    "autowhitelisted for more %02d:%02d:%02d", 
		    queueid, addr, from, rcpt, h, mn, s);
		retval = EXF_AUTO;	
		break;

	case 1: /* Not found */
		retval = EXF_NONE;
		break;

	default:
		retval = EXF_NONE;
		syslog(LOG_ERR, "db->get failed: %s", strerror(errno));
		break;
	}

	return retval;
}

void
autowhite_get(in, from, rcpt, date, awp)
	struct in_addr *in;
	char *from;
	char *rcpt;
	time_t *date;
	struct autowhite *awp;
{
	struct autowhite aw;
	time_t now;
	time_t autowhite_validity = conf.c_autowhite_validity;
	DBT key;
	DBT rec;
	char keystr[KEYLEN + 1];

	if (awp == NULL)
		awp = &aw;

	bzero(awp, sizeof(*awp));
	now = time(NULL);

	awp->a_in.s_addr = in->s_addr;
	strncpy(awp->a_from, from, ADDRLEN);
	awp->a_from[ADDRLEN] = '\0';
	strncpy(awp->a_rcpt, rcpt, ADDRLEN);
	awp->a_rcpt[ADDRLEN] = '\0';

	if (date == NULL)
		awp->a_expire = now + autowhite_validity;
	else
		awp->a_expire = *date;

	key.data = autowhite_makekey(keystr, KEYLEN, in, from, rcpt);
	key.size = strlen(key.data) + 1;
	rec.data = awp;
	rec.size = sizeof(*awp);

	AUTOWHITE_WRLOCK;
	if (aw_db->put(aw_db, &key, &rec, 0) != 0)
		syslog(LOG_ERR, "db->put failed: %s", strerror(errno));
	dump_dirty++;
	AUTOWHITE_UNLOCK;

	if (conf.c_debug) {
		char addr[IPADDRLEN + 1];

		 inet_ntop(AF_INET, in, addr, IPADDRLEN);
		 syslog(LOG_DEBUG, "%s from %s to %s autowhitelisted for %lds",
		     addr, awp->a_from, awp->a_rcpt, awp->a_expire - now);
	}

	return;
}

void
autowhite_put(keystr)
	char *keystr;
{
	DBT key;

	if (conf.c_debug)
		syslog(LOG_DEBUG, "removing key \"%s\" from autowhite", keystr);

	key.data = keystr;
	key.size = strlen(keystr) + 1;

	AUTOWHITE_WRLOCK;
	if (aw_db->del(aw_db, &key, 0) != 0)
		syslog(LOG_ERR, "db->del failed: %s", strerror(errno));
	dump_dirty++;
	aw_db->sync(aw_db, 0); /* Flush changes to disk */
	AUTOWHITE_UNLOCK;

	return;
}

char *
autowhite_makekey(data, len, in, from, rcpt)
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

	if (conf.c_lazyaw) {
		snprintf(data, len, "%s", addr);
	} else {
		for (i = 0; (i < ADDRLEN) && (from[i] != '\0'); i++)
			fromcase[i] = tolower(from[i]);
		fromcase[i] = '\0';

		for (i = 0; (i < ADDRLEN) && (rcpt[i] != '\0'); i++)
			rcptcase[i] = tolower(rcpt[i]);
		rcptcase[i] = '\0';

		snprintf(data, len, "%s\t%s\t%s", addr, fromcase, rcptcase); 
	}
	data[len] = '\0';

	printf("key = \"%s\"\n", data);
	return data;
}

int
autowhite_update(new_db, stream) /* aw_db must be write-locked */
	DB *new_db;
	FILE *stream;
{
	int finished = 0;
	DBT key;
	char keystr[KEYLEN + 1];
	DBT rec;
	struct autowhite *aw;
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
		syslog(LOG_INFO, "Rebuilding autowhite database keys");

	if (stream != NULL) {
		fprintf(stream, "\n\n#\n# Auto-whitelisted tuples\n#\n");
		fprintf(stream, "# Sender IP    %32s    %32s    Expire\n",
		    "Sender e-mail", "Recipient e-mail");
	}

	while (!finished) {
		res = aw_db->seq(aw_db, &key, &rec, flag);
		flag = R_NEXT;

		printf("key.size = %d  rec.size = %d\n", key.size, rec.size);
		switch (res) {
		case 0:
			/* Skip the DB option record */
			if (strcmp(key.data, DB_OPTIONS) == 0)
				break;

			count++;
			aw = (struct autowhite *)rec.data;

			/* 
			 * Handle timeouts 
			 */
			if (aw->a_expire < now) {
				deleted++;

				if (conf.c_debug) {
					char addr[IPADDRLEN + 1];

					inet_ntop(AF_INET, &aw->a_in,
					    addr, IPADDRLEN);
					syslog(LOG_DEBUG,
					    "awdel: %s from %s to %s timed out",
					    addr, aw->a_from, aw->a_rcpt);
				}

				if (aw_db->del(aw_db, &key, 0) != 0)
					syslog(LOG_ERR, "db->del failed: %s",
					    strerror(errno));
				dump_dirty++;

				/* 
				 * Break: we don't want to update this key
				 * as it has just gone away
				 */
				break;
			}

			/*
			 * Update the key by overwriting the current record. 
			 */
			if (new_db) {
				key.data = autowhite_makekey(keystr, 
				    KEYLEN, &aw->a_in, aw->a_from, aw->a_rcpt);
				key.size = strlen(keystr) + 1;

				if (new_db->put(new_db, &key, 
				    &rec, R_CURSOR) != 0)
					syslog(LOG_ERR, "db->put failed: %s",
					    strerror(errno));
				dump_dirty++;
			}

			/*
			 * Output the data to a text dumpfile
			 */
			if (stream == NULL)
				break;

			localtime_r(&aw->a_expire, &tm);
			strftime(textdate, DATELEN, "%Y-%m-%d %T", &tm);

			inet_ntop(AF_INET, &aw->a_in, addr, IPADDRLEN);

			fprintf(stream, 
			    "%s     %32s    %32s    %ld AUTO # %s\n",
			    addr, aw->a_from, aw->a_rcpt, 
			    (unsigned long)aw->a_expire, textdate);

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
		aw_db->sync(aw_db, 0);

	if (conf.c_debug) {
		struct timeval end;
		struct timeval duration;

		gettimeofday(&end, NULL);
		timersub(&end, &begin, &duration);

		syslog(LOG_DEBUG, 
		    "autowhite_update done in %ld.%06lds, deleted %d over %d",
		    duration.tv_sec, duration.tv_usec, deleted, count);
	}

	return count;
}

void
autowhite_db_options(void) {
	DBT key;
	DBT rec;
	struct db_options *dbo;
	struct db_options dborec;
	int found;
	DB *new_db;
	char new_db_name[MAXPATHLEN + 1];

	key.data = DB_OPTIONS;
	key.size = strlen(DB_OPTIONS) + 1;

	AUTOWHITE_RDLOCK;
	found = aw_db->get(aw_db, &key, &rec, 0);
	AUTOWHITE_UNLOCK;

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
		    "%s.%s", conf.c_autowhitedb, "new");

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
		 * The database remain locked until we replaced
		 * the old one.
		 */
		AUTOWHITE_WRLOCK;
		autowhite_update(new_db, NULL);

		/*
		 * At that stage we don't need the older database
		 * anymore, close it.
		 */
		aw_db->close(aw_db);

		/*
		 * Replace the older database
		 */
		if (rename(new_db_name, conf.c_autowhitedb) != 0) {
			syslog(LOG_ERR, "cannot replace \"%s\" by \"%s\": %s",
			    conf.c_autowhitedb, new_db_name, strerror(errno));
			exit(EX_OSERR);
		}

		/*
		 * The newer database can now be used
		 */
		aw_db = new_db;
		AUTOWHITE_UNLOCK;
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

		AUTOWHITE_WRLOCK;
		if (aw_db->put(aw_db, &key, &rec, 0) != 0)
			syslog(LOG_ERR, "option record could not be saved: "
			    "db->put failed: %s", strerror(errno));
		dump_dirty++;
		AUTOWHITE_UNLOCK;

		break;

	default: /* error */
		syslog(LOG_ERR, "option record could not be found: "
		    "db->get failed: %s", strerror(errno));
		break;
	}

	AUTOWHITE_RDLOCK;
	aw_db->sync(aw_db, 0);
	AUTOWHITE_UNLOCK;

	return;
}
