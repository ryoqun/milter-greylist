/* $Id: sync.c,v 1.32 2004/03/22 21:56:35 manu Exp $ */

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
__RCSID("$Id");
#endif
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <pthread.h>
#include <syslog.h>
#include <sysexits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pending.h"
#include "sync.h"
#include "autowhite.h"
#include "milter-greylist.h"

int sync_master_runs = 0;
struct peerlist peer_head;
pthread_rwlock_t peer_lock; /* For the peer list */
pthread_rwlock_t sync_lock; /* For all peer's sync queue */
pthread_cond_t sync_sleepflag;

int 
peer_init(void) {
	int error;

	LIST_INIT(&peer_head);
	if ((error = pthread_rwlock_init(&peer_lock, NULL)) == 0)
		return error;

	if ((error = pthread_rwlock_init(&sync_lock, NULL)) == 0)
		return error;

	if ((error = pthread_cond_init(&sync_sleepflag, NULL)) == 0)
		return error;

	return 0;
}

void 
peer_clear(void) {
	struct peer *peer;
	struct sync *sync;

	PEER_WRLOCK;
	SYNC_WRLOCK;

	while(!LIST_EMPTY(&peer_head)) {
		peer = LIST_FIRST(&peer_head);
		while(!TAILQ_EMPTY(&peer->p_deferred)) {
			sync = TAILQ_FIRST(&peer->p_deferred);
			TAILQ_REMOVE(&peer->p_deferred, sync, s_list);
			peer->p_qlen--;
			free(sync);
		}
			
		if (peer->p_stream != NULL)
			fclose(peer->p_stream);

		LIST_REMOVE(peer, p_list);
		free(peer);
	}

	SYNC_UNLOCK;
	PEER_UNLOCK;

	return;	
}

void 
peer_add(addr)
	struct in_addr *addr;
{
	struct peer *peer;

	if ((peer = malloc(sizeof(*peer))) == NULL) {
		perror("cannot allocate memory");
		exit(EX_OSERR);
	}

	peer->p_qlen = 0;
	peer->p_stream = NULL;
	memcpy(&peer->p_addr, addr, sizeof(peer->p_addr));
	inet_ntop(AF_INET, &peer->p_addr, peer->p_name, IPADDRLEN);
	TAILQ_INIT(&peer->p_deferred);

	PEER_WRLOCK;
	LIST_INSERT_HEAD(&peer_head, peer, p_list);
	PEER_UNLOCK;

	if (debug)
		printf("load peer %s\n", peer->p_name);
		    

	return;
}

void
peer_create(pending)
	struct pending *pending;
{
	struct peer *peer;

	PEER_RDLOCK;
	if (LIST_EMPTY(&peer_head))
		goto out;

	LIST_FOREACH(peer, &peer_head, p_list) 
		sync_queue(peer, PS_CREATE, pending);

out:
	PEER_UNLOCK;
	
	return;
}

void
peer_delete(pending)
	struct pending *pending;
{
	struct peer *peer;

	PEER_RDLOCK;
	if (LIST_EMPTY(&peer_head))
		goto out;

	LIST_FOREACH(peer, &peer_head, p_list) 
		sync_queue(peer, PS_DELETE, pending);

out:
	PEER_UNLOCK;
	
	return;
}

int
sync_send(peer, type, pending)	/* peer list is read-locked */
	struct peer *peer;
	peer_sync_t type;
	struct pending *pending;
{
	char sep[] = " \n\t\r";
	char *replystr;
	int replycode;
	char line[LINELEN + 1];

	if ((peer->p_stream == NULL) && (peer_connect(peer) != 0))
		return -1;

	if (type == PS_CREATE)
		fprintf(peer->p_stream, "add ");
	else
		fprintf(peer->p_stream, "del ");

	fprintf(peer->p_stream, "addr %s from %s rcpt %s date %ld\r\n", 
	    pending->p_addr, pending->p_from, 
	    pending->p_rcpt, (long)pending->p_tv.tv_sec);
	fflush(peer->p_stream);

	/* 
	 * Check the return code 
	 */
	sync_waitdata(peer->p_socket);
	if (fgets(line, LINELEN, peer->p_stream) == NULL) {
		syslog(LOG_ERR, "lost connexion with peer %s: "
		    "%s (%d entries queued)", 
		    peer->p_name, strerror(errno), peer->p_qlen);
		fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	if ((replystr = strtok(line, sep)) == NULL) {
		syslog(LOG_ERR, "Unexpected reply \"%s\" from %s, "
		    "closing connexion (%d entries queued)", 
		    line, peer->p_name, peer->p_qlen);
		fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	replycode = atoi(replystr);
	if (replycode != 201) {
		syslog(LOG_ERR, "Unexpected reply \"%s\" from %s, "
		    "closing connexion (%d entries queued)", 
		    line, peer->p_name, peer->p_qlen);
		fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	syslog(LOG_DEBUG, "sync one entry with %s", peer->p_name);

	return 0;
}

int
peer_connect(peer)	/* peer list is read-locked */
	struct peer *peer;
{
	struct protoent *pe;
	struct servent *se;
	int proto;
	struct sockaddr_in laddr;
	struct sockaddr_in raddr;
	int service;
	int s;
	char *replystr;
	int replycode;
	FILE *stream;
	char sep[] = " \n\t\r";
	char peername[IPADDRLEN + 1];
	char line[LINELEN + 1];
	int param;

	if (peer->p_stream != NULL)
		syslog(LOG_ERR, "peer_connect called and peer->p_stream != 0");

	if ((pe = getprotobyname("tcp")) == NULL)
		proto = 6;
	else
		proto = pe->p_proto;

	inet_ntop(AF_INET, &peer->p_addr, peername, IPADDRLEN);

	if ((s = socket(AF_INET, SOCK_STREAM, proto)) == -1) {
		syslog(LOG_ERR, "cannot sync with peer %s, "
		    "socket failed: %s (%d entries queued)", 
		    peername, strerror(errno), peer->p_qlen);
		return -1;
	}

	if ((se = getservbyname(MXGLSYNC_NAME, "tcp")) == NULL)
		service = MXGLSYNC_PORT;
	else
		service = se->s_port;

	bzero((void *)&laddr, sizeof(laddr));
#ifdef HAVE_SA_LEN
	laddr.sin_len = sizeof(laddr);
#endif
	laddr.sin_family = AF_INET;
	laddr.sin_port = 0;
	laddr.sin_addr.s_addr = INADDR_ANY;

	if (bind(s, (struct sockaddr *)&laddr, sizeof(laddr)) != 0) { 
		syslog(LOG_ERR, "cannot sync with peer %s, "
		    "bind failed: %s (%d entries queued)",
		    peername, strerror(errno), peer->p_qlen);
		close(s);
		return -1;
	}

	bzero((void *)&raddr, sizeof(raddr));
#ifdef HAVE_SA_LEN
	raddr.sin_len = sizeof(raddr);
#endif
	raddr.sin_family = AF_INET;
	raddr.sin_port = htons(service);
	raddr.sin_addr = peer->p_addr;

	if (connect(s, (struct sockaddr *)&raddr, sizeof(raddr)) != 0) {
		syslog(LOG_ERR, "cannot sync with peer %s, "
		    "connect failed: %s (%d entries queued)", 
		    peername, strerror(errno), peer->p_qlen);
		close(s);
		return -1;
	}

	param = O_NONBLOCK;
	if (fcntl(s, F_SETFL, &param) != 0) {
		syslog(LOG_ERR, "cannot set non blocking I/O with %s: %s",
		    peername, strerror(errno));
	}

	if ((stream = fdopen(s, "w+")) == NULL) {
		syslog(LOG_ERR, "cannot sync with peer %s, "
		    "fdopen failed: %s (%d entries queued)", 
		    peername, strerror(errno), peer->p_qlen);
		close(s);
		return -1;
	}

	if (setvbuf(stream, NULL, _IOLBF, 0) != 0)
		syslog(LOG_ERR, "cannot set line buffering with peer %s: %s", 
		    peername, strerror(errno));	

	sync_waitdata(s);	
	if (fgets(line, LINELEN, stream) == NULL) {
		syslog(LOG_ERR, "Lost connexion with peer %s: "
		    "%s (%d entries queued)", 
		    peername, strerror(errno), peer->p_qlen);
		goto bad;
	}

	if ((replystr = strtok(line, sep)) == NULL) {
		syslog(LOG_ERR, "Unexpected reply \"%s\" from peer %s "
		    "closing connexion (%d entries queued)", 
		    line, peername, peer->p_qlen);
		goto bad;
	}

	replycode = atoi(replystr);
	if (replycode != 200) {
		syslog(LOG_ERR, "Unexpected reply \"%s\" from peer %s "
		    "closing connexion (%d entries queued)", 
		    line, peername, peer->p_qlen);
		goto bad;
	}

	syslog(LOG_INFO, "Connection to %s established", peername);
	peer->p_stream = stream;
	peer->p_socket = s;
	return 0;

bad:
	fclose(stream);
	peer->p_stream = NULL;

	return -1;
}

void
sync_master_restart(void) {
	pthread_t tid;
	int empty;

	PEER_RDLOCK;
	empty = LIST_EMPTY(&peer_head);
	PEER_UNLOCK;

	if (empty || sync_master_runs)
		return;

	sync_master_runs = 1;
	if (pthread_create(&tid, NULL, (void *)sync_master, NULL) != 0) {
		syslog(LOG_ERR, "Cannot run MX sync thread: %s\n",
		    strerror(errno));
		exit(EX_OSERR);
	}
}

/* ARGSUSED0 */
void
sync_master(dontcare)
	void *dontcare;
{
	struct protoent *pe;
	struct servent *se;
	int proto;
	struct sockaddr_in laddr;
	int service;
	int optval;
	int s;

	if ((pe = getprotobyname("tcp")) == NULL)
		proto = 6;
	else
		proto = pe->p_proto;

	if ((s = socket(AF_INET, SOCK_STREAM, proto)) == -1) {
		syslog(LOG_ERR, "cannot start MX sync, socket failed: %s", 
		    strerror(errno));
		sync_master_runs = 0;
		return;
	}

	if ((se = getservbyname(MXGLSYNC_NAME, "tcp")) == NULL)
		service = MXGLSYNC_PORT;
	else
		service = se->s_port;

	optval = 1;
	if ((setsockopt(s, SOL_SOCKET, SO_REUSEADDR, 
	    &optval, sizeof(optval))) != 0) {
		syslog(LOG_ERR, "cannot set SO_REUSEADDR: %s", 
		    strerror(errno));
	}

	optval = 1;
	if ((setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
	    &optval, sizeof(optval))) != 0) {
		syslog(LOG_ERR, "cannot set SO_KEEPALIVE: %s", 
		    strerror(errno));
	}

	bzero((void *)&laddr, sizeof(laddr));
#ifdef HAVE_SA_LEN
	laddr.sin_len = sizeof(laddr);
#endif
	laddr.sin_family = AF_INET;
	laddr.sin_port = htons(service);
	laddr.sin_addr.s_addr = INADDR_ANY;

	if (bind(s, (struct sockaddr *)&laddr, sizeof(laddr)) != 0) {
		syslog(LOG_ERR, "cannot start MX sync, bind failed: %s", 
		    strerror(errno));
		sync_master_runs = 0;
		close(s);
		return;
	}

	if (listen(s, MXGLSYNC_BACKLOG) != 0) {
		syslog(LOG_ERR, "cannot start MX sync, listen failed: %s", 
		    strerror(errno));
		sync_master_runs = 0;
		close(s);
		return;
	}

	while (1) {
		struct sockaddr_in raddr;
		socklen_t socklen;
		int fd;
		FILE *stream;
		pthread_t tid;
		struct peer *peer;
		char peerstr[IPADDRLEN + 1];

		bzero((void *)&raddr, sizeof(raddr));
		socklen = sizeof(raddr);
		if ((fd = accept(s, (struct sockaddr *)&raddr, 
		    &socklen)) == -1) {
			syslog(LOG_ERR, "incoming connexion "
			    "failed: %s\n", strerror(errno));

			if (errno != ECONNABORTED)
				exit(EX_OSERR);
			continue;
		}

		inet_ntop(AF_INET, &raddr.sin_addr, peerstr, IPADDRLEN);
		syslog(LOG_INFO, "Incoming MX sync connexion from %s", 
		    peerstr);

		if ((stream = fdopen(fd, "w+")) == NULL) {
			syslog(LOG_ERR, 
			    "incoming connexion from %s failed, "
			    "fdopen fail: %s", peerstr, strerror(errno));
			close(fd);
			exit(EX_OSERR);
		}

		if (setvbuf(stream, NULL, _IOLBF, 0) != 0)
			syslog(LOG_ERR, "cannot set line buffering: %s\n", 
			    strerror(errno));	
		
		/*
		 * Check that the orginator IP is one of our peers
		 */
		PEER_RDLOCK;

		if (LIST_EMPTY(&peer_head)) {
			fprintf(stream, "105 No more peers, shutting down!\n");

			PEER_UNLOCK;
			sync_master_runs = 0;
			fclose(stream);
			close(s);
			return;
		}
			
		LIST_FOREACH(peer, &peer_head, p_list) {
			if (memcmp(&peer->p_addr, &raddr.sin_addr, 
			    sizeof(peer->p_addr)) == 0)
				break;
		}

		PEER_UNLOCK;

		if (peer == NULL) {
			syslog(LOG_INFO, "Remote host %s is not a peer MX", 
			    peerstr);
			fprintf(stream, 
			    "106 You have no permission to talk, go away!\n");
			fclose(stream);
			continue;
		}

		if (pthread_create(&tid, NULL, (void *)sync_server, 
		    (void *)stream) != 0) {
			syslog(LOG_ERR, "incoming connexion from %s failed, "
			    "pthread_create failed: %s", 
			    peerstr, strerror(errno));
			fclose(stream);
			continue;
		}
	}

	/* NOTREACHED */
	syslog(LOG_ERR, "sync_master quitted unexpectedly");
	return;
}

void
sync_server(arg) 
	void *arg;
{
	FILE *stream = arg;
	char sep[] = " \n\t\r";
	char *cmd;
	char *keyword;
	char *addrstr;
	char *from;
	char *rcpt;
	char *datestr;
	char *cookie;
	char line[LINELEN + 1];
	peer_sync_t action;
	struct in_addr addr;
	time_t date;

	fprintf(stream, "200 Yeah, what do you want?\n");
	fflush(stream);

	while (1) {
		if ((fgets(line, LINELEN, stream)) == NULL)
			break;

		/*
		 * Get the command { quit | help | add | del }
		 */
		cookie = NULL;
		if ((cmd = strtok_r(line, sep, &cookie)) == NULL) {
			fprintf(stream, "101 No command\n");
			fflush(stream);
			continue;
		}

		if (strncmp(cmd, "quit", CMDLEN) == 0) {
			break;
		} else if ((strncmp(cmd, "help", CMDLEN)) == 0) {
			sync_help(stream);
			continue;
		} else if ((strncmp(cmd, "add", CMDLEN)) == 0) {
			action = PS_CREATE;
		} else if ((strncmp(cmd, "del", CMDLEN)) == 0) {
			action = PS_DELETE;
		} else {
			fprintf(stream, "102 Invalid command \"%s\"\n", cmd);
			fflush(stream);
			continue;
		}

		/*
		 * get { "addr" ip_address }
		 */
		if ((keyword = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}

		if (strncmp(keyword, "addr", CMDLEN) != 0) {
			fprintf(stream, 
			    "104 Unexpected keyword \"%s\"\n", keyword);
			fflush(stream);
			continue;
		}

		if ((addrstr = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}
			
		if (inet_pton(AF_INET, addrstr, (void *)&addr) != 1) {
			fprintf(stream, "107 Invalid IP address\n");
			fflush(stream);
			continue;
		}	

		/*
		 * get { "from" email_address }
		 */
		if ((keyword = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}

		if (strncmp(keyword, "from", CMDLEN) != 0) {
			fprintf(stream, 
			    "104 Unexpected keyword \"%s\"\n", keyword);
			fflush(stream);
			continue;
		}

		if ((from = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}

		/*
		 * get { "rcpt" email_address }
		 */
		if ((keyword = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}

		if (strncmp(keyword, "rcpt", CMDLEN) != 0) {
			fprintf(stream, 
			    "104 Unexpected keyword \"%s\"\n", keyword);
			fflush(stream);
			continue;
		}

		if ((rcpt = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}

		/*
		 * get { "date" valid_date }
		 */
		if ((keyword = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}

		if (strncmp(keyword, "date", CMDLEN) != 0) {
			fprintf(stream, 
			    "104 Unexpected keyword \"%s\"\n", keyword);
			fflush(stream);
			continue;
		}

		if ((datestr = strtok_r(NULL, sep, &cookie)) == NULL) {
			fprintf(stream, "103 Incomplete command\n");
			fflush(stream);
			continue;
		}

		date = atoi(datestr);

		/* 
		 * Check nothing remains
		 */
		if ((keyword = strtok_r(NULL, sep, &cookie)) != NULL) {	
			fprintf(stream, 
			    "104 Unexpected keyword \"%s\"\n", keyword);
			fflush(stream);
			continue;
		}

		fprintf(stream, "201 All right, I'll do that\n");
		fflush(stream);

		if (action == PS_CREATE) {
			PENDING_WRLOCK;
			pending_get(&addr, from, rcpt, date);
			PENDING_UNLOCK;
		}
		if (action == PS_DELETE) {
			pending_del(&addr, from, rcpt, date);
			autowhite_add(&addr, from, rcpt, NULL, "(mxsync)");
		}

		/* Flush modifications to disk */
		dump_flush();
	}

	fprintf(stream, "202 Good bye\n");
	fclose(stream);

	return;

}

void
sync_help(stream)
	FILE *stream;
{
	fprintf(stream, "203 Help? Sure, we have help here:\n");
	fprintf(stream, "203 \n");
	fprintf(stream, "203 Available commands are:\n");
	fprintf(stream, "203 help  -- displays this message\n");
	fprintf(stream, "203 quit  -- terminate connexion\n");
	fprintf(stream, 
	    "203 add addr <ip> from <email> rcpt <email> date <time>  "
	    "-- add en entry\n");
	fprintf(stream, 
	    "203 del addr <ip> from <email> rcpt <email> date <time>  "
	    "-- remove en entry\n");
	fflush(stream);

	return;
}

#define COM_TIMEOUT 3
int
sync_waitdata(fd)
	int fd;
{
	fd_set fdr, fde;
	struct timeval timeout;
	int retval;

	FD_ZERO(&fdr);
	FD_SET(fd, &fdr);

	FD_ZERO(&fde);
	FD_SET(fd, &fde);

	timeout.tv_sec = COM_TIMEOUT;
	timeout.tv_usec = 0;

	retval = select(fd + 1, &fdr, NULL, &fde, &timeout); 

	return retval;
}


void
sync_queue(peer, type, pending)	/* peer list must be read-locked */
	struct peer *peer;
	peer_sync_t type;
	struct pending *pending;
{
	struct sync *sync;

	/*
	 * If the queue has overflown, try to wakeup sync_sender to
	 * void it, but do not accept new entries anymore.
	 */
	if (peer->p_qlen >= SYNC_MAXQLEN) {
		syslog(LOG_ERR, "peer %s queue overflow (%d entries), "
		    "discarding new entry", peer->p_name, peer->p_qlen);

	} else {

		if ((sync = malloc(sizeof(*sync))) == NULL) {
			syslog(LOG_ERR, "cannot allocate memory: %s", 
			    strerror(errno)); 
			exit(EX_OSERR);
		}

		sync->s_peer = peer;
		sync->s_type = type;
		/* 
		 * Copy it instead of referencing it, since it could
		 * disapear before been treated. We don't have this
		 * problem with the peer, since the sync lists get
		 * purged at the same time the peer list get purged.
		 * One day, do that better, with refcounts.
		 */
		memcpy(&sync->s_pending, pending, sizeof(*pending)); 

		SYNC_WRLOCK;
		TAILQ_INSERT_HEAD(&peer->p_deferred, sync, s_list);
		SYNC_UNLOCK;
		peer->p_qlen++;
	}

	if (pthread_cond_signal(&sync_sleepflag) != 0) {
		syslog(LOG_ERR, 
		    "cannot wakeup sync_sender: %s", strerror(errno));
		exit(EX_SOFTWARE);
	}
	return;
}

void
sync_sender_start(void) {
	pthread_t tid;

	if (pthread_create(&tid, NULL, (void *)sync_sender, NULL) != 0) {
		syslog(LOG_ERR, "pthread_create failed: %s", strerror(errno));
		exit(EX_OSERR);
	}
	return;
}

/* ARGSUSED0 */
void
sync_sender(dontcare)
	void *dontcare;
{
	int done = 0;
	struct peer *peer;
	struct sync *sync;
	pthread_mutex_t mutex;
	struct timeval tv1, tv2, tv3;

	if (pthread_mutex_init(&mutex, NULL) != 0) {
		syslog(LOG_ERR, "pthread_mutex_init failed: %s\n", 
		    strerror(errno));
		exit(EX_OSERR);
	}

	if (pthread_mutex_lock(&mutex) != 0) {
		syslog(LOG_ERR, "pthread_mutex_lock failed: %s\n", 
		    strerror(errno));
		exit(EX_OSERR);
	}

	while (1) {
		if (pthread_cond_wait(&sync_sleepflag, &mutex) != 0)
			syslog(LOG_ERR, "pthread_cond_wait failed: %s\n", 
			    strerror(errno));
		if (debug) {
			syslog(LOG_DEBUG, "sync_sender running");
			gettimeofday(&tv1, NULL);
		}
		done = 0;

		PEER_RDLOCK;
		if (LIST_EMPTY(&peer_head))
			goto out;
			
		LIST_FOREACH(peer, &peer_head, p_list) {
			/* XXX take a read lock and then upgrade it */
			while (TAILQ_EMPTY(&peer->p_deferred) == 0) {
				SYNC_WRLOCK;
				sync = TAILQ_FIRST(&peer->p_deferred);
				TAILQ_REMOVE(&peer->p_deferred, sync, s_list);
				SYNC_UNLOCK;

				/* 
				 * We cannot keep the lock in sync_send
				 * as the send might timeout. Hence we
				 * remove the item, and put it back if 
				 * the send operation fails.
				 */
				if (sync_send(sync->s_peer, sync->s_type, 
				    &sync->s_pending) != 0) {
					SYNC_WRLOCK;
					TAILQ_INSERT_HEAD(&peer->p_deferred, 
					    sync, s_list);
					SYNC_UNLOCK;

					break;
				}

				peer->p_qlen--;
				free(sync);

				done++;
			}
		}
out:
		PEER_UNLOCK;

		if (debug) {
			gettimeofday(&tv2, NULL);
			timersub(&tv2, &tv1, &tv3);
			syslog(LOG_DEBUG, "sync_sender sleeping, "
			    "done %d entries in %ld.%06lds", done,
			    tv3.tv_sec, tv3.tv_usec);
		}
	}
}
