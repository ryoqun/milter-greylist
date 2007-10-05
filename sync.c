/* $Id: sync.c,v 1.80 2007/10/05 23:12:47 manu Exp $ */

/*
 * Copyright (c) 2004-2007 Emmanuel Dreyfus
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
__RCSID("$Id: sync.c,v 1.80 2007/10/05 23:12:47 manu Exp $");
#endif
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <syslog.h>
#include <sysexits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pending.h"
#include "sync.h"
#include "conf.h"
#include "autowhite.h"
#include "milter-greylist.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

#define SYNC_PROTO_CURRENT 3

struct sync_master_sock {
	int runs;
	int sock;
};

/* errors returned by stdio that should not cause an exit */
static int sync_ignored_errno[] = { 
#ifdef EAGAIN
	EAGAIN,
#endif /* EAGAIN */
#ifdef ECONNABORTED
	ECONNABORTED,
#endif /* ECONNABORTED */
#ifdef EMFILE
	EMFILE,
#endif /* EMFILE */
#ifdef ENFILE
	ENFILE,
#endif /* ENFILE */
#ifdef ENOBUFS
	ENOBUFS,
#endif /* ENOBUFS */
#ifdef ENOMEM
	ENOMEM,
#endif /* ENOMEM */
#ifdef ENOSR
	ENOSR,
#endif /* ENOSR */
#ifdef EWOULDBLOCK
	EWOULDBLOCK,
#endif /* EWOULDBLOCK */
	0,
};

static pthread_mutex_t sync_master_lock = PTHREAD_MUTEX_INITIALIZER;
struct sync_master_sock sync_master4 = { 0, -1 };
struct sync_master_sock sync_master6 = { 0, -1 };

struct peerlist peer_head;
pthread_rwlock_t peer_lock; /* For the peer list */

static pthread_mutex_t sync_dirty_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sync_sleepflag = PTHREAD_COND_INITIALIZER;
static int sync_dirty = 0;

static void sync_listen(char *, char *, struct sync_master_sock *);
static int local_addr(const struct sockaddr *sa, const socklen_t salen);
static int sync_queue_poke(struct peer *, struct sync *);
static struct sync * sync_queue_peek(struct peer *);
static int select_protocol(struct peer *, int, FILE *);
static void sync_vers(FILE *, int);
static int is_fatal(int);

void
peer_init(void) {
	int error;

	LIST_INIT(&peer_head);
	if ((error = pthread_rwlock_init(&peer_lock, NULL)) != 0) {
		mg_log(LOG_ERR, 
		    "pthread_rwlock_init failed: %s", strerror(error));
		exit(EX_OSERR);
	}

	return;
}

void 
peer_clear(void) {
	struct peer *peer;
	struct sync *sync;

	PEER_WRLOCK;

	while(!LIST_EMPTY(&peer_head)) {
		peer = LIST_FIRST(&peer_head);

		while((sync = sync_queue_peek(peer)) != NULL)
			sync_free(sync);
			
		if (peer->p_stream != NULL)
			Fclose(peer->p_stream);

		LIST_REMOVE(peer, p_list);
		pthread_mutex_destroy(&peer->p_mtx);
		free(peer->p_name);
		free(peer);
	}

	PEER_UNLOCK;

	return;	
}

void 
peer_add(peername)
	char *peername;
{
	struct peer *peer;

	if ((peer = malloc(sizeof(*peer))) == NULL ||
	    (peer->p_name = strdup(peername)) == NULL) {
		mg_log(LOG_ERR, "cannot add peer: %s", strerror(errno));
		exit(EX_OSERR);
	}

	peer->p_qlen = 0;
	peer->p_stream = NULL;
	peer->p_flags = 0;
	TAILQ_INIT(&peer->p_deferred);
	pthread_mutex_init(&peer->p_mtx, NULL);

	PEER_WRLOCK;
	LIST_INSERT_HEAD(&peer_head, peer, p_list);
	PEER_UNLOCK;

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "load peer %s", peer->p_name);

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
		sync_queue(peer, PS_CREATE, pending, -1); /* -1: unused */

out:
	PEER_UNLOCK;
	
	return;
}

void
peer_delete(pending, autowhite)
	struct pending *pending;
	time_t autowhite;
{
	struct peer *peer;

	PEER_RDLOCK;
	if (LIST_EMPTY(&peer_head))
		goto out;

	LIST_FOREACH(peer, &peer_head, p_list) 
		sync_queue(peer, PS_DELETE, pending, autowhite);

out:
	PEER_UNLOCK;
	
	return;
}

static int
sync_queue_poke(peer, sync)
	struct peer *peer;
	struct sync *sync;
{
	int r = 0;

	pthread_mutex_lock(&peer->p_mtx);
	if (peer->p_qlen < SYNC_MAXQLEN) {
		TAILQ_INSERT_HEAD(&peer->p_deferred, sync, s_list);
		peer->p_qlen++;
		r = 1;
	}
	pthread_mutex_unlock(&peer->p_mtx);
	return r;
}

static struct sync *
sync_queue_peek(peer)
	struct peer *peer;
{
	struct sync *sync;

	pthread_mutex_lock(&peer->p_mtx);
	sync = TAILQ_FIRST(&peer->p_deferred);
	if (!TAILQ_EMPTY(&peer->p_deferred)) {
		TAILQ_REMOVE(&peer->p_deferred, sync, s_list);
		peer->p_qlen--;
	}
	pthread_mutex_unlock(&peer->p_mtx);
	return sync;
}

int
sync_send(peer, type, pending, autowhite) /* peer list is read-locked */
	struct peer *peer;
	peer_sync_t type;
	struct pending *pending;
	time_t autowhite;
{
	char sep[] = " \n\t\r";
	char *replystr;
	int replycode;
	char line[LINELEN + 1];
	char *cookie = NULL;
	char *keyw;
	char awstr[LINELEN + 1];
	int bw;

	if ((peer->p_stream == NULL) && (peer_connect(peer) != 0))
		return -1;

	*line = '\0';
	switch(type) {
	case PS_FLUSH:
		bw = snprintf(line, LINELEN, "flush addr %s\r\n",
		    pending->p_addr);
		break;
	case PS_CREATE:
		bw = snprintf(line, LINELEN, "add addr %s from %s "
		    "rcpt %s date %ld\r\n", pending->p_addr, 
			pending->p_from, pending->p_rcpt, 
			(long)pending->p_tv.tv_sec);
		break;
	default:
		if (peer->p_vers >= 2) {
			keyw = "del2";
			snprintf(awstr, LINELEN, " aw %ld", (long)autowhite);
		} else {
			keyw = "del";
			awstr[0] = '\0';
		}
		bw = snprintf(line, LINELEN, "%s addr %s from %s "
		    "rcpt %s date %ld%s\r\n", keyw, pending->p_addr, 
			pending->p_from, pending->p_rcpt, 
			(long)pending->p_tv.tv_sec, awstr);
		break;
	}

	if (bw > LINELEN) {
		mg_log(LOG_ERR, "closing connexion with peer %s: "
		    "send buffer would overflow (%d entries queued)", 
		    peer->p_name, peer->p_qlen);
		Fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	bw = fprintf(peer->p_stream, "%s", line);
	if (bw != strlen(line)) {
		mg_log(LOG_ERR, "closing connexion with peer %s: "
		    "%s (%d entries queued) - I was unable to send "
		    "complete line \"%s\" - bytes written: %i", 
		    peer->p_name, strerror(errno), peer->p_qlen, 
		    line, bw);
		Fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	fflush(peer->p_stream);

	/* 
	 * Check the return code 
	 */
	get_more:
	sync_waitdata(peer->p_socket);
	if (fgets(line, LINELEN, peer->p_stream) == NULL) {
		if (errno == EAGAIN) {
			if ( feof(peer->p_stream) ) {
				mg_log(LOG_ERR, "lost connexion with peer %s: "
		  		  "%s (%d entries queued)", 
				    peer->p_name, strerror(errno), peer->p_qlen);
				Fclose(peer->p_stream);
				peer->p_stream = NULL;
				return -1;
			}
			goto get_more;
		}
		mg_log(LOG_ERR, "lost connexion with peer %s: "
		    "%s (%d entries queued)", 
		    peer->p_name, strerror(errno), peer->p_qlen);
		Fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	/*
	 * On some systems, opening a stream on a socket introduce
	 * weird behavior: the in and out buffers get mixed up. 
	 * By calling fflush() after each read operation, we fix that
	 */
	fflush(peer->p_stream);

	if ((replystr = strtok_r(line, sep, &cookie)) == NULL) {
		mg_log(LOG_ERR, "Unexpected reply \"%s\" from %s, "
		    "closing connexion (%d entries queued)", 
		    line, peer->p_name, peer->p_qlen);
		Fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	replycode = atoi(replystr);
	if (replycode != 201) {
		mg_log(LOG_ERR, "Unexpected reply \"%s\" from %s, "
		    "closing connexion (%d entries queued)", 
		    line, peer->p_name, peer->p_qlen);
		Fclose(peer->p_stream);
		peer->p_stream = NULL;
		return -1;
	}

	if (conf.c_debug)
		mg_log(LOG_DEBUG, "sync one entry with %s", peer->p_name);

	return 0;
}

int
peer_connect(peer)	/* peer list is read-locked */
	struct peer *peer;
{
	struct servent *se;
#ifdef HAVE_GETADDRINFO
	struct addrinfo hints, *res0, *res;
	int err;
#else
	struct protoent *pe;
	int proto;
	sockaddr_t raddr;
	socklen_t raddrlen;
#endif
	sockaddr_t laddr;
	socklen_t laddrlen;
	char *laddrstr;
	int service;
	int s = -1;
	char *replystr;
	int replycode;
	FILE *stream;
	char sep[] = " \n\t\r";
	char line[LINELEN + 1];
	int param;
	char *cookie = NULL;

	if (peer->p_stream != NULL)
		mg_log(LOG_ERR, "peer_connect called and peer->p_stream != 0");

	if (conf.c_syncport != NULL) {
		service = htons(atoi(conf.c_syncport));
	} else {
		if ((se = getservbyname(MXGLSYNC_NAME, "tcp")) == NULL)
		    service = htons(atoi(MXGLSYNC_PORT));
		else
		    service = se->s_port;
	}

#ifdef HAVE_GETADDRINFO
	bzero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(peer->p_name, "0", &hints, &res0)) != 0) {
		mg_log(LOG_ERR, "cannot sync with peer %s, "
		    "getaddrinfo failed: %s (%d entries queued)",
		    peer->p_name, gai_strerror(err), peer->p_qlen);
		return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		/*We only test an address family which kernel supports. */
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
			continue;
		close(s);

		if (local_addr(res->ai_addr, res->ai_addrlen)) {
			peer->p_flags |= P_LOCAL;
			freeaddrinfo(res0);
			return -1;
		}
	}

	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (s == -1)
			continue;

		switch (res->ai_family) {
		case AF_INET:
			SA4(res->ai_addr)->sin_port = service;
			if (conf.c_syncsrcaddr != NULL) {
				laddrstr = conf.c_syncsrcaddr;
			} else {
				laddrstr = "0.0.0.0";
				}
			break;
#ifdef AF_INET6
		case AF_INET6:
			SA6(res->ai_addr)->sin6_port = service;
			laddrstr = "::";
			break;
#endif
		default:
			mg_log(LOG_ERR, "cannot sync, unknown address family");
			close(s);
			s = -1;
			continue;
		}
		laddrlen = sizeof(laddr);
		if (ipfromstring(laddrstr, SA(&laddr), &laddrlen,
		    res->ai_family) == 1 &&
		    bind(s, SA(&laddr), laddrlen) == 0 &&
		    connect(s, res->ai_addr, res->ai_addrlen) == 0)
			break;
		close(s);
		s = -1;
	}
	freeaddrinfo(res0);
	if (s < 0) {
		mg_log(LOG_ERR,
		    "cannot sync with peer %s: %s (%d entries queued)",
		    peer->p_name, strerror(errno), peer->p_qlen);
		return -1;
	}
#else
	raddrlen = sizeof(raddr);
	if (ipfromstring(peer->p_name, SA(&raddr), &raddrlen,
	    AF_UNSPEC) != 1) {
		mg_log(LOG_ERR, "cannot sync, invalid address");
		return -1;
	}

	if (local_addr(SA(&raddr), raddrlen)) {
		peer->p_flags |= P_LOCAL;
		return -1;
	}

	switch (SA(&raddr)->sa_family) {
	case AF_INET:
		SA4(&raddr)->sin_port = service;
		if (conf.c_syncsrcaddr != NULL) {
			laddrstr = conf.c_syncsrcaddr;
		} else {
			laddrstr = "0.0.0.0";
			}
		break;
#ifdef AF_INET6
	case AF_INET6:
		SA6(&raddr)->sin6_port = service;
		laddrstr = "::";
		break;
#endif
	default:
		mg_log(LOG_ERR, "cannot sync, unknown address family");
		return -1;
	}

	if ((pe = getprotobyname("tcp")) == NULL)
		proto = 6;
	else
		proto = pe->p_proto;

	if ((s = socket(SA(&raddr)->sa_family, SOCK_STREAM, proto)) == -1) {
		mg_log(LOG_ERR, "cannot sync with peer %s, "
		    "socket failed: %s (%d entries queued)", 
		    peer->p_name, strerror(errno), peer->p_qlen);
		return -1;
	}

	laddrlen = sizeof(laddr);
	if (ipfromstring(laddrstr, SA(&laddr), &laddrlen,
	    SA(&raddr)->sa_family) != 1) {
		mg_log(LOG_ERR, "cannot sync, invalid address");
		close(s);
		return -1;
	}

	if (bind(s, SA(&laddr), laddrlen) != 0) {
		mg_log(LOG_ERR, "cannot sync with peer %s, "
		    "bind failed: %s (%d entries queued)",
		    peer->p_name, strerror(errno), peer->p_qlen);
		close(s);
		return -1;
	}

	if (connect(s, SA(&raddr), raddrlen) != 0) {
		mg_log(LOG_ERR, "cannot sync with peer %s, "
		    "connect failed: %s (%d entries queued)", 
		    peer->p_name, strerror(errno), peer->p_qlen);
		close(s);
		return -1;
	}
#endif

	param = O_NONBLOCK;
	if (fcntl(s, F_SETFL, param) != 0) {
		mg_log(LOG_ERR, "cannot set non blocking I/O with %s: %s",
		    peer->p_name, strerror(errno));
	}

	errno = 0;
	if ((stream = Fdopen(s, "w+")) == NULL) {
		mg_log(LOG_ERR, "cannot sync with peer %s, "
		    "fdopen failed: %s (%d entries queued)", 
		    peer->p_name, 
		    (errno == 0) ? "out of stdio streams" : strerror(errno),
		    peer->p_qlen);
		close(s);
		return -1;
	}

#ifdef USE_FD_POOL
	s = fileno(stream);     /* the socket descriptor could have been replaced by Fdopen() ! */
#endif

	if (setvbuf(stream, NULL, _IOLBF, 0) != 0)
		mg_log(LOG_ERR, "cannot set line buffering with peer %s: %s", 
		    peer->p_name, strerror(errno));

	sync_waitdata(s);	
	if (fgets(line, LINELEN, stream) == NULL) {
		mg_log(LOG_ERR, "Lost connexion with peer %s: "
		    "%s (%d entries queued)", 
		    peer->p_name, strerror(errno), peer->p_qlen);
		goto bad;
	}

	/*
	 * On some systems, opening a stream on a socket introduce
	 * weird behavior: the in and out buffers get mixed up. 
	 * By calling fflush() after each read operation, we fix that
	 */
	fflush(stream);

	if ((replystr = strtok_r(line, sep, &cookie)) == NULL) {
		mg_log(LOG_ERR, "Unexpected reply \"%s\" from peer %s "
		    "closing connexion (%d entries queued)", 
		    line, peer->p_name, peer->p_qlen);
		goto bad;
	}

	replycode = atoi(replystr);
	if (replycode != 200) {
		mg_log(LOG_ERR, "Unexpected reply \"%s\" from peer %s "
		    "closing connexion (%d entries queued)", 
		    line, peer->p_name, peer->p_qlen);
		goto bad;
	}

	if ((peer->p_vers = select_protocol(peer, s, stream)) == 0)
		goto bad;	

	mg_log(LOG_INFO, "Connection to %s established, protocol version %d", 
	    peer->p_name, peer->p_vers);
	peer->p_stream = stream;
	peer->p_socket = s;

	return 0;

bad:
	Fclose(stream);
	peer->p_stream = NULL;

	return -1;
}

void
sync_master_stop(void) {
	if (sync_master4.sock != 1) {
		close(sync_master4.sock);
		sync_master4.sock = -1;
	}

	if (sync_master6.sock != 1) {
		close(sync_master6.sock);
		sync_master6.sock = -1;
	}
}

void
sync_master_restart(void) {
	pthread_t tid;
	int empty;
	int error;

	PEER_RDLOCK;
	empty = LIST_EMPTY(&peer_head);
	PEER_UNLOCK;

	pthread_mutex_lock(&sync_master_lock);
	if (empty || sync_master4.runs || sync_master6.runs)
		goto last;

	if (conf.c_syncaddr != NULL) {
		if (strchr(conf.c_syncaddr, ':'))
		    sync_listen(conf.c_syncaddr, conf.c_syncport,
				&sync_master6);
		else
		    sync_listen(conf.c_syncaddr, conf.c_syncport,
				&sync_master4);
	} else {

#ifdef AF_INET6
		sync_listen("::", conf.c_syncport, &sync_master6);
#endif
		sync_listen("0.0.0.0", conf.c_syncport, &sync_master4);
	}


	if (!sync_master4.runs && !sync_master6.runs) {
		mg_log(LOG_ERR, "cannot start MX sync, socket failed: %s",
		    strerror(errno));
		exit(EX_OSERR);
	}
	if (sync_master6.runs) {
		if ((error = pthread_create(&tid, NULL, sync_master,
		    (void *)&sync_master6)) != 0) {
			mg_log(LOG_ERR, 
			    "Cannot run MX sync thread for IPv6: %s",
			    strerror(error));
			exit(EX_OSERR);
		}
		if ((error = pthread_detach(tid)) != 0) {
			mg_log(LOG_ERR, 
			    "pthread_detach failed for IPv6 MX sync: %s",
			    strerror(error));
			exit(EX_OSERR);
		}
	}
	if (sync_master4.runs) {
		if ((error = pthread_create(&tid, NULL, sync_master,
		    (void *)&sync_master4)) != 0) {
			mg_log(LOG_ERR, 
			    "Cannot run MX sync thread for IPv4: %s",
			    strerror(error));
			exit(EX_OSERR);
		}
		if ((error = pthread_detach(tid)) != 0) {
			mg_log(LOG_ERR, 
			    "pthread_detach failed for IPv4 MX sync: %s",
			    strerror(error));
			exit(EX_OSERR);
		}
	}
last:
	pthread_mutex_unlock(&sync_master_lock);
}

void *
sync_master(arg)
	void *arg;
{
	struct sync_master_sock *sms = arg;

	conf_retain();
	for (;;) {
		sockaddr_t raddr;
		socklen_t raddrlen;
		int fd;
		FILE *stream;
		pthread_t tid;
		struct peer *peer;
		char peerstr[IPADDRSTRLEN];
		int error;
		int sock;

		pthread_mutex_lock(&sync_master_lock);
		sock = sms->sock;
		pthread_mutex_unlock(&sync_master_lock);

		/* TODO: accept connections in nonblocking mode
		 * in order to watch conf change */
		bzero((void *)&raddr, sizeof(raddr));
		raddrlen = sizeof(raddr);
		if ((fd = accept(sock, SA(&raddr), &raddrlen)) == -1) {
			mg_log(LOG_ERR, "incoming connexion "
			    "failed: %s", strerror(errno));

			if (is_fatal(errno))
                        	exit(EX_OSERR);


		}
		unmappedaddr(SA(&raddr), &raddrlen);

		conf_release();
		conf_retain();

		iptostring(SA(&raddr), raddrlen, peerstr, sizeof(peerstr));
		mg_log(LOG_INFO, "Incoming MX sync connexion from %s", 
		    peerstr);

		errno = 0;
		if ((stream = Fdopen(fd, "w+")) == NULL) {
			mg_log(LOG_ERR, 
			    "incoming connexion from %s failed, "
			    "fdopen fail: %s", peerstr, 
		    	    (errno == 0) ? "out of stdio streams"
					 : strerror(errno));
			close(fd);
			exit(EX_OSERR);
		}

		if (setvbuf(stream, NULL, _IOLBF, 0) != 0)
			mg_log(LOG_ERR, "cannot set line buffering: %s", 
			    strerror(errno));	
		
		/*
		 * Check that the orginator IP is one of our peers
		 */
		PEER_RDLOCK;

		if (LIST_EMPTY(&peer_head)) {
			fprintf(stream, "105 No more peers, shutting down!\n");

			PEER_UNLOCK;
			Fclose(stream);
			pthread_mutex_lock(&sync_master_lock);
			close(sms->sock);
			sms->sock = -1;
			sms->runs = 0;
			pthread_mutex_unlock(&sync_master_lock);
			conf_release();
			return NULL;
		}
			
		LIST_FOREACH(peer, &peer_head, p_list) {
#ifdef HAVE_GETADDRINFO
			struct addrinfo hints, *res0, *res;
			int err;
			int match = 0;

			bzero(&hints, sizeof(hints));
			hints.ai_flags = AI_PASSIVE;
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			err = getaddrinfo(peer->p_name, "0", &hints, &res0);
			if (err != 0) {
				mg_log(LOG_ERR, "cannot resolve %s: %s",
				    peer->p_name, gai_strerror(err));
				continue;
			}
			for (res = res0; res; res = res->ai_next) {
				if (ip_equal(SA(&raddr), res->ai_addr)) {
					match = 1;
					break;
				}
			}
			freeaddrinfo(res0);
			if (match)
				break;
#else
			sockaddr_t addr;
			socklen_t addrlen;

			addrlen = sizeof(addr);
			if (ipfromstring(peer->p_name, SA(&addr), &addrlen,
			     AF_UNSPEC) != 1) {
				mg_log(LOG_ERR, "cannot resolve %s",
				    peer->p_name);
				continue;
			}
			if (ip_equal(SA(&raddr), SA(&addr)))
				break;
#endif
		}

		PEER_UNLOCK;

		if (peer == NULL) {
			mg_log(LOG_INFO, "Remote host %s is not a peer MX", 
			    peerstr);
			fprintf(stream, 
			    "106 You have no permission to talk, go away!\n");
			Fclose(stream);
			continue;
		}

		if ((error = pthread_create(&tid, NULL, 
		    (void *(*)(void *))sync_server, (void *)stream)) != 0) {
			mg_log(LOG_ERR, "incoming connexion from %s failed, "
			    "pthread_create failed: %s", 
			    peerstr, strerror(error));
			Fclose(stream);
			continue;
		}
		if ((error = pthread_detach(tid)) != 0) {
			mg_log(LOG_ERR, "incoming connexion from %s failed, "
			    "pthread_detach failed: %s",
			    peerstr, strerror(error));
			exit(EX_OSERR);
		}
	}

	/* NOTREACHED */
	mg_log(LOG_ERR, "sync_master quitted unexpectedly");
	return NULL;
}

/* sync_master_lock must be locked */
static void
sync_listen(addr, port, sms)
        char *addr, *port;
	struct sync_master_sock *sms;
{
	struct protoent *pe;
	struct servent *se;
	int proto;
	sockaddr_t laddr;
	socklen_t laddrlen;
	int service;
	int optval;
	int s;

	sms->runs = 1;
	laddrlen = sizeof(laddr);
	if (ipfromstring(addr, SA(&laddr), &laddrlen, AF_UNSPEC) != 1) {
		sms->runs = 0;
		return;
	}

	if ((pe = getprotobyname("tcp")) == NULL)
		proto = 6;
	else
		proto = pe->p_proto;

	if (port != NULL)
		service = htons(atoi(port));
	else {
		if ((se = getservbyname(MXGLSYNC_NAME, "tcp")) == NULL)
		    service = htons(atoi(MXGLSYNC_PORT));
		else
		    service = se->s_port;
	}

	switch (SA(&laddr)->sa_family) {
	case AF_INET:
		SA4(&laddr)->sin_port = service;
		break;
#ifdef AF_INET6
	case AF_INET6:
		SA6(&laddr)->sin6_port = service;
		break;
#endif
	default:
		sms->runs = 0;
		return;
	}

	if ((s = socket(SA(&laddr)->sa_family, SOCK_STREAM, proto)) == -1) {
		sms->runs = 0;
		return;
	}

	optval = 1;
	if ((setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
	    &optval, sizeof(optval))) != 0) {
		mg_log(LOG_ERR, "cannot set SO_REUSEADDR: %s",
		    strerror(errno));
	}

	optval = 1;
	if ((setsockopt(s, SOL_SOCKET, SO_KEEPALIVE,
	    &optval, sizeof(optval))) != 0) {
		mg_log(LOG_ERR, "cannot set SO_KEEPALIVE: %s",
		    strerror(errno));
	}

#ifdef IPV6_V6ONLY
	if (SA(&laddr)->sa_family == AF_INET6) {
		optval = 1;
		if ((setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
		    &optval, sizeof(optval))) != 0) {
			mg_log(LOG_ERR, "cannot set IPV6_V6ONLY: %s",
			    strerror(errno));
		}
	}
#endif

	if (bind(s, SA(&laddr), laddrlen) != 0) {
		mg_log(LOG_ERR, "cannot start MX sync, bind failed: %s",
		    strerror(errno));
		sms->runs = 0;
		close(s);
		return;
	}

	if (listen(s, MXGLSYNC_BACKLOG) != 0) {
		mg_log(LOG_ERR, "cannot start MX sync, listen failed: %s",
		    strerror(errno));
		sms->runs = 0;
		close(s);
		return;
	}

	sms->sock = s;
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
	char from_clean[ADDRLEN + 1];
	char rcpt_clean[ADDRLEN + 1];
	char *datestr;
	char *awstr;
	char *cookie;
	char line[LINELEN + 1];
	peer_sync_t action;
	sockaddr_t addr;
	socklen_t addrlen;
	time_t date;
	time_t aw;
	
	conf_retain();

	aw = time(NULL) + conf.c_autowhite_validity;
	fprintf(stream, "200 Yeah, what do you want?\n");
	fflush(stream);

	for (;;) {
		if ((fgets(line, LINELEN, stream)) == NULL)
			break;

		/*
		 * On some systems, opening a stream on a socket introduce
		 * weird behavior: the in and out buffers get mixed up. 
		 * By calling fflush() after each read operation, we fix that
		 */
		fflush(stream);

		/*
		 * Get the command { quit | help | add | del | del2 | flush }
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
		} else if ((strncmp(cmd, "vers3", CMDLEN)) == 0) {
			sync_vers(stream, 3);
			continue;
		} else if ((strncmp(cmd, "vers2", CMDLEN)) == 0) {
			sync_vers(stream, 2);
			continue;
		} else if ((strncmp(cmd, "add", CMDLEN)) == 0) {
			action = PS_CREATE;
		} else if ((strncmp(cmd, "del2", CMDLEN)) == 0) {
			action = PS_DELETE;
			aw = -1;
		} else if ((strncmp(cmd, "del", CMDLEN)) == 0) {
			action = PS_DELETE;
		} else if ((strncmp(cmd, "flush", CMDLEN)) == 0) {
			action = PS_FLUSH;
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
			
		addrlen = sizeof(addr);
		if (ipfromstring(addrstr, SA(&addr), &addrlen,
		    AF_UNSPEC) != 1) {
			fprintf(stream, "107 Invalid IP address\n");
			fflush(stream);
			continue;
		}	

		if (action == PS_FLUSH) {
			from = NULL;
			rcpt = NULL;
			date = 0;
			goto eol;
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
		(void)strncpy_rmsp(from_clean, from, ADDRLEN);
		from = from_clean;

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
		(void)strncpy_rmsp(rcpt_clean, rcpt, ADDRLEN);
		rcpt = rcpt_clean;

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

		if (aw == -1) {
			/*
			 * get { "aw" valid_date }
			 */
			if ((keyword = strtok_r(NULL, sep, &cookie)) == NULL) {
				fprintf(stream, "103 Incomplete command\n");
				fflush(stream);
				continue;
			}

			if (strncmp(keyword, "aw", CMDLEN) != 0) {
				fprintf(stream, 
				    "104 Unexpected keyword \"%s\"\n", keyword);
				fflush(stream);
				continue;
			}

			if ((awstr = strtok_r(NULL, sep, &cookie)) == NULL) {
				fprintf(stream, "103 Incomplete command\n");
				fflush(stream);
				continue;
			}

			aw = atoi(awstr);
		}

		/* 
		 * Check nothing remains
		 */
eol:
		if ((keyword = strtok_r(NULL, sep, &cookie)) != NULL) {	
			fprintf(stream, 
			    "104 Unexpected keyword \"%s\"\n", keyword);
			fflush(stream);
			continue;
		}

		fprintf(stream, "201 All right, I'll do that\n");
		fflush(stream);

		if (action == PS_CREATE) {
			int dirty = 0;
			PENDING_LOCK;
			/* delay = -1 means unused: we supply the date */
			if (pending_get(SA(&addr), addrlen, from, rcpt, date))
				++dirty;
			PENDING_UNLOCK;
			dump_touch(dirty);
		}
		if (action == PS_DELETE) {
			pending_del(SA(&addr), addrlen, from, rcpt, date);
			autowhite_add(SA(&addr), addrlen, from, 
			    rcpt, &aw, "(mxsync)");
		}
		if (action == PS_FLUSH) {
			pending_del_addr(SA(&addr), addrlen, NULL, 0);
			autowhite_del_addr(SA(&addr), addrlen);
		}

		/* Flush modifications to disk */
		dump_flush();
	}

	fprintf(stream, "202 Good bye\n");
	Fclose(stream);

	conf_release();

	return;

}

static void
sync_vers(stream, vers)
	FILE *stream;
	int vers;
{
	if (vers <= SYNC_PROTO_CURRENT) {
		fprintf(stream, 
		    "%d Yes, I speak version %d, what do you think?\n",
		    800 + vers, vers);
	} else {
		fprintf(stream, "108 Invalid vers%d command\n", vers);
	}
	fflush(stream);
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
	fprintf(stream, "203 vers2 -- speak version 2 protocol\n");
	fprintf(stream, "203 vers3 -- speak version 3 protocol\n");
	fprintf(stream, 
	    "203 add addr <ip> from <email> rcpt <email> date <time>  "
	    "-- add en entry\n");
	fprintf(stream, 
	    "203 del addr <ip> from <email> rcpt <email> date <time>  "
	    "-- remove en entry\n");
	fprintf(stream, 
	    "203 del2 addr <ip> from <email> rcpt <email> date <time> "
	    "aw <time> -- remove en entry, adding it to autowhite with "
	    "given delay (version 2 only)\n");
	fprintf(stream, 
	    "203 flush addr <ip> -- remove anything about an ip "
	    " (version 3 only)\n");
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
sync_queue(peer, type, pending, autowhite)/* peer list must be read-locked */
	struct peer *peer;
	peer_sync_t type;
	struct pending *pending;
	time_t autowhite;
{
	int error;
	struct sync *sync;

	if (peer->p_flags & P_LOCAL)
		return;

	if ((sync = malloc(sizeof(*sync))) == NULL) {
		mg_log(LOG_ERR, "cannot allocate memory: %s", 
		    strerror(errno)); 
		exit(EX_OSERR);
	}

	sync->s_peer = peer;
	sync->s_type = type;
	sync->s_autowhite = autowhite;
	sync->s_pending = pending_ref(pending);

	/*
	 * If the queue has overflown, try to wakeup sync_sender to
	 * void it, but do not accept new entries anymore.
	 */
	if (!sync_queue_poke(peer, sync)) {
		mg_log(LOG_ERR, "peer %s queue overflow (%d entries), "
		    "discarding new entry", peer->p_name, peer->p_qlen);
		sync_free(sync);
	}

	pthread_mutex_lock(&sync_dirty_lock);
	sync_dirty = 1;
	pthread_mutex_unlock(&sync_dirty_lock);
	if ((error = pthread_cond_signal(&sync_sleepflag)) != 0) {
		mg_log(LOG_ERR, 
		    "cannot wakeup sync_sender: %s", strerror(error));
		exit(EX_SOFTWARE);
	}
	return;
}

void
sync_free(sync)
	struct sync *sync;
{
	pending_free(sync->s_pending);
	free(sync);
}

void
sync_sender_start(void) {
	pthread_t tid;
	int error;

	if ((error = pthread_create(&tid, NULL, 
	    (void *(*)(void *))sync_sender, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_create failed: %s", strerror(error));
		exit(EX_OSERR);
	}
	if ((error = pthread_detach(tid)) != 0) {
		mg_log(LOG_ERR, "pthread_detach failed: %s", strerror(error));
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
	int error;

	if ((error = pthread_mutex_init(&mutex, NULL)) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_init failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	if ((error = pthread_mutex_lock(&mutex)) != 0) {
		mg_log(LOG_ERR, "pthread_mutex_lock failed: %s", 
		    strerror(error));
		exit(EX_OSERR);
	}

	for (;;) {
		pthread_mutex_lock(&sync_dirty_lock);
		while (!sync_dirty)
			pthread_cond_wait(&sync_sleepflag, &sync_dirty_lock);
		sync_dirty = 0;
		pthread_mutex_unlock(&sync_dirty_lock);

		conf_retain();

		if (conf.c_debug) {
			mg_log(LOG_DEBUG, "sync_sender running");
			gettimeofday(&tv1, NULL);
		}
		done = 0;

		PEER_RDLOCK;
		if (LIST_EMPTY(&peer_head))
			goto out;
			
		LIST_FOREACH(peer, &peer_head, p_list) {
			/* Don't try to sync with ourselves */
			if (peer->p_flags & P_LOCAL)
				continue;

			while ((sync = sync_queue_peek(peer)) != NULL ) {

				if (sync_send(sync->s_peer, sync->s_type, 
				    sync->s_pending, sync->s_autowhite) != 0) {
					if (!sync_queue_poke(peer, sync))
						sync_free(sync);

					break;
				}

				sync_free(sync);

				done++;
			}
		}
out:
		PEER_UNLOCK;

		if (conf.c_debug) {
			gettimeofday(&tv2, NULL);
			timersub(&tv2, &tv1, &tv3);
			mg_log(LOG_DEBUG, "sync_sender sleeping, "
			    "done %d entries in %ld.%06lds", done,
			    tv3.tv_sec, tv3.tv_usec);
		}

		conf_release();
	}
}


static int
local_addr(sa, salen)
	const struct sockaddr *sa;
	const socklen_t salen;
{
	sockaddr_t addr;
	int	sfd, islocal;

	memcpy(&addr, sa, salen);
	switch(sa->sa_family) {
	case AF_INET:
		SA4(&addr)->sin_port = 0;
		break;

#ifdef AF_INET6
	case AF_INET6:
		SA6(&addr)->sin6_port = 0;
		break;
#endif

	default:
		mg_log(LOG_ERR, "local_addr: unsupported AF %d",
		    sa->sa_family);
		return -1;
		break;
	}

	if ((sfd = socket(sa->sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		mg_log(LOG_ERR, "local_addr: socket failed: %s",
		    strerror(errno));
		return -1;
	}

	errno = 0;	 /* Solaris' bind() does not set errno... */
	if (bind(sfd, sa, salen) == -1) {
		if (errno != EADDRNOTAVAIL && 
#ifdef __FreeBSD__
		    errno != EINVAL &&
#endif
#ifdef __sun
		    errno != 0 &&
#endif
		    1) {
			mg_log(LOG_ERR, "local_addr: bind failed: %s",
			    strerror(errno));
			islocal = -1;
		} else {
			islocal = 0;
		}
	} else {
		islocal = 1;
	}

	close(sfd);

	return islocal;
}

static int 
select_protocol(peer, s, stream)
	struct peer *peer;
	int s;
	FILE *stream;
{
	char line[LINELEN + 1];
	int vers;
	char *replystr;
	int replycode;
	char sep[] = " \n\t\r";
	char *cookie = NULL;

	for (vers = SYNC_PROTO_CURRENT; vers > 1; vers--) {
		fprintf(stream, "vers%d\n", vers);

		fflush(stream);

		sync_waitdata(s);	
		if (fgets(line, LINELEN, stream) == NULL) {
			mg_log(LOG_ERR, "Lost connexion with peer %s: "
			    "%s (%d entries queued)", 
			    peer->p_name, strerror(errno), peer->p_qlen);
			return 0;
		}

		if ((replystr = strtok_r(line, sep, &cookie)) == NULL) {
			mg_log(LOG_ERR, "Unexpected reply \"%s\" from peer %s "
			    "closing connexion (%d entries queued)", 
			    line, peer->p_name, peer->p_qlen);
			return 0;
		}

		fflush(stream);

		replycode = atoi(replystr);
		if (replycode != 800 + vers) {
			mg_log(LOG_DEBUG, 
			    "peer %s answered code %d to command vers%d",
			    peer->p_name, replycode, vers);
		} else {
			return vers;
		}
	}

	return 1;
}

void
peer_flush(pending)
	struct pending *pending;
{
	struct peer *peer;

	PEER_RDLOCK;
	if (LIST_EMPTY(&peer_head))
		goto out;

	LIST_FOREACH(peer, &peer_head, p_list) {
		/* Unsupported before verseion 3 */
		if (peer->p_vers < 3)
			continue;
		sync_queue(peer, PS_FLUSH, pending, -1); /* -1: unused */
	}

out:
	PEER_UNLOCK;
	
	return;
}

static int 
is_fatal(err)
	int err;
{
	int *i;

	for (i = sync_ignored_errno; *i; i++)
		if (errno == *i)
			return 0;
	return 1;
}
