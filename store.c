#include "config.h"

/* XXXmanu licence? */

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#ifdef __RCSID
__RCSID("$Id: store.c,v 1.1 2009/04/19 00:55:32 manu Exp $");
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

#include "dump.h"
#include "pending.h"
#include "store.h"
#include "conf.h"
#include "sync.h"

#ifdef USE_DMALLOC
#include <dmalloc.h> 
#endif

/* 
 * Initialize storage backend. No lock needed 
 */
void mg_init(void) {
	dump_init();
	pending_init();
	dump_reload();		/* Reload a saved greylist */

	return;
}

/* 
 * Start storage thread 
 */
void mg_start(void)	{
	/*
	 * Start the dumper thread
	 */
	dumper_start();

	/*
	 * Run the peer MX greylist sync threads
	 */
	sync_master_restart();
	sync_sender_start();

	return;
}


tuple_t mg_tuple_check(tuple)
	struct tuple_fields tuple;
{
	return pending_check(tuple.sa, tuple.salen,
	    tuple.from, tuple.rcpt, tuple.remaining, tuple.elapsed,
	    tuple.queueid, tuple.gldelay, tuple.autowhite);
}

/* 
 * stop storage background threads 
 */
void mg_tuple_stop(void) {
	dumper_stop();
	return;
}

/* 
 * close storage backend 
 */
void mg_tuple_close(void) {
	return;
}
