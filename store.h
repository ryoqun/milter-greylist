#ifndef _STORE_H_
#define _STORE_H_

/* XXXmanu license ? */

struct tuple_fields {
	struct sockaddr *sa;
	socklen_t salen;
        char    *from;
        char    *rcpt;
	time_t	*remaining;	/* report back remaining 
				   time before activation */
	time_t	*elapsed;	/* report back elapsed time 
				   since first encounter */
	char	*queueid;	/* for logging purposes */
	time_t	gldelay;	/* delay time for new greylist entry */
	time_t	autowhite;	/* time-out for autowhite entry */
};

/* 
 * initialize storage backend 
 */
void mg_init();		

/* 
 * start storage background threads 
 */
void mg_start();

/* 
 * check tuple status, add and update if necessary 
 */
tuple_t mg_tuple_check(struct tuple_fields);

/* 
 * in case backend needs cleaning up 
 */
int mg_tuple_vacuum();

/* 
 * stop storage background threads 
 */
void mg_tuple_stop();

/* 
 * safely close storage backend 
 */
void mg_tuple_close();                       

#endif /* _STORE_H_ */
