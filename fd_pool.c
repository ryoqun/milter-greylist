/*
 * Copyright (c) 2007 Johann Klasek
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
 *        This product includes software developed by Johann Klasek
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

/*
 * fd_pool.c  Stdio stream function replacement for limited stdio implementations
 *
 * 2007-06-04 Johann E. Klasek, johann at klasek at
 *
 *
 * Description:
 *	Some stdio stream implementation suffers from limitation or
 *	backward compatibility. Especially Solaris 9 and previous
 *	versions in the LWP32 programming model have a limit in the
 *	FILE datastructure where the file descriptor field has only
 *	a width of 8 bits. Therefore stdio streams are only
 *	capable in handling file descriptors in the range from 0 to 255.
 *	Some application accessing the FILE structure components directly
 *	(e.g. the _file field) through the past years. The structure has
 *	never be change to provide backward compatibility for and prevent 
 *	breaking existing applications (binaries).
 *	Even Solaris 9 offers a maximum number of 65536 file descriptors
 *	only descriptors 0 to 255 can be stored into the FILE structure.
 *	If descriptor values greater 255 are passed to e.g. fdopen()
 *	this library function simply fails with errno unset!
 *
 *	Solaris 10 offers several solution to cope with this situation
 *	(based on source or binary applications).
 *
 * 	The solution is mainly for versions previous to Solaris 10.
 *	This module provides a replacement for the functions
 *	fdopen() and fclose(). The idea is to reserve a pool of
 *	open descriptors (associated /dev/null)
 *	with values <256 which are aquired as needed by fdopen_ext().
 *	On the other hand fclose_ext() tries to return a descriptor
 *	lower than 256 to the reserved pool. The latter is could not
 *	assured in all cases because the real fclose() call releases
 * 	the associated description which could not be reclaimed without
 *	a delay. A parallel running thread could grab the closed
 *	descriptor during the delay ...
 *	The whole system works only in situations where not more
 *	then 256 streams are used in parallel despite the maximum
 *	number of open descriptors could grow much greater.
 *
 * References:
 *	http://developers.sun.com/solaris/articles/stdio_256.html
 *	http://www.science.uva.nl/pub/solaris/solaris2.html
 *		3.48) How can I increase the number of file descriptors per process?
 *	http://www.research.att.com/~gsf/download/ref/sfio/sfio.html
 */

#ifdef USE_FD_POOL
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <sysexits.h>

#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdarg.h>

#include "fd_pool.h"

/* size of the pool of low descriptors, from 4 to 256 */
#define FD_POOL_SIZE 64

/* an array of free/used descriptors - representing the pool */
static char fd_pool[256];

/* the current count of free low descriptors */
static int fd_pool_free=0;

/* take logging function from milter-greylist */
#include "milter-greylist.h"

/* public file which is used to aquire new open descriptors ... */
#define FNAME "/dev/null"


/***
 *** aquire a new open file descriptor (by means of an open dummy file)
 ***
 *** return: >=0 | -1 ... open descriptor | error
 ***/

int fd_new_desc() {
	int descriptor;

        if ((descriptor = open(FNAME, O_RDWR)) < 0) {
                mg_log(LOG_ERR, "fd_pool: can't create dummy file descriptor file %s: %s", FNAME,
                        strerror(errno));
                return -1;
        }
	return descriptor;
}


/***
 *** aquire a new low valued open file descriptor 
 ***
 *** return: 0 <= descriptor < 256 
 ***/

int fd_new_low_desc() {
	int descriptor;

        if ((descriptor = fd_new_desc()) >= 256 || descriptor < 0) {
                mg_log(LOG_ERR, "fd_pool: %s", (descriptor < 0 ? "can't allocate a new descriptor" : "can't allocate small dummy file descriptor (<256) - out of luck!") );
                exit(EX_OSERR);	/* fatal situation - must exit */
        }
	return descriptor;
}


/***
 *** initialize the module - build up the low file descriptor pool
 ***
 *** return: 0
 ***/

int fd_pool_init(void) {
	int i;
	memset(fd_pool,0, sizeof(fd_pool));

	for(i=0;i<FD_POOL_SIZE;i++) {
	    fd_pool[fd_new_low_desc()] = 1;
	}

        fd_pool_free=FD_POOL_SIZE;

	return 0;
}


/***
 *** fclose() replacement
 ***
 *** return: < 0 | otherwise  ... error | ok
 ***/

int fclose_ext(FILE *stream) {

  int old_descriptor = fileno(stream);
  int descriptor;
  int new_descriptor = 0;
  int ret, err;

  if ( old_descriptor < 256 && old_descriptor >=0 ) {

	if ( fd_pool_free >= FD_POOL_SIZE ) {
		return fclose(stream);	/* pool is full, we dont want a low descriptor back ... */
					/* just pass to the original function */
	}

	/* we try to get a descriptor >= 256, if not put it back to */
	/* the low file descriptor pool */
	while( (new_descriptor = fd_new_desc()) < 256 && new_descriptor >= 0
	       && fd_pool_free < FD_POOL_SIZE ) {
		if (fd_pool[new_descriptor] == 0) {
			fd_pool[new_descriptor] = 1;
			fd_pool_free++;
        		mg_log(LOG_INFO, "fclose_ext: adding new descriptor %d into low fd pool", 
				new_descriptor);
		}
		
	}
	if ( new_descriptor < 256 && new_descriptor >= 0 && fd_pool_free >= FD_POOL_SIZE ) {
		close(new_descriptor);  /* not needed anymore ... */
		return fclose(stream);	/* got only low valued descriptor but the pool is full ... */
					/* pass to the original function */
	}
	if ( fd_pool_free >= FD_POOL_SIZE ) {
		close(new_descriptor);  /* not needed anymore ... */
		return fclose(stream);	/* got only low valued descriptor and the pool is full ... */
					/* pass to the original function */
	}
	if ( new_descriptor < 0 ) {
		ret = fclose(stream); /* closes also the descriptor of the stream! */
		err = errno;
		descriptor = fd_new_desc(); /* try to allocate again, after the fclose(), maybe */
						/* we can reclaim the closed descriptor ... */
		if ( descriptor < 0 ) {
        		mg_log(LOG_ERR, "fclose_ext: fd_new_desc failed: low descriptor %d lost! (%s)",
			old_descriptor, strerror(errno));
		}
	}
	else { /* new_descriptor >= 256 */

		ret = fclose(stream); /* closes also the descriptor of the stream! */
		err = errno;
		descriptor = dup(new_descriptor); /* grab the closed/returned descriptor - the lowest */
					  /* available descriptor will be aquired - bit of racy ... */
					  /* maybe some other systemcall of another thread is faster */
		if ( descriptor < 0 ) {
        		mg_log(LOG_ERR, "fclose_ext: dup failed: low descriptor %d lost! (%s)",
			old_descriptor, strerror(errno));
		}
		close(new_descriptor);
	}
	/* but if we are in luck, we got some other low descriptor, not necessarily the one from the */
	/* closed stream */
	if ( descriptor >= 256 ) {
        	mg_log(LOG_ERR, "fclose_ext: low descriptor %d lost!", old_descriptor);
		close(descriptor);
	}
	else if ( descriptor < 0 ) {
		/* do nothing, an error has been already emitted above */
	}
	else if ( fd_pool[descriptor] == 0 ) {
	    if ( fd_pool_free >= FD_POOL_SIZE ) {
		/* pool already full, we do not need this low descriptor, release it */
		close(descriptor);
	    }
	    else {
		fd_pool[descriptor] = 1;
		fd_pool_free++;
        	mg_log(LOG_INFO, "fclose_ext: taking descriptor %d back into low fd pool", descriptor);
	    }

	}
	/* else: fd_pool[descriptor] == 1 : some strangeness, descriptor already marked as */
	/*	released into the FD pool. Should neven happen ... */


	errno = err;		/* restore state from original fclose() call */
	return ret;
  }
  else return fclose(stream);	/* descriptor not in lower range, let original function handle this case */

}


/***
 *** get_pool_desc
 ***
 *** return: < 0 | otherwise  ... error | descriptor (in range 0-255)
 ***/

int get_pool_desc(int desc) {
	int i;
	int fd;

	if (desc < 0) return desc;

	for(i=0; i<256; i++) {
		if (fd_pool[i] == 1) {
			/* dup a large fd to a small fd  */
			fd = dup2(desc, i); close(desc);
			fd_pool[i] = 0;
			fd_pool_free--;
        		mg_log(LOG_INFO, "fdopen_ext: get_pool_desc: descriptor %d reused as %d", desc, i);
			break;
		}
	}
	if (i >= 256 || fd_pool_free == 0) {
		return -1;
	}
	return i;
}



/***
 *** fdopen_ext
 ***
 *** return: NULL | otherwise  ... error | new opened stream
 ***/

FILE *fdopen_ext(int fd, char *mode) {
	int descriptor;

	if (fd >= 256) {
	  /* if we got a non low descriptor, try to map it into to low descriptor pool */
	  descriptor = get_pool_desc(fd);
	  if (descriptor < 0) {
        		mg_log(LOG_ERR, "fdopen_ext: no free low file descriptor");
			return fdopen(fd, mode);
	  }
	  return fdopen(descriptor, mode);
	}
	return fdopen(fd, mode);

}



/***
 *** fopen_ext
 ***
 *** return: NULL | otherwise  ... error | new opened stream
 ***/

FILE *fopen_ext(char *path, char *mode) {
	int descriptor;
	FILE *stream;
	int err;

	descriptor = fd_new_desc();
	if (descriptor >= 256) {
		descriptor = get_pool_desc(descriptor);
	}
	if (descriptor < 0) return fopen(path, mode);

	/* we have a low descriptor */
	close(descriptor); 

	/* after releasing it, we hope the following fopen() call can aquire it ... */
	stream = fopen(path, mode);
	err = errno;

	if (stream != NULL) {
		if ( descriptor == fileno(stream) ) {
			/* we are in luck, fopen has successfully aquired our low descriptor ... */
			return stream;
		}
		else {
			/* descriptor missed, some other has taken it, but fopen() successful! */
			mg_log(LOG_INFO, "fopen_ext: descriptor %d lost!", descriptor);
			errno = err;
			return stream;
		}
	}
	else {
		mg_log(LOG_ERR, "fopen_ext: failed and descriptor %d lost!", descriptor);
		errno = err;
		return stream;
	}

	/* not very safe and can be raced out by other threads which may took the descriptor */
	/* earlier ... :( */
}
#endif /* USE_FD_POOL */
