# $Id: configure.ac,v 1.54 2004/03/21 22:51:41 manu Exp $
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(milter-greylist, 0.23, manu@netbsd.org)
AC_CONFIG_SRCDIR([milter-greylist.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL
AC_CHECK_PROGS(MKDEP, mkdep)
AC_CHECK_PROGS(RM, rm)
AC_CHECK_PROGS(MV, mv)
AC_CHECK_PROGS(TEST, test)
AC_CHECK_PROGS(SED, sed)
AC_CHECK_PROGS(TRUE, true)

# Path to required packages
AC_ARG_WITH(libmilter, 
	[  --with-libmilter=DIR   Find libmilter in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,--rpath=$withval/lib"])
AC_ARG_WITH(libpthread, 
	[  --with-libpthread=DIR  Find libpthread in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,--rpath=$withval/lib"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h sys/param.h netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_STRFTIME
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
AC_FUNC_STAT
AC_CHECK_FUNCS([bzero gettimeofday malloc inet_ntoa strerror select socket])

# Check for socket functions linking. On Solaris, -lsocket -lnsl is required
AC_CHECK_LIB([socket], [socket], [LIBS="$LIBS -lsocket"], [])
AC_CHECK_LIB([socket -lnsl], [socket], [LIBS="$LIBS -lsocket -lnsl"], [])

# Check for libpthread. On FreeBSD, the libc_r does the job.
AC_CHECK_LIB(pthread, pthread_create, 
	[LIBS="$LIBS -lpthread"],
	[AC_CHECK_LIB(c_r, pthread_create, 
		[LIBS="$LIBS -lc_r"],
		[echo "Required libpthread not found. Use --with-libpthread"; 
		 exit 1;])
	 ])

# Check for libmilter. For sendmail-8.12.1, -lsm is required too.
# This uses a gross hack on the second AC_CHECK_LIB first argument, but using 
# [-lsm] in the optionnal 5th argument does not seems to help at all.
AC_CHECK_LIB(milter, smfi_register,
    [LIBS="$LIBS -lmilter"],
    [AC_CHECK_LIB([milter -lsm], smfi_register,
        [LIBS="$LIBS -lmilter -lsm"],
        [AC_CHECK_LIB([milter -lsmutil], smfi_register,
            [LIBS="$LIBS -lmilter -lsmutil"],
                [echo "Required libmilter not found. Use --with-libmilter"; 
                exit 1;])
        ])
])

# Some Linux flavors have an outdated <sys/queue.h>
AC_MSG_CHECKING([if your <sys/queue.h> is outdated])
oldqueue=no
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/queue.h>
	],[
		#ifndef TAILQ_FIRST
		# error Your <sys/queue.h> is outdated
		#endif
	])], [oldqueue=no], 
	[AC_DEFINE([HAVE_OLD_QUEUE_H], [], [old <sys/queue.h>]) oldqueue=yes])
AC_MSG_RESULT([$oldqueue])

# Linux requires -D_XOPEN_SOURCE=500 to build with libpthread and -Wall
AC_MSG_CHECKING([whether you need -D_XOPEN_SOURCE to use libpthread])
xopen=no
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/types.h>
		#include <pthread.h>
	],[
		pthread_rwlock_t lock;
	])], [xopen=no], [CFLAGS="$CFLAGS -D_XOPEN_SOURCE=500"; xopen=yes])
AC_MSG_RESULT([$xopen])

# Linux does not have a sa_len field in sockaddr
AC_CHECK_MEMBER([struct sockaddr.sa_len],
	[AC_DEFINE([HAVE_SA_LEN], [], [sa_len field in struct sockaddr])],, [
		#include <sys/types.h>
		#include <sys/socket.h>
	])

# GNU pth-2.0.0 has a bug with rwlock. 
AC_MSG_CHECKING([for broken rwlock in libpthread])
brokenpth=yes
AC_RUN_IFELSE([AC_LANG_PROGRAM([
		#if STDC_HEADERS
		# include <stdlib.h>
		#else
		# ifdef __cplusplus
		extern "C" void exit (int);
		# else
		void exit (int);
		# endif
		#endif

		#if HAVE_SYS_TIME_H
		# include <sys/time.h>
		#else
		struct timeval {
			long tv_sec;
			long tv_usec;
		};
		#endif

		#if HAVE_SYS_TYPES_H
		# include <sys/types.h>
		#else 
		#endif

		#if HAVE_UNISTD_H
		# include <unistd.h>
		#else
		# ifdef __cplusplus
		extern "C" unsigned int exit (unsigned int);
		extern "C" int 
		    select(int, void *, void *, void *, struct timeval *);
		# else
		unsigned int exit (unsigned int);
		int select(int, void *, void *, void *, struct timeval *);
		# endif
		#endif

		#include <pthread.h>
		pthread_rwlock_t lock;
  
		#ifdef __cplusplus
		extern "C" void testfunc (void *);
		extern "C" void yield(void);
		#else
		void testfunc();
		void yeild(void);
		#endif

		/*
		 * On some Linux flavors, using sleep(3) instead
		 * of select causes an infinite hang.
		 */
		void yield (void)
		{
			struct timeval tv;

			tv.tv_sec = 1;
			tv.tv_usec = 0;
			if (select(0, NULL, NULL, NULL, &tv) != 0)
				exit(EXIT_FAILURE);
			return;
		}

		#ifdef __cplusplus
		void testfunc (void *dontcare)
		#else
		void testfunc (dontcare) void *dontcare;
		#endif
		{
			if (pthread_rwlock_rdlock(&lock) != 0)
				exit(EXIT_FAILURE);
			yield();
			if (pthread_rwlock_unlock(&lock) != 0)
				exit(EXIT_FAILURE);
			return;
		}
	],[
		pthread_t tid;

		if (pthread_rwlock_init(&lock, NULL) != 0)
			exit(EXIT_FAILURE);
		if (pthread_create(&tid, NULL, (void *)testfunc, NULL) != 0)
			exit(EXIT_FAILURE);
		if (pthread_rwlock_rdlock(&lock) != 0)
			exit(EXIT_FAILURE);
		yield();
		if (pthread_rwlock_unlock(&lock) != 0)
			exit(EXIT_FAILURE);
		if (pthread_join(tid, NULL) != 0)
			exit(EXIT_FAILURE);
		return 0;
	])], [brokenpth=no], 
	AC_DEFINE([HAVE_BROKEN_RWLOCK], [], [broken rwlock in libpthread]))
AC_MSG_RESULT([$brokenpth])

# Record the build environnement for milter-greylist -r
AC_DEFINE_UNQUOTED([BUILD_ENV], ["`logname`@`uname -n`:`pwd` `date`"], 
    [Build environnement]) 

# Options
AC_ARG_WITH(user,
	[  --with-user=USERNAME   The user that will run milter-greylist ],
	[AC_SUBST(USER, $withval)], [AC_SUBST(USER, root)])
AC_ARG_WITH(conffile,  
	[  --with-conffile=PATH Location of config file],
	[CFLAGS=$CFLAGS" -DCONFFILE=\\\"$withval\\\""])
AC_ARG_WITH(dumpfile,
	[  --with-dumpfile=PATH   Location of dump file],
	[CFLAGS=$CFLAGS" -DDUMPFILE=\\\"$withval\\\""])
AC_ARG_WITH(delay,  
	[  --with-delay=VALUE     Delay before accepting mail],
	[CFLAGS=$CFLAGS" -DDELAY=$withval"])
AC_ARG_WITH(timeout,  
	[  --with-timeout=VALUE   Timeout before we forget about a send],
	[CFLAGS=$CFLAGS" -DTIMEOUT=$withval"])
AC_ARG_WITH(autowhite,  
	[  --with-autowhite=VALUE How long auto-whitelisting lasts],
	[CFLAGS=$CFLAGS" -DAUTOWHITE_DELAY=$withval"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
