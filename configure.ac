# $Id: configure.ac,v 1.33 2004/03/12 10:29:01 manu Exp $
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(milter-greylist, 0.15, manu@netbsd.org)
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
AC_ARG_WITH(libmiter, 
	[  --with-libmilter=DIR   Find libmilter in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,--rpath=$withval/lib"])
AC_ARG_WITH(libpthread, 
	[  --with-libpthread=DIR  Find libpthread in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,--rpath=$withval/lib"])

AC_CHECK_LIB(pthread, pthread_create, 
	[LIBS="$LIBS -lpthread"],
	[AC_CHECK_LIB(c_r, pthread_create, 
		[LIBS="$LIBS -lc_r"],
		[echo "Required libpthread not found. Use --with-libpthread"; 
		 exit 1;])
	 ])

AC_CHECK_LIB(milter, smfi_register,
	[LIBS="$LIBS -lmilter"],
	[AC_CHECK_LIB(milter, smfi_register,
		[LIBS="$LIBS -lmilter -lsm"],
		[echo "Required libmilter not found. Use --with-libmilter"; 
		 exit 1;], [-lsm])
	])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h sys/param.h netdb.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
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

AC_MSG_CHECKING([whether you need -D_XOPEN_SOURCE to use libpthread])
xopen=no
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/types.h>
		#include <pthread.h>
	],[
		pthread_rwlock_t lock;
	])], [xopen=no], [CFLAGS="$CFLAGS -D_XOPEN_SOURCE=500"; xopen=yes])
AC_MSG_RESULT([$xopen])

AC_DEFINE([HAVE_SA_LEN], [], [sa_len field in struct sockaddr])
AC_CHECK_MEMBER([struct sockaddr.sa_len], , 
	[AC_DEFINE(HAVE_SA_LEN)], [
		#include <sys/types.h>
		#include <sys/socket.h>
	])

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
