# $Id: configure.ac,v 1.7 2004/02/29 23:10:05 manu Exp $
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(milter-greylist, 0.2, manu@netbsd.org)
AC_CONFIG_SRCDIR([milter-greylist.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_INSTALL
AC_CHECK_PROGS(MKDEP, mkdep)
AC_CHECK_PROGS(RM, rm)
AC_CHECK_PROGS(SED, sed)

# Path to required packages
AC_ARG_WITH(libmiter, 
	[  --with-libmilter=DIR   Find libmilter in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,--rpath=$withval/lib"])
AC_ARG_WITH(libpthread, 
	[  --with-libpthread=DIR  Find libpthread in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,--rpath=$withval/lib"])

# Checks for libraries.
AC_CHECK_LIB(pthread, pthread_create, 
	[LIBS="$LIBS -lpthread"],
	[echo "Required libpthread not found. Use --with-libpthread"; exit 1;])

AC_CHECK_LIB(milter, smfi_register,
	[LIBS="$LIBS -lmilter"],
	[echo "Required libmilter not found. Use --with-libmilter"; exit 1;],
	[-lpthread])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([bzero gettimeofday malloc inet_ntoa strerror])

# Options
AC_ARG_WITH(user,
	[  --with-user=USERNAME   The user that will run milter-greylist ],
	[AC_SUBST(USER, $withval)], [AC_SUBST(USER, root)])

AC_ARG_WITH(exceptfile,  
	[  --with-exceptfile=PATH Location of whitelist],
	[CFLAGS=$CFLAGS" -DEXCEPTFILE=\\\"$withval\\\""])
AC_ARG_WITH(dumpfile,
	[  --with-dumpfile=PATH   Location of dump file],
	[CFLAGS=$CFLAGS" -DDUMPFILE=\\\"$withval\\\""])
AC_ARG_WITH(delay,  
	[  --with-delay=VALUE     Delay before accepting mail],
	[CFLAGS=$CFLAGS" -DDELAY=$withval"])
AC_ARG_WITH(timeout,  
	[  --with-timeout=VALUE   Timeout before we forget about a send],
	[CFLAGS=$CFLAGS" -DTIMEOUT=$withval"])
AC_ARG_WITH(dumpfreq,  
	[  --with-dumpfreq=VALUE  Delay between grey list dump], 
	[CFLAGS=$CFLAGS" -DDUMPFREQ=$withval"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
