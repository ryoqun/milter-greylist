# $Id: configure.ac,v 1.1 2004/02/21 13:55:25 manu Exp $
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(milter-greylist, 0.1, manu@netbsd.org)
AC_CONFIG_SRCDIR([except.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_CHECK_PROGS(MKDEP, mkdep)
AC_CHECK_PROGS(RM, rm)

# Path to required packages
AC_ARG_WITH(libmiter, 
	[  --with-libmilter=DIR   Find libmilter in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" LDFLAGS=$LDFLAGS" -L$withval/lib"])
AC_ARG_WITH(libpthread, 
	[  --with-libpthread=DIR  Find libpthread in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" LDFLAGS=$LDFLAGS" -L$withval/lib"])

# Options
AC_ARG_WITH(exceptfile,
	[  --with-exceptfile=PATH Default execption file location is PATH],
	[CFLAGS=$CFLAGS" -DEXCEPTFILE=\""$withval"\""])
AC_ARG_WITH(dumpfile,
	[  --with-dumpfile=PATH   Default dump file location is PATH],
	[CFLAGS=$CFLAGS" -DDUMPFILE=\""$withval"\""])
AC_ARG_WITH(delay,
	[  --with-delay=VALUE     Default delay is VALUE],
	[CFLAGS=$CFLAGS" -DDELAY=\""$withval"\""])
AC_ARG_WITH(dumpfreq,
	[  --with-dumpfreq=VALUE  Default dump frequency is VALUE],
	[CFLAGS=$CFLAGS" -DDUMPFREQ=\""$withval"\""])
AC_ARG_WITH(timout,
	[  --with-timeout=VALUE  Default timout is VALUE],
	[CFLAGS=$CFLAGS" -DTIMEOUT=\""$withval"\""])

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
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_TIME

# Checks for library functions.
AC_CHECK_FUNCS([bzero gettimeofday malloc inet_ntoa strerror])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
