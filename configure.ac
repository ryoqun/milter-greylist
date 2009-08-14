# $Id: configure.ac,v 1.248 2009/08/14 00:35:33 manu Exp $
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(milter-greylist, 4.3.3, manu@netbsd.org)
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

# Check that the compiler won't bug us for -Wall
AC_MSG_CHECKING([if compiler accepts -Wall])
SAVEDCFLAGS=$CFLAGS
CFLAGS=$CFLAGS" -Wall"
wall="no"
AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])], 
    [wall="yes"; SAVEDCFLAGS=$CFLAGS; efl=$efl" -Wall"])
AC_MSG_RESULT([$wall])
CFLAGS=$SAVEDCFLAGS

NORPSAVEDLDFLAGS=$LDFLAGS

# Any linker will probably accept -L
rpath="-L"

# Check if the linker accepts -R
AC_MSG_CHECKING([if ld accepts -R])
SAVEDLDFLAGS=$LDFLAGS
LDFLAGS=$LDFLAGS" -Wl,-R=/"
AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])], 
    [rpath="-R"; ldrpath=yes], [ldrpath=no])
LDFLAGS=$SAVEDLDFLAGS
AC_MSG_RESULT([$ldrpath])

# Check if the linker accepts --rpath 
AC_MSG_CHECKING([if ld accepts --rpath])
SAVEDLDFLAGS=$LDFLAGS
LDFLAGS=$LDFLAGS" -Wl,--rpath=/"
AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])], 
    [rpath="--rpath="; ldrpath=yes], [ldrpath=no])
LDFLAGS=$SAVEDLDFLAGS
AC_MSG_RESULT([$ldrpath])

# Path to required packages
AC_ARG_WITH(db,
        [  --with-db=DIR   Find Berkeley DB in DIR],
        [CFLAGS=$CFLAGS" -I$withval/include"
            LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])
AC_ARG_WITH(libmilter, 
	[  --with-libmilter=DIR   Find libmilter in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])
AC_ARG_WITH(libpthread, 
	[  --with-libpthread=DIR  Find libpthread in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include" 
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])
use_libbind=no
SAVEDLDFLAGS=$LDFLAGS
SAVEDCFLAGS=$CFLAGS
AC_ARG_WITH(libbind, 
	[  --with-libbind=DIR	Find libbind in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include/bind -I$withval/include"
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"
	    AC_CHECK_LIB(bind, bind9_getaddresses, [
		SAVEDLDFLAGS=$LDFLAGS
		SAVEDCFLAGS=$CFLAGS
	    LIBS="-lbind $LIBS"
	    use_libbind=yes
	    ], [AC_CHECK_LIB(bind9, bind9_getaddresses, [
                SAVEDLDFLAGS=$LDFLAGS
                SAVEDCFLAGS=$CFLAGS
                LIBS="-lbind9 $LIBS"
                use_libbind=yes
	    ], [echo "neither -lbind nor -lbind9 worked. check config.log for details"
		exit 1;])
	 ])
])
LDFLAGS=$SAVEDLDFLAGS
CFLAGS=$SAVEDCFLAGS
AC_ARG_WITH(openssl,
	[  --with-openssl=DIR  Find OpenSSL in DIR],
	[LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])
AC_ARG_WITH(openldap, 
	[  --with-openldap=DIR  Find OpenLDAP in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include -DUSE_LDAP -DLDAP_DEPRECATED" 
	    LIBS="-lldap_r -llber $LIBS"
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])
AC_ARG_WITH(libcurl, 
	[  --with-libcurl=DIR  Find libcurl in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include -DUSE_CURL" 
	    LIBS="-lcurl $LIBS"
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])
AC_ARG_WITH(libGeoIP, 
	[  --with-libGeoIP=DIR  Find libGeoIP in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include -DUSE_GEOIP" 
	    LIBS="-lGeoIP $LIBS"
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])
AC_ARG_WITH(libdmalloc,
	[  --with-libdmalloc=DIR  Find libdmalloc in DIR],
	[CFLAGS=$CFLAGS" -I$withval/include -DUSE_DMALLOC" 
	    LIBS="-ldmalloc $LIBS"
	    LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h syslog.h unistd.h sys/param.h netdb.h getopt.h sys/cdefs.h arpa/nameser.h stdbool.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Do we need -lpthread with -lbind?
if test $use_libbind = yes ; then
	AC_MSG_CHECKING([if -lbind needs -lpthread to link])
	lbind_needs_lpthread=no
	SAVEDLIBS=$LIBS
	AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])], 
	    [],
	    [
		LIBS="-lpthread $LIBS"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([],[])],
		    [lbind_needs_lpthread=yes]);
	    ]);
	if test $lbind_needs_lpthread = yes ; then
		SAVEDLIBS=$LIBS
	fi
	AC_MSG_RESULT($lbind_needs_lpthread)
	LIBS=$SAVEDLIBS
fi

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_STRFTIME
AC_FUNC_MEMCMP
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_SETVBUF_REVERSED
AC_FUNC_STAT
AC_CHECK_FUNCS([bzero gettimeofday malloc inet_ntoa strerror select socket initgroups strlcat vsyslog])


# Check for libpthread. On FreeBSD, the libc_r does the job.
# On digitalUNIX, libpthreads (with a trailing s) is the library to use
# FIXME: FreeBSD 4.x wants -pthread
AC_CHECK_LIB([pthread], [pthread_create], 
    [LIBS="$LIBS -lpthread"],
    [AC_CHECK_LIB([c_r], [pthread_create], 
        [LIBS="$LIBS -lc_r"],
	[AC_CHECK_LIB([pthreads -lpthread], [pthread_create],
            [LIBS="$LIBS -lpthreads -lpthread"],
                [echo "Required libpthread not found. Use --with-libpthread"; 
                 exit 1;])
	])
     ])

# Try to configure for libspf2
SAVEDLDFLAGS=$LDFLAGS
SAVEDCFLAGS=$CFLAGS
AC_ARG_WITH(libspf2,
       [  --with-libspf2=DIR  Find libspf2 in DIR],
       [LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"
           CFLAGS=$CFLAGS" -I$withval/include"
           AC_CHECK_LIB(spf2, SPF_server_new, [
               SAVEDLDFLAGS=$LDFLAGS
               SAVEDCFLAGS=$CFLAGS
               LIBS=$LIBS" -lspf2"
               AC_DEFINE([HAVE_SPF2], [], [we use libspf2])
               ],[AC_CHECK_LIB([spf2 -lintl],  SPF_server_new, [
                       SAVEDLDFLAGS=$LDFLAGS
                       SAVEDCFLAGS=$CFLAGS
                       LIBS=$LIBS" -lspf2 -lintl"
                       AC_DEFINE([HAVE_SPF2], [], [we use libspf2])
               ], [echo "libspf2 not found, check config.log for details"
                   echo "Remove --with-libspf2 to build without SPF support"
                   exit 1;])
       ])
])
LDFLAGS=$SAVEDLDFLAGS
CFLAGS=$SAVEDCFLAGS

# Try to configure for libspf2 1.0
SAVEDLDFLAGS=$LDFLAGS
SAVEDCFLAGS=$CFLAGS
AC_ARG_WITH(libspf2_10,
       [  --with-libspf2_10=DIR  Find libspf2 1.0 in DIR],
       [LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"
           CFLAGS=$CFLAGS" -I$withval/include"
           AC_CHECK_LIB(spf2, SPF_create_config, [
               SAVEDLDFLAGS=$LDFLAGS
               SAVEDCFLAGS=$CFLAGS
               LIBS=$LIBS" -lspf2"
               AC_DEFINE([HAVE_SPF2_10], [], [we use libspf2 1.0])
               ],[AC_CHECK_LIB([spf2 -lintl],  SPF_create_config, [
                       SAVEDLDFLAGS=$LDFLAGS
                       SAVEDCFLAGS=$CFLAGS
                       LIBS=$LIBS" -lspf2 -lintl"
                       AC_DEFINE([HAVE_SPF2_10], [], [we use libspf2 1.0])
               ], [echo "libspf2 1.0 not found, check config.log for details"
                   echo "Remove --with-libspf2_10 to build without SPF support"
                   exit 1;])
       ])
])
LDFLAGS=$SAVEDLDFLAGS
CFLAGS=$SAVEDCFLAGS

# Try to configure for libspf_alt
SAVEDLDFLAGS=$LDFLAGS
SAVEDCFLAGS=$CFLAGS
AC_ARG_WITH(libspf_alt, 
	[  --with-libspf_alt=DIR  Find libspf_alt in DIR],
	[LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"
	    CFLAGS=$CFLAGS" -I$withval/include"
	    AC_CHECK_LIB(spf_alt, SPF_create_config, [
		SAVEDLDFLAGS=$LDFLAGS
		SAVEDCFLAGS=$CFLAGS
		LIBS=$LIBS" -lspf_alt"
		AC_DEFINE([HAVE_SPF_ALT], [], [we use libspf_alt])
		],[AC_CHECK_LIB([spf_alt -lintl],  SPF_create_config, [
			SAVEDLDFLAGS=$LDFLAGS
			SAVEDCFLAGS=$CFLAGS
			LIBS=$LIBS" -lspf_alt -lintl"
			AC_DEFINE([HAVE_SPF_ALT], [], [we use libspf_alt])
		], [echo "libspf_alt not found, check config.log for details"
		    echo "Remove --with-libspf_alt to build without SPF support"
		    exit 1;])
	])
])
LDFLAGS=$SAVEDLDFLAGS
CFLAGS=$SAVEDCFLAGS

# Try to configure for libspf
SAVEDLDFLAGS=$LDFLAGS
SAVEDCFLAGS=$CFLAGS
AC_ARG_WITH(libspf, 
	[  --with-libspf=DIR  Find libspf in DIR],
	[LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"
	    CFLAGS=$CFLAGS" -I$withval/include"
	    AC_CHECK_LIB(spf, SPF_init, [
		SAVEDLDFLAGS=$LDFLAGS
		SAVEDCFLAGS=$CFLAGS
		LIBS=$LIBS" -lspf"
		AC_DEFINE([HAVE_SPF], [], [we use libspf])
		], [echo "libspf not found, check config.log for details"
		    echo "Remove --with-libspf to build without SPF support"
		    exit 1;])
])
LDFLAGS=$SAVEDLDFLAGS
CFLAGS=$SAVEDCFLAGS

# Try to configure for libdkim
SAVEDLDFLAGS=$LDFLAGS
SAVEDCFLAGS=$CFLAGS
AC_ARG_WITH(libdkim, 
	[  --with-libdkim=DIR  Find Sendmail's libdkim in DIR],
	[LDFLAGS=$LDFLAGS" -L$withval/lib -Wl,$rpath$withval/lib"
	    CFLAGS=$CFLAGS" -I$withval/include"
	    AC_CHECK_LIB([dkim -lsm -lcrypto], dkim_init, [
		SAVEDLDFLAGS=$LDFLAGS
		SAVEDCFLAGS=$CFLAGS
		LIBS=$LIBS" -ldkim -lcrypto"
		AC_DEFINE([USE_DKIM], [], [we use libdkim])
		], [echo "libdkim not found, check config.log for details"
		    echo "Remove --with-dkim to build without DKIM support"
		    exit 1;])
])
LDFLAGS=$SAVEDLDFLAGS
CFLAGS=$SAVEDCFLAGS



AC_ARG_ENABLE(rpath,
	[  --disable-rpath	do not hardcode runtime library paths],
	[if test x$enableval = xno; then
		LDFLAGS=$NORPSAVEDLDFLAGS
	fi])

# Check for socket functions linking. On Solaris, -lsocket -lnsl is required
AC_CHECK_LIB([socket], [socket], [LIBS="$LIBS -lsocket"], 
	[AC_CHECK_LIB([socket -lnsl], [socket], 
		[LIBS="$LIBS -lsocket -lnsl"], [])
	])

# Check for inet_aton (libmilter uses it). On solaris, -lresolv is required
AC_CHECK_LIB([resolv], [inet_aton], [LIBS="$LIBS -lresolv"], []) 

# Check for inet_pton (libmilter uses it). On solaris, -lnsl is required
AC_CHECK_LIB([nsl], [inet_pton], [LIBS="$LIBS -lnsl"], []) 

# Check for getaddrinfo and getnameinfo
AC_DEFUN([IPv6_CHECK_FUNC], [
AH_TEMPLATE(AS_TR_CPP(HAVE_$1), [Define to 1 if you have the `]$1[' function.])
AC_CHECK_FUNC($1, [dnl
  ac_cv_lib_socket_$1=no
  ac_cv_lib_inet6_$1=no
], [dnl
  AC_CHECK_LIB(socket, $1, [dnl
    LIBS="$LIBS -lsocket"
    ac_cv_lib_inet6_$1=no
  ], [dnl
    AC_MSG_CHECKING([whether your system has IPv6 directory])
    AC_CACHE_VAL(ipv6_cv_dir, [dnl
      for ipv6_cv_dir in /usr/local/v6 /usr/inet6 no; do
	if test $ipv6_cv_dir = no -o -d $ipv6_cv_dir; then
	  break
	fi
      done])dnl
    AC_MSG_RESULT($ipv6_cv_dir)
    if test $ipv6_cv_dir = no; then
      ac_cv_lib_inet6_$1=no
    else
      if test x$ipv6_libinet6 = x; then
	ipv6_libinet6=no
	SAVELDFLAGS="$LDFLAGS"
	LDFLAGS="$LDFLAGS -L$ipv6_cv_dir/lib"
      fi
      AC_CHECK_LIB(inet6, $1, [dnl
	if test $ipv6_libinet6 = no; then
	  ipv6_libinet6=yes
	  LIBS="$LIBS -linet6"
	fi],)dnl
      if test $ipv6_libinet6 = no; then
	LDFLAGS="$SAVELDFLAGS"
      fi
    fi])dnl
])dnl
ipv6_cv_$1=no
if test $ac_cv_func_$1 = yes -o $ac_cv_lib_socket_$1 = yes \
     -o $ac_cv_lib_inet6_$1 = yes
then
  ipv6_cv_$1=yes
fi
if test $ipv6_cv_$1 = no; then
  if test $1 = getaddrinfo; then
    for ipv6_cv_pfx in o n; do
      AC_EGREP_HEADER(${ipv6_cv_pfx}$1, netdb.h,
		      [AC_CHECK_FUNC(${ipv6_cv_pfx}$1)])
      if eval test X\$ac_cv_func_${ipv6_cv_pfx}$1 = Xyes; then
        ipv6_cv_$1=yes
        break
      fi
    done
  fi
fi
if test $ipv6_cv_$1 = yes; then
  AC_DEFINE_UNQUOTED(AS_TR_CPP(HAVE_$1))
  ifelse([$2], , :, [$2])
else
  ifelse([$3], , :, [$3])
fi])

IPv6_CHECK_FUNC(getaddrinfo)
IPv6_CHECK_FUNC(getnameinfo)

# Check if <time.h> defines timeradd (and timersub)
AC_MSG_CHECKING([if <time.h> defines timeradd])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#if HAVE_TIME_H
		#include <time.h>
		#endif
		#ifdef HAVE_SYS_TIME_H
		#include <sys/time.h>
		#endif
	],[
		#ifndef timeradd
		error timeradd undefined
		#endif
	])], [timeradd=yes], 
	[AC_DEFINE([HAVE_MISSING_TIMERADD], 
	    [], [<time.h> defines timeradd]) timeradd=no])
AC_MSG_RESULT([$timeradd])

# Check if -D_REENTRANT is needed for localtime_r, gmtime_r, strtok_r
SAVEDCFLAGS=$CFLAGS
CFLAGS=$CFLAGS$efl
AC_MSG_CHECKING([if -D_REENTRANT is needed to use localtime_r and strtok_r])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
               #include <time.h>
               #include <stdio.h>
       ],[[

               (void)localtime_r(NULL, NULL);
	       (void)strtok_r(NULL, NULL, NULL);
       ]])], [dreentrant=no],
               [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
                               #define _REENTRANT
                               #include <stdio.h>
                       ],[[
                                (void)localtime_r(NULL, NULL);
	       			(void)strtok_r(NULL, NULL, NULL);
                       ]])],
                       [SAVEDCFLAGS=$SAVEDCFLAGS" -D_REENTRANT";
                        dreentrant=yes], [dreentrant=no])
       ])
AC_MSG_RESULT([$dreentrant])
CFLAGS=$SAVEDCFLAGS

# Check if -D__EXTENSIONS__ is needed for snprintf, getopt, seteuid...
SAVEDCFLAGS=$CFLAGS
CFLAGS=$CFLAGS$efl
AC_MSG_CHECKING([if -D__EXTENSIONS__ is needed to use snprintf])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <stdio.h>
	],[[
		char dst[16 + 1];

		snprintf(dst, 16, "test");
	]])], [dextensions=no],
		[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
				#define __EXTENSIONS__
				#include <stdio.h>
			],[[
				char dst[16 + 1];

				snprintf(dst, 16, "test");
			]])], 
			[SAVEDCFLAGS=$SAVEDCFLAGS" -D__EXTENSIONS__"; 
			 dextensions=yes], [dextensions=no])
	])
AC_MSG_RESULT([$dextensions])
CFLAGS=$SAVEDCFLAGS

# Solaris 256 streams limitation worakround
AC_ARG_ENABLE(stdio-hack,
        [  --enable-stdio-hack   Use workaround for Solaris stdio limitation],
        [CFLAGS=$CFLAGS" -DUSE_FD_POOL"])

# Check for DRAC
AC_ARG_ENABLE(drac,
	[  --enable-drac	Enable DRAC support],
	[if test x$enableval = xyes; then CFLAGS=$CFLAGS" -DUSE_DRAC"; fi])
AC_ARG_ENABLE(p0f, 
	[  --enable-p0f		Enable p0f support],
	[if test x$enableval = xyes; then CFLAGS=$CFLAGS" -DUSE_P0F"; fi])

# Check for SpamAssassin
AC_ARG_ENABLE(spamassassin, 
	[  --enable-spamassassin	Enable SpamAssassin support],
	[if test x$enableval = xyes; then CFLAGS=$CFLAGS" -DUSE_SPAMD"; fi])

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

# Check if -lpthreads is needed after -lmilter
AC_MSG_CHECKING([if -lpthread is needed after -lmilter])
SAVEDLIBS=$LIBS
AC_LINK_IFELSE([AC_LANG_PROGRAM([
		#include <pthread.h>
		#include <libmilter/mfapi.h>
	],[
		pthread_self();
		smfi_main();
	])], [pthend=no], [LIBS=$LIBS" -lpthread"; 
		AC_LINK_IFELSE([AC_LANG_PROGRAM([
			#include <pthread.h>
			#include <libmilter/mfapi.h>
		],[
			pthread_self();
			smfi_main();
		])], [pthend=yes; SAVEDLIBS=$LIBS], [pthend=no])
	])

LIBS=$SAVEDLIBS
AC_MSG_RESULT([$pthend])

# Some Linux flavors have an outdated <sys/queue.h>
AC_MSG_CHECKING([if <sys/queue.h> is outdated])
oldqueue=no
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/queue.h>
	],[
		#ifndef TAILQ_FIRST
		error Your <sys/queue.h> is outdated
		#endif
	])], [oldqueue=no], 
	[AC_DEFINE([HAVE_OLD_QUEUE_H], [], [old <sys/queue.h>]) oldqueue=yes])
AC_MSG_RESULT([$oldqueue])

# Darwin is unable to define two __RCSID in the same file
AC_MSG_CHECKING([if __RCSID can be used twice in the same source])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/cdefs.h>
		#ifdef __RCSID
		__RCSID("Id1");
		__RCSID("Id2");
		#endif
	],[
		/* nothing */
	])], [rcsidtwice=yes], 
	[AC_DEFINE([HAVE_BROKEN_RCSID], [], 
	    [__RCSID cannot be used twice]) rcsidtwice=no])
AC_MSG_RESULT([$rcsidtwice])

# Digital UNIX's native compiler require -pthread when using libpthread
# It also require -D_XOPEN_SOURCE=500 for various reasons I have not 
# been abe to isolate. Let's define both there.
AC_MSG_CHECKING([whether <pthreads.h> wants -pthread])
SAVEDCFLAGS=$CFLAGS
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <pthread.h>],[])],
	[pthreadfl=no], 
	[CFLAGS=$CFLAGS" -pthread -D_XOPEN_SOURCE=500";
	 AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <pthread.h>],[])],
		[pthreadfl=yes; SAVEDCFLAGS=$CFLAGS], [pthreadfl=no])
	])
CFLAGS=$SAVEDCFLAGS
AC_MSG_RESULT([$pthreadfl])

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

# Tru64 Unix needs -D_OSF_SOURCE for IPV6 support
SAVEDCFLAGS=$CFLAGS
CFLAGS=$CFLAGS" -D_XOPEN_SOURCE=500 -D_BSD_SOURCE"
AC_MSG_CHECKING([if -D_OSF_SOURCE is needed for IPV6 support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <netinet/in.h>
	],[[
		#ifdef AF_INET6
		  struct in6_addr s;
		#endif
	]])], [dosfsource=no],
		[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
				#define _OSF_SOURCE
				#include <sys/socket.h>
				#include <netinet/in.h>
			],[[
				#ifdef AF_INET6
				  struct in6_addr s;
				#endif
			]])], 
			[SAVEDCFLAGS=$SAVEDCFLAGS" -D_OSF_SOURCE"; 
			 dosfsource=yes], [dosfsource=no])
	])
AC_MSG_RESULT([$dosfsource])
CFLAGS=$SAVEDCFLAGS

# Linux does not have a sa_len field in sockaddr
AC_CHECK_MEMBER([struct sockaddr.sa_len],
	[AC_DEFINE([HAVE_SA_LEN], [], [sa_len field in struct sockaddr])],, [
		#include <sys/types.h>
		#include <sys/socket.h>
	])

# Pre-RFC2553 system does not have a sin6_scope_id field in sockaddr_in6
AC_CHECK_MEMBER([struct sockaddr_in6.sin6_scope_id],
	[AC_DEFINE([HAVE_SIN6_SCOPE_ID], [1],
	    [sin6_scope_id field in struct sockaddr_in6])],, [
		#include <sys/types.h>
		#include <sys/socket.h>
		#include <netinet/in.h>
	])

# Darwin seems to have no definition for socklen_t beyond _BSD_SOCKLEN_T_
AC_MSG_CHECKING([if socklen_t is missing])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
		#include <sys/types.h>
		#include <sys/socket.h>
	],[
		socklen_t slen;
	])], [socklen=no], 
	[AC_DEFINE([HAVE_MISSING_SOCKLEN_T], [], 
	    [missing socklen_t definition]) socklen=yes])
AC_MSG_RESULT([$socklen])

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

# Check is DNS resolver is re-entrant
AC_ARG_WITH(thread-safe-resolver,
	[  --with-thread-safe-resolver   Resolver is thread-safe],
	[rdns=yes],[
		SAVEDCFLAGS=$CFLAGS
		CFLAGS=$CFLAGS$efl
		AC_MSG_CHECKING([if DNS resolver is re-entrant])
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
				#define _BSD_SOURCE

				#include <sys/types.h>
				#include <netinet/in.h>
				#include <arpa/inet.h>
				#include <arpa/nameser.h>
				#include <resolv.h>
			],[
				struct __res_state res;

				res_ninit(&res);
			])], [rdns=yes], [rdns=no])
		AC_MSG_RESULT([$rdns])
		CFLAGS=$SAVEDCFLAGS
	])

# Check for DNSRBL
AC_ARG_ENABLE(dnsrbl,
	[  --enable-dnsrbl	Enable DNSRBL support],
	[if test x$rdns = xyes; then
		SAVEDCFLAGS=$CFLAGS" -DUSE_DNSRBL"
		# For Debian
		CFLAGS=
		AC_TRY_LINK([#include <stdio.h>
		             #include <arpa/nameser.h>
			], [ int result = ns_initparse(NULL, 0, NULL); ],
			[],[ AC_CHECK_LIB([resolv], [ns_initparse],
			    [LIBS="$LIBS -lresolv"], [
				if test -r /usr/lib/libresolv.a; then
					LIBS="$LIBS /usr/lib/libresolv.a"
				else
					AC_MSG_WARN([ns_initparse not found])
				fi
			    ])
		])
		CFLAGS=$SAVEDCFLAGS
	 else
		echo "--enable-dnsrbl used but DNS resolver is not thread safe";
		echo "Try installing BIND9 and using --with-libbind, or if you";
		echo "know what you are doing, use --with-thread-safe-resolver";
		exit 1;
	 fi
	])

# We enable some features for Postfix
AC_ARG_ENABLE(postfix,
	[  --enable-postfix	Enable Postfix support],
	[if test x$enableval = xyes; then
		CFLAGS=$CFLAGS" -DUSE_POSTFIX"
	 fi
	])

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
	[CFLAGS=$CFLAGS" -DGLDELAY=$withval"])
AC_ARG_WITH(timeout,  
	[  --with-timeout=VALUE   Timeout before we forget about a send],
	[CFLAGS=$CFLAGS" -DTIMEOUT=$withval"])
AC_ARG_WITH(autowhite,  
	[  --with-autowhite=VALUE How long auto-whitelisting lasts],
	[CFLAGS=$CFLAGS" -DAUTOWHITE_DELAY=$withval"])
AC_ARG_WITH([drac-db],
	[  --with-drac-db=PATH   Where is the DRAC database ],
	[CFLAGS=$CFLAGS" -DDRACDB=\\\"$withval\\\""])

AC_CONFIG_FILES([Makefile milter-greylist.spec])
AC_OUTPUT
