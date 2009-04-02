# $Id: Makefile,v 1.122.2.3 2009/04/02 04:12:48 manu Exp $

#
# Copyright (c) 2004 Emmanuel Dreyfus
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#        This product includes software developed by Emmanuel Dreyfus
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#

CFLAGS= 	-g -O2 -Wall -I/usr/pkg/include -D_BSD_SOURCE -I${SRCDIR} -I. 
LDFLAGS=	 -L/usr/pkg/lib -Wl,--rpath=/usr/pkg/lib
LIBS= 		 -lpthread -lresolv -lmilter
prefix=		/usr/local
exec_prefix=	${prefix}
SYSCONFDIR=	${prefix}/etc
LOCALSTATEDIR=	${prefix}/var
SRCDIR=		.
BINDIR=		${exec_prefix}/bin
SBINDIR=        ${exec_prefix}/sbin
MANDIR=		${prefix}/man
USER=		root

CC=		gcc
MKDEP=		mkdep
RM=		rm
MV=		mv
TEST=		test
SED=		sed
INSTALL=	/usr/bin/install -c
LEX=		flex
YACC=		bison -y
TRUE=		true

OBJ= 		milter-greylist.o pending.o sync.o dnsrbl.o list.o macro.o \
		conf_yacc.o dump_yacc.o conf.o autowhite.o dump.o spf.o \
		acl.o urlcheck.o stat.o clock.o geoip.o fd_pool.o prop.o \
		ldapcheck.o dkimcheck.o p0f.o spamd.o
SRC= 		milter-greylist.c pending.c sync.c conf.c macro.c stat.c \
		clock.c autowhite.c dump.c spf.c acl.c dnsrbl.c list.c \
		urlcheck.c geoip.c prop.c ldapcheck.c dkimcheck.c p0f.c spamd.c
GENSRC=		conf_yacc.c conf_lex.c dump_yacc.c dump_lex.c  

VPATH=		${SRCDIR}

all:		milter-greylist rc-bsd.sh rc-redhat.sh \
		rc-solaris.sh rc-debian.sh rc-gentoo.sh rc-suse.sh

milter-greylist:	${OBJ}
	${CC} -o milter-greylist ${OBJ} ${LDFLAGS} ${LIBS}

sync_yacc.o:	sync_yacc.c sync_lex.c
conf_yacc.o:	conf_yacc.c conf_lex.c
dump_yacc.o:	dump_yacc.c dump_lex.c

sed_subst = "s|@BINDIR[@]|${BINDIR}|g; s|@SBINDIR[@]|${SBINDIR}|g; s|@USER[@]|${USER}|g"

rc-bsd.sh:      rc-bsd.sh.in
	${SED} ${sed_subst} ${SRCDIR}/rc-bsd.sh.in > rc-bsd.sh
rc-redhat.sh:    rc-redhat.sh.in
	${SED} ${sed_subst} ${SRCDIR}/rc-redhat.sh.in > rc-redhat.sh
rc-solaris.sh:    rc-solaris.sh.in
	${SED} ${sed_subst} ${SRCDIR}/rc-solaris.sh.in > rc-solaris.sh
rc-debian.sh:    rc-debian.sh.in
	${SED} ${sed_subst} ${SRCDIR}/rc-debian.sh.in > rc-debian.sh
rc-gentoo.sh:    rc-gentoo.sh.in
	${SED} ${sed_subst} ${SRCDIR}/rc-gentoo.sh.in > rc-gentoo.sh
rc-suse.sh:	 rc-suse.sh.in
	${SED} ${sed_subst} ${SRCDIR}/rc-suse.sh.in > rc-suse.sh

install-daemon-to-bin: milter-greylist
	${INSTALL} -d -m 755 ${DESTDIR}${BINDIR}
	${INSTALL} -m 755 milter-greylist ${DESTDIR}${BINDIR}

install-sbin: milter-greylist
	${INSTALL} -d -m 755 ${DESTDIR}${SBINDIR}
	${INSTALL} -m 755 milter-greylist ${DESTDIR}${SBINDIR}

install-man:
	${INSTALL} -d -m 755 ${DESTDIR}${MANDIR}/man8
	${INSTALL} -d -m 755 ${DESTDIR}${MANDIR}/man5
	${INSTALL} -m 644 ${SRCDIR}/milter-greylist.8 ${DESTDIR}${MANDIR}/man8
	${INSTALL} -m 644 ${SRCDIR}/greylist.conf.5 ${DESTDIR}${MANDIR}/man5

install-conf:
	${INSTALL} -d -m 755 ${DESTDIR}/etc/mail
	${TEST} -f ${DESTDIR}/etc/mail/greylist.conf -o 	\
		-f ${DESTDIR}/etc/mail/greylist.except || 	\
	     ${INSTALL} -m 644 ${SRCDIR}/greylist.conf ${DESTDIR}/etc/mail
	@${TEST} -f ${DESTDIR}/etc/mail/greylist.except && (	 	   \
		echo "	================================================"; \
		echo "	 WARNING: the config file name has changed,     "; \
		echo "	 Please rename /etc/mail/greylist.except, the   "; \
		echo "	 default name is now in /etc/mail/greylist.conf "; \
		echo "	================================================"; \
	) || ${TRUE}

install-db:
	${INSTALL} -d -m 755 -o ${USER} ${DESTDIR}/var/milter-greylist
	@${TEST} -f ${DESTDIR}/var/db/greylist.db && (			 	   \
		echo "	================================================"; \
		echo "	  WARNING: the dump file location has changed,  "; \
		echo "	  Please move /var/db/greylist.db, the default  "; \
		echo "	  location is now in /var/milter-greylist/      "; \
		echo "	================================================"; \
	) || ${TRUE}

install: install-daemon-to-bin install-man install-conf install-db

depend:
	${MKDEP} ${CPPFLAGS} ${CFLAGS} ${SRC}

clean:
	${RM} -f milter-greylist ${OBJ} ${GENSRC} \
	rc-redhat.sh rc-bsd.sh rc-solaris.sh rc-debian.sh rc-gentoo.sh \
	rc-suse.sh

realclean:	clean
	${RM} -Rf Makefile config.h config.log config.status \
		 autom4te.cache configure.lineno *.orig *.bak autoscan.log

.SUFFIXES:	.o .c .h .y .l
.l.c:
	${LEX} -o$@ $<
.y.c:
	${YACC} -p`echo $@|${SED} 's/^\([^_]\{1,\}_\).*$$/\1/'` $<
	${MV} y.tab.c $@

# This is a target for debugging
start:	milter-greylist
	./milter-greylist -D -v -p milter-greylist.sock	
