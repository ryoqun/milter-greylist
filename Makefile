# $Id: Makefile,v 1.13.2.1 2004/11/28 17:40:42 manu Exp $

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

CFLAGS= 	-g -O2 -Wall -I/usr/pkg/include -D_XOPEN_SOURCE=500 -D_BSD_SOURCE
LDFLAGS=	 -L/usr/pkg/lib -Wl,--rpath=/usr/pkg/lib
LIBS= 		 -lresolv -lpthread -lmilter
prefix=		/usr/local
exec_prefix=	${prefix}
SYSCONFDIR=	${prefix}/etc
LOCALSTATEDIR=	${prefix}/var
BINDIR=		${exec_prefix}/bin
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

OBJ= 		milter-greylist.o pending.o except.o sync.o \
		conf_yacc.o dump_yacc.o conf.o autowhite.o dump.o spf.o
SRC= 		milter-greylist.c pending.c except.c sync.c conf.c \
		autowhite.c dump.c spf.c
GENSRC=		conf_yacc.c conf_lex.c dump_yacc.c dump_lex.c 

all:		milter-greylist rc-bsd.sh rc-redhat.sh \
		rc-solaris.sh rc-debian.sh rc-gentoo.sh

milter-greylist:	${OBJ}
	${CC} -o milter-greylist ${OBJ} ${LDFLAGS} ${LIBS}

sync_yacc.o:	sync_yacc.c sync_lex.c
conf_yacc.o:	conf_yacc.c conf_lex.c
dump_yacc.o:	dump_yacc.c dump_lex.c

rc-bsd.sh:      rc-bsd.sh.in
	${SED} "s|@BINDIR[@]|${BINDIR}|g; s|@USER[@]|${USER}|g" \
	    rc-bsd.sh.in > rc-bsd.sh
rc-redhat.sh:    rc-redhat.sh.in
	${SED} "s|@BINDIR[@]|${BINDIR}|g; s|@USER[@]|${USER}|g" \
	    rc-redhat.sh.in > rc-redhat.sh
rc-solaris.sh:    rc-solaris.sh.in
	${SED} "s|@BINDIR[@]|${BINDIR}|g; s|@USER[@]|${USER}|g" \
	    rc-solaris.sh.in > rc-solaris.sh
rc-debian.sh:    rc-debian.sh.in
	${SED} "s|@BINDIR[@]|${BINDIR}|g; s|@USER[@]|${USER}|g" \
	    rc-debian.sh.in > rc-debian.sh
rc-gentoo.sh:    rc-gentoo.sh.in
	${SED} "s|@BINDIR[@]|${BINDIR}|g; s|@USER[@]|${USER}|g" \
	    rc-gentoo.sh.in > rc-gentoo.sh

install:	milter-greylist
	${INSTALL} -d -m 755 ${BINDIR}
	${INSTALL} -d -m 755 ${MANDIR}/man8
	${INSTALL} -d -m 755 ${MANDIR}/man5
	${INSTALL} -m 755 milter-greylist ${BINDIR}
	${INSTALL} -m 644 milter-greylist.8 ${MANDIR}/man8
	${INSTALL} -m 644 greylist.conf.5 ${MANDIR}/man5
	${TEST} -f /etc/mail/greylist.conf -o -f /etc/mail/greylist.except || \
	     ${INSTALL} -m 644 greylist.conf /etc/mail
	${INSTALL} -d -m 755 -o ${USER} /var/milter-greylist
	@${TEST} -f /var/db/greylist.db && (			 	   \
		echo "	================================================"; \
		echo "	  WARNING: the dump file location has changed,  "; \
		echo "	  Please move /var/db/greylist.db, the default  "; \
		echo "	  location is now in /var/milter-greylist/      "; \
		echo "	================================================"; \
	) || ${TRUE}
	@${TEST} -f /etc/mail/greylist.except && (		 	   \
		echo "	================================================"; \
		echo "	 WARNING: the config file name has changed,     "; \
		echo "	 Please rename /etc/mail/greylist.except, the   "; \
		echo "	 default name is now in /etc/mail/greylist.conf "; \
		echo "	================================================"; \
	) || ${TRUE}

depend:
	${MKDEP} ${CFLAGS} ${SRC}

clean:
	${RM} -f milter-greylist ${OBJ} ${GENSRC} \
	rc-redhat.sh rc-bsd.sh rc-solaris.sh rc-debian.sh rc-gentoo.sh

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
