# $Id: Makefile,v 1.1.1.1 2004/02/21 00:01:17 manu Exp $

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

CFLAGS= -I/usr/pkg/include -Wall -Werror -ansi 
LIBS=	-L/usr/pkg/lib -Wl,--rpath=/usr/pkg/lib -lpthread -lmilter
OBJ= milter-greylist.o pending.o syncer.o except.o
SRC= milter-greylist.c pending.c syncer.c except.c


milter-greylist:	${OBJ}
	cc -o milter-greylist ${OBJ} ${LIBS}

all:	depend milter-greylist

depend:
	mkdep ${CFLAGS} ${SRC}
clean:
	rm -f milter-greylist ${OBJ}

start:	milter-greylist
	rm -f /home/manu/milter-greylist.sock
	./milter-greylist -v -p milter-greylist.sock	
