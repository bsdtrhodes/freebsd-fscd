#
# $Id: Makefile 2063 2013-06-03 14:03:41Z bsdtrhodes $
#

PROG=	fscd
MAN=	fscd.conf.5 fscd.8
CONF=	fscd.conf

DPADD=	${LIBKVM}
LDADD=	-lkvm -lpthread -lutil

WARNS=	2

#CFLAGS+=	-std=c99 -g -O0
CFLAGS+=	-std=c99

install:
	install -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} fscd /usr/sbin/
	install -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} fscd.conf.5 /usr/share/man/man5/
	install -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} fscd.8 /usr/share/man/man8/
	install -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} fscd.conf /etc/

.include <bsd.prog.mk>
