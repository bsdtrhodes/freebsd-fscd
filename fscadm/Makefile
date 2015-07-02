#
# $Id: Makefile 2063 2013-06-03 14:03:41Z bsdtrhodes $
#

PROG=	fscadm
MAN=	fscadm.8

WARNS?=	2

install:
	install -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} fscadm /usr/bin/
	install -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} fscadm.8.gz /usr/share/man/man8/


.include <bsd.prog.mk>
