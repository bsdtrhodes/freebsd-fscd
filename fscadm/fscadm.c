/*-
 * Copyright (c) 2009-2010 Tom Rhodes. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: fscadm.c 2063 2013-06-03 14:03:41Z bsdtrhodes $
 */

/*
 * fscadm - control utility for FreeBSD services monitoring
 * named after the Solaris version with a similar name.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc/"
#endif

#define SOCK_PATH _PATH_VARRUN"fscd.sock"
#define CONF_PATH SYSCONFDIR"fscd.conf"
#define VERSION "1.1"

void	usage(void);
void	version(void);
int	daemonconnect(char *);

static char *socketname = NULL;

int
main(int argc, char *argv[])
{
	char *sendstr;
	int error = 0;
	int ch;
	int i;

	/* check arguments */
	while ((ch = getopt(argc, argv, "Vs:")) != -1)
		switch (ch) {
			case 'V':
				version();
				break;
			case 's':
				if (asprintf(&socketname, "%s", optarg) < 0)
					err(1, "asprintf");
				break;
			default:
				usage();
				break;
		}
	argc -= optind;
	argv += optind;

	if (!socketname && asprintf(&socketname, "%s", SOCK_PATH) < 0)
		err(EX_OSERR, "asprintf");
	if (argc == 0)
		usage();

	/* shutdown, status */
	if ((strcmp(argv[0], "shutdown") == 0) 
			|| (strcmp(argv[0], "status") == 0)) {
		if (argc != 1)
			usage();
		if (asprintf(&sendstr, "%s:", argv[0]) < 0)
			err(EX_OSERR, "asprintf");
		error = daemonconnect(sendstr);
	/* disable/enable */
	} else if ((strcmp(argv[0], "disable") == 0)
			|| (strcmp(argv[0], "enable") == 0)) {
		for (i = 1; i < argc; i++) {
			if (asprintf(&sendstr, "%s:%s", argv[0], argv[i]) < 0) {
				warn("asprintf");
				continue;
			}

			error += daemonconnect(sendstr);
			free(sendstr);
		}
	} else {
		warnx("unknown command: %s", argv[0]);
		usage();
	}

	return error;
}

/*
 * Print usage information.
 */
void
usage(void)
{
	printf( "usage:  fscadm enable <service> [service ...]\n"
			"        fscadm disable <service> [service ...]\n"
			"        fscadm shutdown\n"
			"        fscadm status\n"
			"\n"
			"options:\n"
			"        -V   Print out version.\n"
			"        -s S Use socket S instead of standard.\n " );
	exit(EX_USAGE);
}

/*
 * Print version information.
 */
void
version(void)
{
	fprintf(stderr, "fscadm version: %s\n", VERSION);
	exit(EX_USAGE);
}

/*
 * Connect to the daemon, send given task to the socket, wait for reply.
 * Return the first char the daemon sent back as returncode.
 */
int
daemonconnect(char *task)
{
	int s, len, nbytes, retcode = 0;
	struct sockaddr_un remote;
	char recdata[LINE_MAX];

	if ((s = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
		err(EX_OSERR, "socket");

	remote.sun_family = PF_LOCAL;
	strncpy(remote.sun_path, socketname ? socketname : SOCK_PATH,
			sizeof remote.sun_path);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family) + 1;
	if (connect(s, (struct sockaddr *)&remote, len) == -1)
		err(EX_OSERR, "connect");

	if (send(s, task, strlen(task), 0) == -1)
		err(EX_OSERR, "send");

	do {
		memset(recdata, 0, sizeof(recdata));
		nbytes = recv(s, recdata, sizeof(recdata) - 1, 0);
		if (nbytes > 0)
			printf("%s", recdata);
	} while (recdata[strlen(recdata) - 1] != 4); /* 4 = EOT */

	if (nbytes < 0) {
		warn("recv");
		retcode = nbytes;
	}

	close(s);
	return retcode;
}
