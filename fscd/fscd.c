/*-
 * Copyright (c) 2009-2012 Tom Rhodes. All rights reserved.
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
 * $Id: fscd.c 2076 2014-10-05 01:24:54Z bsdtrhodes $
 */

/*
 * fscd - FreeBSD Services Control Daemon.  Monitors services through
 * kqueue and attempts to restart them if they should terminate.
 */

#include <sys/cdefs.h>
#if defined(__FreeBSD__)
__FBSDID("$FreeBSD$");
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <kvm.h>
#include <limits.h>
#include <paths.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#if defined(__FreeBSD__)
#include <libutil.h>
#else
#include <util.h>
#endif

/* Portability to pkgsrc. */
#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc/"
#endif

#define SOCK_PATH _PATH_VARRUN"fscd.sock"
#define CONF_FILE SYSCONFDIR"fscd.conf"
#define SERVICE "service"
#define STATUS "onestatus"
#define START "restart" // restart is more reliable than just start.
#define VERSION "1.2"

struct spid {
	pid_t svpid;
	SLIST_ENTRY(spid) next;
};

SLIST_HEAD(spid_list_head, spid);

struct service {
	char *svname;
	struct spid_list_head svpids;
	SLIST_ENTRY(service) next;
};

SLIST_HEAD(service_list_head, service);

struct fscd_cfg {
	struct service_list_head service_list;
	pthread_mutex_t service_mtx;
	int service_thr_int;
	pthread_t service_thr;
	int kq;
};

struct restart_params {
	struct fscd_cfg *config;
	char *sname;
};

#if defined(__FreeBSD__)
	static struct pidfh *pfh = NULL;
#endif

static int daemonize = 0;
static char *socketname = NULL;
static char *conffile = NULL;

static void fscd_shutdown(int);
static int readconf(struct fscd_cfg *);
static int print_status(struct fscd_cfg *, int);
static int handle_restart(struct fscd_cfg *, char *);
static int handle_waiting(struct fscd_cfg *, char *);
static int handle_task(struct fscd_cfg *, char *, int);
static void usage(void);
static void version(void);
static void *connect_monitor(void *);
static void *wait_restart(void *);
static void handle_queue(struct fscd_cfg *, struct kevent *);
static void handle_sig(int);
static void ignore_sig(int);
static void printlog(int, const char *, ...);
static int process_exited(const int);
static int service_registered(struct fscd_cfg *, const char *);
static int service_running(const char *);
static struct service *make_service(const char *);
static int start_service(struct service *);
static int register_service(struct fscd_cfg *, struct service *);
static int unregister_service(struct fscd_cfg *, char *);
static int fill_pids(struct service *);
static int kqueue_service(struct fscd_cfg *, struct service *);

int
main(int argc, char *argv[])
{
	int monthrint, newevent, ch, force = 0;
	struct fscd_cfg config;
	struct service svs;
	struct kevent kq_events;
	struct stat nb_stat;
	char errorstr[LINE_MAX];
	int verbosity = 0;

	/* check arguments */
	while ((ch = getopt(argc, argv, "Vdvfs:c:")) != -1)
		switch (ch) {
			case 'V': /* Print version string. */
				version();
				break;
			case 'd': /* Daemonize. */
				daemonize = 1;
				break;
			case 'c': /* Change config file */
				if (asprintf(&conffile, "%s", optarg) <= 0)
					err(1, "asprintf");
				break;
			case 'v': /* Verbosity. */
				++verbosity;
				break;
			case 'f': /* Force overwrite. */
				force = 1;
				break;
			case 's': /* Change socketname. */
				if (asprintf(&socketname, "%s", optarg) <= 0)
					err(1, "asprintf");
				break;
			default:
				usage();
				break;
		}
	argc -= optind;
	argv += optind;

	switch (verbosity) {
		case 0:
			setlogmask(LOG_UPTO(LOG_WARNING));
			break;
		case 1:
			setlogmask(LOG_UPTO(LOG_NOTICE));
			break;
		case 2:
			setlogmask(LOG_UPTO(LOG_INFO));
			break;
		default:
			setlogmask(LOG_UPTO(LOG_DEBUG));
			break;
	}

	/* initialize values */
	if (!socketname && asprintf(&socketname, "%s", SOCK_PATH) <= 0)
		err(1, "asprintf");
	if (!conffile && asprintf(&conffile, "%s", CONF_FILE) <= 0)
		err(1, "asprintf");
	if (stat(conffile, &nb_stat) != 0)
		warn("cannot stat configuration");
	if (stat(socketname, &nb_stat) == 0) {
		if (!force)
			err(1, "socket exists, specify -f to overwrite");
		else if (unlink(socketname) == -1)
			err(1, "deleting old socket");
	}

#if defined(__FreeBSD__)
	if ((pfh = pidfile_open(NULL, 0644, NULL)) == NULL)
		err(1, "pidfile_open");
#endif

	if (daemonize && daemon(0, 0) == -1)
		err(1, "daemon");

#if defined(__FreeBSD__)
	if (pidfile_write(pfh) == -1)
		err(1, "pidfile_write");
#else
	if (pidfile(NULL) == -1)
		err(1, "pidfile");
#endif

	memset(&config, 0, sizeof(config));
	memset(&svs, 0, sizeof(svs));
	SLIST_INIT(&config.service_list);
	config.kq = kqueue();
	if (pthread_mutex_init(&config.service_mtx, NULL))
		err(1, "pthread_mutex_init");

	/* set up signal handler */
	signal(SIGPIPE, ignore_sig);

	signal(SIGHUP, handle_sig);
	signal(SIGINT, handle_sig);
	signal(SIGALRM, handle_sig);
	signal(SIGTERM, handle_sig);
	signal(SIGXCPU, handle_sig);
	signal(SIGXFSZ, handle_sig);
	signal(SIGVTALRM, handle_sig);
	signal(SIGUSR1, handle_sig);
	signal(SIGUSR2, handle_sig);

	printlog(LOG_NOTICE, "Starting.");

	monthrint = pthread_create(&(config.service_thr), NULL,
	    connect_monitor, &config);

	/* Read configuration */
	readconf(&config);

	printlog(LOG_INFO, "Monitoring processes...");

	while (1) {
		newevent = kevent(config.kq, NULL, 0, &kq_events, 1, NULL);
		if (newevent == 1) {
			handle_queue(&config, &kq_events);
		} else if (newevent == -1) {
			if (strerror_r(errno, errorstr, sizeof errorstr))
				printlog(LOG_ERR, "kevent: Received error.");
			else
				printlog(LOG_ERR, "kevent: %s", errorstr);
		}
	}
	return 0;
}

/*
 * Called when an event occurred. Check event and take action.
 */
static void
handle_queue(struct fscd_cfg *config, struct kevent *kq_events)
{
	int status, pretcode;
	struct service *svs;
	struct spid *svpid;

	if (! (kq_events->fflags & NOTE_EXIT))
		return;

	pthread_mutex_lock(&config->service_mtx);
	SLIST_FOREACH(svs, &config->service_list, next) {
		SLIST_FOREACH(svpid, &svs->svpids, next) {
			if (kq_events->ident == (uintptr_t)svpid->svpid) {
				status = kq_events->data;
				if (WIFSIGNALED(status)) {
					printlog(LOG_ERR, "%s caught signal %d"
					    " and exited", svs->svname,
					    WTERMSIG(status));
					pretcode = process_exited(status);
				} else if (WIFEXITED(status)) {
					printlog(LOG_ERR, "%s exited with "
					    "status %d",
					    svs->svname, WEXITSTATUS(status));
					pretcode = 0;
				} else {
					continue;
				}

				if (pretcode == 1 && handle_restart(config,
				    svs->svname) == 0) {
					printlog(LOG_ERR, "%s was restarted",
					    svs->svname);
				} else if (pretcode == 0 && handle_waiting(config,
				    svs->svname) == 0) {
					printlog(LOG_ERR, "%s waiting for restart.",
					    svs->svname);
				} else {
					printlog(LOG_ERR, "%s failed to restart.",
							svs->svname);
					printlog(LOG_ERR, "%s removed from monitoring.",
							svs->svname);
					unregister_service(config, svs->svname);
				}
			}
		}
	}
	pthread_mutex_unlock(&config->service_mtx);

	return;
}

/*
 * Determine the status of the exited process. If it is a signal which is likely
 * to be user-issued, return 0, 1 otherwise.
 */
static int
process_exited(int status)
{
	switch (WTERMSIG(status)) {
		case SIGINT:
		case SIGKILL:
		case SIGTERM:
		case SIGUSR1:
		case SIGUSR2:
			return 0;
		default:
			return 1;
	}
}

/*
 * Called when a daemon died. Restart the daemon.
 */
static int
handle_restart(struct fscd_cfg *config, char *sname)
{
	int ret;
	struct service *svs;
	struct spid *svpid;

	SLIST_FOREACH(svs, &config->service_list, next) {
		if (strcmp(svs->svname, sname) != 0)
			continue;

		/* Remove all pids. */
		SLIST_FOREACH(svpid, &svs->svpids, next) {
			SLIST_REMOVE(&svs->svpids, svpid, spid, next);
			free(svpid);
		}

		if ((ret=start_service(svs))) {
			if (ret < 0)
				printlog(LOG_ERR, "%s could not be restarted.",
				    svs->svname);
			else
				printlog(LOG_ERR, "%s could not be restarted. Set "
				    "%s_enable to YES in %cetc/rc.conf.",
				    svs->svname, svs->svname, '/');
			return ret;
		} else if ((ret=fill_pids(svs))) {
			printlog(LOG_ERR, "Could not get pids for service.");
			return ret;
		} else if (kqueue_service(config, svs)) {
			printlog(LOG_ERR, "Could not monitor service.");
			return -1;
		}

		return 0;
	}

	return -1;
}

/*
 * Call the waiting function when a daemon died by user's hand.
 */
static int
handle_waiting(struct fscd_cfg *config, char *sname)
{
	pthread_t tmpthr;
	struct restart_params *inputv;

	inputv = malloc(sizeof(struct restart_params));
	inputv->config = config;
	inputv->sname = strdup(sname);
	return pthread_create(&tmpthr, NULL, wait_restart, inputv);
}

/*
 * Wait a certain amount of time before attempting to restart the service.
 */
static void *
wait_restart(void *var)
{
	struct restart_params *inputv;
	struct service *svs;
	struct spid *svpid;
	int retries;

	inputv = var;
	for (retries = 6; retries >= 0; retries--) {
		SLIST_FOREACH(svs, &inputv->config->service_list, next) {
			if (strcmp(svs->svname, inputv->sname) != 0)
				continue;

			/* Remove all pids. */
			SLIST_FOREACH(svpid, &svs->svpids, next) {
				SLIST_REMOVE(&svs->svpids, svpid, spid, next);
				free(svpid);
			}

			/* Wait for 100 seconds for the service to restart. */
			pthread_mutex_lock(&inputv->config->service_mtx);
			if (!fill_pids(svs)) {
				if (kqueue_service(inputv->config, svs))
					printlog(LOG_ERR, "Could not monitor "
					    "service.");
				else
					printlog(LOG_INFO, "Service %s was "
					    "restarted, but not by me.",
					    svs->svname);
				pthread_mutex_unlock(&inputv->config->service_mtx);
				free(inputv->sname);
				free(inputv);
				return NULL;
			}
			pthread_mutex_unlock(&inputv->config->service_mtx);
			break;
		}
		if (!svs) {
			printlog(LOG_ERR, "Service %s was removed from "
			    "monitoring while I was waiting for it to restart.",
			    inputv->sname);
			free(inputv->sname);
			free(inputv);
			return NULL;
		}
		sleep(10);
	}
	printlog(LOG_ERR, "Service %s was not restarted. Doing it myself.",
	    svs->svname);
	pthread_mutex_lock(&inputv->config->service_mtx);
	if (handle_restart(inputv->config, svs->svname) == 0) {
		printlog(LOG_ERR, "%s was restarted",
			svs->svname);
	} else {
		printlog(LOG_ERR, "%s failed to restart.",
				svs->svname);
		printlog(LOG_ERR, "%s removed from monitoring.",
				svs->svname);
		unregister_service(inputv->config, svs->svname);
	}
	pthread_mutex_unlock(&inputv->config->service_mtx);
	free(inputv->sname);
	free(inputv);
	return NULL;
}

/*
 * Called on user's behalf. Echo list of processes to socket.
 */
static int
print_status(struct fscd_cfg *config, int sock_fd)
{
	struct service *svs;
	struct spid *svpid;
	char *statstream;
	char errorstr[LINE_MAX];
	char eot = 4;
	char status = 0;

	send(sock_fd, &status, 1, 0);

	/* Our own pid. */
	if (asprintf(&statstream, "The fscd pid is %d.\n", getpid()) <= 0) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "asprintf failed.");
		else
			printlog(LOG_ERR, "asprintf: %s", errorstr);
	} else {
		if (send(sock_fd, statstream, strlen(statstream), 0) == -1) {
			if (strerror_r(errno, errorstr, sizeof errorstr))
				printlog(LOG_ERR, "send failed.");
			else
				printlog(LOG_ERR, "send: %s", errorstr);
		}
		free(statstream);
	}

	/* Monitored pids header. */
	if (asprintf(&statstream, "%-40s %s\n-------------------------------"
	    "-------------------\n", "process name", "pid") <= 0) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "asprintf failed.");
		else
			printlog(LOG_ERR, "asprintf: %s", errorstr);
	} else {
		if (send(sock_fd, statstream, strlen(statstream), 0) == -1) {
			if (strerror_r(errno, errorstr, sizeof errorstr))
				printlog(LOG_ERR, "send failed.");
			else
				printlog(LOG_ERR, "send: %s", errorstr);
		}
		free(statstream);
	}

	/* Monitored pids. */
	SLIST_FOREACH(svs, &config->service_list, next) {
		SLIST_FOREACH(svpid, &svs->svpids, next) {
			if (asprintf(&statstream, "%-40s %d\n",
			    svs->svname, svpid->svpid) > 0) {
				if (send(sock_fd, statstream,
				    strlen(statstream), 0) == -1) {
					if (strerror_r(errno, errorstr,
					    sizeof errorstr))
						printlog(LOG_ERR,
						    "send failed.");
					else
						printlog(LOG_ERR,
						    "send: %s", errorstr);
					free(statstream);
					break;
				}
				free(statstream);
			} else {
				if (strerror_r(errno, errorstr,
				    sizeof errorstr))
					printlog(LOG_ERR, "asprintf for send "
					    "failed.");
				else
					printlog(LOG_ERR, "asprintf for send "
					    "failed: %s", errorstr);
			}
		}
	}
	send(sock_fd, &eot, 1, 0);
	return 0;
}

/*
 * Print usage information.
 */
static void
usage(void)
{
	fprintf(stderr, "usage: fscd\n"
					"options:\n"
					"	-V   Show version info.\n"
					"	-d   Daemonize.\n"
					"	-v   Verbosity, use multiple times.\n"
					"	-s S Use socket S.\n"
					"	-c C Use config file C.\n");
	exit(EX_USAGE);
}

/*
 * Print version information.
 */
static void
version(void)
{
	fprintf(stderr, "fscd version %s\n", VERSION);
	exit(EX_USAGE);
}

/*
 * Print an error message either to stdout or to syslog, depending on debug
 * being set.
 */
static void
printlog(int priority, const char *logstr, ...)
{
	va_list tmplist;

	va_start(tmplist, logstr);

	vsyslog(priority, logstr, tmplist);

	va_end(tmplist);
	return;
}

/*
 * Check whether a service given by sname is running. We use service(8)
 * for that. It knows best about the running specifica of the service.
 */
static int
service_running(const char *sname)
{
	char *cmdstr;
	char errorstr[LINE_MAX];
	int retcode;

	if (asprintf(&cmdstr, SERVICE " %s " STATUS, sname) <= 0) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "asprintf for checking state of %s "
			    "failed: %s", sname, errorstr);
		else
			printlog(LOG_ERR, "asprintf for checking state of %s "
			    "failed.", sname);
		return 0;
	}

	retcode = system(cmdstr);
	free(cmdstr);
	if (WEXITSTATUS(retcode))
		return 0;
	else
		return 1;
}

/*
 * Check whether a service given by sname is already registered in our process
 * list.
 */
static int
service_registered(struct fscd_cfg *config, const char *sname)
{
	int ret = 0;
	struct service *curlist;

	SLIST_FOREACH(curlist, &config->service_list, next)
		if (strcmp(sname, curlist->svname) == 0) {
			ret = 1;
			break;
		}

	return ret;
}

/*
 * Create a struct service from the given name.
 */
static struct service*
make_service(const char *sname)
{
	struct service *svs;
	char errorstr[LINE_MAX];

	svs = malloc(sizeof(struct service));
	if (!svs) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "malloc for %s failed:", svs->svname,
			    errorstr);
		else
			printlog(LOG_ERR, "malloc for %s failed.", svs->svname);
		return NULL;
	}

	if (asprintf(&svs->svname, "%s", sname) <= 0) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "asprintf for %s failed:",
			    svs->svname, errorstr);
		else
			printlog(LOG_ERR, "asprintf for %s failed.",
			    svs->svname);
		free(svs);
		return NULL;
	}
	SLIST_INIT(&svs->svpids);

	return svs;
}

/*
 * Get the pids for given process, and fill the structs, emptying the
 * list if it is not empty.
 * Return 0 if process is running and we filled pids, 1 if not.
 */
static int
fill_pids(struct service *svs)
{
	struct spid *svpid;
	char *cmdstr;
	char *tmpstr, *ttmpstr;
	char *pinputp;
	char pinput[LINE_MAX];
	char errorstr[LINE_MAX];
	FILE *pp;
	int retcode;
	pid_t pid;

	/* Empty list. */
	if (!SLIST_EMPTY(&svs->svpids)) {
		SLIST_FOREACH(svpid, &svs->svpids, next) {
			SLIST_REMOVE(&svs->svpids, svpid, spid, next);
			free(svpid);
		}
	}

	if (asprintf(&cmdstr, SERVICE " %s " STATUS, svs->svname) <= 0) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "asprintf failed: %s", svs->svname,
			    errorstr);
		else
			printlog(LOG_ERR, "asprintf failed.", svs->svname);
		return -1;
	}

	pp = popen(cmdstr, "r");
	free(cmdstr);
	if (pp == NULL) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "popen failed: %s", svs->svname,
			    errorstr);
		else
			printlog(LOG_ERR, "popen failed.", svs->svname);
		return -1;
	}

	while (fgets(pinput, sizeof pinput, pp) != NULL) {
		if (strstr(pinput, "_enable to YES in") != NULL) {
			pclose(pp);
			return 1;
		}

		/* Scan the output for a separated list of numbers assuming
		 * they are pids.  We cannot scan for the service's name, as
		 * the name might be different to the service script name.
		 * Though we could assume the service name is properly set
		 * in its rc script and we could thus just parse the script
		 * ourselves, exceptions here might have the same probability
		 * as services with different service and script names
		 * So we have to skip the first portion up to the
		 * "is not running" or "is runnind as pid" and assume
		 * service(8) returns the right script's output.
		 */
		for (pinputp = strtok_r(pinput, " .,\t\n", &ttmpstr);
				pinputp;
				pinputp = strtok_r(NULL, " .,\t\n", &ttmpstr)) {
			pid = strtoul(pinputp, &tmpstr, 10);
			if (tmpstr && tmpstr > pinputp) {
				if (pid > 0 && getsid(pid) != -1) {
					svpid = malloc(sizeof(struct spid));
					svpid->svpid = pid;
					SLIST_INSERT_HEAD(&svs->svpids, svpid,
					    next);
				}
			}
		}
	}

	retcode = pclose(pp);
	if (WEXITSTATUS(retcode)) {
		return -1;
	}

	return 0;
}

/*
 * Start a service given by sname, try filling out pids.
 */
static int
start_service(struct service *svs)
{
	char errorstr[LINE_MAX];
	int wcnt;
	int ret;
	int retcode;
	char *cmdstr;
	char pinput[LINE_MAX];
	FILE *pp;

	if (asprintf(&cmdstr, SERVICE " %s " START, svs->svname) <= 0) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "asprintf for executing %s "
			    "failed: %s", svs->svname, errorstr);
		else
			printlog(LOG_ERR, "asprintf for executing %s "
			    "failed.", svs->svname);
		return -1;
	}

	pp = popen(cmdstr, "r");
	free(cmdstr);
	if (pp == NULL) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "popen failed: %s", svs->svname,
			    errorstr);
		else
			printlog(LOG_ERR, "popen failed.", svs->svname);
		return -1;
	}

	while (fgets(pinput, sizeof pinput, pp) != NULL) {
		if (strstr(pinput, "_enable to YES in") != NULL) {
			pclose(pp);
			return 1;
		}
	}
	retcode = pclose(pp);

	if (WEXITSTATUS(retcode)) {
		return -1;
	}

	/* Refresh our stored pid and re-register with kqueue. */
	ret = -1;
	for (wcnt = 10; wcnt >= 0; wcnt--)
		if (!fill_pids(svs)) {
			ret = 0;
			break;
		} else {
			sleep(1);
		}

	return ret;
}

/*
 * Register a service to kqueue.
 */
static int
kqueue_service(struct fscd_cfg *config, struct service *svs)
{
	struct spid *svpid;
	struct kevent kq_events;
	char errorstr[LINE_MAX];

	SLIST_FOREACH(svpid, &svs->svpids, next) {
		memset(&kq_events, 0, sizeof(struct kevent));
		EV_SET(&kq_events, svpid->svpid, EVFILT_PROC, EV_ADD |
			    EV_ENABLE | EV_ONESHOT, NOTE_EXIT, 0, 0);
		if (kevent(config->kq, &kq_events, 1, NULL, 0, NULL) == -1) {
			if (strerror_r(errno, errorstr, sizeof errorstr))
				printlog(LOG_ERR, "Registering kq event "
				    "failed");
			else
				printlog(LOG_ERR, "Registering kq event "
				    "failed: %s", errorstr);
			return -1;
		}
	}

	return 0;
}

/*
 * Register a running service, filling out pids, if needed.
 * Wait up to given number of seconds (and try every second) for restart.
 */
static int
register_service(struct fscd_cfg *config, struct service *svs)
{
	if (SLIST_EMPTY(&svs->svpids))
		fill_pids(svs);

	if (kqueue_service(config, svs))
		return -1;

	SLIST_INSERT_HEAD(&config->service_list, svs, next);
	printlog(LOG_INFO, "%s has been added.", svs->svname);

	return 0;
}

/*
 * Remove a service from the list and free it.
 * Return 0 on success, 1 if nothing was found.
 */
static int
unregister_service(struct fscd_cfg *config, char *svc_name_in)
{
	struct spid *svpid;
	struct service *svs;
	int ret = 1;

	SLIST_FOREACH(svs, &config->service_list, next)
		if (strcmp(svs->svname, svc_name_in) == 0) {
			SLIST_REMOVE(&config->service_list, svs, service, next);
			SLIST_FOREACH(svpid, &svs->svpids, next) {
				SLIST_REMOVE(&svs->svpids, svpid, spid, next);
				free(svpid);
			}
			printlog(LOG_INFO, "%s has been removed.", svs->svname);
			free(svs->svname);
			free(svs);
			ret = 0;
			break;
		}
	return ret;
}

/*
 * Open the configuration. Read services from that file and start and
 * monitor them if they are not running.
 */
static int
readconf(struct fscd_cfg *config)
{
	int ret = 0;
	char finput[LINE_MAX];
	char errorstr[LINE_MAX];
	FILE *fd;
	struct service *svs;
	unsigned int nlindex;

	fd = fopen(conffile, "r");
	if (fd == NULL) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "Opening configuration failed");
		else
			printlog(LOG_ERR, "Opening configuration failed: %s",
			    errorstr);
		return -1;
	}

	pthread_mutex_lock(&config->service_mtx);
	while ((fgets(finput, sizeof finput, fd)) != NULL) {
		nlindex = strcspn(finput, "\n");
		if (nlindex < sizeof finput)
			finput[nlindex] = 0;
		if (finput[0] == '#')
			continue;
		if (service_running(finput)) {
			if (service_registered(config, finput)) {
				continue;
			} else {
				/* Service already running. Just register. */
				svs = make_service(finput);
				if (!svs) {
					printlog(LOG_ERR, "%s could not be "
					    "built a structure for.",
					    svs->svname);
					ret = -1;
				} else if ((ret=register_service(config, svs))) {
					if (ret < 0)
						printlog(LOG_ERR, "%s could "
						    "not be monitored.",
						    svs->svname);
					else
						printlog(LOG_ERR, "%s could "
						    "not be monitored. Set "
						    "%s_enable to YES in "
						    "%cetc/rc.conf.",
						    svs->svname, svs->svname,
						    '/');
					free(svs->svname);
					free(svs);
				} else {
					printlog(LOG_INFO, "%s is being monitored.",
					    svs->svname);
				}
			}
		} else {
			if (service_registered(config, finput)) {
				/*
				 * Service already registered. We should never
				 * get to this point!
				 */
				printlog(LOG_ERR, "%s is registered, but not "
				    "running.", finput);
				ret = -1;
			} else {
				/* Service not running. Try to start and register. */
				svs = make_service(finput);
				if (!svs) {
					printlog(LOG_ERR, "%s could not be "
					    "built a structure for.", svs->svname);
					ret = -1;
				} else if ((ret=start_service(svs))) {
					if (ret < 0)
						printlog(LOG_ERR, "%s could "
						    "not be started.", svs->svname);
					else
						printlog(LOG_ERR, "%s could "
						    "not be started. Set "
						    "%s_enable to YES in "
						    "%cetc/rc.conf.",
						    svs->svname, svs->svname,
						    '/');
					free(svs->svname);
					free(svs);
				} else if ((ret=register_service(config, svs))) {
					if (ret < 0)
						printlog(LOG_ERR, "%s could "
						    "not be monitored.",
						    svs->svname);
					else
						printlog(LOG_ERR, "%s could "
						    "not be monitored. Set "
						    "%s_enable to YES in "
						    "%cetc/rc.conf.",
						    svs->svname, svs->svname,
						    '/');
					free(svs->svname);
					free(svs);
				} else if ((ret=handle_waiting(config, svs->svname))) {
					printlog(LOG_ERR, "%s failed to wait for start.",
							svs->svname);
					printlog(LOG_ERR, "%s removed from monitoring.",
							svs->svname);
					unregister_service(config, svs->svname);
				} else {
					printlog(LOG_INFO, "%s started from "
					    "config file.", svs->svname);
				}
			}
		}
	}
	pthread_mutex_unlock(&config->service_mtx);
	fclose(fd);
	return ret;
}

/*
 * The client sends us a string for each service, which takes
 * the form of a verb, some require qualifiers like the service name.
 * For example: enable:sshd
 */
static void *
connect_monitor(void *var)
{
	int s, s2, len;
	unsigned int cnt;
	struct sockaddr_un local, remote;
	struct fscd_cfg *config;
	char taskstr[LINE_MAX];
	char errorstr[LINE_MAX];

	printlog(LOG_INFO, "Server thread started.");

	config = var;
	memset(&local, 0, sizeof(local));
	memset(&remote, 0, sizeof(remote));

	if ((s = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "Creating socket failed.");
		else
			printlog(LOG_ERR, "Creating socket failed: %s",
			    errorstr);
		exit(1);
	}

	local.sun_family = PF_LOCAL;
	strcpy(local.sun_path, socketname);
	if (unlink(local.sun_path) == -1)
		if (errno != ENOENT) {
			if (strerror_r(errno, errorstr, sizeof errorstr))
				printlog(LOG_ERR, "Deleting socket failed.");
			else
				printlog(LOG_ERR, "Deleting socket failed: %s",
				    errorstr);
			exit(1);
		}

	len = strlen(local.sun_path) + sizeof(local.sun_family) + 1;
	if (bind(s, (struct sockaddr *)&local, len) == -1) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
				printlog(LOG_ERR, "Binding to socket failed.");
		else
			printlog(LOG_ERR, "Binding to socket failed: %s",
			    errorstr);
		exit(1);
	}

	if (chmod(socketname, S_IRWXU) == -1) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "Changing socket permissions "
			    "failed.");
		else
			printlog(LOG_ERR, "Changing socket permissions "
			    "failed: %s", errorstr);
		exit(1);
	}

	if (listen(s, 5) == -1) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "Listening to socket failed.");
		else
			printlog(LOG_ERR, "Listening to socket failed: %s",
			    errorstr);
		exit(1);
	}

	for (;;) {
		int done, nbytes;
		cnt = sizeof(remote);
		/* Attempt to gracefully handle accept() failure. */
		for (int retries = 5; retries >= 0; retries--) {
			s2 = accept(s, (struct sockaddr *)&remote, &cnt);
			if (s2 >= 0) {
				break;
			} else if (errno == EINTR || errno == ECONNABORTED) {
				if (retries == 0) {
					if (strerror_r(errno, errorstr,
					    sizeof errorstr))
						printlog(LOG_ERR, "accept "
						    "retries exhausted.");
					else
						printlog(LOG_ERR, "accept "
						    "retries exhausted: %s",
						    errorstr);
					exit(1);
				} else {
					sleep(1);
					continue;
				}
			} else {
				exit(1);
			}
		}

		done = 0;
		do {
			nbytes = recv(s2, taskstr, sizeof(taskstr), 0);
			if (nbytes <= 0) {
				if (nbytes == -1) {
					if (strerror_r(errno, errorstr,
					    sizeof errorstr))
						printlog(LOG_ERR, "receiving "
						    "from client failed.");
					else
						printlog(LOG_ERR, "receiving "
						    "from client failed: %s",
						    errorstr);
				}
				done = 1;
			}

			taskstr[nbytes] = '\0';
			handle_task(config, taskstr, s2);
			done = 1;
		} while (!done);
		close(s2);
	}
}

/*
 * A message was written to the socket. Parse it and act accordingly.
 */
static int
handle_task(struct fscd_cfg *config, char *serviceline, int sock_fd)
{
	char *arglst[2], **iter;
	char *sendstr;
	struct service *svs;
	char eot = 4;
	char status =0;

	for (iter = arglst; (*iter = strsep(&serviceline, ":")) != NULL;) {
		if (**iter != '\0')
			if (++iter >= &arglst[2])
				break;
	}

	pthread_mutex_lock(&config->service_mtx);

	/* enable */
	if (strcmp(arglst[0], "enable") == 0) {
		if (service_registered(config, arglst[1])) {
			asprintf(&sendstr, "Service already registered.\n");
			status = 1;
		} else {
			svs = make_service(arglst[1]);
			if (!svs) {
				asprintf(&sendstr, "Error building process "
				    "structure.\n");
				status = 1;
			} else if (!service_running(svs->svname) &&
			    start_service(svs)) {
				asprintf(&sendstr, "Could not start "
				    "service.\n");
				status = 1;
			} else if (register_service(config, svs)) {
				asprintf(&sendstr, "Could not monitor "
				    "service.\n");
				status = 1;
			} else {
				asprintf(&sendstr, "Monitoring service.\n");
				status = 0;
			}
		}
		send(sock_fd, &status, 1, 0);
		send(sock_fd, sendstr, strlen(sendstr), 0);
		send(sock_fd, &eot, 1, 0);
		free(sendstr);
		pthread_mutex_unlock(&config->service_mtx);
		return 0;

	/* disable */
	} else if (strcmp(arglst[0], "disable") == 0) {
		if (unregister_service(config, arglst[1])) {
			asprintf(&sendstr, "Removing service failed: "
			    "Not found.\n");
			status = 1;
		} else {
			asprintf(&sendstr, "Service removed.\n");
			status = 0;
		}
		send(sock_fd, &status, 1, 0);
		send(sock_fd, sendstr, strlen(sendstr), 0);
		send(sock_fd, &eot, 1, 0);
		free(sendstr);
		pthread_mutex_unlock(&config->service_mtx);
		return 0;

	/* shutdown */
	} else if (strcmp(arglst[0], "shutdown") == 0) {
		asprintf(&sendstr, "fscd shutting down.\n");
		status = 0;
		send(sock_fd, &status, 1, 0);
		send(sock_fd, sendstr, strlen(sendstr), 0);
		send(sock_fd, &eot, 1, 0);
		free(sendstr);
		/* We already have the lock, shutdown. */
		fscd_shutdown(0);
		/*
		 * We should never get here, but the unlock helps
		 * -Wthread-safety-analysis
		 */
		pthread_mutex_unlock(&config->service_mtx);
		return 0;

	/* status */
	} else if (strcmp(arglst[0], "status") == 0) {
		print_status(config, sock_fd);
		pthread_mutex_unlock(&config->service_mtx);
		return 0;
	}

	pthread_mutex_unlock(&config->service_mtx);
	return -1;
}

/*
 * Make a clean shutdown.
 * Empty the list, free all services, close the kqueue, and unlink socket.
 */
static void
fscd_shutdown(int exitcode)
{
	printlog(LOG_INFO, "fscd shutdown requested.");
	(void)unlink(socketname);

#if defined(__FreeBSD__)
	if (pfh && pidfile_remove(pfh))
		err(1, "pidfile_remove");
#endif
	exit(exitcode);
}

/*
 * Handle a signal.
 * XXX: Currently, there's no signal handling except for shutting
 * down on the registered signals. There might be some in the future.
 */
static void
handle_sig(int sig)
{
	sig = 1;
	fscd_shutdown(sig);
}

/*
 * On pipe errors, don't exit.
 */
static void
ignore_sig(int sig)
{
	if (sig == SIGPIPE)
		printlog(LOG_ERR, "Received broken pipe.");
	return;
}
