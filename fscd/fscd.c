/*-
 * Copyright (c) 2009-2026 Tom Rhodes. All rights reserved.
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
#include <time.h>
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

/* Useful macro defines. */
#define PKG_SYSCONFDIR "/usr/local/etc/"
#define SOCK_PATH _PATH_VARRUN"fscd.sock"
#define PID_FILE _PATH_VARRUN"fscd.pid"
#define CONF_FILE PKG_SYSCONFDIR"fscd.conf"
#define SERVICE "service"
#define STATUS "onestatus"
#define START "restart" // restart is more reliable than just start.
#define VERSION "1.2"

/* TEMPORARY - should be passed via config file/command */
#define RETRY_INTERVAL  60
#define RETRY_COUNT	5

struct spid {
	pid_t svpid;
	SLIST_ENTRY(spid) next;
};
SLIST_HEAD(spid_list_head, spid);

struct service {
	char *svname;
	int restarting;
	struct spid_list_head svpids;
	SLIST_ENTRY(service) next;
};
SLIST_HEAD(service_list_head, service);

struct retry_entry {
	char *service;
	unsigned int wait;
	unsigned int retries_left;
	struct timespec next_attempt;
	SLIST_ENTRY(retry_entry) next;
};
SLIST_HEAD(retry_queue, retry_entry);

struct fscd_cfg {
	struct service_list_head service_list;
	struct retry_queue retry_queue;
	pthread_mutex_t service_mtx;
	pthread_cond_t retry_cv;
	int service_thr_int;
	pthread_t service_thr;
	pthread_t retry_thr;
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
static char *pidfilename = NULL;
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
static int retry_service(struct fscd_cfg *, const char *);
static int remove_retry(struct fscd_cfg *, const char *);
static void *retry_worker(void *);
static int run_restart_command(const char *);

int
main(int argc, char *argv[])
{
	int newevent, ch, force, error;
	struct fscd_cfg config;
	struct service svs;
	struct kevent kq_events;
	struct stat nb_stat;
	char errorstr[LINE_MAX];
	pthread_condattr_t retry_attr;
	int verbosity = 1;

	/* Check arguments */
	while ((ch = getopt(argc, argv, "Vdvfp:s:c:")) != -1)
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
			case 'p': /* Change pidfile. */
				if (asprintf(&pidfilename, "%s", optarg) <= 0)
					err(1, "asprintf");
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

	/*
	 * Verbosity 1 is the default as I felt it important to log
	 * notices, such as restarts and retry counts, which are not
	 * errors but important enough to write log entries. It can
	 * be altered through the documented option.
	 */
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

	/* Initialization phase (paths and files). */
	if (!socketname && asprintf(&socketname, "%s", SOCK_PATH) < 0)
		err(1, "asprintf");
	if (!conffile && asprintf(&conffile, "%s", CONF_FILE) < 0)
		err(1, "asprintf");

	if (stat(PID_FILE, &nb_stat) == 0)
		errx(1, "A pidfile exists: %s, not starting.", PID_FILE);
	else if (errno != ENOENT)
		err(1, "Unable to stat pidfile: %s", PID_FILE);

	if (lstat(socketname, &nb_stat) == 0) {
		if (!force)
			errx(1, "Socket exists: %s, specify -f to overwrite.",
			    socketname);
		if (unlink(socketname) == -1)
			err(1, "Deleting old socket.");
	} else if (errno != ENOENT) {
		err(1, "Unable to stat socket: %s.", socketname);
	}

	/* Lacking a config file is not fatal. */
	if (stat(conffile, &nb_stat) == -1) {
		warnx("Configuration file: %s, does not exist. Services "
		    "need added manually.", conffile);
		printlog(LOG_NOTICE, "Configuration file: %s not found, no "
		    "services will be added during start up.", CONF_FILE);
	}

#if defined(__FreeBSD__)
	if ((pfh = pidfile_open(pidfilename, 0644, NULL)) == NULL)
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
	SLIST_INIT(&config.retry_queue);
	config.kq = kqueue();
	if (config.kq == -1)
		err(1, "kqueue");
	if ((error = pthread_mutex_init(&config.service_mtx, NULL)))
		errc(1, error, "pthread_mutex_init");
	if ((error = pthread_condattr_init(&retry_attr)) != 0)
		errc(1, error, "pthread_condattr_init");
	if ((error = pthread_condattr_setclock(&retry_attr,
	    CLOCK_MONOTONIC)) != 0)
		errc(1, error, "pthread_condattr_setclock");

	error = pthread_cond_init(&config.retry_cv, &retry_attr);
	pthread_condattr_destroy(&retry_attr);
	if (error != 0)
		errc(1, error, "pthread_cond_init");

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

	printlog(LOG_NOTICE, "Starting ...");

	if ((error = pthread_create(&config.service_thr, NULL,
	    connect_monitor, &config)) != 0)
		errc(1, error, "pthread_create");
	if ((error = pthread_create(&config.retry_thr, NULL, retry_worker,
	    &config)) != 0)
		errc(1, error, "pthread_create retry_worker");

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
	struct service *svs, *svs_found = NULL;
	struct spid *svpid;
	char *sname;

	if (! (kq_events->fflags & NOTE_EXIT))
		return;

	/*
	 * Locate the service owning the pid that exited.  Find it and
	 * take action afterwards.
	 */
	pthread_mutex_lock(&config->service_mtx);
	SLIST_FOREACH(svs, &config->service_list, next) {
		SLIST_FOREACH(svpid, &svs->svpids, next) {
			if (kq_events->ident == (uintptr_t)svpid->svpid) {
				svs_found = svs;
				break;
			}
		}
		if (svs_found != NULL)
			break;
	}

	if (svs_found == NULL) {
		pthread_mutex_unlock(&config->service_mtx);
		return;
	}

	if (svs_found->restarting) {
		pthread_mutex_unlock(&config->service_mtx);
		return;
	}

	status = kq_events->data;
	if (WIFSIGNALED(status)) {
		printlog(LOG_ERR, "%s caught signal %d and exited",
		    svs_found->svname, WTERMSIG(status));
		pretcode = process_exited(status);
	} else if (WIFEXITED(status)) {
		printlog(LOG_ERR, "%s exited with status %d",
		    svs_found->svname, WEXITSTATUS(status));
		pretcode = 0;
	} else {
		pthread_mutex_unlock(&config->service_mtx);
		return;
	}

	/*
	 * The mutex is dropped in handle_restart(), duplicate to be safe.
	 */
	sname = strdup(svs_found->svname);
	if (sname == NULL) {
		printlog(LOG_ERR, "could not copy service name before "
		    "attempting to restart service: %s", svs_found->svname);
		pthread_mutex_unlock(&config->service_mtx);
		return;
	}

	if (pretcode == 1 && handle_restart(config, sname) == 0) {
		printlog(LOG_NOTICE, "%s was restarted", sname);
	} else if (pretcode == 0 &&
	    handle_waiting(config, sname) == 0) {
		printlog(LOG_NOTICE, "%s waiting for restart.",
		    sname);
	} else {
		if (retry_service(config, sname) != 0) {
			printlog(LOG_ERR, "%s could not be scheduled "
			    "for a retry. An administrator should "
			    " remove and re-add the service.", sname);
		}
	}

	pthread_mutex_unlock(&config->service_mtx);
	free(sname);
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
 * Execute the restart command for a named service.
 * This purposely does not modify the service list
 * or the PID lists.
 *
 * Returns 0 if the command ran successfully.
 * Returns -1 if a failure occurred.
 *
 * It is the responsibility of the caller to hold the
 * lock and to check if the service has been set to
 * a "restarting" state to prevent multiple calls to
 * service(8) for the same service.
 */
static int
run_restart_command(const char *sname)
{
	char errorstr[LINE_MAX];
	char *cmdstr;
	char pinput[LINE_MAX];
	FILE *pp;
	int retcode;

	if (asprintf(&cmdstr, SERVICE " %s " START, sname) < 0) {
		printlog(LOG_ERR, "Could not build restart command "
		    "for service: %s.", sname);
		return -1;
	}

	pp = popen(cmdstr, "r");
	free(cmdstr);
	if (pp == NULL) {
		if (strerror_r(errno, errorstr, sizeof(errorstr)) == 0)
			printlog(LOG_ERR, "popen failed for service: %s: %s.",
			    sname, errorstr);
		else
			printlog(LOG_ERR, "popen failed for service: %s",
			    sname);
		return -1;
	}

	while (fgets(pinput, sizeof(pinput), pp) != NULL) {
		if (strstr(pinput, "_enable to YES in /etc/rc.conf.") != NULL) {
			(void)pclose(pp);
			return 1;
		}
	}

	retcode = pclose(pp);
	if (retcode == -1 || !WIFEXITED(retcode) || WEXITSTATUS(retcode) != 0)
		return -1;

	return 0;
}

/*
 * Called when a service died. Restart the service.
 *
 * Returns 0 if the restart was successful.
 * Returns 1 if the service was already restarting.
 * Returns -1 if the restart failed.
 * Returns -2 if the service was not found (removed from fscd).
 *
 * The caller must hold service_mtx, returns with service_mtx held.
 */
static int
handle_restart(struct fscd_cfg *config, char *sname)
{
	struct service *svs;
	char *name;
	int ret;

	/*
	 * Find the service while the mutex is held.
	 */
	SLIST_FOREACH(svs, &config->service_list, next) {
		if (strcmp(svs->svname, sname) == 0)
			break;
	}

	if (svs == NULL) {
		printlog(LOG_NOTICE, "Service: %s is no longer registered. "
		    "The restart was cancelled.", sname);
		return -2;
	}

	if (svs->restarting != 0) {
		printlog(LOG_NOTICE, "Service: %s was already restarting "
		    "and will not be restarted now.", sname);
		return 1;
	}

	name = strdup(svs->svname);
	if (name == NULL) {
		printlog(LOG_ERR, "Could not copy service name for restart.");
		return -1;
	}

	/*
	 * If ret returns -1, it's an error. If we get 0, it was
	 * successful. The "restarting == 1" check was already
	 * done.
	 */
	svs->restarting = 1;
	pthread_mutex_unlock(&config->service_mtx);
	ret = run_restart_command(name);
	pthread_mutex_lock(&config->service_mtx);

	/* Find the service again, the pointer may have become stale. */
	SLIST_FOREACH(svs, &config->service_list, next) {
		if (strcmp(svs->svname, name) == 0)
			break;
	}

	if (svs == NULL) {
		printlog(LOG_NOTICE, "Service: %s is no longer "
		    "registered after restart attempt.", name);
		free(name);
		return -2;
	}

	/* Check our cmd run */
	if (ret == -1) {
		printlog(LOG_ERR, "Service: %s could not be "
		    "restarted. If any retry attempts exist, a "
		    "retry will be attempted.", name);
		svs->restarting = 0;
		free(name);
		return -1;
	}

	/*
	 * If we are here, the restart succeeded. Refresh the PID
	 * list and register the monitoring while the mutex hold remains.
	 */
	if (fill_pids(svs) != 0) {
		printlog(LOG_ERR, "Could not get PIDS for service: %s.", name);
		svs->restarting = 0;
		free(name);
		return -1;
	}

	if (SLIST_EMPTY(&svs->svpids)) {
		printlog(LOG_ERR, "No PIDS found for service: %s.", name);
		svs->restarting = 0;
		free(name);
		return -1;
	}

	if (kqueue_service(config, svs) != 0) {
		printlog(LOG_ERR, "Could not monitor service: %s.", name);
		svs->restarting = 0;
		free(name);
		return -1;
	}

	/*
	 * Return service to a "not restarting" state, free memory, and return.
	 */
	svs->restarting = 0;
	free(name);
	return 0;
}

/*
 * Call the waiting function when a daemon died by user's hand.
 */
static int
handle_waiting(struct fscd_cfg *config, char *sname)
{
	pthread_t tmpthr;
	struct restart_params *inputv;
	int error;

	inputv = malloc(sizeof(struct restart_params));
	if (inputv == NULL) {
		printlog(LOG_ERR, "Could not allocate memory for "
		    "restart parameters.");
		return -1;
	}

	inputv->config = config;
	inputv->sname = strdup(sname);
	if (inputv->sname == NULL) {
		printlog(LOG_ERR, "Could not allocate restart parameters.");
		free(inputv);
		return -1;
	}

	error = pthread_create(&tmpthr, NULL, wait_restart, inputv);
	if (error != 0) {
		free(inputv->sname);
		free(inputv);
		return -1;
	}

	/* If the thread is never joined, detach. */
	error = pthread_detach(tmpthr);
	if (error != 0)
		printlog(LOG_ERR, "Could not detach restart thread.");

	return 0;
}

/*
 * Wait a certain amount of time before attempting to restart the service.
 */
static void *
wait_restart(void *var)
{
	struct restart_params *inputv;
	struct service *svs;
	int retries, found;

	inputv = var;
	for (retries = 6; retries >= 0; retries--) {
		found = 0;
		/*
		 * Traverse the service list under the mutex.  fill_pids()
		 * frees and rebuilds the pid list, so the operation must be
		 * done with the lock held; it is dropped only while sleeping.
		 */
		pthread_mutex_lock(&inputv->config->service_mtx);
		SLIST_FOREACH(svs, &inputv->config->service_list, next) {
			if (strcmp(svs->svname, inputv->sname) != 0)
				continue;

			found = 1;
			/* Wait for the service to restart on its own. */
			if (!fill_pids(svs)) {
				if (kqueue_service(inputv->config, svs))
					printlog(LOG_ERR, "Could not monitor "
					    "service.");
				else
					printlog(LOG_INFO, "Service: %s was "
					    "restarted, but not by me.",
					    svs->svname);
				pthread_mutex_unlock(&inputv->config->service_mtx);
				free(inputv->sname);
				free(inputv);
				return NULL;
			}
			break;
		}
		pthread_mutex_unlock(&inputv->config->service_mtx);
		if (!found) {
			printlog(LOG_ERR, "Service: %s was removed from "
			    "monitoring while I was waiting for it to restart.",
			    inputv->sname);
			free(inputv->sname);
			free(inputv);
			return NULL;
		}
		sleep(10);
	}

	/*
	 * The service did not come back on its own.  Look it up again under
	 * the lock (it may have been removed while we slept) and restart it.
	 */
	pthread_mutex_lock(&inputv->config->service_mtx);
	svs = NULL;
	SLIST_FOREACH(svs, &inputv->config->service_list, next)
		if (strcmp(svs->svname, inputv->sname) == 0)
			break;

	/*
	 * Using inputv->sname is surely be safe here, it's owned by this worker
	 * thread and is independent of the service list. It remains valid
	 * while handle_restart() drops and reacquires service_mtx.
	 */
	if (svs == NULL) {
		printlog(LOG_ERR, "Service %s was removed from monitoring "
		    "while I was waiting for it to restart.", inputv->sname);
	} else if (handle_restart(inputv->config, inputv->sname) == 0) {
		printlog(LOG_NOTICE, "Service: %s was restarted.",
		    inputv->sname);
	} else {
		if (retry_service(inputv->config, inputv->sname) != 0) {
			printlog(LOG_ERR, "Service: %s could not be scheduled "
			    " for retry", inputv->sname);
		}
	}
	pthread_mutex_unlock(&inputv->config->service_mtx);
	free(inputv->sname);
	free(inputv);
	return NULL;
}

/*
 * Schedule a failed restart for a retry.
 * The caller must hold service_mtx.
 * Return 0 if a retry is pending, -1 if the service allocation
 * fails, or was unregistered (and not found).
 */
static int
retry_service(struct fscd_cfg *config, const char *sname)
{
	struct retry_entry *entry;
	struct service *svs;

	/* Safe because caller holds service_mtx. */
	SLIST_FOREACH(svs, &config->service_list, next) {
		if (strcmp(svs->svname, sname) == 0)
			break;
	}

	if (svs == NULL) {
		printlog(LOG_NOTICE, "Service: %s is no longer registered. "
		    "A retry will not be scheduled.", sname);
		    return -1;
	}

	if (svs->restarting) {
		printlog(LOG_NOTICE, "Service: %s is already restarting. "
		    "A retry will not be scheduled at this time.", sname);
		return 0;
	}

	/* Retry entries only exist for registered services. Check. */
	if (!service_registered(config, sname)) {
		printlog(LOG_NOTICE, "Service: %s is no longer registered. "
		    "A retry will not be scheduled.", sname);
		return -1;
	}

	SLIST_FOREACH(entry, &config->retry_queue, next) {
		if (strcmp(entry->service, sname) == 0) {
			printlog(LOG_NOTICE, "%s already has a pending "
			    "retry waiting.", sname);
			return 0;
		}
	}

	entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		printlog(LOG_ERR, "Unable to allocate retry entry "
		    "for %s.", sname);
		return -1;
	}

	entry->service = strdup(sname);
	if (entry->service == NULL) {
		printlog(LOG_ERR, "Could not copy service name for "
		    "service retry entry: %s.", sname);
		free(entry);
		return -1;
	}

	entry->wait = RETRY_INTERVAL;
	entry->retries_left = RETRY_COUNT;
	if (clock_gettime(CLOCK_MONOTONIC, &entry->next_attempt) == -1) {
		printlog(LOG_ERR, "Could not get monotonic time for "
		    "service: %s.", sname);
		free(entry->service);
		free(entry);
		return -1;
	}

	/* Add to restart queue, log the information. */
	entry->next_attempt.tv_sec += entry->wait;
	SLIST_INSERT_HEAD(&config->retry_queue, entry, next);
	printlog(LOG_NOTICE, "Service: %s was submitted to the restart "
	    "queue. First retry in %u seconds.", entry->service, entry->wait);
	pthread_cond_signal(&config->retry_cv);

	return 0;
}

/*
 * Remove a service from retry. Used for both "disable" and for
 * retry exhaustion.
 *
 * The caller of this function must hold service_mtx
 * Returns 0 if the service is removed
 * Returns 1 if the service is not found.
 */
static int
remove_retry(struct fscd_cfg *config, const char *sname)
{
	struct retry_entry *entry;

	SLIST_FOREACH(entry, &config->retry_queue, next) {
		if (strcmp(entry->service, sname) != 0)
			continue;

		SLIST_REMOVE(&config->retry_queue, entry,
		    retry_entry, next);
		free(entry->service);
		free(entry);
		pthread_cond_signal(&config->retry_cv);
		return 0;
	}
	return 1;
}

/*
 * Process scheduled retries.
 * The worker holds service_mtx while checking the retry queue and attempting
 * a restart. In handle_restart(), service_mtx is unlocked while calling out
 * to service(8), but we call it with the lock held.
 */
static void *
retry_worker(void *var)
{
	struct fscd_cfg *config;
	struct retry_entry *entry;
	struct retry_entry *due_entry;
	struct timespec now;
	int clock_error, error, ret;
	char *sname;

	config = var;
	for (;;) {
		pthread_mutex_lock(&config->service_mtx);
		clock_error = 0;

		/*
		 * Find a service with the earliest deadline.
		 * Recheck after every wakeup.
		 */
		for (;;) {
			if (SLIST_EMPTY(&config->retry_queue)) {
				error = pthread_cond_wait(&config->retry_cv,
				    &config->service_mtx);
				if (error != 0) {
					pthread_mutex_unlock(&config->service_mtx);
					printlog(LOG_ERR, "pthread_cond_wait "
					    "failed: %s", strerror(error));
					return NULL;
				}
				continue;
			}

			due_entry = NULL;
			SLIST_FOREACH(entry, &config->retry_queue, next) {
				if (due_entry == NULL ||
				    entry->next_attempt.tv_sec <
				    due_entry->next_attempt.tv_sec ||
				    (entry->next_attempt.tv_sec ==
				    due_entry->next_attempt.tv_sec &&
				    entry->next_attempt.tv_nsec <
				    due_entry->next_attempt.tv_nsec))
				due_entry = entry;
			}

			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
				printlog(LOG_ERR, "Could not get monotonic "
				    "time.");
				clock_error = 1;
				break;
			}

			if (due_entry->next_attempt.tv_sec < now.tv_sec ||
			    (due_entry->next_attempt.tv_sec == now.tv_sec &&
			    due_entry->next_attempt.tv_nsec <= now.tv_nsec))
				break;

			error = pthread_cond_timedwait(&config->retry_cv,
			    &config->service_mtx, &due_entry->next_attempt);
			if (error != 0 && error != ETIMEDOUT) {
				pthread_mutex_unlock(&config->service_mtx);
				printlog(LOG_ERR, "pthread_cond_timedwait "
				    "failed: %s", strerror(error));
				return NULL;
			}
		}

		/*
		 * Don't process a retry if the clock check failed.
		 * Also, release the mutex before sleeping.
		 */
		if (clock_error) {
			pthread_mutex_unlock(&config->service_mtx);
			sleep(1);
			continue;
		}

		/*
		 * A due entry is processed while holding the mutex,
		 * and handle_restart() should be called while holding
		 * the mutex, it will drop and reacquire as needed before
		 * calling service(8). Perform checks here to be safe.
		 */
		printlog(LOG_NOTICE, "Retrying service: %s.",
		    due_entry->service);

		sname = strdup(due_entry->service);
		if (sname == NULL) {
			printlog(LOG_ERR, "Failed to copy service: %s "
			    "name for retry entry.", due_entry->service);
			pthread_mutex_unlock(&config->service_mtx);
			sleep(1);
			continue;
		}

		/*
		 * Validate the return from handle_restart().
		 * If we receive 0, a reschedule is not needed.
		 * If we receive 1, it was already restarting, do not
		 * change restart counts.
		 * If we receive -1, it failed, continue to exhaust the counts.
		 */
		ret = handle_restart(config, sname);
		if (ret == 0) {
			printlog(LOG_NOTICE, "%s restarted successfully",
			    sname);
			(void)remove_retry(config, sname);
			pthread_mutex_unlock(&config->service_mtx);
			free(sname);
			continue;
		} else if (ret == 1) {
			printlog(LOG_NOTICE, "Service: %s was already "
			    "restarting.", sname);
			due_entry = NULL;
			SLIST_FOREACH(entry, &config->retry_queue, next) {
				if (strcmp(entry->service, sname) == 0) {
					due_entry = entry;
					break;
				}
			}
			/*
			 * A restart attempt in progress, move the deadline
			 * forward to prevent a possible busy loop while the
			 * other attempt is in progress. This is done as the
			 * loop finds the earliest deadline and if this
			 * particular deadline is in the past, the same
			 * entry is immediately eligible again, creating a
			 * loop.
			 */
			if (due_entry != NULL) {
				if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
					printlog(LOG_ERR, "Could not get "
					    "monotonic clock time to defer "
					    "retry for service: %s.", sname);
					pthread_mutex_unlock(&config->
					    service_mtx);
					free(sname);
					sleep(1);
					continue;
				}
				due_entry->next_attempt = now;
				due_entry->next_attempt.tv_sec +=
				   RETRY_INTERVAL;

			}
			pthread_mutex_unlock(&config->service_mtx);
			free(sname);
			continue;
		} else if (ret == -2) {
			printlog(LOG_NOTICE, "Service: %s was unregistered. "
			    "Removing restart queue entry for %s.", sname,
			    sname);
			(void)remove_retry(config, sname);
			pthread_mutex_unlock(&config->service_mtx);
			free(sname);
			continue;
		}

		/*
		 * Find our place again. The pointer may be stale.
		 */
		due_entry = NULL;
		SLIST_FOREACH(entry, &config->retry_queue, next) {
			if (strcmp(entry->service, sname) == 0) {
				due_entry = entry;
				break;
			}
		}

		if (due_entry == NULL) {
			printlog(LOG_NOTICE, "Retry entry for service: %s "
			    "was removed while a restart was in progress.",
			    sname);
			    pthread_mutex_unlock(&config->service_mtx);
			    free(sname);
			    continue;
		}
	
		/*
		 * In the future, this should consider the clock failure
		 * an explicit operational error.
		 */
		if (due_entry->retries_left >= 1) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
				printlog(LOG_ERR, "Could not get monotonic "
				    "time to reschedule retry for service: "
				    "%s.", sname);
				pthread_mutex_unlock(&config->service_mtx);
				free(sname);
				sleep(1);
				continue;
			}

			due_entry->retries_left--;
			due_entry->next_attempt = now;
			due_entry->next_attempt.tv_sec += due_entry->wait;
			printlog(LOG_ERR, "Retry failed for %s, %u attempts "
			    "remaining.", sname,
			    due_entry->retries_left);
		} else if (due_entry->retries_left == 0) {
			printlog(LOG_ERR, "Retries exhausted for %s.",
			    sname);
			printlog(LOG_ERR, "An administrator should review "
			    "and consider removing and re-adding %s to "
			    "monitoring.", sname);
			(void)(remove_retry(config, sname));
			pthread_mutex_unlock(&config->service_mtx);
			free(sname);
			continue;
		}

		pthread_mutex_unlock(&config->service_mtx);
		free(sname);
	}
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
					"	-p P Use pidfile P.\n"
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
	if (retcode == -1 || !WIFEXITED(retcode) ||
	    WEXITSTATUS(retcode) != 0)
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
			printlog(LOG_ERR, "malloc for %s failed.", sname);
		else
			printlog(LOG_ERR, "malloc for %s failed: %s",
			    sname, errorstr);
		return NULL;
	}
	svs->svname = NULL;

	if (asprintf(&svs->svname, "%s", sname) <= 0) {
		if (strerror_r(errno, errorstr, sizeof errorstr))
			printlog(LOG_ERR, "asprintf for %s failed.", sname);
		else
			printlog(LOG_ERR, "asprintf for %s failed: %s",
			    sname, errorstr);
		free(svs);
		return NULL;
	}
	svs->restarting = 0;
	SLIST_INIT(&svs->svpids);

	return svs;
}

/*
 * Get the pids for given process, and fill the structs, emptying the
 * list if it is not empty.
 *
 * This function must be called while holding the lock.
 *
 * Return 0 if we found a pid.
 * Return 1 if we could not find a pid.
 * Return -1 if we encountered an error.
 */
static int
fill_pids(struct service *svs)
{
	struct spid *svpid, *svpid_tmp;
	char *cmdstr, *tmpstr, *ttmpstr;
	char *pinputp;
	char pinput[LINE_MAX], errorstr[LINE_MAX];
	FILE *pp;
	int retcode, found_pid;
	pid_t pid;

	/* Empty list. */
	if (!SLIST_EMPTY(&svs->svpids)) {
		SLIST_FOREACH_SAFE(svpid, &svs->svpids, next, svpid_tmp) {
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
		if (strerror_r(errno, errorstr, sizeof(errorstr)) == 0)
			printlog(LOG_ERR, "popen failed: %s: %s.", svs->svname,
			    errorstr);
		else
			printlog(LOG_ERR, "popen failed for %s.", svs->svname);
		return -1;
	}

	/*
	 * If we receive "_enable to YES in" then the service is unlikely
	 * to be enabled in rc.conf. Return "1" in that case.
	 */
	found_pid = 0;
	while (fgets(pinput, sizeof(pinput), pp) != NULL) {
		if (strstr(pinput, "_enable to YES in") != NULL) {
			pclose(pp);
			return 1;
		}

		/* 
		 * Scan the output for a separated list of numbers assuming
		 * they are pids. The service name may be different from the
		 * start/stop file name.
		 */
		for (pinputp = strtok_r(pinput, " .,\t\n", &ttmpstr);
			pinputp != NULL;
			pinputp = strtok_r(NULL, " .,\t\n", &ttmpstr)) {
			pid = strtoul(pinputp, &tmpstr, 10);

			/* Only accept numeric token. */
			if (tmpstr == pinputp || *tmpstr != '\0')
				continue;

			if (pid > 0 && getsid(pid) != -1) {
				svpid = malloc(sizeof(*svpid));
				if (svpid == NULL) {
					printlog(LOG_ERR, "Could not "
					    "allocate PID for service: "
					    "%s.", svs->svname);
					    (void)pclose(pp);
					    return -1;
				}
				svpid->svpid = pid;
				SLIST_INSERT_HEAD(&svs->svpids, svpid,
				    next);

				found_pid = 1;
				break;
			}
		}
		if (found_pid)
		break;
	}

	retcode = pclose(pp);
	if (retcode == -1 || !WIFEXITED(retcode) ||
	    WEXITSTATUS(retcode) != 0)
		return -1;

	if (SLIST_EMPTY(&svs->svpids))
		return 1;

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
	if (retcode == -1 || !WIFEXITED(retcode) ||
	    WEXITSTATUS(retcode) != 0)
		return -1;

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
 * Remove a service from the monitoring list and free it.
 * Check and remove any retry entry, if one exists.
 * Return 0 on success, 1 if nothing was found.
 */
static int
unregister_service(struct fscd_cfg *config, char *svc_name_in)
{
	struct spid *svpid, *svpid_tmp;
	struct service *svs, *svs_tmp;
	int ret = 1;

	SLIST_FOREACH_SAFE(svs, &config->service_list, next, svs_tmp) {
		if (strcmp(svs->svname, svc_name_in) != 0)
			continue;

		SLIST_REMOVE(&config->service_list, svs, service, next);
		(void)remove_retry(config, svs->svname);

		SLIST_FOREACH_SAFE(svpid, &svs->svpids, next, svpid_tmp) {
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
 *
 * Do not call while holding a lock. The appropriate locking is performed
 * here as services will be read and added to the monitoring queue.
 *
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
					    "built a structure for.", finput);
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
					    "built a structure for.", finput);
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
				} else if ((ret=handle_waiting(config,
				    svs->svname))) {
					printlog(LOG_ERR, "%s failed to wait "
					    "for %s to start. It is "
					    "recommended that the service be "
					    "removed and re-added.",
					    svs->svname);
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
	if (strlcpy(local.sun_path, socketname, sizeof(local.sun_path))
	    >= sizeof(local.sun_path)) {
		printlog(LOG_ERR, "Socket path too long.");
		exit(1);
	}
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
			nbytes = recv(s2, taskstr, sizeof(taskstr) - 1, 0);
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
				break;
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
 *
 * When adding (enable), removing (disable), getting a status, or
 * shutting down, handle_task() holds the lock and releases it
 * after performing the requested task.
 */
static int
handle_task(struct fscd_cfg *config, char *serviceline, int sock_fd)
{
	char *arglst[2] = { NULL, NULL }, **iter;
	char *sendstr;
	struct service *svs;
	char eot = 4;
	char status = 0;

	for (iter = arglst; (*iter = strsep(&serviceline, ":")) != NULL;) {
		if (**iter != '\0')
			if (++iter >= &arglst[2])
				break;
	}

	pthread_mutex_lock(&config->service_mtx);

	if (arglst[0] == NULL) {
		pthread_mutex_unlock(&config->service_mtx);
		return -1;
	}

	/* A service name is required for enable and disable. */
	if ((strcmp(arglst[0], "enable") == 0 ||
	    strcmp(arglst[0], "disable") == 0) &&
	    (arglst[1] == NULL || arglst[1][0] == '\0')) {
		status = 1;
		asprintf(&sendstr, "No service name given.\n");
		send(sock_fd, &status, 1, 0);
		send(sock_fd, sendstr, strlen(sendstr), 0);
		send(sock_fd, &eot, 1, 0);
		free(sendstr);
		pthread_mutex_unlock(&config->service_mtx);
		return 0;
	}

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
				free(svs->svname);
				free(svs);
			} else if (register_service(config, svs)) {
				asprintf(&sendstr, "Could not monitor "
				    "service.\n");
				status = 1;
				free(svs->svname);
				free(svs);
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
			(void)remove_retry(config, arglst[1]);
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
