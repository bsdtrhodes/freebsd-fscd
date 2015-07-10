# freebsd-fscd
FreeBSD fscd files for public pulling, testing, etc..  This *should* work on NetBSD as well.

FSCD was an idea I had ages ago to implement a similar mechanism to Sun's (now Oracle's) FMRI inside of FreeBSD.  Using XML configurations would have required way too much efforts and, since many people still supported launchd, I chose to not integrate into the run control (rc) system.

Instead, this application may work as an independent application, allowing a user to either set up a configuration file to start applications via a configuration file, or just use the normal rc.conf and add the monitored applications.

If the application should crash, fscd will attempt to restart.  Failure will leave a log entry in syslog.  May be interesting to provide a better notification mechanism.

Reasons to use:

o kqueue() support provides push rather than pulling the applications, reducing system resources;

o Integration with FreeBSD's rc and service utilities do not require much overhead for configuration;

o Other applications may be too bloated or too configuration heavy for some reasons.

Reasons to not use:

o You have something better that provides, say, web dashboard and multiple server monitoring, beyond the scope of fscd.

o You're using a non-BSD operating system.
