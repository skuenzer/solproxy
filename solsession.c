/*
 *  Copyright 2016 Simon Kuenzer
 *
 *  SOLproxy is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU Lesser General Public License as published by the
 *  Free Software Foundation, either version 3.0 of the License, or (at your
 *  option) any later version.
 *
 *  SOLproxy is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 *  License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with SOLproxy. If not, see
 *  <http://www.gnu.org/licenses/>.
 */
/*
 *  Some parts are copied from ipmiconsole from GNU FreeIPMI Project:
 *  Copyright (C) 2007-2012 Lawrence Livermore National Security, LLC.
 *  Copyright (C) 2006-2007 The Regents of the University of California.
 *  Produced at Lawrence Livermore National Laboratory (cf, DISCLAIMER).
 *  Written by Albert Chu <chu11@llnl.gov>
 *  UCRL-CODE-221226
 *  See also: ipmiconsole/ipmiconsole.c in freeipmi-1.1.6.tar.gz
 */
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "solsession.h"

/******************************************************************************
 * SESSIONS                                                                  *
 ******************************************************************************/
#define BUFLEN	4096

int solsession(struct args *args, int fd)
/*
 * Establish and proxy a IPMI connection
 * 
 * Code in this function is mainly adapted from the ipmiconsole tool
 * shipped with the GNU FreeIPMI package (see ipmiconsole/ipmiconsole.c in freeipmi-1.1.6.tar.gz)
 */
{
	ipmiconsole_ctx_t ictx;
	int cd = -1;
	int ret = 0;
	int rc;

	char buf[BUFLEN];
	ssize_t n;
	fd_set r_set;
	struct timeval timeout;

	dprintf(D_L0, "Establishing IPMI connection to %s...\n", args->hostname);
	ictx = ipmiconsole_ctx_create(args->hostname, &args->config, &args->protocol, &args->engine);
	if (!ictx) {
		eprintf("Could not establish connection to %s: %s\n", args->hostname, strerror(errno));
		return -1;
	}

	rc = ipmiconsole_engine_submit_block(ictx);
	if (rc < 0)
		eprintf("Could not establish connection to %s: %s\n", args->hostname, ipmiconsole_ctx_errormsg(ictx));
	if ((rc < 0) || sigterm) {
		ret = -1;
		goto exit;
	}

	cd = ipmiconsole_ctx_fd(ictx);
	if (cd < 0) {
		eprintf("Could not retrieve file descriptor from SOL session: %s\n", ipmiconsole_ctx_errormsg(ictx));
		ret = -1;
		goto exit;
	}
	dprintf(D_L0, "SOL session opened\n");

	/*
	 * ictx - IPMI console control interface
	 * fd - Passed descriptor (e.g., socket)
	 * cd - Descriptor of IPMI console
	 */
	for (;;) {
		FD_ZERO(&r_set);
		FD_SET(cd, &r_set);	/* IMPI console */
		FD_SET(fd, &r_set);	/* passed descriptor */

		timeout.tv_sec = 0;
		timeout.tv_usec = 250000;

		if (sigterm)
			goto exit;

		/* wait for data */
		rc = select(cd + 1, &r_set, NULL, NULL, &timeout);
		if (sigterm)
			goto exit;
		if (rc < 0) {
		  eprintf("Error while waiting for I/O: %d\n", rc);
			ret = -1;
			goto exit;
		}

		/* Data available on passed descriptor */
		if (FD_ISSET(fd, &r_set)) {
			n = read(fd, buf, BUFLEN);
			if (n < 0) { /* read error */
				eprintf("Could not read from input\n");
				ret = -1;
				goto exit;
			}
			if (!n)
				goto exit;

			/* copy data (fd -> cd) */
			if (write(cd, buf, n) != n) {
				eprintf("Sending data to SOL session failed\n");
				ret = -1;
				goto exit;
			}
		}

		/* Data available on SOL session */
		if (FD_ISSET(cd, &r_set)) {
			n = read(cd, buf, BUFLEN);
			if (n < 0) { /* read error */
				eprintf("Reading data from SOL session failed: %s\n", ipmiconsole_ctx_errormsg(ictx));
				ret = -1;
				goto exit;
			}
			if (!n) {
				/* It is possible that errnum can equal success.
				 * Most likely scenario is user sets a flag in the
				 * libipmiconsole.conf file that alters the behavior of
				 * what this tool expects to happen.  For example, if
				 * user specifies deactivate on the command line, we
				 * know to quit early.  However, if the user does so in
				 * libipmiconsole.conf, we as a tool won't know to
				 * expect it.
				 */
				if (ipmiconsole_ctx_errnum(ictx) == IPMICONSOLE_ERR_SOL_STOLEN) {
					eprintf("%s\n", ipmiconsole_ctx_errormsg (ictx));
					ret = -1;
				} else if (ipmiconsole_ctx_errnum(ictx) != IPMICONSOLE_ERR_SUCCESS) {
					eprintf("SOL session failed: %s\n", ipmiconsole_ctx_errormsg (ictx));
					ret = -1;
				}
				goto exit;
			}

			/* copy data (cd -> fd) */
			if (write (fd, buf, n) != n) {
				eprintf("Sending data to output failed\n");
				ret = -1;
				goto exit;
			}
		}
	}

exit:
	if (cd > 0) {
		close(cd);
		dprintf(D_L0, "IPMI connection closed\n");
	}
	return ret;

}
