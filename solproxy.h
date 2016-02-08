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
#ifndef SOLPROXY_H
#define SOLPROXY_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipmiconsole.h>

#define min(a, b) \
	({ __typeof__ (a) __a = (a); \
	   __typeof__ (b) __b = (b); \
	   __a < __b ? __a : __b; })
#define max(a, b) \
	({ __typeof__ (a) __a = (a); \
	   __typeof__ (b) __b = (b); \
	   __a > __b ? __a : __b; })

#define LISTEN_PORT	6023

struct args {
	int listen_port;
	char* hostname;
	struct ipmiconsole_ipmi_config config;
	struct ipmiconsole_protocol_config protocol;
	struct ipmiconsole_engine_config engine;
};

extern volatile unsigned int sigterm;
extern unsigned int verbosity;

/*
 * Signal handling
 */
#define SHT_INTR	(SA_SIGINFO)			/* interruptible system calls on signals */
#define SHT_RESTART	(SA_SIGINFO | SA_RESTART)	/* noninterruptible system calls on signals */

void set_sigterm_handler(int type);	/* (re-)registers sigterm handler */

/*
 * Print helpers
 */
#define D_L0		1
#define D_L1		2
#define D_L2		3
#define D_MAX		D_L2

#define eprintf(...)		fprintf(stderr, __VA_ARGS__)
#define fatalf(...) \
	do { \
		eprintf(__VA_ARGS__); \
	} while(0)
#define fatal()		fatalf("%s\n", strerror(errno))
#define dief(...) \
	do { fatalf(__VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while(0)
#define die() \
	do { \
		fatal(); \
		exit(EXIT_FAILURE); \
	} while(0)
#define dprintf(lvl, ...) \
	do { \
		if (verbosity >= lvl) \
			fprintf(stdout, __VA_ARGS__); \
	} while(0)
#define printvar(var, fmt) \
	do { \
		if (verbosity >= D_MAX) \
			printf(#var ": "#fmt"\n", var); \
	} while(0)

#endif /* SOLPROXY_H */
