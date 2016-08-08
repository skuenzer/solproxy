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
#include <getopt.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "solproxy.h"
#include "solsession.h"

volatile unsigned int sigterm = 0x0;
unsigned int verbosity = 0x0;


/******************************************************************************
 * SIGNAL HANDLING                                                            *
 ******************************************************************************/
static void sigterm_handler(int signal, siginfo_t *_unused, void *_unused2)
{
	sigterm = 1;
}


void set_sigterm_handler(int type)
{
	struct sigaction sig_action;

	sigemptyset(&sig_action.sa_mask);
	sig_action.sa_sigaction = &sigterm_handler;
	sig_action.sa_flags = type;
	sigaction(SIGQUIT, &sig_action, NULL);
	sigaction(SIGTERM, &sig_action, NULL);
	sigaction(SIGINT,  &sig_action, NULL);
}


/******************************************************************************
 * ARGUMENT PARSING                                                           *
 ******************************************************************************/
const char *short_opts = "h?vVu:p:L:w:";

static struct option long_opts[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"version",	no_argument,		NULL,	'V'},
	{"verbose",	no_argument,		NULL,	'v'},
	{"user",	required_argument,	NULL,	'u'},
	{"password",	required_argument,	NULL,	'p'},
	{"port",	required_argument,	NULL,	'L'},
	{"workaround",	required_argument,	NULL,	'w'},
	{NULL, 0, NULL, 0} /* end of list */
};

static void print_version()
{
	printf("SOLproxy (build: %s %s)\n", __DATE__, __TIME__);
}

static void print_usage(char *argv0)
{
	printf("Usage: %s [OPTION]... [IPMI HOST]\n", argv0);
	printf("Tunnels serial over LAN (SOL) traffic through an TCP socket.\n");
	printf("The programs establishes a connection to the remote IPMI host\n");
	printf("whenever a connection was established to the TCP socket.\n");
	printf("\n");
	printf("Mandatory arguments to long options are mandatory for short options too.\n");
	printf("  -h, --help                 display this help and exit\n");
	printf("  -V, --version              display program version and exit\n");
	printf("  -v, --verbose              increase verbosity level (max. %d times)\n", D_MAX);
	printf("  -u, --user [NAME]          User name for IPMI login\n");
	printf("  -p, --password [PASSWORD]  Password for IPMI login\n");
	printf("  -L, --port [NUMBER]        Listen on port NUMBER (default: %u)\n", LISTEN_PORT);
	printf("  -w, --workaround [FLAG]    Enable a workaround flag, e.g.,\n"
	       "                              intel2, supermicro2, sun2\n");
	printf("\n");
	printf("Example:\n");
	printf("  # Start proxy\n");
	printf("  %s -u ADMIN -p ADMIN -w supermicro2 ipmihost.localdomain\n", argv0);
	printf("  # Connect to the proxy with telnet\n");
	printf("  telnet localhost %u\n", LISTEN_PORT);
}


static void parse_args_setval_str(char** target, const char* value)
{
	if (*target)
		free(*target);
	*target = strdup(value);
	if (!*target)
		die();
}

static int parse_args_setval_int(int* target, const char* value)
{
	if (sscanf(optarg, "%d", target) != 1)
		return -EINVAL;
	return 0;
}

static void clear_args(struct args *args)
{
	if (args->hostname)
		free(args->hostname);

	if (args->config.k_g)
		free(args->config.k_g);
	if (args->config.password)
		free(args->config.password);
	if (args->config.username)
		free(args->config.username);

	memset(args, 0, sizeof(*args));
}

static int parse_args(int argc, char **argv, struct args *args)
/*
 * Parse arguments on **argv (number of args on argc)
 * with GNUOPTS to *args
 *
 * This function will exit the program for itself
 * when -h or -V is parsed or a fatal error happens
 * (such as ENOMEM)
 *
 * -EINVAL will be returned on parsing errors or
 * invalid options
 *
 * *args has to be passed in a cleared state
 */
{
	int opt, opt_index = 0;

	/*
	 * set default values
	 */
	args->listen_port = LISTEN_PORT;

	args->config.workaround_flags = 0;
	/*
	 * IPMICONSOLE_WORKAROUND_AUTHENTICATION_CAPABILITIES
	 * IPMICONSOLE_WORKAROUND_INTEL_2_0_SESSION
	 * IPMICONSOLE_WORKAROUND_SUPERMICRO_2_0_SESSION
	 * IPMICONSOLE_WORKAROUND_SUN_2_0_SESSION
	 * IPMICONSOLE_WORKAROUND_OPEN_SESSION_PRIVILEGE
	 * IPMICONSOLE_WORKAROUND_NON_EMPTY_INTEGRITY_CHECK_VALUE
	 * IPMICONSOLE_WORKAROUND_IGNORE_SOL_PAYLOAD_SIZE
	 * IPMICONSOLE_WORKAROUND_IGNORE_SOL_PORT
	 * IPMICONSOLE_WORKAROUND_SKIP_SOL_ACTIVATION_STATUS
	 */
	args->config.cipher_suite_id = 3;
	/*
	 * 0 - Authentication Algorithm = None; Integrity Algorithm = None; Confidentiality Algorithm = None
	 * 1 - Authentication Algorithm = HMAC-SHA1; Integrity Algorithm = None; Confidentiality Algorithm = None
	 * 2 - Authentication Algorithm = HMAC-SHA1; Integrity Algorithm = HMAC-SHA1-96; Confidentiality Algorithm = None
	 * 3 - Authentication Algorithm = HMAC-SHA1; Integrity Algorithm = HMAC-SHA1-96; Confidentiality Algorithm = AES-CBC-128
	 * 6 - Authentication Algorithm = HMAC-MD5; Integrity Algorithm = None; Confidentiality Algorithm = None
	 * 7 - Authentication Algorithm = HMAC-MD5; Integrity Algorithm = HMAC-MD5-128; Confidentiality Algorithm = None
	 * 8 - Authentication Algorithm = HMAC-MD5; Integrity Algorithm = HMAC-MD5-128; Confidentiality Algorithm = AES-CBC-128
	 * 11 - Authentication Algorithm = HMAC-MD5; Integrity Algorithm = MD5-128; Confidentiality Algorithm = None
	 * 12 - Authentication Algorithm = HMAC-MD5; Integrity Algorithm = MD5-128; Confidentiality Algorithm = AES-CBC-128
	 * 17 - Authentication Algorithm = HMAC-SHA256; Integrity Algorithm = HMAC_SHA256_128; Confidentiality Algorithm = AES-CBC-128
	 */
	args->config.k_g_len = 0;
	args->config.privilege_level = IPMICONSOLE_PRIVILEGE_USER;
	/*
	 * IPMICONSOLE_PRIVILEGE_USER
	 * IPMICONSOLE_PRIVILEGE_OPERATOR
	 * IPMICONSOLE_PRIVILEGE_ADMIN
	 */
	args->engine.behavior_flags = 0;
	/*
	 * IPMICONSOLE_BEHAVIOR_ERROR_ON_SOL_INUSE
	 * IPMICONSOLE_BEHAVIOR_DEACTIVATE_ONLY
	 */
	args->engine.debug_flags = 0;
	/*
	 * IPMICONSOLE_DEBUG_STDOUT
	 * IPMICONSOLE_DEBUG_STDERR
	 * IPMICONSOLE_DEBUG_SYSLOG
	 * IPMICONSOLE_DEBUG_FILE
	 * IPMICONSOLE_DEBUG_IPMI_PACKETS
	 */
	args->engine.engine_flags = 0;
	/*
	 * IPMICONSOLE_ENGINE_SERIAL_KEEPALIVE
	 * IPMICONSOLE_ENGINE_SERIAL_KEEPALIVE_EMPTY
	 * IPMICONSOLE_ENGINE_LOCK_MEMORY
	 */

	args->protocol.acceptable_packet_errors_count = -1;
	args->protocol.keepalive_timeout_len = -1;
	args->protocol.maximum_retransmission_count = -1;
	args->protocol.retransmission_backoff_count = -1;
	args->protocol.retransmission_keepalive_timeout_len = -1;
	args->protocol.retransmission_timeout_len = 500;
	args->protocol.session_timeout_len = 60000;

	/*
	 * Parse options
	 */
	for(;;) {
		opt = getopt_long(argc, argv, short_opts, long_opts, &opt_index);

		if (opt == -1)    /* end of options */
			break;

		switch (opt) {
		case 'h':
		case '?': /* usage */
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);

		case 'V': /* version */
			print_version();
			exit(EXIT_SUCCESS);
		case 'v': /* verbosity */
			if (verbosity < D_MAX)
				verbosity++;
			if (verbosity == D_MAX)
				args->engine.debug_flags = IPMICONSOLE_DEBUG_STDERR;
			break;
		case 'u': /* user */
			parse_args_setval_str(&args->config.username, optarg);
			break;
		case 'p': /* passwd */
			parse_args_setval_str(&args->config.password, optarg);
			break;
		case 'L': /* listen_port */
			if (parse_args_setval_int(&args->listen_port, optarg) < 0) {
				eprintf("Specified listen port is invalid\n");
				return -EINVAL;
			}
			break;
		case 'w': /* worksaround */
			if (strcmp("intel2", optarg) == 0) {
				args->config.workaround_flags |= IPMICONSOLE_WORKAROUND_INTEL_2_0_SESSION;
			} else if (strcmp("supermicro2", optarg) == 0) {
				args->config.workaround_flags |= IPMICONSOLE_WORKAROUND_SUPERMICRO_2_0_SESSION;
			} else if (strcmp("sun2", optarg) == 0) {
				args->config.workaround_flags |= IPMICONSOLE_WORKAROUND_SUN_2_0_SESSION;
			} else {
				eprintf("Unknown workaround flag: %s\n", optarg);
				return -EINVAL;
			}
			break;
		default:
			eprintf("Unrecognized option\n");
			return -EINVAL;
		}
	}

	/* extra parameter available? */
	if (argc <= optind) {
		eprintf("IPMI host not specified.\n");
		return -EINVAL;
	}

	parse_args_setval_str(&args->hostname, argv[optind]);
	return 0;
}


/******************************************************************************
 * MAIN                                                                       *
 ******************************************************************************/
int main(int argc, char **argv)
{
	struct args args;
	struct sockaddr_in local_addr;
	struct sockaddr_in remote_addr;
	socklen_t remote_addr_len = sizeof(remote_addr_len);
	int listen_s, connection_s;
	int ret = 0;

	/*
	 * Signal handling
	 */
	set_sigterm_handler(SHT_RESTART);

	/*
	 * ARGUMENT PARSING
	 */
	memset(&args, 0, sizeof(args));
	memset(&local_addr, 0, sizeof(local_addr));
	memset(&remote_addr, 0, sizeof(remote_addr));
	if (parse_args(argc, argv, &args) < 0)
		exit(EXIT_FAILURE);
	if (verbosity > 0) {
		print_version();
		printf("Verbosity increased to level %d\n", verbosity);
	}
	printvar(args.listen_port, "%x");
	printvar(args.hostname, "%s");
	printvar(args.config.cipher_suite_id, "%x");
	printvar(args.config.k_g, "%s");
	printvar(args.config.k_g_len, "%x");
	printvar(args.config.password, "%s");
	printvar(args.config.privilege_level, "%x");
	printvar(args.config.username, "%s");
	printvar(args.config.workaround_flags, "%x");
	printvar(args.engine.behavior_flags, "%x");
	printvar(args.engine.debug_flags, "%x");
	printvar(args.engine.engine_flags, "%x");
	printvar(args.protocol.acceptable_packet_errors_count, "%x");
	printvar(args.protocol.keepalive_timeout_len, "%x");
	printvar(args.protocol.maximum_retransmission_count, "%x");
	printvar(args.protocol.retransmission_backoff_count, "%x");
	printvar(args.protocol.retransmission_keepalive_timeout_len, "%x");
	printvar(args.protocol.retransmission_timeout_len, "%x");
	printvar(args.protocol.session_timeout_len, "%x");

	/*
	 * MAIN
	 */
	dprintf(D_L1, "Initializing IPMI console engine...\n");
	if (ipmiconsole_engine_init(1, args.engine.debug_flags) < 0)
		dief("Could not initialize IPMI console engine: %s\n", strerror(errno));
	listen_s = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_s < 0)
		dief("Could not open listening socket: %s\n", strerror(errno));
	local_addr.sin_family		= AF_INET;
	local_addr.sin_addr.s_addr	= INADDR_ANY;
	local_addr.sin_port		= htons(args.listen_port);
	if (bind(listen_s, (struct sockaddr *) &local_addr, sizeof(local_addr)) < 0)
		dief("Could not bind socket: %s\n", strerror(errno));

	/*
	 * MAIN
	 */
	dprintf(D_L1, "Entering proxy loop...\n");
	for (;;) {
		listen(listen_s, 1);	/* accept 1 connection */
		dprintf(D_L0, "Listening on %s:%d...\n", inet_ntoa(local_addr.sin_addr), ntohs(local_addr.sin_port));

		set_sigterm_handler(SHT_INTR);
		connection_s = accept(listen_s, (struct sockaddr *) &remote_addr, &remote_addr_len);
		if (sigterm)
			break;
		if (connection_s < 0) {
			fatalf("Could not accept incoming connection: %s\n", strerror(errno));
			return -1;
		}
		set_sigterm_handler(SHT_RESTART);
		dprintf(D_L0, "Connection from %s\n", inet_ntoa(remote_addr.sin_addr));

		ret = solsession(&args, connection_s);
		if (ret < 0)
		  dprintf(D_L0, "Session terminated with error: %d\n", ret);
		dprintf(D_L0, "Connection closed\n");
		close(connection_s);

		/*
		 * ToDo:
		 *  Implement distinction of SIGPIPE signal between closed TCP
		 *  socket by foreign host and broken stdout, stderr
		 */
		if (sigterm)
			break;
	}
	dprintf(D_L1, "Proxy stopped\n");

	/*
	 * EXIT
	 */
	close(listen_s);
	ipmiconsole_engine_teardown(1);
	dprintf(D_L1, "IPMI console engine stopped\n");

	clear_args(&args);
	if (ret < 0)
		exit(EXIT_FAILURE);
	else
		exit(EXIT_SUCCESS);
}
