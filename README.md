SOLproxy
========

SOLproxy is a TCP proxy application for Serial-over-LAN
(part of recent IPMI, BMC firmwares). It can be used,
for example, to access serial consoles with a reliable
TCP connection (e.g., telnet) or for debugging kernels
remotely (e.g., kgdb).


Prerequisites
-------------

For compiling libipmiconsole is required. It is part of the
FreeIPMI package (http://www.gnu.org/software/freeipmi/).
On Debian/Ubuntu you can install it with:

    apt-get install libipmiconsole-dev libfreeipmi-dev


Compiling
---------

Use make to build SOLproxy:

    make


Running
-------

Run SOLproxy on a machine that has access to the target IPMI
interface:

    ./solproxy -u ADMIN -p ADMIN -L 23 [IPMI HOST]

Connect to the serial console with telnet:

    telnet localhost

In order to get an overview of available options, use
`--help`:

    ./solproxy --help
