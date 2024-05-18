u-relay-tproxy is an LD_PRELOAD library. It redirects TCP socket connect calls
to other destinations of choice through Unix domain sockets. It can also apply
a Proxy Protocol v2 header in front of the data, which allows the application
on the other end of the Unix domain socket to still be able to read the
original IP address and port number given to the connect() system call.


This is an LD_PRELOAD library, so it will not work with setuid binaries or
statically linked binaries. However, there are a number of ways to get around
this, namely, and this applies to all LD_PRELOAD libraries:
* Run the setuid binary as non-setuid by using `setpriv --no-new-privs`.
 - Note that although e.g. a non-setuid ping binary cannot create a raw ICMP
 socket, it can still obtain the socket through other means, for example, by
 intercepting socket() with the second parameter as SOCK_RAW to instead connect
 to an external daemon and receive the socket through the SCM_RIGHTS control
 message. Not implemented here, but can still be a future idea.
* Applications written in golang (go) can be compiled with gccgo to make a
 dynamically linked executable which uses libc functions to make system calls.
 Such an executable can be used with LD_PRELOAD.

`make PARACONTAINERIZATION=1` makes a "paracontainerzed"
(similar to paravirtualization, but with containers instead of virtual machines)
build of u-relay-tproxy intended to be loaded into a Docker container. It
removes versioning information from some symbols, so that it can still be
compatible with certain container images even if they have older versions of
glibc. This allows a Docker container to run with `--net=none`, then Internet
access can still be made available by way of this LD_PRELOAD library and Unix
domain sockets mounted within a bind mount volume.

Usage:

env LD_PRELOAD=/path/to/liburelay-tproxy.so \
[URELAY_TPROXY_...=...]
[PJTL_GAIHACK_...=...]

The recognized environment variables are:
URELAY_TPROXY_FILE  -- specify a configuration file. Must be in binary form.
                       My miscutils repo contains u-relay-tproxy-asmgen, which
                       can be used to generate this file.
URELAY_TPROXY_LOCAL_FLAGS -- specify a numeric flags word (will be parsed by
                       strtoull(flags, NULL, 0)). bit positions mean:
                       0x10000 ("shutdown hack") - SHUT_RD aliased to SHUT_RDWR
                           in Unix domain sockets, intended for slirp4netns, but
                           doesn't seem to fix the busy loop issue.
                       0x20000 ("fastopen hack") - if a sendmsg/sendto is 
                           attempted with the MSG_FASTOPEN flag set, then it
                           will just return -1 with errno=EPIPE without sending
                           anything. Intended for Unbound DNS server.
                       0x40000 ("getsockname hack") - if a getsockname call
                           returns AF_UNIX, then instead make it return AF_INET6
                           with sin6_addr = :: and sin6_port = 0. Intended for
                           Mozilla Firefox.
                       0x80000 ("GAI hack") - also enable the gai-hack module.
                           Initially a separate library, but is now integrated.
URELAY_TPROXY_IDX_FILES -- IDX_FILES
IDX_FILES := IDX_FILE | IDX_FILE ";" IDX_FILES
IDX_FILE := number "," domain_name | number "=" filename

TODO:
document how to use it with nginx (`use poll` in events, substitute the first 16 bits to link-local prefix).
allow disabling clearing the AI_ADDRCONFIG flag in gai-hack
