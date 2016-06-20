ipvd
====

IP via DNS (ipvd) is a DNS server that returns the querying client's IP address
as an "A" record for IPv4 clients and as an "AAAA" record for IPv6 clients. The
contents of the DNS request is mostly irrelevant. As long as it contains no
more than a single, valid question, the ipvd server should respond.

To build the binary, run `make` in the root of this repository which will
create an executable named "ipvd". The ipvd server has been succesfully tested
on Linux and OpenBSD 5.9.

Example
-------

Running the server:

    ipvd$ sudo ./ipvd -u "$(id -u nobody)"
    2016-06-14T21:16:09-0700 Now bound to port 53
    2016-06-14T21:16:09-0700 Dropped privileges; now running as UID 65534
    2016-06-14T21:16:09-0700 Now accepting DNS requests
    2016-06-14T21:16:20-0700 Received 30B from ::1
    2016-06-14T21:16:20-0700 Sending 47B response

Querying the server:

    ~$ dig x @localhost

    ; <<>> DiG 9.9.5-9+deb8u6-Debian <<>> x @localhost
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54679
    ;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; WARNING: recursion requested but not available

    ;; QUESTION SECTION:
    ;x.                             IN      A

    ;; ANSWER SECTION:
    x.                      0       IN      AAAA    ::1

    ;; Query time: 0 msec
    ;; SERVER: ::1#53(::1)
    ;; WHEN: Tue Jun 14 21:16:20 PDT 2016
    ;; MSG SIZE  rcvd: 47

A sample shell script is provided for running ipvd inside a chroot. It depends
on the non-POSIX commands `chroot(8)` and `mktemp(1)`. The following is an
example of the script executed on Linux using sudo:

    $ sudo ./run-in-chroot.sh -u "$(id -u nobody)"
    [sudo] password for ...:
    2016-06-20T06:08:25+0000 Now bound to port 53
    2016-06-20T06:08:25+0000 Dropped privileges; now running as UID 65534
    2016-06-20T06:08:25+0000 Now accepting DNS requests

In this example, the script is executed on OpenBSD after assuming the role of
the super user:

    $ su
    Password:
    # ./run-in-chroot.sh -u "$(id -u nobody)"
    2016-06-19T23:47:06+0000 Now bound to port 53
    2016-06-19T23:47:06+0000 Dropped privileges; now running as UID 32767
    2016-06-19T23:47:06+0000 Now accepting DNS requests

Any arguments passed to the script will be passed directly to the ipvd binary.

Options
-------

- -h: Show this text and exit.
- -0: Bind to any interface available.
- -4: Only bind to IPv4 interfaces.
- -6: Only bind to IPv6 interfaces.
- -l HOSTNAME: Bind to associated with specified hostname.
- -p PORT: Bind to specific port. Defaults to 53.
- -u UID: After binding to network, call setuid(UID).

Exit Statuses
-------------

- 1: Fatal error encountered during initialization.
- 2: Fatal error encountered while attempting process a packet.
