/**
 * This is a DNS server that returns the IP address of a client querying it.
 * Refer to the "usage" function for more information.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

void close_server_socket(void);
void log_printf(const char *, ...);
int main(int, char **);
void usage(char *);

#define SIZEOF_LONGEST_UDP_PACKET 65535

#define DNS_DEFAULT_PORT 53

#define DNS_OPCODE_BITMASK 0x78

#define IPV4_MAPPED_IPV6_ADDR_PREFIX \
    ((uint8_t []) {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255})

/**
 * Convert an expression a string literal after performing macro expansion.
 *
 * @param expression Expression to be represented as a string.
 *
 * @return String literal
 */
#define STRINGIFY_AFTER_EXPANSION(expression) STRINGIFY(expression)

/**
 * Convert an expression a string literal.
 *
 * @param expression Expression to be represented as a string.
 *
 * @return String literal
 */
#define STRINGIFY(expression) #expression

/**
 * Return a non-zero value if the given address is an IPv4-mapped IPv6 address
 * and zero otherwise.
 *
 * @param addr Populated instance of `struct sockaddr_in6`.
 *
 * @return Value indicating if `addr` represents  an IPv4-mapped IPv6 address.
 */
#define IS_IPV4_ADDR(addr) (!memcmp(&addr.sin6_addr.s6_addr[0], \
    &(IPV4_MAPPED_IPV6_ADDR_PREFIX), sizeof(IPV4_MAPPED_IPV6_ADDR_PREFIX)))

/**
 * Works like perror(3) but prepends a timestamp to the error message and also
 * writes to stdout instead of stderr.
 */
#define log_perror(prefix) log_printf("%s: %s", prefix, strerror(errno))

/**
 * Works like puts(3) but prepends a timestamp to the text.
 */
#define log_puts(text) log_printf(text)

/**
 * DNS response codes.
 */
typedef enum {
    RCODE_NO_ERROR = 0,
    RCODE_FORMAT_ERROR = 1,
    RCODE_NOT_IMPLEMENTED = 4,
    RCODE_REFUSED = 5,
} rcode_et;

/**
 * Socket file descriptor used by the server.
 */
static int sockfd = -1;

/**
 * Display application usage information.
 *
 * @param self Name or path of compiled executable.
 */
void usage(char *self)
{
    printf(
        "Usage: %s [OPTION...]\n"
        "\n"
        "This is a DNS server that returns the querying client's IP address "
        "as an \"A\"\nrecord for IPv4 clients and as an \"AAAA\" record for "
        "IPv6 clients.\n"
        "\n"
        "Exit statuses:\n"
        " 1     Fatal error encountered during initialization.\n"
        " 2     Fatal error encountered while attempting process a packet.\n"
        "\n"
        "Options:\n"
        " -h             Show this text and exit.\n"
        " -0             Bind to any interface available.\n"
        " -4             Only bind to IPv4 interfaces.\n"
        " -6             Only bind to IPv6 interfaces.\n"
        " -l HOSTNAME    Bind to associated with specified hostname.\n"
        " -p PORT        Bind to specific port. Defaults to 53.\n"
        " -u UID         After binding to network, call setuid(UID).\n"
        , self
    );
}

/**
 * Close the server socket file descriptor.
 */
void close_server_socket(void)
{
    close(sockfd);
}

/**
 * Works like printf(3) but prepends a timestamp to the text, always adds a
 * trailing newline and does not return a value.
 *
 * @param format C printf format string.
 * @param ... Values to be formatted and displayed.
 */
#ifdef __GNUC__
// Used to silence "format string is not a string literal" warnings on
// GCC-compatible compilers.
__attribute__((__format__(__printf__, 1, 0)))
#endif
void log_printf(const char *format, ...)
{
    va_list argument_ptr;
    struct tm *now;
    time_t current_time = time(NULL);
    int status;
    char timestamp[26]; // Length of ISO8601 timestamp plus space and null.

    if (!(now = localtime(&current_time))) {
        perror("localtime");
        return;
    } else if (!strftime(timestamp, sizeof(timestamp),
      "%Y-%m-%dT%H:%M:%S%z ", now)) {
        return;
    } else if ((status = fputs(timestamp, stdout)) < 0) {
        return;
    }

    va_start(argument_ptr, format);
    status = vprintf(format, argument_ptr);
    va_end(argument_ptr);

    if (status < 0) {
        return;
    }

    putchar('\n');
}

int main(int argc, char **argv)
{
    struct sockaddr *clientaddr;
    char client_ip[INET6_ADDRSTRLEN];
    uint8_t *cursor;
    int gaierr;
    const char *error;
    int i;
    int option;
    ssize_t packet_size;
    long int long_int;
    struct sockaddr_in ipv4_client;
    struct sockaddr_in6 ipv6_client;
    int is_ipv4_client;
    rcode_et rcode;
    uint8_t recv_packet_buf[SIZEOF_LONGEST_UDP_PACKET];
    uint8_t reply_packet_buf[SIZEOF_LONGEST_UDP_PACKET];
    size_t reply_packet_size;
    struct addrinfo *serveraddr;
    socklen_t sizeof_clientaddr;
    uid_t uid = geteuid();

    struct addrinfo addr_hints = {
        .ai_flags = AI_PASSIVE | AI_NUMERICSERV,
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *addr_res = NULL;
    int errno_copy = 0;
    char *hostname = NULL;
    char *portstr = STRINGIFY_AFTER_EXPANSION(DNS_DEFAULT_PORT);
    int socket_address_family = AF_INET6;

    while ((option = getopt(argc, argv, "+046hl:p:u:")) != -1) {
        switch (option) {
          // Bind to any interface available.
          case '0':
            addr_hints.ai_family = AF_UNSPEC;
            break;

          // Only bind to IPv4 interfaces.
          case '4':
            addr_hints.ai_family = AF_INET;
            break;

          // Only bind to IPv6 interfaces.
          case '6':
            addr_hints.ai_family = AF_INET6;
            break;

          // Show help text and exit.
          case 'h':
            usage(argv[0]);
            return 0;

          // Bind to associated with specified hostname.
          case 'l':
            if (strstr(optarg, ":")) {
                addr_hints.ai_family = AF_INET6;
            }
            hostname = optarg;
            break;

          // Bind to specific port. Defaults to 53.
          case 'p':
            errno = 0;
            long_int = strtol(optarg, NULL, 10);
            if (errno) {
                perror("Invalid port argument");
                return 1;
            } else if (long_int < 1 || long_int > 65535) {
                fprintf(stderr, "Port must be an integer from 1 to 65535.\n");
                return 1;
            }
            portstr = optarg;
            break;

          // After binding to network, call setuid(...).
          case 'u':
            errno = 0;
            long_int = strtol(optarg, NULL, 10);
            if (errno) {
                perror("Invalid UID argument");
                return 1;
            } else if (long_int < 0) {
                fprintf(stderr, "UID number is out of bounds.\n");
                return 1;
            }
            uid = (uid_t) long_int;
            break;

          case '+':
            // Using "+" to ensure POSIX-style argument parsing is a GNU
            // extension, so an explicit check for "+" as a flag is added for
            // other getopt(3) implementations.
            fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], option);
          default:
            return 1;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected command line parameters.\n");
        return 1;
    }

    // Configure protocol version-specific parameters.
    if (addr_hints.ai_family == AF_INET) {
        socket_address_family = AF_INET;
        clientaddr = (struct sockaddr *) &ipv4_client;
    } else {
        socket_address_family = AF_INET6;
        clientaddr = (struct sockaddr *) &ipv6_client;
    }

    if ((sockfd = socket(socket_address_family, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        return 1;
    } else {
        atexit(close_server_socket);
    }

    // Query the system for suitable hosts to bind to.
    if ((gaierr = getaddrinfo(hostname, portstr, &addr_hints, &addr_res))) {
        error = gai_strerror(gaierr);
        if (hostname) {
            fprintf(stderr, "Could not resolve \"%s\": %s\n", hostname, error);
        } else {
            fprintf(stderr, "Could not find network interface: %s\n", error);
        }
        return 1;
    }

    // Attempt to bind to every host returned.
    for (serveraddr = addr_res; serveraddr; serveraddr = serveraddr->ai_next) {
        if (!bind(sockfd, (struct sockaddr *) serveraddr->ai_addr,
          serveraddr->ai_addrlen)) {
            if (hostname) {
                log_printf("Now bound to port %s on %s", portstr, hostname);
            } else {
                log_printf("Now bound to port %s", portstr);
            }
            break;
        }
        errno_copy = errno;
    }

    freeaddrinfo(addr_res);

    if (!serveraddr) {
        errno = errno_copy;
        perror("Could not bind server to socket");
        return 1;
    }

    // Drop priveles if the UID given differs from the effective UID.
    if (geteuid() != uid) {
        while (1) {
            if (setuid(uid)) {
                if (errno != EAGAIN) {
                    perror("setuid");
                    return 1;
                }
            } else {
                break;
            }
        }
        log_printf("Dropped privileges; now running as UID %u", uid);
    }

    log_puts("Now accepting DNS requests");
    while (1) {
        if (socket_address_family == AF_INET) {
            sizeof_clientaddr = sizeof(ipv4_client);
        } else if (socket_address_family == AF_INET6) {
            sizeof_clientaddr = sizeof(ipv6_client);
        }

        if ((packet_size = recvfrom(sockfd, recv_packet_buf,
          sizeof(recv_packet_buf), 0, clientaddr, &sizeof_clientaddr)) == -1) {

            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }
            log_perror("Fatal error (recvfrom)");
            return 2;
        }

        if (socket_address_family == AF_INET) {
            if (sizeof_clientaddr > sizeof(ipv4_client)) {
                log_puts("Fatal error: client address unexpectedly truncated");
                return 2;
            }

            if (!inet_ntop(ipv4_client.sin_family, &ipv4_client.sin_addr,
              client_ip, sizeof(client_ip))) {
                log_perror("Fatal error (inet_ntop)");
                return 2;
            }
        } else if (socket_address_family == AF_INET6) {
            if (sizeof_clientaddr > sizeof(ipv6_client)) {
                log_puts("Fatal error: client address unexpectedly truncated");
                return 2;
            }

            if (!inet_ntop(ipv6_client.sin6_family, &ipv6_client.sin6_addr,
              client_ip, sizeof(client_ip))) {
                log_perror("Fatal error (inet_ntop)");
                return 2;
            }
        }

        log_printf("Received %lluB from %s", packet_size, client_ip);

        if (packet_size < 19) {
            // Header:         12B
            // Question (1):    3B (label)
            //                  2B (type)
            //                  2B (class)
            //                 ---
            // Total:          19B
            log_puts("Packet is too small to be valid and will be ignored");
            continue;
        }

        // DNS Response Header
        // ===================
        //
        //                                 1  1  1  1  1  1
        //   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      ID                       |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // Copy message ID from incoming packet.
        cursor = &reply_packet_buf[0];
        (*cursor++) = recv_packet_buf[0];
        (*cursor++) = recv_packet_buf[1];

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 1| 0  0  0  0| 0| 0| 1| 0| 0  0  0| ?  ?  ?  ?|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // Create reply header and specific that recursion is not supported.
        // The response code is initially left empty but will be changed if an
        // exceptional state arises later.
        (*cursor++) = 0x81;
        (*cursor++) = 0x00;

        if (packet_size > 273) {
            // There's no reason for this server to accept multiple queries
            // from a single client since it only provides a single answer.
            //
            // Header:         12B
            // Question (1):  257B (label)
            //                  2B (type)
            //                  2B (class)
            //                 ---
            // Total:         273B
            log_puts("Refusing to process suspiciously large packet");
            rcode = RCODE_REFUSED;
            goto send_packet;
        } else if ((recv_packet_buf[2] & DNS_OPCODE_BITMASK)) {
            // The server only supports standard queries (opcode value 0).
            log_puts("Received unsupported opcode");
            rcode = RCODE_NOT_IMPLEMENTED;
            goto send_packet;
        } else {
            rcode = RCODE_NO_ERROR;
        }

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    QDCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ANCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // Only one question will be answered regardless of how many were
        // received.
        (*cursor++) = 0x00;
        (*cursor++) = 0x01;

        (*cursor++) = 0x00;
        (*cursor++) = 0x01;

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    NSCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                    ARCOUNT                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // No NS or AR type records will ever be returned, so the count for
        // both fields is 0.
        (*cursor++) = 0x00;
        (*cursor++) = 0x00;

        (*cursor++) = 0x00;
        (*cursor++) = 0x00;

        // DNS Query Question
        // ==================
        //
        // Extract the question from the client's request with a light amount
        // of validation.
        for (i = 12; i < packet_size; i++) {
            // Extract the label up to and including the null byte.
            if (((*cursor++) = recv_packet_buf[i]) == 0) {
                if ((i <= 13) || ((i + 4) >= packet_size)) {
                    log_puts("Format error: question field is malformed");
                    rcode = RCODE_FORMAT_ERROR;
                    goto send_packet;
                }

                // After reaching the end of the label, copy the next four
                // bytes that make up the type and class.
                (*cursor++) = recv_packet_buf[i + 1];
                (*cursor++) = recv_packet_buf[i + 2];
                (*cursor++) = recv_packet_buf[i + 3];
                (*cursor++) = recv_packet_buf[i + 4];
                break;
            }
        }

        if (socket_address_family == AF_INET) {
            is_ipv4_client = 1;
        } else {
            is_ipv4_client = IS_IPV4_ADDR(ipv6_client);
        }

        // DNS Query Answer
        // ================
        //
        //                                  1  1  1  1  1  1
        //    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                                               |
        // /                                               /
        // /                      NAME                     /
        // |                                               |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        // | 1  1  0  0  0  0  0  0  0  0  0  0  1  1  0  0|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // RFC 1035, the DNS spec, allows answers to provide byte offsets
        // pointing to a label to eliminate redundancy in replies and reduce
        // the packet size. The first two bits of the name field indicate that
        // the field is a pointer instead of a label, and the remaining bits
        // are the byte offset within the packet of that label. The client's
        // question, which will include a label, will always be at an offset of
        // 12 bytes which is hardcoded here in the second octet.
        (*cursor++) = 0xc0;
        (*cursor++) = 0x0c;

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      TYPE                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  ?  ?  ?  ?  ?  ?  ?  ?|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // For "A" records, the type is 1 (0x0001), and the for "AAAA" records,
        // it is 28 (0x001C).
        (*cursor++) = 0x00;
        (*cursor++) = is_ipv4_client ? 0x01 : 0x1c;

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                     CLASS                     |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  1|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // Class IN (internet).
        (*cursor++) = 0x00;
        (*cursor++) = 0x01;

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                      TTL                      |
        // |                                               |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0|
        // | 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // No caching (TTL of 0 seconds).
        (*cursor++) = 0x00;
        (*cursor++) = 0x00;
        (*cursor++) = 0x00;
        (*cursor++) = 0x00;

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // |                   RDLENGTH                    |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 0  0  0  0  0  0  0  0  0  0  0  ?  ?  ?  ?  ?|
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // "A" records span 4 bytes, and "AAAA" records span 16 bytes.
        (*cursor++) = 0x00;
        (*cursor++) = is_ipv4_client ? 0x04 : 0x10;

        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        // /                     RDATA                     /
        // /                                               /
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // / ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?  ?/
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        //
        // Copy the bytes representing the IP address.
        if (socket_address_family == AF_INET6) {
            for (i = is_ipv4_client ? 12 : 0; i < 16; i++) {
                (*cursor++) = ipv6_client.sin6_addr.s6_addr[i];
            }
        } else {
            memcpy(cursor, &ipv4_client.sin_addr.s_addr, 4);
            cursor += 4;
        }

send_packet:
        if (rcode) {
            // If a problem was encountered, set the rcode value and zero out
            // the next 8 bytes which to indicate that there will be no data
            // after the header.
            cursor = &reply_packet_buf[3];
            (*cursor++) = (uint8_t) rcode;
            for (i = 0; i < 8; i++) {
                (*cursor++) = 0x00;
            }
        }

        reply_packet_size = (size_t) (cursor - &reply_packet_buf[0]);
        log_printf("Sending %lluB response", reply_packet_size);

        while ((sendto(sockfd, &reply_packet_buf, reply_packet_size, 0,
          clientaddr, sizeof_clientaddr)) == -1) {
            if (errno != EINTR) {
                log_perror("Fatal error (sendto)");
                return 2;
            }
        }
    }
}
