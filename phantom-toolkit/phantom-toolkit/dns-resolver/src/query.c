/* query.c — UDP query with TCP fallback */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/dns.h"

char g_nameserver[64] = "8.8.8.8";
int  g_use_tcp        = 0;
int  g_verbose        = 0;
int  g_json           = 0;
int  g_short_output   = 0;
int  g_trace          = 0;

static uint16_t g_query_id = 1;

static long ms_diff(struct timespec *a, struct timespec *b) {
    return (b->tv_sec - a->tv_sec) * 1000 +
           (b->tv_nsec - a->tv_nsec) / 1000000;
}

static int query_udp(const char *server, const uint8_t *qbuf, int qlen,
                     uint8_t *rbuf, int rbuflen) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { DNS_TIMEOUT_SEC, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in srv = {0};
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons(DNS_PORT);
    inet_pton(AF_INET, server, &srv.sin_addr);

    for (int i = 0; i < DNS_RETRIES; i++) {
        if (sendto(fd, qbuf, (size_t)qlen, 0,
                   (struct sockaddr *)&srv, sizeof(srv)) < 0) continue;
        ssize_t n = recvfrom(fd, rbuf, (size_t)rbuflen, 0, NULL, NULL);
        if (n > 0) { close(fd); return (int)n; }
    }
    close(fd);
    return -1;
}

static int query_tcp(const char *server, const uint8_t *qbuf, int qlen,
                     uint8_t *rbuf, int rbuflen) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv = { DNS_TIMEOUT_SEC, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in srv = {0};
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(DNS_PORT);
    inet_pton(AF_INET, server, &srv.sin_addr);

    if (connect(fd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        close(fd); return -1;
    }

    /* TCP DNS: 2-byte length prefix */
    uint8_t lenbuf[2] = { (uint8_t)(qlen >> 8), (uint8_t)(qlen & 0xFF) };
    send(fd, lenbuf, 2, 0);
    send(fd, qbuf, (size_t)qlen, 0);

    uint8_t rlen[2];
    if (recv(fd, rlen, 2, MSG_WAITALL) != 2) { close(fd); return -1; }
    int rsize = (rlen[0] << 8) | rlen[1];
    if (rsize <= 0 || rsize > rbuflen) { close(fd); return -1; }

    int got = 0;
    while (got < rsize) {
        int r = (int)recv(fd, rbuf + got, (size_t)(rsize - got), 0);
        if (r <= 0) break;
        got += r;
    }
    close(fd);
    return got;
}

int dns_query(const char *server, const char *name, uint16_t qtype,
              dns_response_t *resp) {
    uint8_t qbuf[DNS_MAX_PKT];
    uint8_t rbuf[DNS_MAX_PKT];

    uint16_t id = g_query_id++;
    int qlen = dns_build_query(qbuf, sizeof(qbuf), name, qtype, id);
    if (qlen < 0) return -1;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int rlen = g_use_tcp
        ? query_tcp(server, qbuf, qlen, rbuf, sizeof(rbuf))
        : query_udp(server, qbuf, qlen, rbuf, sizeof(rbuf));

    clock_gettime(CLOCK_MONOTONIC, &t1);

    if (rlen < 0) return -1;

    /* TC bit set — retry over TCP */
    if (!g_use_tcp && rlen >= 4) {
        uint16_t flags = ntohs(*(uint16_t *)(rbuf + 2));
        if (flags & DNS_TC) {
            if (g_verbose) printf(";; Truncated, retrying over TCP\n");
            rlen = query_tcp(server, qbuf, qlen, rbuf, sizeof(rbuf));
            if (rlen < 0) return -1;
        }
    }

    if (dns_parse_response(rbuf, rlen, resp) < 0) return -1;
    resp->rtt_ms = (int)ms_diff(&t0, &t1);
    return 0;
}
