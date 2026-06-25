/* connect_scan.c — parallel non-blocking connect() scan */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/scanner.h"

typedef struct {
    uint32_t      ip;
    uint16_t     *ports;
    int           start;
    int           end;
    port_result_t *results;
} scan_task_t;

static void *scan_range(void *arg) {
    scan_task_t *t = (scan_task_t *)arg;
    for (int i = t->start; i < t->end; i++) {
        uint16_t port = t->ports[i];
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        /* Non-blocking */
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr = {0};
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons(port);
        addr.sin_addr.s_addr = t->ip;

        int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (rc == 0) {
            t->results[i].state = STATE_OPEN;
        } else if (errno == EINPROGRESS) {
            struct timeval tv;
            tv.tv_sec  = g_scan_cfg.timeout_ms / 1000;
            tv.tv_usec = (g_scan_cfg.timeout_ms % 1000) * 1000;
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
                int err = 0;
                socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                t->results[i].state = (err == 0) ? STATE_OPEN : STATE_CLOSED;
            } else {
                t->results[i].state = STATE_FILTERED;
            }
        } else {
            t->results[i].state = STATE_CLOSED;
        }
        close(fd);
        t->results[i].port = port;
    }
    free(t);
    return NULL;
}

void connect_scan(uint32_t ip, uint16_t *ports, int nports, port_result_t *results) {
    int chunk = (nports + MAX_THREADS - 1) / MAX_THREADS;
    pthread_t tids[MAX_THREADS];
    int nthr = 0;

    for (int i = 0; i < nports; i += chunk) {
        scan_task_t *t = malloc(sizeof(scan_task_t));
        if (!t) break;
        t->ip      = ip;
        t->ports   = ports;
        t->start   = i;
        t->end     = (i + chunk < nports) ? i + chunk : nports;
        t->results = results;
        if (pthread_create(&tids[nthr], NULL, scan_range, t) == 0)
            nthr++;
        else
            free(t);
    }
    for (int i = 0; i < nthr; i++) pthread_join(tids[i], NULL);
}
