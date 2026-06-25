/* server.c — TCP listener + thread-per-connection */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/httpd.h"

httpd_config_t g_httpd_cfg;

typedef struct { int fd; char ip[INET_ADDRSTRLEN]; } conn_t;

static void *handle_conn(void *arg) {
    conn_t *c = (conn_t *)arg;
    int fd = c->fd;

    /* Connection timeout */
    struct timeval tv = { CONN_TIMEOUT, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    http_request_t req;
    memset(&req, 0, sizeof(req));

    if (parse_request(fd, &req) == 0) {
        router_dispatch(fd, &req);
    } else {
        send_error(fd, 400);
    }

    free_request(&req);
    close(fd);
    free(c);
    return NULL;
}

void server_run(void) {
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); exit(1); }

    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)g_httpd_cfg.port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(srv, BACKLOG) < 0) {
        perror("listen"); exit(1);
    }

    signal(SIGPIPE, SIG_IGN);
    printf("\033[1;33m[HTTPD]\033[0m Listening on port %d, root=%s\n",
           g_httpd_cfg.port, g_httpd_cfg.root);

    while (1) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int fd = accept(srv, (struct sockaddr *)&cli, &cli_len);
        if (fd < 0) continue;

        conn_t *c = malloc(sizeof(conn_t));
        if (!c) { close(fd); continue; }
        c->fd = fd;
        inet_ntop(AF_INET, &cli.sin_addr, c->ip, sizeof(c->ip));

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, handle_conn, c);
        pthread_attr_destroy(&attr);
    }
    close(srv);
}
