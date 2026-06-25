/* http_parser.c — HTTP/1.1 request parser */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/httpd.h"

static int recv_line(int fd, char *buf, int maxlen) {
    int n = 0;
    char c, prev = 0;
    while (n < maxlen - 1) {
        if (recv(fd, &c, 1, 0) <= 0) return -1;
        if (prev == '\r' && c == '\n') { buf[n-1] = '\0'; return n-1; }
        buf[n++] = c;
        prev = c;
    }
    return -1;
}

static void parse_query(http_request_t *req) {
    char *q = strchr(req->uri, '?');
    if (q) {
        strncpy(req->query, q + 1, sizeof(req->query) - 1);
        strncpy(req->path, req->uri, (size_t)(q - req->uri));
        req->path[q - req->uri] = '\0';
    } else {
        strncpy(req->path, req->uri, sizeof(req->path) - 1);
    }
}

/* Reject path traversal */
static int safe_path(const char *path) {
    return strstr(path, "..") == NULL;
}

int parse_request(int fd, http_request_t *req) {
    char line[MAX_URI_LEN + 64];

    /* Request line */
    if (recv_line(fd, line, sizeof(line)) < 0) return -1;
    if (sscanf(line, "%15s %8191s %15s",
               req->method, req->uri, req->version) != 3) return -1;
    if (!safe_path(req->uri)) return -1;
    parse_query(req);

    /* Headers */
    req->nheaders = 0;
    while (1) {
        if (recv_line(fd, line, sizeof(line)) < 0) break;
        if (line[0] == '\0') break;
        char *colon = strchr(line, ':');
        if (!colon || req->nheaders >= MAX_HEADERS) continue;
        *colon = '\0';
        http_header_t *h = &req->headers[req->nheaders++];
        strncpy(h->key,   line,    sizeof(h->key) - 1);
        strncpy(h->value, colon+2, sizeof(h->value) - 1);
    }

    /* Body */
    const char *cl_str = NULL;
    for (int i = 0; i < req->nheaders; i++) {
        if (strcasecmp(req->headers[i].key, "Content-Length") == 0) {
            cl_str = req->headers[i].value;
            break;
        }
    }
    if (cl_str) {
        int clen = atoi(cl_str);
        if (clen > 0 && clen <= MAX_BODY_LEN) {
            req->body = malloc((size_t)clen + 1);
            if (req->body) {
                int got = 0;
                while (got < clen) {
                    int r = (int)recv(fd, req->body + got, (size_t)(clen - got), 0);
                    if (r <= 0) break;
                    got += r;
                }
                req->body[got] = '\0';
                req->body_len  = got;
            }
        }
    }
    return 0;
}

void free_request(http_request_t *req) {
    if (req->body) { free(req->body); req->body = NULL; }
}
