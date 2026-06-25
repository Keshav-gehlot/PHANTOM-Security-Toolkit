/* router.c */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/httpd.h"

typedef struct { char method[16]; char path[256]; route_handler_t fn; } route_t;
static route_t g_routes[MAX_ROUTES];
static int     g_nroutes = 0;

static void health_handler(const http_request_t *req, http_response_t *resp) {
    (void)req;
    const char *body = "{\"status\":\"ok\"}";
    resp->status    = 200;
    resp->body      = (uint8_t *)strdup(body);
    resp->body_len  = (int)strlen(body);
    resp->free_body = 1;
    strncpy(resp->content_type, "application/json", sizeof(resp->content_type)-1);
}

void register_route(const char *method, const char *path, route_handler_t fn) {
    if (g_nroutes >= MAX_ROUTES) return;
    strncpy(g_routes[g_nroutes].method, method, 15);
    strncpy(g_routes[g_nroutes].path,   path,   255);
    g_routes[g_nroutes].fn = fn;
    g_nroutes++;
}

void router_dispatch(int fd, const http_request_t *req) {
    /* Built-in routes */
    if (strcmp(req->path, "/health") == 0) {
        http_response_t resp = {0};
        health_handler(req, &resp);
        send_response(fd, resp.status, resp.content_type,
                      resp.body, resp.body_len, NULL);
        if (resp.free_body) free(resp.body);
        return;
    }
    /* Custom routes */
    for (int i = 0; i < g_nroutes; i++) {
        if (strcmp(g_routes[i].method, req->method) == 0 &&
            strcmp(g_routes[i].path,   req->path  ) == 0) {
            http_response_t resp = {0};
            g_routes[i].fn(req, &resp);
            send_response(fd, resp.status, resp.content_type,
                          resp.body, resp.body_len, NULL);
            if (resp.free_body) free(resp.body);
            return;
        }
    }
    /* Static file serving */
    if (strcmp(req->method, "GET") == 0 || strcmp(req->method, "HEAD") == 0) {
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s%s",
                 g_httpd_cfg.root, req->path);
        send_file(fd, fullpath, req);
        return;
    }
    send_error(fd, 405);
}
