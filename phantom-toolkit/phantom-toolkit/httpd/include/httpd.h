#ifndef HTTPD_H
#define HTTPD_H

#include <stdint.h>
#include <pthread.h>

#define MAX_HEADERS      64
#define MAX_URI_LEN      8192
#define MAX_HEADER_BLOCK 16384
#define MAX_BODY_LEN     (10*1024*1024)
#define MAX_ROUTES       64
#define BACKLOG          128
#define CONN_TIMEOUT     30

typedef struct {
    char key[256];
    char value[1024];
} http_header_t;

typedef struct {
    char         method[16];
    char         uri[MAX_URI_LEN];
    char         version[16];
    char         path[MAX_URI_LEN];
    char         query[MAX_URI_LEN];
    http_header_t headers[MAX_HEADERS];
    int          nheaders;
    uint8_t     *body;
    int          body_len;
} http_request_t;

typedef struct {
    int     status;
    char    content_type[128];
    uint8_t *body;
    int     body_len;
    int     free_body;
} http_response_t;

typedef struct {
    int    port;
    char   root[512];
    int    max_threads;
    char   access_log[256];
    int    dir_listing;
} httpd_config_t;

typedef void (*route_handler_t)(const http_request_t *, http_response_t *);

extern httpd_config_t g_httpd_cfg;

/* server.c */
void server_run(void);

/* http_parser.c */
int  parse_request(int fd, http_request_t *req);
void free_request(http_request_t *req);

/* router.c */
void register_route(const char *method, const char *path, route_handler_t fn);
void router_dispatch(int fd, const http_request_t *req);

/* response.c */
void send_response(int fd, int status, const char *ctype,
                   const uint8_t *body, int blen, const char *extra_headers);
void send_file(int fd, const char *path, const http_request_t *req);
void send_error(int fd, int status);

/* mime.c */
const char *mime_type(const char *path);

/* logger.c */
void logger_init(const char *path);
void logger_access(const char *ip, const char *method, const char *uri,
                   int status, int bytes, const char *ua);
void logger_close(void);

#endif /* HTTPD_H */
