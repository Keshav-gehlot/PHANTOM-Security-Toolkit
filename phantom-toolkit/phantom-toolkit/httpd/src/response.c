/* response.c — HTTP response builder */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/socket.h>
#include "../include/httpd.h"

static const char *status_text(int s) {
    switch (s) {
        case 200: return "OK";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        default:  return "Unknown";
    }
}

static void rfc1123_date(char *buf, size_t len) {
    time_t t = time(NULL);
    struct tm *gmt = gmtime(&t);
    strftime(buf, len, "%a, %d %b %Y %H:%M:%S GMT", gmt);
}

void send_response(int fd, int status, const char *ctype,
                   const uint8_t *body, int blen, const char *extra_headers) {
    char date[64];
    rfc1123_date(date, sizeof(date));

    char hdr[2048];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Server: phantom-httpd/1.0\r\n"
        "Date: %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "%s"
        "\r\n",
        status, status_text(status),
        date,
        ctype ? ctype : "application/octet-stream",
        blen,
        extra_headers ? extra_headers : "");

    send(fd, hdr, (size_t)hlen, MSG_NOSIGNAL);
    if (body && blen > 0) {
        int sent = 0;
        while (sent < blen) {
            int r = (int)send(fd, body + sent, (size_t)(blen - sent), MSG_NOSIGNAL);
            if (r <= 0) break;
            sent += r;
        }
    }
    /* Linger so client can drain before FIN */
    struct linger sl = {1, 1};
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
}

void send_file(int fd, const char *path, const http_request_t *req) {
    /* Redirect dir without trailing slash */
    struct stat st;
    if (stat(path, &st) < 0) { send_error(fd, 404); return; }

    char actual[1024];
    strncpy(actual, path, sizeof(actual)-1);
    if (S_ISDIR(st.st_mode)) {
        snprintf(actual, sizeof(actual), "%s/index.html", path);
        if (stat(actual, &st) < 0) { send_error(fd, 403); return; }
    }

    int filefd = open(actual, O_RDONLY);
    if (filefd < 0) { send_error(fd, 404); return; }

    uint8_t *buf = malloc((size_t)st.st_size);
    if (!buf) { close(filefd); send_error(fd, 500); return; }

    ssize_t n = read(filefd, buf, (size_t)st.st_size);
    close(filefd);

    const char *mime = mime_type(actual);
    send_response(fd, 200, mime, buf, (int)n, NULL);
    logger_access("client", req->method, req->uri, 200, (int)n, "-");
    free(buf);
}

void send_error(int fd, int status) {
    char body[256];
    int blen = snprintf(body, sizeof(body),
        "<html><body><h1>%d %s</h1></body></html>",
        status, status_text(status));
    send_response(fd, status, "text/html", (uint8_t *)body, blen, NULL);
}
