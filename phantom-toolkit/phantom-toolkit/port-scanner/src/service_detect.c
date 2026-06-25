/* service_detect.c — banner grab + signature matching */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../include/scanner.h"

typedef struct { uint16_t port; const char *name; } port_name_t;
static const port_name_t PORT_NAMES[] = {
    {21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},{53,"dns"},
    {80,"http"},{110,"pop3"},{143,"imap"},{443,"https"},{445,"smb"},
    {3306,"mysql"},{3389,"rdp"},{5432,"postgresql"},{6379,"redis"},
    {8080,"http-alt"},{8443,"https-alt"},{27017,"mongodb"},{0,NULL}
};

static const char *port_to_service(uint16_t port) {
    for (int i = 0; PORT_NAMES[i].name; i++)
        if (PORT_NAMES[i].port == port) return PORT_NAMES[i].name;
    return "unknown";
}

void detect_service(uint32_t ip, port_result_t *r) {
    strncpy(r->service, port_to_service(r->port), sizeof(r->service)-1);
    if (r->state != STATE_OPEN) return;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;

    struct timeval tv = { 2, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(r->port);
    addr.sin_addr.s_addr = ip;

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return;
    }

    /* Send probe for HTTP */
    if (r->port == 80 || r->port == 8080 || r->port == 8443 || r->port == 443) {
        const char *probe = "HEAD / HTTP/1.0\r\n\r\n";
        send(fd, probe, strlen(probe), 0);
    }

    char buf[256] = {0};
    recv(fd, buf, sizeof(buf)-1, 0);
    close(fd);

    if (buf[0]) {
        strncpy(r->banner, buf, sizeof(r->banner)-1);
        /* Null-terminate at first newline */
        char *nl = strchr(r->banner, '\n');
        if (nl) *nl = '\0';
        nl = strchr(r->banner, '\r');
        if (nl) *nl = '\0';

        /* Signature matching */
        if (strstr(buf, "SSH-"))    strncpy(r->service, "ssh",   sizeof(r->service)-1);
        if (strstr(buf, "220 "))    strncpy(r->service, "ftp/smtp", sizeof(r->service)-1);
        if (strstr(buf, "HTTP/"))   strncpy(r->service, "http",  sizeof(r->service)-1);
        if (strstr(buf, "MySQL"))   strncpy(r->service, "mysql", sizeof(r->service)-1);
        if (strstr(buf, "+OK"))     strncpy(r->service, "pop3",  sizeof(r->service)-1);
        if (strstr(buf, "* OK"))    strncpy(r->service, "imap",  sizeof(r->service)-1);
    }
}
