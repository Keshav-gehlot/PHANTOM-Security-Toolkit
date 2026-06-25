/* main.c — phantom-httpd entry point */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/httpd.h"

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [--port 8080] [--root ./www] [--log access.log]\n", p);
    exit(1);
}

int main(int argc, char *argv[]) {
    memset(&g_httpd_cfg, 0, sizeof(g_httpd_cfg));
    g_httpd_cfg.port = 8080;
    strncpy(g_httpd_cfg.root, "./www", sizeof(g_httpd_cfg.root)-1);
    strncpy(g_httpd_cfg.access_log, "access.log", sizeof(g_httpd_cfg.access_log)-1);

    static struct option opts[] = {
        {"port",  required_argument, 0, 'p'},
        {"root",  required_argument, 0, 'r'},
        {"log",   required_argument, 0, 'l'},
        {0,0,0,0}
    };
    int opt, idx;
    while ((opt = getopt_long(argc, argv, "", opts, &idx)) != -1) {
        switch (opt) {
            case 'p': g_httpd_cfg.port = atoi(optarg); break;
            case 'r': strncpy(g_httpd_cfg.root, optarg, sizeof(g_httpd_cfg.root)-1); break;
            case 'l': strncpy(g_httpd_cfg.access_log, optarg, sizeof(g_httpd_cfg.access_log)-1); break;
            default: usage(argv[0]);
        }
    }

    printf("\033[1;33m"
           "╔══════════════════════════════════════╗\n"
           "║     PHANTOM-HTTPD  v1.0              ║\n"
           "║     HTTP/1.1 Server from Scratch     ║\n"
           "╚══════════════════════════════════════╝\n"
           "\033[0m");

    logger_init(g_httpd_cfg.access_log);
    server_run();
    logger_close();
    return 0;
}
