/* main.c — phantom-ids entry point */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/ids.h"

config_t g_config;

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -i <iface> [-t <threshold>] [-l <logfile>] [-v]\n"
        "  -i  Network interface to capture on (e.g. eth0)\n"
        "  -t  SYN scan threshold (default: %d packets/5s)\n"
        "  -l  Log file path (default: alerts.log)\n"
        "  -v  Verbose mode\n",
        prog, SYN_THRESHOLD);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    int opt;
    memset(&g_config, 0, sizeof(g_config));
    g_config.threshold = SYN_THRESHOLD;
    strncpy(g_config.logfile, "alerts.log", sizeof(g_config.logfile) - 1);

    while ((opt = getopt(argc, argv, "i:t:l:v")) != -1) {
        switch (opt) {
            case 'i': strncpy(g_config.interface, optarg, sizeof(g_config.interface)-1); break;
            case 't': g_config.threshold = atoi(optarg); break;
            case 'l': strncpy(g_config.logfile, optarg, sizeof(g_config.logfile)-1); break;
            case 'v': g_config.verbose = 1; break;
            default:  usage(argv[0]);
        }
    }

    if (!g_config.interface[0]) {
        fprintf(stderr, "Error: interface required\n");
        usage(argv[0]);
    }

    printf("\033[1;32m"
           "╔══════════════════════════════════════╗\n"
           "║        PHANTOM-IDS  v1.0             ║\n"
           "║  Intrusion Detection System          ║\n"
           "╚══════════════════════════════════════╝\n"
           "\033[0m");

    alert_init(g_config.logfile);
    rules_init(g_config.threshold);
    capture_init(g_config.interface);
    capture_loop();
    alert_close();

    return EXIT_SUCCESS;
}
