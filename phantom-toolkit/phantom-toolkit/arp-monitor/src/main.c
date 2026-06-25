/* main.c — phantom-arp entry point */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/arp.h"

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s --mode <monitor|spoof> -i <iface> [options]\n"
        "  --mode monitor         Passive ARP anomaly detection\n"
        "  --mode spoof           ARP cache poisoning (needs root)\n"
        "  -i <iface>             Network interface\n"
        "  --target <ip>          Victim IP (spoof mode)\n"
        "  --gateway <ip>         Gateway IP (spoof mode)\n"
        "  -v                     Verbose\n"
        "  -l <logfile>           Anomaly log file\n", p);
    exit(1);
}

int main(int argc, char *argv[]) {
    memset(&g_arp_cfg, 0, sizeof(g_arp_cfg));
    strncpy(g_arp_cfg.logfile, LOG_FILE, sizeof(g_arp_cfg.logfile)-1);

    static struct option opts[] = {
        {"mode",    required_argument,0,'m'},
        {"target",  required_argument,0,'t'},
        {"gateway", required_argument,0,'g'},
        {0,0,0,0}
    };
    int opt, idx;
    while ((opt = getopt_long(argc, argv, "i:vl:", opts, &idx)) != -1) {
        switch (opt) {
            case 'i': strncpy(g_arp_cfg.interface, optarg, sizeof(g_arp_cfg.interface)-1); break;
            case 'm': strncpy(g_arp_cfg.mode,      optarg, sizeof(g_arp_cfg.mode)-1); break;
            case 't': strncpy(g_arp_cfg.target_ip, optarg, sizeof(g_arp_cfg.target_ip)-1); break;
            case 'g': strncpy(g_arp_cfg.gateway_ip,optarg, sizeof(g_arp_cfg.gateway_ip)-1); break;
            case 'v': g_arp_cfg.verbose = 1; break;
            case 'l': strncpy(g_arp_cfg.logfile,   optarg, sizeof(g_arp_cfg.logfile)-1); break;
        }
    }

    if (!g_arp_cfg.interface[0] || !g_arp_cfg.mode[0]) usage(argv[0]);

    printf("\033[1;33m"
           "╔══════════════════════════════════════╗\n"
           "║     PHANTOM-ARP  v1.0                ║\n"
           "║     ARP Monitor / Spoofer            ║\n"
           "╚══════════════════════════════════════╝\n"
           "\033[0m");

    if (strcmp(g_arp_cfg.mode, "monitor") == 0) {
        arp_monitor_run();
    } else if (strcmp(g_arp_cfg.mode, "spoof") == 0) {
        if (!g_arp_cfg.target_ip[0] || !g_arp_cfg.gateway_ip[0]) {
            fprintf(stderr, "Spoof mode requires --target and --gateway\n");
            usage(argv[0]);
        }
        arp_spoof_run();
    } else {
        fprintf(stderr, "Unknown mode: %s\n", g_arp_cfg.mode);
        usage(argv[0]);
    }
    return 0;
}
