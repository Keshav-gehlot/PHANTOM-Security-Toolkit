/* main.c — phantom-scan entry point */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "../include/scanner.h"

scan_config_t g_scan_cfg;

/* Top 100 most common ports */
const uint16_t TOP_PORTS[] = {
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
    1723,3306,3389,5900,8080,8443,8888,
    /* extended common */
    20,69,79,88,119,123,137,138,161,179,194,389,427,465,514,
    515,543,544,548,554,587,631,636,646,873,990,993,1080,1194,
    1433,1521,2049,2082,2083,2086,2087,2095,2096,3000,3128,
    4444,5000,5432,5555,5601,6379,6443,7001,8000,8008,8081,
    8082,8083,8084,8085,8086,8087,8088,8089,8090,8181,8888,
    9000,9090,9200,9300,9418,27017,27018,27019,28017,0
};
#define N_TOP_PORTS (sizeof(TOP_PORTS)/sizeof(TOP_PORTS[0]) - 1)

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s <target> [options]\n"
        "  -sS           SYN scan (needs root)\n"
        "  -sT           Connect scan (default)\n"
        "  -sV           Service/version detection\n"
        "  -O            OS detection\n"
        "  -p <range>    Port range (e.g. 1-1024 or 22,80,443)\n"
        "  --top-ports N Scan top N ports\n"
        "  --timeout ms  Per-port timeout (default: 1000)\n"
        "  --oJ <file>   JSON output\n"
        "  --oN <file>   Normal output\n", p);
    exit(1);
}

static int parse_ports(const char *spec, uint16_t *ports, int maxports) {
    int n = 0;
    char buf[256];
    strncpy(buf, spec, sizeof(buf)-1);
    char *tok = strtok(buf, ",");
    while (tok && n < maxports) {
        char *dash = strchr(tok, '-');
        if (dash) {
            *dash = '\0';
            int lo = atoi(tok), hi = atoi(dash+1);
            for (int p = lo; p <= hi && n < maxports; p++)
                ports[n++] = (uint16_t)p;
        } else {
            ports[n++] = (uint16_t)atoi(tok);
        }
        tok = strtok(NULL, ",");
    }
    return n;
}

int main(int argc, char *argv[]) {
    memset(&g_scan_cfg, 0, sizeof(g_scan_cfg));
    g_scan_cfg.connect_scan = 1;
    g_scan_cfg.timeout_ms   = DEFAULT_TIMEOUT_MS;

    if (argc < 2) usage(argv[0]);
    strncpy(g_scan_cfg.target, argv[1], sizeof(g_scan_cfg.target)-1);

    static struct option opts[] = {
        {"top-ports",required_argument,0,'T'},
        {"timeout",  required_argument,0,'t'},
        {"oJ",       required_argument,0,'J'},
        {"oN",       required_argument,0,'N'},
        {0,0,0,0}
    };

    int opt, idx;
    char port_spec[256] = "";
    while ((opt = getopt_long(argc, argv+1, "sSTVOp:", opts, &idx)) != -1) {
        switch (opt) {
            case 's':
                if (optarg && optarg[0]=='S') { g_scan_cfg.syn_scan=1; g_scan_cfg.connect_scan=0; }
                if (optarg && optarg[0]=='V') g_scan_cfg.service_detect=1;
                break;
            case 'S': g_scan_cfg.syn_scan=1; g_scan_cfg.connect_scan=0; break;
            case 'V': g_scan_cfg.service_detect=1; break;
            case 'O': g_scan_cfg.os_detect=1; break;
            case 'p': strncpy(port_spec, optarg, sizeof(port_spec)-1); break;
            case 'T': g_scan_cfg.top_ports = atoi(optarg); break;
            case 't': g_scan_cfg.timeout_ms = atoi(optarg); break;
            case 'J': strncpy(g_scan_cfg.output_json,   optarg, sizeof(g_scan_cfg.output_json)-1); break;
            case 'N': strncpy(g_scan_cfg.output_normal, optarg, sizeof(g_scan_cfg.output_normal)-1); break;
        }
    }

    /* Resolve target */
    if (inet_pton(AF_INET, g_scan_cfg.target, &g_scan_cfg.target_ip) != 1) {
        fprintf(stderr, "Invalid IP address: %s\n", g_scan_cfg.target);
        return 1;
    }

    /* Build port list */
    uint16_t *ports;
    int nports;

    if (port_spec[0]) {
        ports  = malloc(65536 * sizeof(uint16_t));
        nports = parse_ports(port_spec, ports, 65535);
    } else if (g_scan_cfg.top_ports > 0) {
        int n = g_scan_cfg.top_ports;
        if (n > (int)N_TOP_PORTS) n = (int)N_TOP_PORTS;
        ports  = malloc((size_t)n * sizeof(uint16_t));
        nports = n;
        for (int i = 0; i < n; i++) ports[i] = TOP_PORTS[i];
    } else {
        /* Default: top ports */
        nports = (int)N_TOP_PORTS;
        ports  = malloc((size_t)nports * sizeof(uint16_t));
        for (int i = 0; i < nports; i++) ports[i] = TOP_PORTS[i];
    }

    port_result_t *results = calloc((size_t)nports, sizeof(port_result_t));

    printf("\033[1;31m"
           "╔══════════════════════════════════════╗\n"
           "║     PHANTOM-SCAN  v1.0               ║\n"
           "║     Lite Port Scanner                ║\n"
           "╚══════════════════════════════════════╝\n"
           "\033[0m");
    printf("Target: %s | Ports: %d | Mode: %s\n\n",
           g_scan_cfg.target, nports,
           g_scan_cfg.syn_scan ? "SYN" : "CONNECT");

    /* Run scan */
    if (g_scan_cfg.syn_scan)
        syn_scan(g_scan_cfg.target_ip, ports, nports, results);
    else
        connect_scan(g_scan_cfg.target_ip, ports, nports, results);

    /* Service detection */
    if (g_scan_cfg.service_detect) {
        for (int i = 0; i < nports; i++)
            if (results[i].state == STATE_OPEN)
                detect_service(g_scan_cfg.target_ip, &results[i]);
    } else {
        for (int i = 0; i < nports; i++)
            if (results[i].state == STATE_OPEN) {
                extern const char *port_to_service(uint16_t);
                results[i].port = ports[i];
            }
    }

    output_results(results, nports, g_scan_cfg.target);

    free(ports);
    free(results);
    return 0;
}
