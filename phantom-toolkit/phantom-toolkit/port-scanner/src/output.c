/* output.c — nmap-style table + JSON output */
#include <stdio.h>
#include <string.h>
#include "../include/scanner.h"

static const char *state_str(port_state_t s) {
    switch (s) {
        case STATE_OPEN:     return "\033[1;32mopen    \033[0m";
        case STATE_CLOSED:   return "\033[1;31mclosed  \033[0m";
        case STATE_FILTERED: return "\033[1;33mfiltered\033[0m";
        default:             return "unknown ";
    }
}

static const char *state_str_plain(port_state_t s) {
    switch (s) {
        case STATE_OPEN:     return "open";
        case STATE_CLOSED:   return "closed";
        case STATE_FILTERED: return "filtered";
        default:             return "unknown";
    }
}

void output_results(port_result_t *results, int nports, const char *target) {
    int open_count = 0;
    for (int i = 0; i < nports; i++)
        if (results[i].state == STATE_OPEN) open_count++;

    printf("\n\033[1;36mPHANTOM SCAN RESULTS\033[0m\n");
    printf("Target: %s\n", target);
    printf("%-7s %-10s %-16s %s\n", "PORT", "STATE", "SERVICE", "BANNER");
    printf("%-7s %-10s %-16s %s\n", "----", "-----", "-------", "------");

    for (int i = 0; i < nports; i++) {
        if (results[i].state == STATE_CLOSED) continue; /* hide closed */
        printf("%-5u/tcp %-18s %-16s %s\n",
               results[i].port,
               state_str(results[i].state),
               results[i].service,
               results[i].banner[0] ? results[i].banner : "-");
    }
    printf("\n%d open port(s) found\n", open_count);

    /* JSON output */
    if (g_scan_cfg.output_json[0]) {
        FILE *f = fopen(g_scan_cfg.output_json, "w");
        if (!f) return;
        fprintf(f, "{\n  \"target\": \"%s\",\n  \"ports\": [\n", target);
        int first = 1;
        for (int i = 0; i < nports; i++) {
            if (results[i].state == STATE_CLOSED) continue;
            if (!first) fprintf(f, ",\n");
            fprintf(f,
                "    {\"port\":%u,\"state\":\"%s\","
                "\"service\":\"%s\",\"banner\":\"%s\"}",
                results[i].port,
                state_str_plain(results[i].state),
                results[i].service,
                results[i].banner);
            first = 0;
        }
        fprintf(f, "\n  ]\n}\n");
        fclose(f);
        printf("JSON saved to %s\n", g_scan_cfg.output_json);
    }

    /* Greppable output */
    if (g_scan_cfg.output_normal[0]) {
        FILE *f = fopen(g_scan_cfg.output_normal, "w");
        if (!f) return;
        fprintf(f, "# PHANTOM-SCAN target=%s\n", target);
        for (int i = 0; i < nports; i++) {
            if (results[i].state == STATE_CLOSED) continue;
            fprintf(f, "Host: %s / Ports: %u/%s/tcp/%s\n",
                    target, results[i].port,
                    state_str_plain(results[i].state),
                    results[i].service);
        }
        fclose(f);
    }
}
