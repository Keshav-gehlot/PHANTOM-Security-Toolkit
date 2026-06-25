/* alert.c — alert output and logging */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "../include/ids.h"

static FILE *g_logfp = NULL;

static const char *alert_type_str(alert_type_t t) {
    switch (t) {
        case ALERT_PORT_SCAN:      return "PORT_SCAN";
        case ALERT_ICMP_FLOOD:     return "ICMP_FLOOD";
        case ALERT_SUSPICIOUS_PORT:return "SUSPICIOUS_PORT";
        default:                   return "GENERIC";
    }
}

static const char *alert_color(alert_type_t t) {
    switch (t) {
        case ALERT_PORT_SCAN:       return "\033[1;31m"; /* red */
        case ALERT_ICMP_FLOOD:      return "\033[1;35m"; /* magenta */
        case ALERT_SUSPICIOUS_PORT: return "\033[1;33m"; /* yellow */
        default:                    return "\033[1;36m"; /* cyan */
    }
}

void alert_init(const char *logfile) {
    if (logfile && logfile[0]) {
        g_logfp = fopen(logfile, "a");
        if (!g_logfp) perror("fopen logfile");
    }
}

void alert_fire(alert_type_t type, uint32_t src_ip, uint32_t dst_ip,
                uint16_t sport, uint16_t dport, const char *detail) {
    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    char timebuf[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    inet_ntop(AF_INET, &src_ip, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &dst_ip, dst_buf, sizeof(dst_buf));
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Terminal output */
    fprintf(stderr,
            "%s[ALERT]\033[0m [%s] %-18s %s:%u -> %s:%u | %s\n",
            alert_color(type),
            timebuf,
            alert_type_str(type),
            src_buf, sport,
            dst_buf, dport,
            detail);

    /* Log file output */
    if (g_logfp) {
        fprintf(g_logfp,
                "[%s] %s | %s:%u -> %s:%u | %s\n",
                timebuf,
                alert_type_str(type),
                src_buf, sport,
                dst_buf, dport,
                detail);
        fflush(g_logfp);
    }
}

void alert_close(void) {
    if (g_logfp) {
        fclose(g_logfp);
        g_logfp = NULL;
    }
}
