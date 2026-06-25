#ifndef IDS_H
#define IDS_H

#include <stdint.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#define MAX_TRACKED_IPS  1024
#define SYN_THRESHOLD    10
#define ICMP_THRESHOLD   50
#define WINDOW_SECONDS   5
#define LOG_BUFSIZE      512

typedef struct {
    uint32_t ip;
    int      syn_count;
    int      icmp_count;
    time_t   window_start;
} ip_track_t;

typedef struct {
    char interface[64];
    int  threshold;
    char logfile[256];
    int  verbose;
} config_t;

typedef enum {
    ALERT_PORT_SCAN,
    ALERT_ICMP_FLOOD,
    ALERT_SUSPICIOUS_PORT,
    ALERT_GENERIC
} alert_type_t;

extern config_t g_config;

/* capture.c */
void capture_init(const char *iface);
void capture_loop(void);
void capture_stop(void);

/* rules.c */
void rules_init(int threshold);
void rules_check_packet(const uint8_t *pkt, int len);

/* alert.c */
void alert_init(const char *logfile);
void alert_fire(alert_type_t type, uint32_t src_ip, uint32_t dst_ip,
                uint16_t sport, uint16_t dport, const char *detail);
void alert_close(void);

#endif /* IDS_H */
