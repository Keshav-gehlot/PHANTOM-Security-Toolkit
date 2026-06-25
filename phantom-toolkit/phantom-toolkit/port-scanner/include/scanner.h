#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAX_THREADS   256
#define DEFAULT_TIMEOUT_MS 1000
#define TOP_PORTS_COUNT    1024

typedef enum { STATE_OPEN, STATE_CLOSED, STATE_FILTERED } port_state_t;

typedef struct {
    uint16_t     port;
    port_state_t state;
    char         service[64];
    char         banner[256];
} port_result_t;

typedef struct {
    char    target[64];
    uint32_t target_ip;
    int     port_start;
    int     port_end;
    int     top_ports;
    int     syn_scan;
    int     connect_scan;
    int     service_detect;
    int     os_detect;
    int     timeout_ms;
    int     min_rate;
    char    output_json[256];
    char    output_normal[256];
} scan_config_t;

extern scan_config_t g_scan_cfg;

/* syn_scan.c */
void syn_scan(uint32_t ip, uint16_t *ports, int nports, port_result_t *results);

/* connect_scan.c */
void connect_scan(uint32_t ip, uint16_t *ports, int nports, port_result_t *results);

/* service_detect.c */
void detect_service(uint32_t ip, port_result_t *r);

/* os_detect.c */
void os_detect(uint32_t ip, int ttl, char *out, int outlen);

/* output.c */
void output_results(port_result_t *results, int nports, const char *target);

/* top_ports array */
extern const uint16_t TOP_PORTS[];

#endif /* SCANNER_H */
