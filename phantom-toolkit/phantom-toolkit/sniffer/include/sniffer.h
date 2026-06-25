#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#define SNAP_LEN       65535
#define STATS_INTERVAL 1       /* seconds */

typedef struct {
    char     interface[64];
    int      proto_filter;     /* 0=all,6=tcp,17=udp,1=icmp */
    uint16_t port_filter;      /* 0 = no filter */
    uint32_t host_filter;      /* 0 = no filter */
    int      min_size;
    int      show_payload;
    int      show_hex;
    int      verbose;
    char     output_file[256];
} sniff_config_t;

typedef struct {
    long total_packets;
    long total_bytes;
    long tcp_count;
    long udp_count;
    long icmp_count;
    long other_count;
} sniff_stats_t;

extern sniff_config_t g_sniff_cfg;
extern sniff_stats_t  g_stats;

/* decode.c */
void decode_packet(const uint8_t *pkt, int len);

/* filter.c */
int filter_packet(int proto, uint32_t src_ip, uint32_t dst_ip,
                  uint16_t sport, uint16_t dport, int len);

/* display.c */
void display_packet(int proto, uint32_t src_ip, uint32_t dst_ip,
                    uint16_t sport, uint16_t dport,
                    uint8_t tcp_flags, int len,
                    const uint8_t *payload, int plen);
void display_hex_dump(const uint8_t *data, int len);
void display_stats(void);

#endif /* SNIFFER_H */
