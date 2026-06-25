/* filter.c — composable packet filters */
#include <string.h>
#include "../include/sniffer.h"

int filter_packet(int proto, uint32_t src_ip, uint32_t dst_ip,
                  uint16_t sport, uint16_t dport, int len) {
    /* Protocol filter */
    if (g_sniff_cfg.proto_filter &&
        g_sniff_cfg.proto_filter != proto) return 0;

    /* Port filter */
    if (g_sniff_cfg.port_filter &&
        g_sniff_cfg.port_filter != sport &&
        g_sniff_cfg.port_filter != dport) return 0;

    /* Host filter */
    if (g_sniff_cfg.host_filter &&
        g_sniff_cfg.host_filter != src_ip &&
        g_sniff_cfg.host_filter != dst_ip) return 0;

    /* Minimum size filter */
    if (len < g_sniff_cfg.min_size) return 0;

    return 1;
}
