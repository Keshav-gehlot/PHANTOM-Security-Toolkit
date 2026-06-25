/* decode.c — multi-layer packet decoder */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/sniffer.h"

void decode_packet(const uint8_t *pkt, int len) {
    if (len < (int)sizeof(struct ethhdr)) return;

    const struct ethhdr *eth = (const struct ethhdr *)pkt;
    uint16_t etype = ntohs(eth->h_proto);
    if (etype != ETH_P_IP) return;   /* IPv4 only */

    int ip_off = sizeof(struct ethhdr);
    if (len < ip_off + (int)sizeof(struct iphdr)) return;

    const struct iphdr *ip = (const struct iphdr *)(pkt + ip_off);
    int ip_hlen = ip->ihl * 4;
    int l4_off  = ip_off + ip_hlen;

    uint32_t src = ip->saddr, dst = ip->daddr;
    int proto = ip->protocol;

    uint16_t sport = 0, dport = 0;
    uint8_t  flags = 0;
    const uint8_t *payload = NULL;
    int plen = 0;

    if (proto == IPPROTO_TCP) {
        if (len < l4_off + (int)sizeof(struct tcphdr)) return;
        const struct tcphdr *tcp = (const struct tcphdr *)(pkt + l4_off);
        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);
        flags = ((uint8_t *)tcp)[13]; /* compact flags byte */
        int tcp_hlen = tcp->doff * 4;
        payload = pkt + l4_off + tcp_hlen;
        plen    = len - l4_off - tcp_hlen;
        g_stats.tcp_count++;

    } else if (proto == IPPROTO_UDP) {
        if (len < l4_off + (int)sizeof(struct udphdr)) return;
        const struct udphdr *udp = (const struct udphdr *)(pkt + l4_off);
        sport   = ntohs(udp->source);
        dport   = ntohs(udp->dest);
        payload = pkt + l4_off + sizeof(struct udphdr);
        plen    = len - l4_off - (int)sizeof(struct udphdr);
        g_stats.udp_count++;

    } else if (proto == IPPROTO_ICMP) {
        g_stats.icmp_count++;
    } else {
        g_stats.other_count++;
    }

    if (!filter_packet(proto, src, dst, sport, dport, len)) return;

    g_stats.total_packets++;
    g_stats.total_bytes += len;

    display_packet(proto, src, dst, sport, dport, flags, len, payload, plen);

    if (g_sniff_cfg.show_hex)
        display_hex_dump(pkt, len < 128 ? len : 128);
    else if (g_sniff_cfg.show_payload && payload && plen > 0)
        display_hex_dump(payload, plen < 64 ? plen : 64);
}
