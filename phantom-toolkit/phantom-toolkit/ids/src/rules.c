/* rules.c — packet inspection and rule matching */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "../include/ids.h"

static ip_track_t g_table[MAX_TRACKED_IPS];
static int        g_count = 0;
static int        g_threshold = SYN_THRESHOLD;

/* Suspicious ports: non-standard service ports */
static const uint16_t SUSPICIOUS_PORTS[] = {
    4444, 5555, 6666, 7777, 8888, 9999,  /* common reverse shell */
    1337, 31337,                           /* elite/backdoor */
    12345, 27374, 54321                    /* classic trojans */
};
#define N_SUSPICIOUS (sizeof(SUSPICIOUS_PORTS)/sizeof(SUSPICIOUS_PORTS[0]))

static ip_track_t *find_or_create(uint32_t ip) {
    time_t now = time(NULL);
    for (int i = 0; i < g_count; i++) {
        if (g_table[i].ip == ip) {
            /* Reset window if expired */
            if (now - g_table[i].window_start > WINDOW_SECONDS) {
                g_table[i].syn_count  = 0;
                g_table[i].icmp_count = 0;
                g_table[i].window_start = now;
            }
            return &g_table[i];
        }
    }
    if (g_count >= MAX_TRACKED_IPS) return NULL;
    g_table[g_count].ip           = ip;
    g_table[g_count].syn_count    = 0;
    g_table[g_count].icmp_count   = 0;
    g_table[g_count].window_start = now;
    return &g_table[g_count++];
}

static int is_suspicious_port(uint16_t port) {
    for (size_t i = 0; i < N_SUSPICIOUS; i++)
        if (SUSPICIOUS_PORTS[i] == port) return 1;
    return 0;
}

void rules_init(int threshold) {
    g_threshold = threshold;
    memset(g_table, 0, sizeof(g_table));
}

void rules_check_packet(const uint8_t *pkt, int len) {
    if (len < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) return;

    const struct ethhdr *eth = (const struct ethhdr *)pkt;
    if (ntohs(eth->h_proto) != ETH_P_IP) return;

    const struct iphdr *ip = (const struct iphdr *)(pkt + sizeof(struct ethhdr));
    int ip_hlen = ip->ihl * 4;
    if (len < (int)(sizeof(struct ethhdr) + ip_hlen)) return;

    const uint8_t *l4 = pkt + sizeof(struct ethhdr) + ip_hlen;
    ip_track_t *track = find_or_create(ip->saddr);
    if (!track) return;

    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &ip->daddr, dst_buf, sizeof(dst_buf));

    if (ip->protocol == IPPROTO_TCP) {
        if (len < (int)(sizeof(struct ethhdr) + ip_hlen + sizeof(struct tcphdr))) return;
        const struct tcphdr *tcp = (const struct tcphdr *)l4;
        uint16_t sport = ntohs(tcp->source);
        uint16_t dport = ntohs(tcp->dest);

        /* Rule 1: SYN scan detection */
        if (tcp->syn && !tcp->ack) {
            track->syn_count++;
            if (track->syn_count >= g_threshold) {
                alert_fire(ALERT_PORT_SCAN, ip->saddr, ip->daddr,
                           sport, dport, "SYN flood / port scan");
                track->syn_count = 0;
            }
        }

        /* Rule 2: HTTP on non-80/443 port */
        if (dport != 80 && dport != 443 && dport != 8080 && dport != 8443) {
            const uint8_t *payload = l4 + tcp->doff * 4;
            int payload_len = len - (int)(sizeof(struct ethhdr) + ip_hlen + tcp->doff * 4);
            if (payload_len > 4 &&
                (memcmp(payload, "GET ", 4) == 0 ||
                 memcmp(payload, "POST", 4) == 0 ||
                 memcmp(payload, "HTTP", 4) == 0)) {
                alert_fire(ALERT_SUSPICIOUS_PORT, ip->saddr, ip->daddr,
                           sport, dport, "HTTP traffic on non-standard port");
            }
        }

        /* Rule 3: Suspicious destination ports */
        if (is_suspicious_port(dport)) {
            char detail[128];
            snprintf(detail, sizeof(detail),
                     "Connection to known backdoor port %u", dport);
            alert_fire(ALERT_SUSPICIOUS_PORT, ip->saddr, ip->daddr,
                       sport, dport, detail);
        }

    } else if (ip->protocol == IPPROTO_ICMP) {
        /* Rule 4: ICMP flood */
        track->icmp_count++;
        if (track->icmp_count >= ICMP_THRESHOLD) {
            alert_fire(ALERT_ICMP_FLOOD, ip->saddr, ip->daddr,
                       0, 0, "ICMP flood detected");
            track->icmp_count = 0;
        }
    }
}
