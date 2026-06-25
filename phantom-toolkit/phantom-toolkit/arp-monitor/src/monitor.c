/* monitor.c — passive ARP table listener + conflict detection */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../include/arp.h"

/* ARP packet structure (Ethernet + IPv4) */
typedef struct __attribute__((packed)) {
    struct ethhdr eth;
    uint16_t htype;     /* hardware type: 1 = Ethernet */
    uint16_t ptype;     /* protocol type: 0x0800 = IPv4 */
    uint8_t  hlen;      /* hardware addr len: 6 */
    uint8_t  plen;      /* protocol addr len: 4 */
    uint16_t oper;      /* 1=request, 2=reply */
    uint8_t  sha[6];    /* sender hardware address */
    uint8_t  spa[4];    /* sender protocol address */
    uint8_t  tha[6];    /* target hardware address */
    uint8_t  tpa[4];    /* target protocol address */
} arp_pkt_t;

static arp_entry_t g_table[ARP_TABLE_SIZE];
static int         g_count   = 0;
static int         g_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

static arp_entry_t *table_lookup(uint32_t ip) {
    for (int i = 0; i < g_count; i++)
        if (g_table[i].ip == ip) return &g_table[i];
    return NULL;
}

static arp_entry_t *table_insert(uint32_t ip, const uint8_t *mac) {
    if (g_count >= ARP_TABLE_SIZE) return NULL;
    arp_entry_t *e = &g_table[g_count++];
    e->ip         = ip;
    memcpy(e->mac, mac, ETH_ALEN);
    e->first_seen = time(NULL);
    e->last_seen  = e->first_seen;
    e->count      = 1;
    e->flagged    = 0;
    return e;
}

static void check_anomaly(uint32_t ip, const uint8_t *new_mac,
                           int is_gratuitous) {
    char ip_buf[INET_ADDRSTRLEN];
    char old_mac_buf[32], new_mac_buf[32];
    inet_ntop(AF_INET, &ip, ip_buf, sizeof(ip_buf));
    mac_to_str(new_mac, new_mac_buf);

    arp_entry_t *existing = table_lookup(ip);
    if (!existing) {
        table_insert(ip, new_mac);
        if (g_arp_cfg.verbose)
            printf("  \033[32m[NEW]\033[0m  %-16s  %s\n", ip_buf, new_mac_buf);
        return;
    }

    existing->last_seen = time(NULL);
    existing->count++;

    /* Anomaly: same IP, different MAC */
    if (memcmp(existing->mac, new_mac, ETH_ALEN) != 0) {
        mac_to_str(existing->mac, old_mac_buf);
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "ARP CONFLICT: IP %s changed MAC %s -> %s%s",
                 ip_buf, old_mac_buf, new_mac_buf,
                 is_gratuitous ? " [GRATUITOUS]" : "");
        printf("  \033[1;31m[ALERT]\033[0m %s\n", msg);
        arp_log(msg);
        existing->flagged = 1;
        memcpy(existing->mac, new_mac, ETH_ALEN);
    } else if (is_gratuitous) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "Gratuitous ARP: %s claims %s", ip_buf, new_mac_buf);
        printf("  \033[1;33m[GRAT]\033[0m  %s\n", msg);
        arp_log(msg);
    }
}

void arp_table_dump(void) {
    printf("\n%-18s %-20s %-12s %-8s %s\n",
           "IP", "MAC", "LAST SEEN", "COUNT", "FLAGS");
    printf("%-18s %-20s %-12s %-8s %s\n",
           "--", "---", "---------", "-----", "-----");
    for (int i = 0; i < g_count; i++) {
        char ip_buf[INET_ADDRSTRLEN], mac_buf[32], ts_buf[20];
        inet_ntop(AF_INET, &g_table[i].ip, ip_buf, sizeof(ip_buf));
        mac_to_str(g_table[i].mac, mac_buf);
        struct tm *t = localtime(&g_table[i].last_seen);
        strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", t);
        printf("%-18s %-20s %-12s %-8d %s\n",
               ip_buf, mac_buf, ts_buf,
               g_table[i].count,
               g_table[i].flagged ? "\033[31mSPOOFED?\033[0m" : "OK");
    }
}

void arp_monitor_run(void) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) { perror("socket"); exit(1); }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, g_arp_cfg.interface, IFNAMSIZ-1);
    ioctl(sock, SIOCGIFINDEX, &ifr);

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ARP);
    bind(sock, (struct sockaddr *)&sll, sizeof(sll));

    signal(SIGINT, handle_sigint);

    printf("\033[1;33m[ARP-MONITOR]\033[0m Listening on %s\n",
           g_arp_cfg.interface);
    printf("%-18s %-20s %s\n", "IP", "MAC", "EVENT");
    printf("%-18s %-20s %s\n", "--", "---", "-----");

    arp_pkt_t pkt;
    while (g_running) {
        ssize_t n = recvfrom(sock, &pkt, sizeof(pkt), 0, NULL, NULL);
        if (n < (ssize_t)sizeof(arp_pkt_t)) continue;
        if (ntohs(pkt.htype) != 1) continue;       /* Ethernet only */
        if (ntohs(pkt.ptype) != ETH_P_IP) continue; /* IPv4 only */

        uint32_t sender_ip;
        memcpy(&sender_ip, pkt.spa, 4);

        /* Gratuitous ARP: sender IP == target IP */
        uint32_t target_ip;
        memcpy(&target_ip, pkt.tpa, 4);
        int is_gratuitous = (sender_ip == target_ip);

        check_anomaly(sender_ip, pkt.sha, is_gratuitous);
    }

    printf("\n");
    arp_table_dump();
    close(sock);
}
