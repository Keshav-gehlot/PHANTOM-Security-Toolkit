/* capture.c — raw socket packet capture for phantom-ids */
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
#include "../include/ids.h"

#define SNAP_LEN 65535

static int  g_sock    = -1;
static int  g_running = 1;
static long g_total_packets = 0;
static long g_total_bytes   = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

void capture_init(const char *iface) {
    struct ifreq ifr;
    struct sockaddr_ll sll;
    struct packet_mreq mr;

    g_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(g_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(g_sock);
        exit(EXIT_FAILURE);
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(g_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(g_sock);
        exit(EXIT_FAILURE);
    }

    /* Enable promiscuous mode */
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;
    if (setsockopt(g_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                   &mr, sizeof(mr)) < 0) {
        perror("setsockopt PROMISC");
    }

    signal(SIGINT, handle_sigint);
    printf("\033[32m[IDS]\033[0m Capturing on %s (promiscuous mode)\n", iface);
}

void capture_loop(void) {
    uint8_t buf[SNAP_LEN];
    ssize_t n;

    while (g_running) {
        n = recvfrom(g_sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) break;
        g_total_packets++;
        g_total_bytes += n;
        rules_check_packet(buf, (int)n);
    }

    printf("\n\033[33m[IDS]\033[0m Captured %ld packets (%ld bytes)\n",
           g_total_packets, g_total_bytes);
}

void capture_stop(void) {
    g_running = 0;
    if (g_sock >= 0) {
        close(g_sock);
        g_sock = -1;
    }
}
