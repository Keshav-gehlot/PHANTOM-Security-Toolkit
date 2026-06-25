/* main.c — phantom-sniffer entry point */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../include/sniffer.h"

sniff_config_t g_sniff_cfg;
sniff_stats_t  g_stats;

static int  g_sock    = -1;
static int  g_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s -i <iface> [options]\n"
        "  --proto  tcp|udp|icmp|all\n"
        "  --port   <port>\n"
        "  --host   <ip>\n"
        "  --payload  show first 64B of payload\n"
        "  --hex      full hex dump\n"
        "  --min-size <bytes>\n"
        "  -v  verbose\n", p);
    exit(1);
}

int main(int argc, char *argv[]) {
    memset(&g_sniff_cfg, 0, sizeof(g_sniff_cfg));
    memset(&g_stats, 0, sizeof(g_stats));

    static struct option opts[] = {
        {"proto",    required_argument, 0, 'p'},
        {"port",     required_argument, 0, 'P'},
        {"host",     required_argument, 0, 'H'},
        {"payload",  no_argument,       0, 'd'},
        {"hex",      no_argument,       0, 'x'},
        {"min-size", required_argument, 0, 'm'},
        {0,0,0,0}
    };

    int opt, idx;
    while ((opt = getopt_long(argc, argv, "i:v", opts, &idx)) != -1) {
        switch (opt) {
            case 'i': strncpy(g_sniff_cfg.interface, optarg, 63); break;
            case 'p':
                if (!strcmp(optarg,"tcp"))  g_sniff_cfg.proto_filter = IPPROTO_TCP;
                if (!strcmp(optarg,"udp"))  g_sniff_cfg.proto_filter = IPPROTO_UDP;
                if (!strcmp(optarg,"icmp")) g_sniff_cfg.proto_filter = IPPROTO_ICMP;
                break;
            case 'P': g_sniff_cfg.port_filter  = (uint16_t)atoi(optarg); break;
            case 'H': inet_pton(AF_INET, optarg, &g_sniff_cfg.host_filter); break;
            case 'd': g_sniff_cfg.show_payload = 1; break;
            case 'x': g_sniff_cfg.show_hex = 1; break;
            case 'm': g_sniff_cfg.min_size = atoi(optarg); break;
            case 'v': g_sniff_cfg.verbose  = 1; break;
        }
    }

    if (!g_sniff_cfg.interface[0]) usage(argv[0]);

    printf("\033[1;36m"
           "╔══════════════════════════════════════╗\n"
           "║     PHANTOM-SNIFFER  v1.0            ║\n"
           "║     Raw Socket Packet Analyzer       ║\n"
           "╚══════════════════════════════════════╝\n"
           "\033[0m");
    printf("Interface: %s\n\n", g_sniff_cfg.interface);

    g_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_sock < 0) { perror("socket"); return 1; }

    struct ifreq ifr;
    strncpy(ifr.ifr_name, g_sniff_cfg.interface, IFNAMSIZ-1);
    ioctl(g_sock, SIOCGIFINDEX, &ifr);

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    bind(g_sock, (struct sockaddr *)&sll, sizeof(sll));

    struct packet_mreq mr = {0};
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;
    setsockopt(g_sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    signal(SIGINT, handle_sigint);

    uint8_t buf[SNAP_LEN];
    while (g_running) {
        ssize_t n = recvfrom(g_sock, buf, sizeof(buf), 0, NULL, NULL);
        if (n <= 0) break;
        decode_packet(buf, (int)n);
    }

    printf("\n\n--- Capture Summary ---\n");
    printf("Total: %ld pkts, %ld bytes\n", g_stats.total_packets, g_stats.total_bytes);
    printf("TCP: %ld  UDP: %ld  ICMP: %ld  Other: %ld\n",
           g_stats.tcp_count, g_stats.udp_count,
           g_stats.icmp_count, g_stats.other_count);

    close(g_sock);
    return 0;
}
