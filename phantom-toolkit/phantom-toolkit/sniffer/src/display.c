/* display.c — color-coded terminal output */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include "../include/sniffer.h"

#define COL_TCP    "\033[36m"   /* cyan */
#define COL_UDP    "\033[33m"   /* yellow */
#define COL_ICMP   "\033[35m"   /* magenta */
#define COL_OTHER  "\033[37m"   /* white */
#define COL_RESET  "\033[0m"

static const char *proto_name(int p) {
    switch (p) {
        case IPPROTO_TCP:  return "TCP ";
        case IPPROTO_UDP:  return "UDP ";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "????";
    }
}

static const char *proto_color(int p) {
    switch (p) {
        case IPPROTO_TCP:  return COL_TCP;
        case IPPROTO_UDP:  return COL_UDP;
        case IPPROTO_ICMP: return COL_ICMP;
        default:           return COL_OTHER;
    }
}

static void tcp_flags_str(uint8_t f, char *out) {
    out[0] = (f & 0x02) ? 'S' : '.';   /* SYN */
    out[1] = (f & 0x10) ? 'A' : '.';   /* ACK */
    out[2] = (f & 0x01) ? 'F' : '.';   /* FIN */
    out[3] = (f & 0x04) ? 'R' : '.';   /* RST */
    out[4] = (f & 0x08) ? 'P' : '.';   /* PSH */
    out[5] = (f & 0x20) ? 'U' : '.';   /* URG */
    out[6] = '\0';
}

void display_packet(int proto, uint32_t src_ip, uint32_t dst_ip,
                    uint16_t sport, uint16_t dport,
                    uint8_t tcp_flags, int len,
                    const uint8_t *payload, int plen) {
    (void)payload; (void)plen;
    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    char timebuf[16], flags_buf[8] = "------";
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = localtime(&ts.tv_sec);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

    inet_ntop(AF_INET, &src_ip, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &dst_ip, dst_buf, sizeof(dst_buf));

    if (proto == IPPROTO_TCP) tcp_flags_str(tcp_flags, flags_buf);

    printf("%s[%s] %s %s%-15s\033[0m:%5u → %s%-15s\033[0m:%5u [%s] %d B\n",
           proto_color(proto),
           timebuf,
           proto_name(proto),
           proto_color(proto),
           src_buf, sport,
           proto_color(proto),
           dst_buf, dport,
           flags_buf,
           len);
}

void display_hex_dump(const uint8_t *data, int len) {
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("  %04x  ", i);
        printf("%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            /* Pad */
            int pad = 15 - (i % 16);
            for (int p = 0; p < pad; p++) printf("   ");
            printf(" | ");
            int row_start = i - (i % 16);
            for (int j = row_start; j <= i; j++) {
                unsigned char c = data[j];
                printf("%c", (c >= 32 && c < 127) ? c : '.');
            }
            printf("\n");
        }
    }
}

void display_stats(void) {
    printf("\r\033[K[PKT:%ld | TCP:%ld | UDP:%ld | ICMP:%ld | "
           "BYTES:%ld]",
           g_stats.total_packets, g_stats.tcp_count,
           g_stats.udp_count, g_stats.icmp_count,
           g_stats.total_bytes);
    fflush(stdout);
}
