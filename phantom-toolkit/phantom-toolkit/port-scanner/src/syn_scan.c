/* syn_scan.c — raw socket SYN stealth scan */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include "../include/scanner.h"

/* Pseudo-header for TCP checksum */
typedef struct {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t tcp_len;
} pseudo_hdr_t;

static uint16_t checksum(const void *data, int len) {
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len) sum += *(const uint8_t *)ptr;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(uint32_t src, uint32_t dst,
                              const struct tcphdr *tcp, int tcplen) {
    char buf[64];
    pseudo_hdr_t *ph = (pseudo_hdr_t *)buf;
    ph->src      = src;
    ph->dst      = dst;
    ph->zero     = 0;
    ph->proto    = IPPROTO_TCP;
    ph->tcp_len  = htons((uint16_t)tcplen);
    memcpy(buf + sizeof(pseudo_hdr_t), tcp, (size_t)tcplen);
    return checksum(buf, (int)sizeof(pseudo_hdr_t) + tcplen);
}

void syn_scan(uint32_t ip, uint16_t *ports, int nports, port_result_t *results) {
    int send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (send_sock < 0 || recv_sock < 0) {
        perror("raw socket (need root)");
        if (send_sock >= 0) close(send_sock);
        if (recv_sock >= 0) close(recv_sock);
        return;
    }

    int one = 1;
    setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct timeval tv = { 0, g_scan_cfg.timeout_ms * 1000 };
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint16_t src_port = 40000 + (uint16_t)(rand() % 10000);
    uint32_t src_ip   = 0;  /* kernel fills */

    /* Mark all filtered by default */
    for (int i = 0; i < nports; i++) {
        results[i].port  = ports[i];
        results[i].state = STATE_FILTERED;
    }

    /* Send SYN packets */
    for (int i = 0; i < nports; i++) {
        char pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
        memset(pkt, 0, sizeof(pkt));

        struct iphdr  *iph = (struct iphdr *)pkt;
        struct tcphdr *tcp = (struct tcphdr *)(pkt + sizeof(struct iphdr));

        iph->ihl      = 5;
        iph->version  = 4;
        iph->tos      = 0;
        iph->tot_len  = htons((uint16_t)sizeof(pkt));
        iph->id       = htons((uint16_t)(rand() & 0xFFFF));
        iph->ttl      = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr    = src_ip;
        iph->daddr    = ip;
        iph->check    = 0; /* kernel computes */

        tcp->source  = htons(src_port);
        tcp->dest    = htons(ports[i]);
        tcp->seq     = htonl((uint32_t)rand());
        tcp->doff    = 5;
        tcp->syn     = 1;
        tcp->window  = htons(65535);
        tcp->check   = tcp_checksum(src_ip, ip, tcp, sizeof(struct tcphdr));

        struct sockaddr_in dst = {0};
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = ip;
        dst.sin_port = htons(ports[i]);

        sendto(send_sock, pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst));
    }

    /* Receive responses */
    char rbuf[4096];
    int  received = 0;
    while (received < nports) {
        ssize_t n = recvfrom(recv_sock, rbuf, sizeof(rbuf), 0, NULL, NULL);
        if (n < 0) break;
        if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;

        struct iphdr  *riph = (struct iphdr *)rbuf;
        int rip_hlen = riph->ihl * 4;
        struct tcphdr *rtcp = (struct tcphdr *)(rbuf + rip_hlen);

        if (riph->saddr != ip) continue;
        if (ntohs(rtcp->dest) != src_port) continue;

        uint16_t sport = ntohs(rtcp->source);
        for (int i = 0; i < nports; i++) {
            if (ports[i] != sport) continue;
            if (rtcp->syn && rtcp->ack) {
                results[i].state = STATE_OPEN;
                /* Send RST to avoid completing handshake */
                char rst[sizeof(struct iphdr) + sizeof(struct tcphdr)];
                memset(rst, 0, sizeof(rst));
                struct iphdr  *rih = (struct iphdr *)rst;
                struct tcphdr *rth = (struct tcphdr *)(rst + sizeof(struct iphdr));
                rih->ihl=5; rih->version=4;
                rih->tot_len=htons((uint16_t)sizeof(rst));
                rih->ttl=64; rih->protocol=IPPROTO_TCP;
                rih->saddr=src_ip; rih->daddr=ip;
                rth->source=htons(src_port);
                rth->dest=htons(sport);
                rth->seq=rtcp->ack_seq;
                rth->doff=5; rth->rst=1;
                rth->check=tcp_checksum(src_ip, ip, rth, sizeof(struct tcphdr));
                struct sockaddr_in rdst={0};
                rdst.sin_family=AF_INET; rdst.sin_addr.s_addr=ip;
                sendto(send_sock, rst, sizeof(rst), 0,
                       (struct sockaddr *)&rdst, sizeof(rdst));
            } else if (rtcp->rst) {
                results[i].state = STATE_CLOSED;
            }
            received++;
            break;
        }
    }

    close(send_sock);
    close(recv_sock);
}
