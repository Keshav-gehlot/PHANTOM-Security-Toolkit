/* arp_utils.c */
#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "../include/arp.h"

arp_config_t g_arp_cfg;

void mac_to_str(const uint8_t *mac, char *out) {
    snprintf(out, 32, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

int str_to_mac(const char *str, uint8_t *mac) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) == 6 ? 0 : -1;
}

int get_iface_mac(const char *iface, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

int get_iface_ip(const char *iface, uint32_t *ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return -1; }
    if (ip) *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    close(fd);
    return 0;
}

static FILE *g_logfp = NULL;
void arp_log(const char *msg) {
    if (!g_logfp) g_logfp = fopen(g_arp_cfg.logfile[0] ? g_arp_cfg.logfile : LOG_FILE, "a");
    if (!g_logfp) return;
    char ts[32]; time_t t = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(g_logfp, "[%s] %s\n", ts, msg);
    fflush(g_logfp);
}
