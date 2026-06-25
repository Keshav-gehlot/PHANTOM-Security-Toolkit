#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/if_arp.h>

#define ARP_TABLE_SIZE  512
#define LOG_FILE        "arp_anomalies.log"

typedef struct {
    uint32_t ip;
    uint8_t  mac[ETH_ALEN];
    time_t   first_seen;
    time_t   last_seen;
    int      count;
    int      flagged;
} arp_entry_t;

typedef struct {
    char    interface[64];
    char    mode[16];        /* "monitor" or "spoof" */
    char    target_ip[32];
    char    gateway_ip[32];
    int     verbose;
    char    logfile[256];
} arp_config_t;

extern arp_config_t g_arp_cfg;

/* monitor.c */
void arp_monitor_run(void);
void arp_table_dump(void);

/* spoof.c */
void arp_spoof_run(void);

/* arp_utils.c */
void mac_to_str(const uint8_t *mac, char *out);
int  str_to_mac(const char *str, uint8_t *mac);
int  get_iface_mac(const char *iface, uint8_t *mac);
int  get_iface_ip(const char *iface, uint32_t *ip);
void arp_log(const char *msg);

#endif /* ARP_H */
