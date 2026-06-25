#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <netinet/in.h>

#define DNS_PORT        53
#define DNS_MAX_PKT     4096
#define DNS_MAX_NAME    256
#define DNS_MAX_RR      64
#define DNS_TIMEOUT_SEC 5
#define DNS_RETRIES     3
#define DNS_CACHE_SIZE  512
#define DNS_MAX_CNAME   10

/* DNS Header (RFC 1035) */
typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_hdr_t;

#define DNS_QR_RESPONSE  0x8000
#define DNS_AA           0x0400
#define DNS_TC           0x0200
#define DNS_RD           0x0100
#define DNS_RA           0x0080
#define DNS_RCODE_MASK   0x000F

/* Record types */
#define DNS_T_A      1
#define DNS_T_NS     2
#define DNS_T_CNAME  5
#define DNS_T_SOA    6
#define DNS_T_PTR   12
#define DNS_T_MX    15
#define DNS_T_TXT   16
#define DNS_T_AAAA  28
#define DNS_T_SRV   33
#define DNS_T_CAA  257
#define DNS_C_IN     1

typedef struct {
    char     name[DNS_MAX_NAME];
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    char     rdata[512];     /* human-readable */
    uint32_t ip;             /* for A records */
    uint8_t  ipv6[16];       /* for AAAA records */
    uint16_t priority;       /* for MX/SRV */
} dns_rr_t;

typedef struct {
    dns_rr_t answers[DNS_MAX_RR];
    int      nanswers;
    dns_rr_t authority[DNS_MAX_RR];
    int      nauthority;
    dns_rr_t additional[DNS_MAX_RR];
    int      nadditional;
    int      rcode;
    int      rtt_ms;
} dns_response_t;

typedef struct {
    char     name[DNS_MAX_NAME];
    uint16_t type;
    dns_rr_t rrs[DNS_MAX_RR];
    int      nrrs;
    time_t   expires;
} cache_entry_t;

extern char    g_nameserver[64];
extern int     g_use_tcp;
extern int     g_verbose;
extern int     g_json;
extern int     g_short_output;
extern int     g_trace;

/* packet.c */
int  dns_build_query(uint8_t *buf, int buflen, const char *name,
                     uint16_t qtype, uint16_t id);
int  dns_parse_response(const uint8_t *buf, int len, dns_response_t *resp);

/* query.c */
int  dns_query(const char *server, const char *name, uint16_t qtype,
               dns_response_t *resp);

/* cache.c */
void         cache_init(void);
cache_entry_t *cache_get(const char *name, uint16_t type);
void         cache_put(const char *name, uint16_t type,
                       dns_rr_t *rrs, int nrrs, uint32_t ttl);

/* resolve.c */
int  resolve(const char *name, uint16_t qtype, dns_response_t *resp);

/* cli.c */
void print_response(const char *name, uint16_t qtype,
                    const dns_response_t *resp);

#endif /* DNS_H */
