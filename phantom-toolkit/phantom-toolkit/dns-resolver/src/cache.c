/* cache.c — in-memory DNS cache with TTL expiry */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/dns.h"

static cache_entry_t g_cache[DNS_CACHE_SIZE];
static int g_cache_count = 0;
static long g_hits = 0, g_misses = 0;

void cache_init(void) {
    memset(g_cache, 0, sizeof(g_cache));
}

cache_entry_t *cache_get(const char *name, uint16_t type) {
    time_t now = time(NULL);
    for (int i = 0; i < g_cache_count; i++) {
        if (g_cache[i].type == type &&
            strcasecmp(g_cache[i].name, name) == 0) {
            if (now >= g_cache[i].expires) {
                /* Expired — evict */
                g_cache[i] = g_cache[--g_cache_count];
                g_misses++;
                return NULL;
            }
            g_hits++;
            return &g_cache[i];
        }
    }
    g_misses++;
    return NULL;
}

void cache_put(const char *name, uint16_t type,
               dns_rr_t *rrs, int nrrs, uint32_t ttl) {
    if (g_cache_count >= DNS_CACHE_SIZE) {
        /* Evict oldest */
        int oldest = 0;
        for (int i = 1; i < g_cache_count; i++)
            if (g_cache[i].expires < g_cache[oldest].expires) oldest = i;
        g_cache[oldest] = g_cache[--g_cache_count];
    }
    cache_entry_t *e = &g_cache[g_cache_count++];
    strncpy(e->name, name, sizeof(e->name)-1);
    e->type    = type;
    e->nrrs    = nrrs < DNS_MAX_RR ? nrrs : DNS_MAX_RR;
    e->expires = time(NULL) + ttl;
    memcpy(e->rrs, rrs, (size_t)e->nrrs * sizeof(dns_rr_t));
}

void cache_dump(void) {
    time_t now = time(NULL);
    printf(";; Cache: %d entries | hits=%ld misses=%ld\n",
           g_cache_count, g_hits, g_misses);
    for (int i = 0; i < g_cache_count; i++) {
        long ttl_left = (long)(g_cache[i].expires - now);
        printf("  %-40s %-6s TTL=%lds\n",
               g_cache[i].name,
               g_cache[i].type == DNS_T_A    ? "A"    :
               g_cache[i].type == DNS_T_AAAA ? "AAAA" :
               g_cache[i].type == DNS_T_MX   ? "MX"   : "?",
               ttl_left > 0 ? ttl_left : 0L);
    }
}
