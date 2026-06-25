/* resolve.c — iterative resolution from root + CNAME following */
#include <stdio.h>
#include <string.h>
#include "../include/dns.h"

/* Root nameservers (a–m.root-servers.net) */
static const char *ROOT_SERVERS[] = {
    "198.41.0.4",    /* a.root-servers.net */
    "199.9.14.201",  /* b.root-servers.net */
    "192.33.4.12",   /* c.root-servers.net */
    "199.7.91.13",   /* d.root-servers.net */
    "192.203.230.10",/* e.root-servers.net */
    "192.5.5.241",   /* f.root-servers.net */
    "192.112.36.4",  /* g.root-servers.net */
    NULL
};

static int iterate_resolve(const char *name, uint16_t qtype,
                            dns_response_t *resp, int depth) {
    if (depth > 20) return -1;

    const char *ns = ROOT_SERVERS[0];
    char current_ns[64];
    strncpy(current_ns, ns, sizeof(current_ns)-1);

    for (int hop = 0; hop < 32; hop++) {
        if (g_trace)
            printf(";; [TRACE] hop=%d querying %s for %s\n",
                   hop, current_ns, name);

        dns_response_t r;
        if (dns_query(current_ns, name, qtype, &r) < 0) return -1;

        /* Got an answer */
        if (r.nanswers > 0) {
            *resp = r;
            return 0;
        }

        /* Got referral in authority section */
        if (r.nauthority > 0) {
            /* Try to find a glue record in additional */
            const char *ns_name = r.authority[0].rdata;
            for (int i = 0; i < r.nadditional; i++) {
                if (strcasecmp(r.additional[i].name, ns_name) == 0 &&
                    r.additional[i].type == DNS_T_A) {
                    strncpy(current_ns,
                            r.additional[i].rdata,
                            sizeof(current_ns)-1);
                    goto next_hop;
                }
            }
            /* No glue — resolve the NS itself recursively */
            dns_response_t ns_resp;
            if (iterate_resolve(ns_name, DNS_T_A, &ns_resp, depth+1) == 0 &&
                ns_resp.nanswers > 0) {
                strncpy(current_ns,
                        ns_resp.answers[0].rdata,
                        sizeof(current_ns)-1);
                goto next_hop;
            }
            return -1;
        }
        return -1;
next_hop:;
    }
    return -1;
}

int resolve(const char *name, uint16_t qtype, dns_response_t *resp) {
    /* Check cache first */
    cache_entry_t *cached = cache_get(name, qtype);
    if (cached) {
        resp->nanswers = cached->nrrs;
        memcpy(resp->answers, cached->rrs,
               (size_t)cached->nrrs * sizeof(dns_rr_t));
        resp->rcode   = 0;
        resp->rtt_ms  = 0;
        if (g_verbose) printf(";; (cache hit)\n");
        return 0;
    }

    int rc;
    if (g_trace) {
        rc = iterate_resolve(name, qtype, resp, 0);
    } else {
        rc = dns_query(g_nameserver, name, qtype, resp);
    }

    if (rc == 0 && resp->nanswers > 0) {
        /* Follow CNAME chain */
        int cname_hops = 0;
        while (cname_hops < DNS_MAX_CNAME) {
            int found_cname = 0;
            for (int i = 0; i < resp->nanswers; i++) {
                if (resp->answers[i].type == DNS_T_CNAME) {
                    char cname_target[DNS_MAX_NAME];
                    strncpy(cname_target, resp->answers[i].rdata,
                            sizeof(cname_target)-1);
                    if (g_verbose)
                        printf(";; CNAME %s -> %s\n", name, cname_target);
                    dns_response_t cr;
                    if (dns_query(g_nameserver, cname_target, qtype, &cr) == 0) {
                        /* Merge answers */
                        for (int j = 0; j < cr.nanswers &&
                             resp->nanswers < DNS_MAX_RR; j++) {
                            resp->answers[resp->nanswers++] = cr.answers[j];
                        }
                    }
                    found_cname = 1;
                    cname_hops++;
                    break;
                }
            }
            if (!found_cname) break;
        }

        /* Store in cache */
        uint32_t min_ttl = resp->answers[0].ttl;
        for (int i = 1; i < resp->nanswers; i++)
            if (resp->answers[i].ttl < min_ttl) min_ttl = resp->answers[i].ttl;
        cache_put(name, qtype, resp->answers, resp->nanswers, min_ttl);
    }
    return rc;
}
