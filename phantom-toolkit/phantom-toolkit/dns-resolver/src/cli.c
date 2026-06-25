/* cli.c — dig-style terminal output + JSON formatter */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/dns.h"

static const char *qtype_str(uint16_t t) {
    switch (t) {
        case DNS_T_A:    return "A";
        case DNS_T_AAAA: return "AAAA";
        case DNS_T_MX:   return "MX";
        case DNS_T_NS:   return "NS";
        case DNS_T_CNAME:return "CNAME";
        case DNS_T_PTR:  return "PTR";
        case DNS_T_TXT:  return "TXT";
        case DNS_T_SOA:  return "SOA";
        case DNS_T_SRV:  return "SRV";
        default:         return "?";
    }
}

static void print_section(const char *section, const dns_rr_t *rrs, int n) {
    if (n == 0) return;
    printf("\n;; %s SECTION:\n", section);
    for (int i = 0; i < n; i++) {
        printf("%-40s %-8u %-6s %-8s %s\n",
               rrs[i].name,
               rrs[i].ttl,
               "IN",
               qtype_str(rrs[i].type),
               rrs[i].rdata);
    }
}

static void print_json(const char *name, uint16_t qtype,
                       const dns_response_t *resp) {
    printf("{\n");
    printf("  \"query\": \"%s\",\n", name);
    printf("  \"type\": \"%s\",\n", qtype_str(qtype));
    printf("  \"rcode\": %d,\n", resp->rcode);
    printf("  \"rtt_ms\": %d,\n", resp->rtt_ms);
    printf("  \"answers\": [\n");
    for (int i = 0; i < resp->nanswers; i++) {
        printf("    {\"name\":\"%s\",\"type\":\"%s\","
               "\"ttl\":%u,\"data\":\"%s\"}%s\n",
               resp->answers[i].name,
               qtype_str(resp->answers[i].type),
               resp->answers[i].ttl,
               resp->answers[i].rdata,
               i < resp->nanswers-1 ? "," : "");
    }
    printf("  ]\n}\n");
}

void print_response(const char *name, uint16_t qtype,
                    const dns_response_t *resp) {
    if (g_json) {
        print_json(name, qtype, resp);
        return;
    }

    if (g_short_output) {
        for (int i = 0; i < resp->nanswers; i++) {
            if (resp->answers[i].type == qtype ||
                resp->answers[i].type == DNS_T_CNAME)
                printf("%s\n", resp->answers[i].rdata);
        }
        return;
    }

    /* dig-style */
    printf("\n; <<>> phantom-dns 1.0 <<>> %s %s\n",
           qtype_str(qtype), name);
    printf(";; Got answer:\n");
    printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: (query)\n",
           resp->rcode == 0 ? "NOERROR" :
           resp->rcode == 3 ? "NXDOMAIN" : "ERROR");
    printf(";; flags: qr rd ra; "
           "QUERY: 1, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
           resp->nanswers, resp->nauthority, resp->nadditional);

    printf("\n;; QUESTION SECTION:\n");
    printf(";%-39s %-6s %-8s %s\n", name, "IN", qtype_str(qtype), "");

    print_section("ANSWER",     resp->answers,    resp->nanswers);
    print_section("AUTHORITY",  resp->authority,  resp->nauthority);
    print_section("ADDITIONAL", resp->additional, resp->nadditional);

    printf("\n;; Query time: %d msec\n", resp->rtt_ms);
    printf(";; SERVER: %s#53\n", g_nameserver);
}
