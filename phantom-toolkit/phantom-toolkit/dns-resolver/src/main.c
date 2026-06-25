/* main.c — phantom-dns entry point */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "../include/dns.h"

static uint16_t parse_qtype(const char *s) {
    if (!s) return DNS_T_A;
    if (strcasecmp(s,"A")    == 0) return DNS_T_A;
    if (strcasecmp(s,"AAAA") == 0) return DNS_T_AAAA;
    if (strcasecmp(s,"MX")   == 0) return DNS_T_MX;
    if (strcasecmp(s,"NS")   == 0) return DNS_T_NS;
    if (strcasecmp(s,"CNAME")== 0) return DNS_T_CNAME;
    if (strcasecmp(s,"PTR")  == 0) return DNS_T_PTR;
    if (strcasecmp(s,"TXT")  == 0) return DNS_T_TXT;
    if (strcasecmp(s,"SOA")  == 0) return DNS_T_SOA;
    if (strcasecmp(s,"SRV")  == 0) return DNS_T_SRV;
    return DNS_T_A;
}

/* Build reverse PTR name from IPv4: 1.2.3.4 -> 4.3.2.1.in-addr.arpa */
static void make_ptr_name(const char *ip, char *out, int outlen) {
    unsigned int a,b,c,d;
    if (sscanf(ip, "%u.%u.%u.%u", &a,&b,&c,&d) == 4)
        snprintf(out, outlen, "%u.%u.%u.%u.in-addr.arpa", d,c,b,a);
    else
        strncpy(out, ip, outlen-1);
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s <name> [TYPE] [options]\n"
        "  --server <ip>    Use specific resolver (default: 8.8.8.8)\n"
        "  --recursive      Iterative resolution from root servers\n"
        "  --ptr <ip>       Reverse DNS lookup\n"
        "  --short          Short output (answers only)\n"
        "  --json           JSON output\n"
        "  --trace          Show resolution hops\n"
        "  --tcp            Force TCP transport\n"
        "  --show-cache     Dump cache contents\n"
        "  -v               Verbose\n", p);
    exit(1);
}

int main(int argc, char *argv[]) {
    cache_init();

    if (argc < 2) usage(argv[0]);

    static struct option opts[] = {
        {"server",     required_argument, 0, 's'},
        {"recursive",  no_argument,       0, 'r'},
        {"ptr",        required_argument, 0, 'P'},
        {"short",      no_argument,       0, 'S'},
        {"json",       no_argument,       0, 'j'},
        {"trace",      no_argument,       0, 't'},
        {"tcp",        no_argument,       0, 'T'},
        {"show-cache", no_argument,       0, 'c'},
        {0,0,0,0}
    };

    char   name[DNS_MAX_NAME] = "";
    char   ptr_ip[64]         = "";
    int    do_recursive       = 0;
    int    show_cache         = 0;
    uint16_t qtype            = DNS_T_A;

    /* First non-option arg is the name */
    int name_set = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            if (!name_set) {
                strncpy(name, argv[i], sizeof(name)-1);
                name_set = 1;
            } else {
                /* Could be type */
                qtype = parse_qtype(argv[i]);
            }
        }
    }

    int opt, idx;
    optind = 1;
    while ((opt = getopt_long(argc, argv, "vs:", opts, &idx)) != -1) {
        switch (opt) {
            case 's': strncpy(g_nameserver, optarg, sizeof(g_nameserver)-1); break;
            case 'r': do_recursive  = 1; g_trace = 0; break;
            case 'P': strncpy(ptr_ip, optarg, sizeof(ptr_ip)-1); break;
            case 'S': g_short_output = 1; break;
            case 'j': g_json    = 1; break;
            case 't': g_trace   = 1; do_recursive = 1; break;
            case 'T': g_use_tcp = 1; break;
            case 'c': show_cache = 1; break;
            case 'v': g_verbose = 1; break;
        }
    }

    /* PTR lookup */
    if (ptr_ip[0]) {
        make_ptr_name(ptr_ip, name, sizeof(name));
        qtype = DNS_T_PTR;
    }

    if (!name[0]) usage(argv[0]);

    if (!g_json && !g_short_output) {
        printf("\033[1;35m"
               "╔══════════════════════════════════════╗\n"
               "║     PHANTOM-DNS  v1.0                ║\n"
               "║     DNS Resolver from Scratch        ║\n"
               "╚══════════════════════════════════════╝\n"
               "\033[0m");
    }

    dns_response_t resp;
    int rc;

    if (do_recursive) {
        rc = resolve(name, qtype, &resp);
    } else {
        rc = dns_query(g_nameserver, name, qtype, &resp);
        /* Store in cache */
        if (rc == 0 && resp.nanswers > 0)
            cache_put(name, qtype, resp.answers, resp.nanswers,
                      resp.answers[0].ttl);
    }

    if (rc < 0) {
        fprintf(stderr, ";; Query failed for %s\n", name);
        return 1;
    }

    print_response(name, qtype, &resp);

    if (show_cache) cache_dump();

    return resp.rcode;
}
