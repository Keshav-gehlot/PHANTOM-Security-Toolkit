/* packet.c — DNS packet construction and parsing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/dns.h"

/* Encode domain name as DNS labels */
static int encode_name(uint8_t *buf, int buflen, const char *name) {
    int pos = 0;
    char tmp[DNS_MAX_NAME];
    strncpy(tmp, name, sizeof(tmp)-1);
    char *tok = strtok(tmp, ".");
    while (tok) {
        int len = (int)strlen(tok);
        if (pos + len + 1 >= buflen) return -1;
        buf[pos++] = (uint8_t)len;
        memcpy(buf + pos, tok, (size_t)len);
        pos += len;
        tok = strtok(NULL, ".");
    }
    buf[pos++] = 0; /* root label */
    return pos;
}

/* Decode compressed DNS name */
static int decode_name(const uint8_t *pkt, int pktlen,
                        int offset, char *out, int outlen) {
    int jumped = 0, orig_offset = offset, jump_count = 0;
    int out_pos = 0;

    while (offset < pktlen) {
        uint8_t len = pkt[offset];
        if (len == 0) {
            if (!jumped) orig_offset = offset + 1;
            break;
        }
        /* Pointer */
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= pktlen) return -1;
            int ptr = ((len & 0x3F) << 8) | pkt[offset+1];
            if (!jumped) orig_offset = offset + 2;
            offset = ptr;
            jumped = 1;
            if (++jump_count > 20) return -1;
            continue;
        }
        offset++;
        if (out_pos + len + 1 >= outlen) return -1;
        if (out_pos > 0) out[out_pos++] = '.';
        memcpy(out + out_pos, pkt + offset, (size_t)len);
        out_pos += len;
        offset  += len;
    }
    out[out_pos] = '\0';
    return jumped ? orig_offset : offset + 1;
}

int dns_build_query(uint8_t *buf, int buflen, const char *name,
                    uint16_t qtype, uint16_t id) {
    memset(buf, 0, (size_t)buflen);
    dns_hdr_t *hdr = (dns_hdr_t *)buf;
    hdr->id      = htons(id);
    hdr->flags   = htons(0x0100); /* RD=1 */
    hdr->qdcount = htons(1);

    int pos = (int)sizeof(dns_hdr_t);
    int nlen = encode_name(buf + pos, buflen - pos, name);
    if (nlen < 0) return -1;
    pos += nlen;

    if (pos + 4 > buflen) return -1;
    *(uint16_t *)(buf + pos) = htons(qtype); pos += 2;
    *(uint16_t *)(buf + pos) = htons(DNS_C_IN); pos += 2;

    return pos;
}

static const char *type_str(uint16_t t) {
    switch (t) {
        case DNS_T_A:    return "A";
        case DNS_T_AAAA: return "AAAA";
        case DNS_T_CNAME:return "CNAME";
        case DNS_T_MX:   return "MX";
        case DNS_T_NS:   return "NS";
        case DNS_T_PTR:  return "PTR";
        case DNS_T_TXT:  return "TXT";
        case DNS_T_SOA:  return "SOA";
        case DNS_T_SRV:  return "SRV";
        default:         return "?";
    }
}

static int parse_rr(const uint8_t *pkt, int pktlen, int offset,
                    dns_rr_t *rr) {
    char name[DNS_MAX_NAME] = {0};
    offset = decode_name(pkt, pktlen, offset, name, sizeof(name));
    if (offset < 0 || offset + 10 > pktlen) return -1;

    strncpy(rr->name, name, sizeof(rr->name)-1);
    rr->type   = ntohs(*(uint16_t *)(pkt + offset));     offset += 2;
    rr->rclass = ntohs(*(uint16_t *)(pkt + offset));     offset += 2;
    rr->ttl    = ntohl(*(uint32_t *)(pkt + offset));     offset += 4;
    uint16_t rdlen = ntohs(*(uint16_t *)(pkt + offset)); offset += 2;

    if (offset + rdlen > pktlen) return -1;

    char rdata[512] = {0};
    if (rr->type == DNS_T_A && rdlen == 4) {
        memcpy(&rr->ip, pkt + offset, 4);
        inet_ntop(AF_INET, pkt + offset, rdata, sizeof(rdata));
    } else if (rr->type == DNS_T_AAAA && rdlen == 16) {
        memcpy(rr->ipv6, pkt + offset, 16);
        inet_ntop(AF_INET6, pkt + offset, rdata, sizeof(rdata));
    } else if (rr->type == DNS_T_CNAME || rr->type == DNS_T_NS ||
               rr->type == DNS_T_PTR) {
        decode_name(pkt, pktlen, offset, rdata, sizeof(rdata));
    } else if (rr->type == DNS_T_MX) {
        rr->priority = ntohs(*(uint16_t *)(pkt + offset));
        char mx_host[DNS_MAX_NAME] = {0};
        decode_name(pkt, pktlen, offset+2, mx_host, sizeof(mx_host));
        snprintf(rdata, sizeof(rdata), "%u %s", rr->priority, mx_host);
    } else if (rr->type == DNS_T_TXT) {
        uint8_t tlen = pkt[offset];
        int copy = tlen < 511 ? tlen : 511;
        memcpy(rdata, pkt + offset + 1, (size_t)copy);
        rdata[copy] = '\0';
    } else {
        snprintf(rdata, sizeof(rdata), "[%u bytes %s]", rdlen, type_str(rr->type));
    }
    strncpy(rr->rdata, rdata, sizeof(rr->rdata)-1);
    return offset + rdlen;
}

int dns_parse_response(const uint8_t *buf, int len, dns_response_t *resp) {
    if (len < (int)sizeof(dns_hdr_t)) return -1;
    memset(resp, 0, sizeof(*resp));

    const dns_hdr_t *hdr = (const dns_hdr_t *)buf;
    uint16_t flags    = ntohs(hdr->flags);
    resp->rcode       = flags & DNS_RCODE_MASK;
    int qdcount       = ntohs(hdr->qdcount);
    int ancount       = ntohs(hdr->ancount);
    int nscount       = ntohs(hdr->nscount);
    int arcount       = ntohs(hdr->arcount);

    int offset = (int)sizeof(dns_hdr_t);

    /* Skip questions */
    char tmp[DNS_MAX_NAME];
    for (int i = 0; i < qdcount; i++) {
        offset = decode_name(buf, len, offset, tmp, sizeof(tmp));
        if (offset < 0) return -1;
        offset += 4; /* qtype + qclass */
    }

    /* Parse answers */
    for (int i = 0; i < ancount && resp->nanswers < DNS_MAX_RR; i++) {
        offset = parse_rr(buf, len, offset, &resp->answers[resp->nanswers]);
        if (offset < 0) break;
        resp->nanswers++;
    }
    /* Parse authority */
    for (int i = 0; i < nscount && resp->nauthority < DNS_MAX_RR; i++) {
        offset = parse_rr(buf, len, offset, &resp->authority[resp->nauthority]);
        if (offset < 0) break;
        resp->nauthority++;
    }
    /* Parse additional */
    for (int i = 0; i < arcount && resp->nadditional < DNS_MAX_RR; i++) {
        offset = parse_rr(buf, len, offset, &resp->additional[resp->nadditional]);
        if (offset < 0) break;
        resp->nadditional++;
    }
    return 0;
}
