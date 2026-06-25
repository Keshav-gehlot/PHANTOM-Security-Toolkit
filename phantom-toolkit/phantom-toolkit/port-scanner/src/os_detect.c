/* os_detect.c — TTL + TCP window fingerprinting */
#include <stdio.h>
#include <string.h>
#include "../include/scanner.h"

void os_detect(uint32_t ip, int ttl, char *out, int outlen) {
    (void)ip;
    /* TTL-based OS guess */
    if (ttl <= 0) {
        snprintf(out, outlen, "Unknown (no TTL)");
    } else if (ttl <= 64) {
        snprintf(out, outlen, "Linux/Unix (TTL=%d)", ttl);
    } else if (ttl <= 128) {
        snprintf(out, outlen, "Windows (TTL=%d)", ttl);
    } else if (ttl <= 255) {
        snprintf(out, outlen, "Cisco/BSD/Solaris (TTL=%d)", ttl);
    } else {
        snprintf(out, outlen, "Unknown (TTL=%d)", ttl);
    }
}
