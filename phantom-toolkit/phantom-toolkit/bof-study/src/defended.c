/*
 * defended.c — HARDENED VERSION of vuln.c
 * Part of phantom-bof: Buffer Overflow Study Tool
 *
 * Compile: gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE
 *               -Wformat -Wformat-security -o defended defended.c
 *
 * Mitigations applied:
 *   1. fgets()  instead of gets()       — bounds-checked input
 *   2. strncpy() instead of strcpy()    — explicit length limit
 *   3. snprintf() instead of sprintf()  — format + length safe
 *   4. Manual stack canary demo         — detect overflow before return
 *   5. Compile flags enforce ASLR+PIE   — randomise address space
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

/* -----------------------------------------------------------------------
 * Manual stack canary implementation (educational).
 * Real compilers insert this automatically with -fstack-protector.
 *
 * A secret random value is placed BETWEEN the buffer and the saved RBP.
 * Before returning, we check it hasn't changed. If it has, an attacker
 * overwrote the stack — we abort instead of jumping to attacker code.
 * ----------------------------------------------------------------------- */
static uint64_t g_canary_secret = 0;

static void canary_init(void) {
    /* Seed with time + addr of stack variable for entropy */
    uint64_t x = (uint64_t)time(NULL);
    uint64_t y = (uint64_t)(uintptr_t)&x;
    g_canary_secret = x ^ (y << 17) ^ 0xDEADBEEFCAFEBABEULL;
}

static void canary_check(uint64_t observed, const char *fn) {
    if (observed != g_canary_secret) {
        fprintf(stderr,
            "\n*** STACK SMASHING DETECTED in %s ***\n"
            "*** Canary expected: 0x%016lx ***\n"
            "*** Canary found:    0x%016lx ***\n"
            "*** ABORTING ***\n",
            fn,
            (unsigned long)g_canary_secret,
            (unsigned long)observed);
        abort();
    }
}

/* SAFE: fgets() limits read to sizeof(buf)-1 bytes */
void safe_input(void) {
    char buf[128];
    uint64_t canary = g_canary_secret;   /* push canary onto stack */

    printf("Enter your name: ");
    fgets(buf, sizeof(buf), stdin);      /* SAFE: hard limit */
    buf[strcspn(buf, "\n")] = '\0';      /* strip newline */

    canary_check(canary, __func__);      /* verify canary intact */
    printf("Hello, %s!\n", buf);
}

/* SAFE: strncpy() + explicit null termination */
void safe_copy(const char *src) {
    char dst[64];
    uint64_t canary = g_canary_secret;

    strncpy(dst, src, sizeof(dst)-1);    /* SAFE: length bounded */
    dst[sizeof(dst)-1] = '\0';           /* guaranteed null terminator */

    canary_check(canary, __func__);
    printf("Copied: %s\n", dst);
}

/* SAFE: snprintf() checks format + length */
void safe_format(const char *user_input) {
    char buf[32];
    uint64_t canary = g_canary_secret;

    snprintf(buf, sizeof(buf), "User: %s", user_input);  /* SAFE */

    canary_check(canary, __func__);
    printf("%s\n", buf);
}

/* Print a comparison of defenses */
static void explain_mitigations(void) {
    printf("\n=== Applied Mitigations ===\n");
    printf("  [1] Stack canary   : random 8-byte value before saved RBP\n");
    printf("      Secret value   : 0x%016lx\n", (unsigned long)g_canary_secret);
    printf("  [2] ASLR + PIE     : base address randomised each run\n");
    printf("  [3] _FORTIFY_SOURCE: libc checks buffer sizes at runtime\n");
    printf("  [4] fgets/strncpy  : all input functions are bounds-checked\n");
    printf("  [5] NX bit (hardware): stack memory not executable\n");
    printf("===========================\n\n");
}

int main(int argc, char *argv[]) {
    canary_init();

    printf("=== PHANTOM-BOF: Defended Demo ===\n");
    printf("Compiled WITH -fstack-protector-strong -pie -D_FORTIFY_SOURCE=2\n\n");

    explain_mitigations();

    if (argc > 1) {
        printf("[*] Testing safe_copy with argv[1]...\n");
        safe_copy(argv[1]);
        printf("[*] safe_format...\n");
        safe_format(argv[1]);
    }

    printf("[*] Testing safe_input...\n");
    safe_input();

    printf("[+] All operations completed safely.\n");
    return 0;
}
