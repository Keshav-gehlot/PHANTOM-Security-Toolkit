/*
 * vuln.c — DELIBERATELY VULNERABLE PROGRAM
 * Part of phantom-bof: Buffer Overflow Study Tool
 *
 * PURPOSE: Educational demonstration of stack buffer overflow.
 *          DO NOT use this code in production.
 *
 * Compile: gcc -fno-stack-protector -z execstack -no-pie -o vuln vuln.c
 * Note:    May also need: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* -----------------------------------------------------------------------
 * UNSAFE: gets() reads unlimited bytes into a fixed buffer.
 * Stack layout (x86-64):
 *
 *   [  buf[128]  ] [  saved RBP  ] [  return addr  ] ...
 *    <-- 128 B -->   <-- 8 B -->     <-- 8 B -->
 *
 * Writing >= 136 bytes overwrites the return address.
 * ----------------------------------------------------------------------- */
void vulnerable_gets(void) {
    char buf[128];     /* UNSAFE: only 128 bytes allocated */
    printf("Enter your name: ");
    gets(buf);         /* UNSAFE: gets() performs NO bounds checking */
                       /* Writing >128 bytes overflows into saved RBP  */
                       /* Writing >136 bytes overwrites return address  */
    printf("Hello, %s!\n", buf);
}

/* -----------------------------------------------------------------------
 * UNSAFE: strcpy() performs no bounds checking.
 * If src > 64 bytes, dst overflows onto the stack.
 * ----------------------------------------------------------------------- */
void vulnerable_strcpy(const char *src) {
    char dst[64];       /* UNSAFE: fixed 64-byte buffer */
    strcpy(dst, src);   /* UNSAFE: copies until null terminator, no limit */
    printf("Copied: %s\n", dst);
}

/* -----------------------------------------------------------------------
 * UNSAFE: sprintf() can overflow if format+args exceed buffer.
 * ----------------------------------------------------------------------- */
void vulnerable_sprintf(const char *user_input) {
    char buf[32];
    sprintf(buf, "User: %s", user_input); /* UNSAFE: no length check */
    printf("%s\n", buf);
}

/* -----------------------------------------------------------------------
 * Helper: print stack addresses for educational analysis
 * ----------------------------------------------------------------------- */
static void print_stack_layout(void) {
    char buf[128];
    printf("\n=== Stack Layout (educational) ===\n");
    printf("buf        addr: %p\n", (void *)buf);
    printf("buf+128    addr: %p  <- saved RBP lives here\n", (void *)(buf+128));
    printf("buf+136    addr: %p  <- return address lives here\n", (void *)(buf+136));
    printf("================================\n\n");
}

int main(int argc, char *argv[]) {
    printf("=== PHANTOM-BOF: Vulnerable Demo ===\n");
    printf("Compiled WITHOUT stack protector (-fno-stack-protector)\n");
    printf("Compiled WITHOUT PIE (-no-pie)\n\n");

    print_stack_layout();

    if (argc > 1) {
        printf("[*] Testing vulnerable_strcpy with argv[1]...\n");
        vulnerable_strcpy(argv[1]);   /* Try: ./vuln $(python3 -c "print('A'*80)") */
    }

    printf("[*] Testing vulnerable_gets...\n");
    vulnerable_gets();

    return 0;
}
