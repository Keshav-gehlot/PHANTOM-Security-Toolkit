// report.cpp — structured terminal report + JSON output
#include <cstdio>
#include <cstring>
#include <cmath>
#include "../include/analyzer.h"

static void entropy_bar(double e) {
    // 0-8 scale, 20 chars wide
    int filled = (int)((e / 8.0) * 20);
    const char *color = e > 7.0 ? "\033[1;31m" :
                        e > 5.5 ? "\033[1;33m" : "\033[1;32m";
    printf("%s[", color);
    for (int i=0;i<20;i++) putchar(i<filled?'\xe2':' ');
    printf("]\033[0m %.2f", e);
}

static int compute_risk(const bin_info_t *info) {
    int score = 0;

    // High entropy sections
    for (int i=0;i<info->nsections;i++)
        if (info->sections[i].entropy > 7.0) score += 15;

    // W+X sections
    for (int i=0;i<info->nsections;i++)
        if (info->sections[i].suspicious &&
            (info->sections[i].flags & 0xC0000000) == 0xC0000000) score += 20;

    // Suspicious imports
    static const char *danger_imports[] = {
        "CreateRemoteThread","VirtualAlloc","WriteProcessMemory",
        "NtUnmapViewOfSection","SetWindowsHookEx","OpenProcess",
        nullptr
    };
    for (int i=0;i<info->nimports;i++)
        for (int j=0; danger_imports[j]; j++)
            if (strstr(info->imports[i].func, danger_imports[j])) { score+=10; break; }

    // Suspicious strings
    for (int i=0;i<info->nstrings;i++)
        if (info->strings[i].category == 5) score += 5;

    // Stripped binary
    if (info->is_stripped) score += 5;

    // No imports (packed?)
    if (info->nimports == 0) score += 20;

    // NX stack disabled
    if (info->format == FORMAT_ELF && !info->nx_stack) score += 15;

    return score > 100 ? 100 : score;
}

void print_report(const bin_info_t *info, const char *filename, int json) {
    int risk = compute_risk(info);
    const char *risk_label = risk >= 60 ? "MALICIOUS"  :
                             risk >= 30 ? "SUSPICIOUS" : "CLEAN";
    const char *risk_color = risk >= 60 ? "\033[1;31m"  :
                             risk >= 30 ? "\033[1;33m"  : "\033[1;32m";

    if (json) {
        printf("{\n");
        printf("  \"file\": \"%s\",\n", filename);
        printf("  \"format\": \"%s\",\n", info->format==FORMAT_PE?"PE":"ELF");
        printf("  \"arch\": \"%s\",\n", info->arch);
        printf("  \"bits\": %d,\n", info->bits);
        printf("  \"type\": \"%s\",\n", info->type);
        printf("  \"entry_point\": \"0x%lx\",\n", (unsigned long)info->entry_point);
        printf("  \"stripped\": %s,\n", info->is_stripped?"true":"false");
        printf("  \"risk_score\": %d,\n", risk);
        printf("  \"risk_label\": \"%s\",\n", risk_label);
        printf("  \"sections\": [\n");
        for (int i=0;i<info->nsections;i++) {
            printf("    {\"name\":\"%s\",\"entropy\":%.2f,\"suspicious\":%s}%s\n",
                   info->sections[i].name, info->sections[i].entropy,
                   info->sections[i].suspicious?"true":"false",
                   i<info->nsections-1?",":"");
        }
        printf("  ],\n");
        printf("  \"imports_count\": %d,\n", info->nimports);
        printf("  \"strings_count\": %d\n", info->nstrings);
        printf("}\n");
        return;
    }

    printf("\033[1;36m");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║          PHANTOM PE/ELF ANALYZER  v1.0              ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\033[0m");

    printf("\n\033[1m[FILE]\033[0m  %s\n", filename);
    printf("  Format     : %s%d\n", info->format==FORMAT_PE?"PE":"ELF", info->bits);
    printf("  Arch       : %s\n", info->arch);
    printf("  Type       : %s\n", info->type);
    printf("  Entry Point: 0x%lx\n", (unsigned long)info->entry_point);
    printf("  Stripped   : %s\n", info->is_stripped?"YES (no symbols)":"No");
    if (info->format == FORMAT_ELF)
        printf("  NX Stack   : %s\n", info->nx_stack?"\033[32mYes (protected)\033[0m":"\033[31mNO (executable stack!)\033[0m");

    // Sections
    printf("\n\033[1m[SECTIONS]\033[0m  %d section(s)\n", info->nsections);
    printf("  %-16s %-12s %-12s %-8s %s\n", "NAME","VADDR","SIZE","FLAGS","ENTROPY");
    printf("  %-16s %-12s %-12s %-8s %s\n", "----","-----","----","-----","-------");
    for (int i=0;i<info->nsections;i++) {
        const auto &s = info->sections[i];
        printf("  %-16s 0x%-10lx %-12lu 0x%-6x ",
               s.name, (unsigned long)s.vaddr,
               (unsigned long)s.raw_size, s.flags);
        entropy_bar(s.entropy);
        if (s.suspicious) printf("  \033[1;31m[!]\033[0m");
        printf("\n");
    }

    // Imports
    printf("\n\033[1m[IMPORTS]\033[0m  %d function(s)\n", info->nimports);
    int shown = 0;
    for (int i=0;i<info->nimports && shown<30;i++) {
        printf("  %-30s  %s\n", info->imports[i].dll, info->imports[i].func);
        shown++;
    }
    if (info->nimports > 30) printf("  ... and %d more\n", info->nimports-30);

    // Strings summary
    int urls=0, ips=0, regs=0, paths=0, susps=0;
    for (int i=0;i<info->nstrings;i++) {
        switch(info->strings[i].category) {
            case 1: urls++;  break;
            case 2: ips++;   break;
            case 3: regs++;  break;
            case 4: paths++; break;
            case 5: susps++; break;
        }
    }
    printf("\n\033[1m[STRINGS]\033[0m  %d total\n", info->nstrings);
    printf("  URLs: %d  IPs: %d  Registry: %d  Paths: %d  \033[1;31mSuspicious: %d\033[0m\n",
           urls, ips, regs, paths, susps);

    // Print suspicious strings
    if (susps > 0) {
        printf("\n  \033[1;31m[SUSPICIOUS STRINGS]\033[0m\n");
        for (int i=0;i<info->nstrings;i++)
            if (info->strings[i].category==5)
                printf("    >> %s\n", info->strings[i].value);
    }

    // Risk score
    printf("\n\033[1m[RISK ASSESSMENT]\033[0m\n");
    printf("  Score : %s%d/100\033[0m\n", risk_color, risk);
    printf("  Verdict: %s%s\033[0m\n\n", risk_color, risk_label);
}
