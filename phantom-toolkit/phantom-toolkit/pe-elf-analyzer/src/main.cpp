// main.cpp — phantom-analyzer entry point
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>
#include "../include/analyzer.h"

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s <binary> [options]\n"
        "  --json          JSON output\n"
        "  --strings-only  Only print extracted strings\n"
        "  --sections-only Only print section table\n", p);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 2) usage(argv[0]);

    const char *filename  = argv[1];
    int do_json    = 0;
    int str_only   = 0;
    int sec_only   = 0;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i],"--json"))         do_json  = 1;
        if (!strcmp(argv[i],"--strings-only")) str_only = 1;
        if (!strcmp(argv[i],"--sections-only"))sec_only = 1;
    }

    // Read file
    std::ifstream f(filename, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        fprintf(stderr, "Cannot open: %s\n", filename);
        return 1;
    }
    auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data((size_t)sz);
    f.read(reinterpret_cast<char *>(data.data()), sz);
    f.close();

    if (sz < 4) {
        fprintf(stderr, "File too small\n"); return 1;
    }

    // Detect format
    bin_info_t info;
    memset(&info, 0, sizeof(info));

    int rc = -1;
    if (data[0] == 0x4D && data[1] == 0x5A) {         // MZ — PE
        rc = parse_pe(data.data(), (size_t)sz, &info);
    } else if (data[0]==0x7f && data[1]=='E' &&
               data[2]=='L'  && data[3]=='F') {         // ELF
        rc = parse_elf(data.data(), (size_t)sz, &info);
    } else {
        fprintf(stderr, "Unknown format (not PE or ELF)\n");
        return 1;
    }

    if (rc < 0) {
        fprintf(stderr, "Parse error\n"); return 1;
    }

    // Extract strings
    extract_strings(data.data(), (size_t)sz, &info);

    if (str_only) {
        for (int i = 0; i < info.nstrings; i++) {
            const char *cat =
                info.strings[i].category==1?"[URL]":
                info.strings[i].category==2?"[IP] ":
                info.strings[i].category==3?"[REG]":
                info.strings[i].category==4?"[PATH]":
                info.strings[i].category==5?"[SUSP]":"     ";
            printf("%s %s\n", cat, info.strings[i].value);
        }
        return 0;
    }

    if (sec_only) {
        printf("%-16s %-12s %-12s %-8s %s\n","NAME","VADDR","SIZE","FLAGS","ENTROPY");
        for (int i=0;i<info.nsections;i++)
            printf("%-16s 0x%-10lx %-12lu 0x%-6x %.2f%s\n",
                   info.sections[i].name,
                   (unsigned long)info.sections[i].vaddr,
                   (unsigned long)info.sections[i].raw_size,
                   info.sections[i].flags,
                   info.sections[i].entropy,
                   info.sections[i].suspicious?" [!]":"");
        return 0;
    }

    print_report(&info, filename, do_json);
    return 0;
}
