#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>
#include <stdio.h>

#define MAX_SECTIONS   96
#define MAX_IMPORTS    512
#define MAX_STRINGS    2048
#define MIN_STR_LEN    5

typedef enum { FORMAT_UNKNOWN, FORMAT_PE, FORMAT_ELF } bin_format_t;

typedef struct {
    char     name[16];
    uint64_t vaddr;
    uint64_t raw_size;
    uint64_t virt_size;
    uint32_t flags;
    double   entropy;
    int      suspicious;   /* wx, high entropy */
} section_t;

typedef struct {
    char dll[128];
    char func[128];
} import_t;

typedef struct {
    char   value[512];
    int    category;  /* 0=generic,1=url,2=ip,3=registry,4=path,5=suspicious */
} extracted_str_t;

typedef struct {
    bin_format_t format;
    int          bits;           /* 32 or 64 */
    uint64_t     entry_point;
    char         arch[32];
    char         type[32];       /* EXE/DLL/SO/EXEC */
    int          is_stripped;
    int          nx_stack;       /* ELF: PT_GNU_STACK exec? */

    section_t    sections[MAX_SECTIONS];
    int          nsections;

    import_t     imports[MAX_IMPORTS];
    int          nimports;

    char         exports[MAX_IMPORTS][128];
    int          nexports;

    extracted_str_t strings[MAX_STRINGS];
    int          nstrings;

    int          risk_score;     /* 0–100 */
    char         risk_label[16]; /* CLEAN / SUSPICIOUS / MALICIOUS */
} bin_info_t;

/* pe_parser.cpp */
int parse_pe(const uint8_t *data, size_t len, bin_info_t *info);

/* elf_parser.cpp */
int parse_elf(const uint8_t *data, size_t len, bin_info_t *info);

/* string_extractor.cpp */
void extract_strings(const uint8_t *data, size_t len, bin_info_t *info);

/* entropy.cpp */
double shannon_entropy(const uint8_t *data, size_t len);

/* report.cpp */
void print_report(const bin_info_t *info, const char *filename, int json);

#endif /* ANALYZER_H */
