// pe_analyzer.cpp — PHANTOM PE Analyzer
// Ported from phantom-toolkit/pe-elf-analyzer/ (pe_parser.cpp, string_extractor.cpp, report.cpp, entropy.cpp)
// Features: PE32/PE32+ parsing, Shannon entropy, import table, suspicious string extraction, risk scoring
// Pure portable C++17 — no platform-specific Windows APIs needed for parsing
#include "phantom/modules.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <cctype>
#include <iomanip>
#include <algorithm>

namespace phantom::modules {

// ─────────────────────────────────────────────────────────────────────────────
// 1. PE Structures  (from pe_parser.cpp)
// ─────────────────────────────────────────────────────────────────────────────
#pragma pack(push, 1)
struct dos_hdr {
    uint16_t e_magic;    // MZ
    uint8_t  _pad[58];
    int32_t  e_lfanew;  // offset to PE header
};
struct coff_hdr {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};
struct opt_hdr32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint8_t  _rest[176];
};
struct opt_hdr64 {
    uint16_t Magic;
    uint8_t  _pad[2];
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint8_t  _rest[176];
};
struct data_dir  { uint32_t VirtualAddress; uint32_t Size; };
struct section_hdr {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint8_t  _pad[12];
    uint32_t Characteristics;
};
struct import_dir {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};
#pragma pack(pop)

#define SEC_MEM_WRITE   0x80000000u
#define SEC_MEM_EXECUTE 0x20000000u

// ─────────────────────────────────────────────────────────────────────────────
// 2. Data Structures
// ─────────────────────────────────────────────────────────────────────────────
static const int MAX_SECTIONS = 64;
static const int MAX_IMPORTS  = 1024;
static const int MAX_STRINGS  = 4096;
static const int MIN_STR_LEN  = 5;

struct SectionInfo {
    char     name[16];
    uint64_t vaddr;
    uint32_t virt_size;
    uint32_t raw_size;
    uint32_t flags;
    double   entropy;
    bool     suspicious; // W+X or high entropy
};

struct ImportEntry {
    char dll[128];
    char func[128];
};

struct StringEntry {
    char value[256];
    int  category; // 0=plain, 1=URL, 2=IP, 3=registry, 4=path, 5=suspicious
};

struct BinInfo {
    // Metadata
    char     arch[16];
    char     type[16]; // EXE, DLL
    int      bits;     // 32 or 64
    uint64_t entry_point;
    bool     is_stripped;
    // Sections
    SectionInfo sections[MAX_SECTIONS];
    int         nsections;
    // Imports
    ImportEntry imports[MAX_IMPORTS];
    int         nimports;
    // Strings
    StringEntry strings[MAX_STRINGS];
    int         nstrings;
};

// ─────────────────────────────────────────────────────────────────────────────
// 3. Shannon Entropy  (from entropy.cpp)
// ─────────────────────────────────────────────────────────────────────────────
static double shannon_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    uint64_t freq[256] = {};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / len;
        e -= p * log2(p);
    }
    return e;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. PE Parser  (from pe_parser.cpp)
// ─────────────────────────────────────────────────────────────────────────────
static uint32_t rva_to_offset(const section_hdr* secs, int n, uint32_t rva) {
    for (int i = 0; i < n; i++)
        if (rva >= secs[i].VirtualAddress &&
            rva <  secs[i].VirtualAddress + secs[i].SizeOfRawData)
            return secs[i].PointerToRawData + (rva - secs[i].VirtualAddress);
    return 0;
}

static bool parse_pe(const uint8_t* data, size_t len, BinInfo& info) {
    if (len < sizeof(dos_hdr)) return false;
    const auto* dos = reinterpret_cast<const dos_hdr*>(data);
    if (dos->e_magic != 0x5A4D) return false; // MZ check

    size_t pe_off = (size_t)(uint32_t)dos->e_lfanew;
    if (pe_off + 4 + sizeof(coff_hdr) >= len) return false;
    if (*(uint32_t*)(data + pe_off) != 0x00004550) return false; // PE\0\0

    const auto* coff = reinterpret_cast<const coff_hdr*>(data + pe_off + 4);
    uint16_t opt_magic = *(uint16_t*)(data + pe_off + 4 + sizeof(coff_hdr));

    info.bits = (opt_magic == 0x020B) ? 64 : 32;

    // Architecture
    switch (coff->Machine) {
        case 0x014C: strncpy_s(info.arch, "x86",    sizeof(info.arch) - 1); break;
        case 0x8664: strncpy_s(info.arch, "x86_64", sizeof(info.arch) - 1); break;
        case 0xAA64: strncpy_s(info.arch, "ARM64",  sizeof(info.arch) - 1); break;
        default:     snprintf(info.arch, sizeof(info.arch), "0x%04x", coff->Machine);
    }

    // File type
    uint16_t ch = coff->Characteristics;
    if      (ch & 0x2000) strncpy_s(info.type, "DLL",        sizeof(info.type) - 1);
    else if (ch & 0x0002) strncpy_s(info.type, "EXE",        sizeof(info.type) - 1);
    else                  strncpy_s(info.type, "OBJ/Unknown", sizeof(info.type) - 1);
    info.is_stripped = (ch & 0x0200) != 0;

    // Entry point
    size_t opt_off = pe_off + 4 + sizeof(coff_hdr);
    if (info.bits == 32) {
        const auto* opt = reinterpret_cast<const opt_hdr32*>(data + opt_off);
        info.entry_point = opt->AddressOfEntryPoint;
    } else {
        const auto* opt = reinterpret_cast<const opt_hdr64*>(data + opt_off);
        info.entry_point = opt->AddressOfEntryPoint;
    }

    // Sections
    size_t sec_off = opt_off + coff->SizeOfOptionalHeader;
    int nsec = std::min((int)coff->NumberOfSections, MAX_SECTIONS);
    const auto* secs = reinterpret_cast<const section_hdr*>(data + sec_off);
    info.nsections = nsec;

    for (int i = 0; i < nsec; i++) {
        auto& s = info.sections[i];
        memset(s.name, 0, sizeof(s.name));
        memcpy(s.name, secs[i].Name, 8);
        s.vaddr     = secs[i].VirtualAddress;
        s.virt_size = secs[i].VirtualSize;
        s.raw_size  = secs[i].SizeOfRawData;
        s.flags     = secs[i].Characteristics;

        uint32_t roff = secs[i].PointerToRawData;
        uint32_t rsz  = secs[i].SizeOfRawData;
        if (roff + rsz <= len && rsz > 0)
            s.entropy = shannon_entropy(data + roff, rsz);

        bool wx       = (s.flags & SEC_MEM_WRITE) && (s.flags & SEC_MEM_EXECUTE);
        bool high_ent = s.entropy > 7.0;
        s.suspicious  = wx || high_ent;
    }

    // Import table (data directory entry 1, offset 8 bytes into data dirs)
    size_t dd_off = opt_off + (info.bits == 32 ? 96 : 112);
    if (dd_off + 8 <= len) {
        const auto* imp_dd = reinterpret_cast<const data_dir*>(data + dd_off + 8);
        uint32_t imp_rva = imp_dd->VirtualAddress;
        if (imp_rva) {
            uint32_t imp_off = rva_to_offset(secs, nsec, imp_rva);
            while (imp_off && imp_off + sizeof(import_dir) <= len &&
                   info.nimports < MAX_IMPORTS - 1) {
                const auto* id = reinterpret_cast<const import_dir*>(data + imp_off);
                if (!id->Name && !id->FirstThunk) break;

                uint32_t name_off = rva_to_offset(secs, nsec, id->Name);
                if (!name_off || name_off >= len) { imp_off += sizeof(import_dir); continue; }

                const char* dll_name = reinterpret_cast<const char*>(data + name_off);

                uint32_t thunk_rva = id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk;
                uint32_t thunk_off = rva_to_offset(secs, nsec, thunk_rva);

                while (thunk_off && thunk_off + 4 <= len && info.nimports < MAX_IMPORTS) {
                    uint32_t entry = *(uint32_t*)(data + thunk_off);
                    if (!entry) break;
                    if (!(entry & 0x80000000u)) {
                        uint32_t hint_off = rva_to_offset(secs, nsec, entry);
                        if (hint_off + 2 < len) {
                            const char* fn = reinterpret_cast<const char*>(data + hint_off + 2);
                            strncpy_s(info.imports[info.nimports].dll,  128, dll_name, _TRUNCATE);
                            strncpy_s(info.imports[info.nimports].func, 128, fn,       _TRUNCATE);
                            info.nimports++;
                        }
                    }
                    thunk_off += (info.bits == 64) ? 8 : 4;
                }
                imp_off += sizeof(import_dir);
            }
        }
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. String Extractor  (from string_extractor.cpp)
// ─────────────────────────────────────────────────────────────────────────────
// Suspicious API/keyword list (from string_extractor.cpp:L23-30 + report.cpp danger_imports)
static const char* SUSP_KEYWORDS[] = {
    "CreateRemoteThread", "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
    "LoadLibrary",        "GetProcAddress","NtUnmapViewOfSection","SetWindowsHookEx",
    "OpenProcess",        "NtCreateThread","RtlCreateUserThread",
    "cmd.exe",            "powershell",    "nc -e",             "bash -i",
    "wget ",              "curl ",         "chmod 777",         "WScript",
    "base64",             "eval(",         "ShellExecute",      "WinExec",
    "CreateProcess",      "RegSetValue",   "RegOpenKey",        "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",          "ZwQueryInformationProcess",
    nullptr
};

static int categorise_string(const char* s) {
    if (strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0 ||
        strncmp(s, "ftp://", 6) == 0) return 1; // URL

    // IP pattern check
    int dots = 0; bool ok = true;
    for (const char* p = s; *p; p++) {
        if (*p == '.') dots++;
        else if (!isdigit((unsigned char)*p)) { ok = false; break; }
    }
    if (ok && dots == 3) return 2; // IP address

    if (strncmp(s, "HKEY_", 5) == 0 || strstr(s, "SOFTWARE\\")) return 3; // registry
    if (s[0] == '/' || strncmp(s, "C:\\", 3) == 0 ||
        strncmp(s, "%APPDATA%", 9) == 0 || strncmp(s, "%TEMP%", 6) == 0) return 4; // path

    for (int i = 0; SUSP_KEYWORDS[i]; i++)
        if (strstr(s, SUSP_KEYWORDS[i])) return 5; // suspicious

    return 0;
}

static void extract_strings(const uint8_t* data, size_t len, BinInfo& info) {
    char buf[512]; int blen = 0;
    for (size_t i = 0; i <= len; i++) {
        unsigned char c = (i < len) ? data[i] : 0;
        if (c >= 0x20 && c < 0x7F && blen < 510) {
            buf[blen++] = (char)c;
        } else {
            if (blen >= MIN_STR_LEN && info.nstrings < MAX_STRINGS) {
                buf[blen] = '\0';
                strncpy_s(info.strings[info.nstrings].value,
                          sizeof(info.strings[0].value), buf, _TRUNCATE);
                info.strings[info.nstrings].category = categorise_string(buf);
                info.nstrings++;
            }
            blen = 0;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Risk Score + Report  (from report.cpp)
// ─────────────────────────────────────────────────────────────────────────────
static int compute_risk(const BinInfo& info) {
    int score = 0;

    // High entropy sections (likely packed/encrypted)
    for (int i = 0; i < info.nsections; i++)
        if (info.sections[i].entropy > 7.0) score += 15;

    // W+X sections
    for (int i = 0; i < info.nsections; i++)
        if (info.sections[i].suspicious &&
            (info.sections[i].flags & 0xC0000000u) == 0xC0000000u) score += 20;

    // Dangerous imports
    static const char* DANGER_IMPORTS[] = {
        "CreateRemoteThread","VirtualAlloc","WriteProcessMemory",
        "NtUnmapViewOfSection","SetWindowsHookEx","OpenProcess",
        "NtCreateThread","RtlCreateUserThread",nullptr
    };
    for (int i = 0; i < info.nimports; i++)
        for (int j = 0; DANGER_IMPORTS[j]; j++)
            if (strstr(info.imports[i].func, DANGER_IMPORTS[j])) { score += 10; break; }

    // Suspicious strings
    for (int i = 0; i < info.nstrings; i++)
        if (info.strings[i].category == 5) score += 5;

    // Stripped binary
    if (info.is_stripped) score += 5;

    // No imports at all (packed?)
    if (info.nimports == 0) score += 20;

    return std::min(score, 100);
}

static void entropy_bar(double e) {
    int filled = (int)((e / 8.0) * 24);
    const char* color = e > 7.0 ? "\033[1;31m" :
                        e > 5.5 ? "\033[1;33m" : "\033[1;32m";
    printf("%s[", color);
    for (int i = 0; i < 24; i++) putchar(i < filled ? '#' : ' ');
    printf("]\033[0m %.2f", e);
}

static void print_report(const BinInfo& info, const std::string& filename) {
    int risk = compute_risk(info);
    const char* label = risk >= 60 ? "MALICIOUS"  :
                        risk >= 30 ? "SUSPICIOUS" : "CLEAN";
    const char* rcol  = risk >= 60 ? "\033[1;31m"  :
                        risk >= 30 ? "\033[1;33m"  : "\033[1;32m";

    printf("\033[1;36m");
    printf("  ╔══════════════════════════════════════════════════════╗\n");
    printf("  ║       PHANTOM PE ANALYZER  v2.0                     ║\n");
    printf("  ╚══════════════════════════════════════════════════════╝\n");
    printf("\033[0m\n");

    // File info
    printf("  \033[1m[FILE]\033[0m  %s\n", filename.c_str());
    printf("    Format      : PE%d\n", info.bits);
    printf("    Architecture: %s\n", info.arch);
    printf("    Type        : %s\n", info.type);
    printf("    Entry Point : 0x%llx\n", (unsigned long long)info.entry_point);
    printf("    Stripped    : %s\n", info.is_stripped ? "\033[33mYES (no debug symbols)\033[0m" : "No");

    // Sections
    printf("\n  \033[1m[SECTIONS]\033[0m  %d section(s)\n", info.nsections);
    printf("    %-12s %-12s %-10s %-8s  ENTROPY\n", "NAME","VADDR","RAW SIZE","FLAGS");
    printf("    %-12s %-12s %-10s %-8s  -------\n", "----","-----","--------","-----");
    for (int i = 0; i < info.nsections; i++) {
        const auto& s = info.sections[i];
        printf("    %-12s 0x%-10llx %-10u 0x%-6x  ",
               s.name, (unsigned long long)s.vaddr, s.raw_size, s.flags);
        entropy_bar(s.entropy);
        if (s.suspicious) printf("  \033[1;31m[!]\033[0m");
        printf("\n");
    }

    // Imports
    printf("\n  \033[1m[IMPORTS]\033[0m  %d function(s)\n", info.nimports);
    if (info.nimports == 0) {
        printf("    \033[1;31m[!] No imports — binary may be packed!\033[0m\n");
    } else {
        int shown = 0;
        for (int i = 0; i < info.nimports && shown < 30; i++) {
            bool danger = false;
            static const char* DI[] = {"CreateRemoteThread","VirtualAlloc",
                "WriteProcessMemory","NtUnmapViewOfSection","SetWindowsHookEx",
                "OpenProcess","NtCreateThread",nullptr};
            for (int j = 0; DI[j]; j++)
                if (strstr(info.imports[i].func, DI[j])) { danger = true; break; }

            if (danger)
                printf("    \033[1;31m%-32s  %s\033[0m\n", info.imports[i].dll, info.imports[i].func);
            else
                printf("    %-32s  %s\n", info.imports[i].dll, info.imports[i].func);
            shown++;
        }
        if (info.nimports > 30)
            printf("    ... and %d more\n", info.nimports - 30);
    }

    // Strings summary
    int urls=0, ips=0, regs=0, paths=0, susps=0;
    for (int i = 0; i < info.nstrings; i++) {
        switch (info.strings[i].category) {
            case 1: urls++;  break; case 2: ips++;   break;
            case 3: regs++;  break; case 4: paths++; break;
            case 5: susps++; break;
        }
    }
    printf("\n  \033[1m[STRINGS]\033[0m  %d total\n", info.nstrings);
    printf("    URLs: %d  IPs: %d  Registry Keys: %d  Paths: %d  "
           "\033[1;31mSuspicious: %d\033[0m\n",
           urls, ips, regs, paths, susps);

    if (susps > 0) {
        printf("\n    \033[1;31m[SUSPICIOUS STRINGS FOUND]\033[0m\n");
        for (int i = 0; i < info.nstrings; i++)
            if (info.strings[i].category == 5)
                printf("      >> %s\n", info.strings[i].value);
    }

    // Risk score
    printf("\n  \033[1m[RISK ASSESSMENT]\033[0m\n");
    printf("    Score  : %s%d/100\033[0m\n", rcol, risk);
    printf("    Verdict: %s%s\033[0m\n\n", rcol, label);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Module Entry Point
// ─────────────────────────────────────────────────────────────────────────────
void run_pe_analyzer() {
    std::cout << "\n\033[1;36m  PHANTOM PE Analyzer\033[0m\n";
    std::cout << "  Enter path to PE file (.exe / .dll): ";
    std::string path;
    std::getline(std::cin, path);
    if (path.empty()) return;

    // Load file
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        std::cerr << "  Cannot open file: " << path << "\n"; return;
    }
    size_t size = (size_t)f.tellg();
    if (size == 0) { std::cerr << "  File is empty.\n"; return; }
    f.seekg(0);
    std::vector<uint8_t> data(size);
    f.read((char*)data.data(), (std::streamsize)size);
    f.close();

    std::cout << "  Loaded " << size << " bytes from " << path << "\n";
    std::cout << "  Analyzing...\n\n";

    BinInfo info{};
    if (!parse_pe(data.data(), size, info)) {
        std::cerr << "  \033[1;31mNot a valid PE file (MZ/PE signature missing).\033[0m\n";
        return;
    }

    std::cout << "  Extracting strings...\n";
    extract_strings(data.data(), size, info);

    // Get filename only for display
    std::string fname = path;
    size_t sep = fname.find_last_of("/\\");
    if (sep != std::string::npos) fname = fname.substr(sep + 1);

    print_report(info, fname);

    // Offer JSON output
    std::cout << "  Save JSON report? (Enter filename or leave blank): ";
    std::string jpath; std::getline(std::cin, jpath);
    if (!jpath.empty()) {
        std::ofstream jf(jpath);
        if (jf) {
            int risk = compute_risk(info);
            jf << "{\n"
               << "  \"file\": \""         << fname         << "\",\n"
               << "  \"arch\": \""         << info.arch     << "\",\n"
               << "  \"bits\": "           << info.bits     << ",\n"
               << "  \"type\": \""         << info.type     << "\",\n"
               << "  \"entry_point\": \"0x" << std::hex << info.entry_point << std::dec << "\",\n"
               << "  \"stripped\": "       << (info.is_stripped ? "true" : "false") << ",\n"
               << "  \"risk_score\": "     << risk           << ",\n"
               << "  \"sections\": [\n";
            for (int i = 0; i < info.nsections; i++) {
                const auto& s = info.sections[i];
                jf << "    {\"name\":\"" << s.name << "\""
                   << ",\"entropy\":" << std::fixed << std::setprecision(2) << s.entropy
                   << ",\"suspicious\":" << (s.suspicious ? "true" : "false") << "}"
                   << (i < info.nsections - 1 ? "," : "") << "\n";
            }
            jf << "  ],\n"
               << "  \"imports_count\": " << info.nimports << ",\n"
               << "  \"strings_count\": " << info.nstrings << "\n"
               << "}\n";
            std::cout << "  JSON saved to " << jpath << "\n";
        }
    }
}

} // namespace phantom::modules
