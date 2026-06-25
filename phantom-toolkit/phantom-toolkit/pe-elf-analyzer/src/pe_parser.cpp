// pe_parser.cpp — PE32/PE32+ static analyzer
#include <cstdio>
#include <cstring>
#include <cstdint>
#include "../include/analyzer.h"
#include "entropy_impl.h"

// DOS / PE structures
#pragma pack(push,1)
struct dos_hdr {
    uint16_t e_magic;      // MZ
    uint8_t  _pad[58];
    int32_t  e_lfanew;     // offset to PE header
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
struct data_dir { uint32_t VirtualAddress; uint32_t Size; };
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

#define SEC_MEM_WRITE   0x80000000
#define SEC_MEM_EXECUTE 0x20000000
#define SEC_MEM_READ    0x40000000

static uint32_t rva_to_offset(const section_hdr *secs, int n, uint32_t rva) {
    for (int i = 0; i < n; i++)
        if (rva >= secs[i].VirtualAddress &&
            rva <  secs[i].VirtualAddress + secs[i].SizeOfRawData)
            return secs[i].PointerToRawData + (rva - secs[i].VirtualAddress);
    return 0;
}

int parse_pe(const uint8_t *data, size_t len, bin_info_t *info) {
    if (len < sizeof(dos_hdr)) return -1;
    const auto *dos = reinterpret_cast<const dos_hdr *>(data);
    if (dos->e_magic != 0x5A4D) return -1;  // MZ

    size_t pe_off = (size_t)(uint32_t)dos->e_lfanew;
    if (pe_off + 4 + sizeof(coff_hdr) >= len) return -1;
    if (*(uint32_t *)(data + pe_off) != 0x00004550) return -1;  // PE\0\0

    const auto *coff = reinterpret_cast<const coff_hdr *>(data + pe_off + 4);
    uint16_t opt_magic = *(uint16_t *)(data + pe_off + 4 + sizeof(coff_hdr));

    info->format = FORMAT_PE;
    info->bits   = (opt_magic == 0x020B) ? 64 : 32;

    // Machine type
    switch (coff->Machine) {
        case 0x014C: strncpy(info->arch, "x86",    sizeof(info->arch)-1); break;
        case 0x8664: strncpy(info->arch, "x86_64", sizeof(info->arch)-1); break;
        case 0xAA64: strncpy(info->arch, "ARM64",  sizeof(info->arch)-1); break;
        default:     snprintf(info->arch, sizeof(info->arch), "0x%04x", coff->Machine);
    }

    // File type from Characteristics
    uint16_t ch = coff->Characteristics;
    if      (ch & 0x2000) strncpy(info->type, "DLL",        sizeof(info->type)-1);
    else if (ch & 0x0002) strncpy(info->type, "EXE",        sizeof(info->type)-1);
    else                  strncpy(info->type, "OBJ/Unknown", sizeof(info->type)-1);

    info->is_stripped = (ch & 0x0200) ? 1 : 0;

    // Entry point
    size_t opt_off = pe_off + 4 + sizeof(coff_hdr);
    if (info->bits == 32) {
        const auto *opt = reinterpret_cast<const opt_hdr32 *>(data + opt_off);
        info->entry_point = opt->AddressOfEntryPoint;
    } else {
        const auto *opt = reinterpret_cast<const opt_hdr64 *>(data + opt_off);
        info->entry_point = opt->AddressOfEntryPoint;
    }

    // Sections
    size_t sec_off = opt_off + coff->SizeOfOptionalHeader;
    int nsec = coff->NumberOfSections;
    if (nsec > MAX_SECTIONS) nsec = MAX_SECTIONS;

    const auto *secs = reinterpret_cast<const section_hdr *>(data + sec_off);
    info->nsections = nsec;

    for (int i = 0; i < nsec; i++) {
        auto &s = info->sections[i];
        memset(s.name, 0, sizeof(s.name));
        memcpy(s.name, secs[i].Name, 8);
        s.vaddr      = secs[i].VirtualAddress;
        s.virt_size  = secs[i].VirtualSize;
        s.raw_size   = secs[i].SizeOfRawData;
        s.flags      = secs[i].Characteristics;

        // Entropy
        uint32_t raw_off = secs[i].PointerToRawData;
        uint32_t raw_sz  = secs[i].SizeOfRawData;
        if (raw_off + raw_sz <= len && raw_sz > 0)
            s.entropy = shannon_entropy(data + raw_off, raw_sz);

        // Suspicious: W+X, high entropy
        bool wx = (s.flags & SEC_MEM_WRITE) && (s.flags & SEC_MEM_EXECUTE);
        bool high_ent = s.entropy > 7.0;
        s.suspicious = (wx || high_ent) ? 1 : 0;
    }

    // Import table — data directory entry 1
    size_t dd_off = opt_off + (info->bits == 32 ? 96 : 112);
    if (dd_off + 8 <= len) {
        const auto *imp_dd = reinterpret_cast<const data_dir *>(data + dd_off + 8);
        uint32_t imp_rva = imp_dd->VirtualAddress;
        if (imp_rva) {
            uint32_t imp_off = rva_to_offset(secs, nsec, imp_rva);
            while (imp_off && imp_off + sizeof(import_dir) <= len && info->nimports < MAX_IMPORTS - 1) {
                const auto *id = reinterpret_cast<const import_dir *>(data + imp_off);
                if (!id->Name && !id->FirstThunk) break;

                uint32_t name_off = rva_to_offset(secs, nsec, id->Name);
                if (!name_off || name_off >= len) { imp_off += sizeof(import_dir); continue; }

                const char *dll_name = reinterpret_cast<const char *>(data + name_off);

                // Walk thunk array
                uint32_t thunk_rva = id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk;
                uint32_t thunk_off = rva_to_offset(secs, nsec, thunk_rva);

                while (thunk_off && thunk_off + 4 <= len && info->nimports < MAX_IMPORTS) {
                    uint32_t entry = *(uint32_t *)(data + thunk_off);
                    if (!entry) break;
                    if (!(entry & 0x80000000)) {
                        uint32_t hint_off = rva_to_offset(secs, nsec, entry);
                        if (hint_off + 2 < len) {
                            const char *fn = reinterpret_cast<const char *>(data + hint_off + 2);
                            strncpy(info->imports[info->nimports].dll,  dll_name, 127);
                            strncpy(info->imports[info->nimports].func, fn,       127);
                            info->nimports++;
                        }
                    }
                    thunk_off += info->bits == 64 ? 8 : 4;
                }
                imp_off += sizeof(import_dir);
            }
        }
    }
    return 0;
}
