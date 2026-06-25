// elf_parser.cpp — ELF32/ELF64 static analyzer
#include <cstdio>
#include <cstring>
#include <cstdint>
#include "../include/analyzer.h"
#include "entropy_impl.h"

#define ELFMAG0  0x7f
#define ELFMAG1  'E'
#define ELFMAG2  'L'
#define ELFMAG3  'F'

#define ET_EXEC 2
#define ET_DYN  3
#define ET_CORE 4

#define PT_LOAD       1
#define PT_DYNAMIC    2
#define PT_INTERP     3
#define PT_GNU_STACK  0x6474e551

#define DT_NULL     0
#define DT_NEEDED   1
#define DT_RPATH   15
#define DT_RUNPATH 29
#define DT_SONAME  14

#define EM_386   3
#define EM_X86_64 62
#define EM_ARM   40
#define EM_AARCH64 183
#define EM_MIPS  8

#pragma pack(push,1)
struct elf_hdr32 {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version, e_entry, e_phoff, e_shoff, e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct elf_hdr64 {
    uint8_t  e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct phdr32 {
    uint32_t p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align;
};
struct phdr64 {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};
struct shdr32 {
    uint32_t sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info, sh_addralign, sh_entsize;
};
struct shdr64 {
    uint32_t sh_name, sh_type;
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;
    uint64_t sh_addralign, sh_entsize;
};
struct dyn64 { int64_t d_tag; uint64_t d_val; };
struct dyn32 { int32_t d_tag; uint32_t d_val; };
#pragma pack(pop)

int parse_elf(const uint8_t *data, size_t len, bin_info_t *info) {
    if (len < 16) return -1;
    if (data[0]!=ELFMAG0||data[1]!=ELFMAG1||data[2]!=ELFMAG2||data[3]!=ELFMAG3) return -1;

    info->format = FORMAT_ELF;
    info->bits   = (data[4] == 2) ? 64 : 32;

    uint16_t e_machine, e_type;
    uint64_t e_entry;
    uint16_t e_phnum, e_shnum, e_shstrndx;
    uint64_t e_phoff, e_shoff;
    uint16_t e_phentsize, e_shentsize;

    if (info->bits == 64) {
        if (len < sizeof(elf_hdr64)) return -1;
        const auto *h = reinterpret_cast<const elf_hdr64 *>(data);
        e_machine=h->e_machine; e_type=h->e_type; e_entry=h->e_entry;
        e_phnum=h->e_phnum; e_shnum=h->e_shnum; e_shstrndx=h->e_shstrndx;
        e_phoff=h->e_phoff; e_shoff=h->e_shoff;
        e_phentsize=h->e_phentsize; e_shentsize=h->e_shentsize;
    } else {
        if (len < sizeof(elf_hdr32)) return -1;
        const auto *h = reinterpret_cast<const elf_hdr32 *>(data);
        e_machine=h->e_machine; e_type=h->e_type; e_entry=h->e_entry;
        e_phnum=h->e_phnum; e_shnum=h->e_shnum; e_shstrndx=h->e_shstrndx;
        e_phoff=h->e_phoff; e_shoff=h->e_shoff;
        e_phentsize=h->e_phentsize; e_shentsize=h->e_shentsize;
    }

    info->entry_point = e_entry;
    switch (e_machine) {
        case EM_386:    strncpy(info->arch,"x86",    sizeof(info->arch)-1); break;
        case EM_X86_64: strncpy(info->arch,"x86_64", sizeof(info->arch)-1); break;
        case EM_ARM:    strncpy(info->arch,"ARM",    sizeof(info->arch)-1); break;
        case EM_AARCH64:strncpy(info->arch,"ARM64",  sizeof(info->arch)-1); break;
        case EM_MIPS:   strncpy(info->arch,"MIPS",   sizeof(info->arch)-1); break;
        default:        snprintf(info->arch,sizeof(info->arch),"0x%04x",e_machine);
    }
    switch (e_type) {
        case ET_EXEC: strncpy(info->type,"EXEC",sizeof(info->type)-1); break;
        case ET_DYN:  strncpy(info->type,"DYN/PIE",sizeof(info->type)-1); break;
        default:      strncpy(info->type,"OTHER",sizeof(info->type)-1);
    }

    // Section headers — get shstrtab for names
    const char *shstrtab = nullptr;
    if (e_shstrndx < e_shnum && e_shoff + (e_shstrndx+1)*e_shentsize <= len) {
        if (info->bits == 64) {
            const auto *sh = reinterpret_cast<const shdr64 *>(data + e_shoff + e_shstrndx*e_shentsize);
            if (sh->sh_offset + sh->sh_size <= len)
                shstrtab = reinterpret_cast<const char *>(data + sh->sh_offset);
        } else {
            const auto *sh = reinterpret_cast<const shdr32 *>(data + e_shoff + e_shstrndx*e_shentsize);
            if (sh->sh_offset + sh->sh_size <= len)
                shstrtab = reinterpret_cast<const char *>(data + sh->sh_offset);
        }
    }

    int nsec = e_shnum < MAX_SECTIONS ? e_shnum : MAX_SECTIONS;
    info->nsections = 0;
    bool has_symtab = false;

    for (int i = 0; i < nsec; i++) {
        auto &s = info->sections[info->nsections];
        if (info->bits == 64) {
            const auto *sh = reinterpret_cast<const shdr64 *>(data + e_shoff + i*e_shentsize);
            if (shstrtab) strncpy(s.name, shstrtab + sh->sh_name, 15);
            s.vaddr    = sh->sh_addr;
            s.raw_size = sh->sh_size;
            s.flags    = (uint32_t)sh->sh_flags;
            if (sh->sh_offset + sh->sh_size <= len && sh->sh_size > 0)
                s.entropy = shannon_entropy(data + sh->sh_offset, (size_t)sh->sh_size);
            if (sh->sh_type == 2) has_symtab = true;
        } else {
            const auto *sh = reinterpret_cast<const shdr32 *>(data + e_shoff + i*e_shentsize);
            if (shstrtab) strncpy(s.name, shstrtab + sh->sh_name, 15);
            s.vaddr    = sh->sh_addr;
            s.raw_size = sh->sh_size;
            s.flags    = sh->sh_flags;
            if (sh->sh_offset + sh->sh_size <= len && sh->sh_size > 0)
                s.entropy = shannon_entropy(data + sh->sh_offset, sh->sh_size);
            if (sh->sh_type == 2) has_symtab = true;
        }
        s.suspicious = (s.entropy > 7.0) ? 1 : 0;
        info->nsections++;
    }

    info->is_stripped = has_symtab ? 0 : 1;

    // Program headers — check PT_GNU_STACK + parse PT_DYNAMIC
    info->nx_stack = 1; // assume NX
    for (int i = 0; i < e_phnum && i < 64; i++) {
        uint32_t p_type; uint64_t p_offset, p_filesz; uint32_t p_flags;
        if (info->bits == 64) {
            const auto *ph = reinterpret_cast<const phdr64 *>(data + e_phoff + i*e_phentsize);
            p_type=ph->p_type; p_offset=ph->p_offset; p_filesz=ph->p_filesz; p_flags=ph->p_flags;
        } else {
            const auto *ph = reinterpret_cast<const phdr32 *>(data + e_phoff + i*e_phentsize);
            p_type=ph->p_type; p_offset=ph->p_offset; p_filesz=ph->p_filesz; p_flags=ph->p_flags;
        }
        if (p_type == PT_GNU_STACK && (p_flags & 1)) info->nx_stack = 0;

        // Parse .dynamic for DT_NEEDED
        if (p_type == PT_DYNAMIC && p_offset + p_filesz <= len && info->nimports < MAX_IMPORTS) {
            if (info->bits == 64) {
                const auto *dyn = reinterpret_cast<const dyn64 *>(data + p_offset);
                // Find strtab
                uint64_t strtab_off = 0;
                for (int j = 0; dyn[j].d_tag != DT_NULL; j++) {
                    if (dyn[j].d_tag == 5) { // DT_STRTAB
                        // Find raw offset via section
                        for (int k = 0; k < info->nsections; k++) {
                            if (info->sections[k].vaddr == dyn[j].d_val) {
                                // approximate offset
                                strtab_off = dyn[j].d_val;
                                break;
                            }
                        }
                    }
                }
                for (int j = 0; dyn[j].d_tag != DT_NULL && info->nimports < MAX_IMPORTS; j++) {
                    if (dyn[j].d_tag == DT_NEEDED) {
                        snprintf(info->imports[info->nimports].dll,
                                 sizeof(info->imports[0].dll),
                                 "NEEDED+0x%lx", (unsigned long)dyn[j].d_val);
                        strncpy(info->imports[info->nimports].func, "(shared lib)", 127);
                        info->nimports++;
                    }
                }
            }
        }
    }
    return 0;
}
