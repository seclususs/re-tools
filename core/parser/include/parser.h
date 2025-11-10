#ifndef RETOOLS_PARSER_H
#define RETOOLS_PARSER_H

#include <string>
#include <vector>
#include <cstdint>

// Definisi Struktur ELF Minimal (64-bit)
struct Elf64_Ehdr_Min {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr_Min {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Sym_Min {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

// Struktur Output High-Level
struct ElfHeader {
    std::string magic;
    uint64_t entry_point;
    uint16_t machine;
    uint16_t section_count;
    bool valid;
};

struct ElfSection {
    std::string name;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t type;
};

struct ElfSymbol {
    std::string name;
    uint64_t value;
    uint64_t size;
    uint8_t info;
};

// Fungsi API Parser
ElfHeader parseHeaderElf(const std::string& filename);
std::vector<ElfSection> parseSectionsElf(const std::string& filename);
std::vector<ElfSymbol> parseSymbolElf(const std::string& filename);

// C Interface untuk Python Bindings
extern "C" {
    // Wrapper untuk ctypes
    struct C_ElfHeader {
        char magic[5];
        uint64_t entry_point;
        uint16_t machine;
        uint16_t section_count;
        int valid;
    };

    C_ElfHeader c_parseHeaderElf(const char* filename);
}

#endif // RETOOLS_PARSER_H