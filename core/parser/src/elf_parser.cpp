#include "parser.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>

// Magic number ELF: 0x7F 'E' 'L' 'F'
static const unsigned char ELF_MAGIC[] = {0x7F, 0x45, 0x4C, 0x46};

ElfHeader parseHeaderElf(const std::string& filename) {
    ElfHeader header;
    header.valid = false;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return header;

    Elf64_Ehdr_Min ehdr;
    file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!file) return header;

    if (std::memcmp(ehdr.e_ident, ELF_MAGIC, 4) != 0) {
        return header; // Bukan file ELF
    }

    header.valid = true;
    header.magic = "ELF";
    header.entry_point = ehdr.e_entry;
    header.machine = ehdr.e_machine;
    header.section_count = ehdr.e_shnum;

    return header;
}

std::vector<ElfSection> parseSectionsElf(const std::string& filename) {
    std::vector<ElfSection> sections;
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) return sections;

    Elf64_Ehdr_Min ehdr;
    file.read(reinterpret_cast<char*>(&ehdr), sizeof(ehdr));
    if (!file || std::memcmp(ehdr.e_ident, ELF_MAGIC, 4) != 0) return sections;

    // Baca Section Header Table
    file.seekg(ehdr.e_shoff);
    std::vector<Elf64_Shdr_Min> shdrs(ehdr.e_shnum);
    file.read(reinterpret_cast<char*>(shdrs.data()), ehdr.e_shnum * sizeof(Elf64_Shdr_Min));

    // Baca String Table untuk nama section
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        std::vector<char> strtab(shdrs[ehdr.e_shstrndx].sh_size);
        file.seekg(shdrs[ehdr.e_shstrndx].sh_offset);
        file.read(strtab.data(), shdrs[ehdr.e_shstrndx].sh_size);

        for (const auto& shdr : shdrs) {
            ElfSection sec;
            sec.addr = shdr.sh_addr;
            sec.offset = shdr.sh_offset;
            sec.size = shdr.sh_size;
            sec.type = shdr.sh_type;
            if (shdr.sh_name < strtab.size()) {
                sec.name = std::string(&strtab[shdr.sh_name]);
            }
            sections.push_back(sec);
        }
    }

    return sections;
}

std::vector<ElfSymbol> parseSymbolElf(const std::string& filename) {
     std::vector<ElfSymbol> symbols;
     return symbols;
}

// Implementasi C Interface
extern "C" {
    C_ElfHeader c_parseHeaderElf(const char* filename) {
        ElfHeader cpp_hdr = parseHeaderElf(std::string(filename));
        C_ElfHeader c_hdr;
        std::strncpy(c_hdr.magic, cpp_hdr.magic.c_str(), sizeof(c_hdr.magic) - 1);
        c_hdr.magic[4] = '\0';
        c_hdr.entry_point = cpp_hdr.entry_point;
        c_hdr.machine = cpp_hdr.machine;
        c_hdr.section_count = cpp_hdr.section_count;
        c_hdr.valid = cpp_hdr.valid ? 1 : 0;
        return c_hdr;
    }
}