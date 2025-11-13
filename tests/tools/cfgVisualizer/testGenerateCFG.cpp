#include "cfg.h"
#include "parser.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <string>

// Definisi struct C++
struct ElfSection {
    std::string name;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t type;
};

// Helper
void create_dummy_elf_file_cfg(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    // Header ELF64
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry 0x400080
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Phoff 64
        0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Shoff 224
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, // Ehsize, Phentsize
        0x01, 0x00, 0x40, 0x00, 0x03, 0x00, 0x01, 0x00  // Phnum, Shentsize, Shnum, Shstrndx
    };
    // Program Header (LOAD .text)
    std::vector<uint8_t> pheader = {
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // Type, Flags
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Offset 128
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Vaddr 0x400080
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Paddr
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Filesz
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Memsz
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Align
    };
    header.insert(header.end(), pheader.begin(), pheader.end());
    header.resize(128, 0); // Padding ke .text offset (128)
    
    // .text section data: (TOTAL 8 bytes)
    // 0x400080: 55          (PUSH RBP)
    // 0x400081: 90          (NOP)
    // 0x400082: 74 02       (JZ 0x400086) - JUMP +2 bytes (ke 0x82 + 2 + 2 = 0x86)
    // -- Block 1 (0x400080) berakhir di sini --
    // 0x400084: 90          (NOP) - Fall-through
    // 0x400085: C3          (RET)
    // -- Block 2 (0x400084) berakhir di sini --
    // 0x400086: 90          (NOP) - Target Jump
    // 0x400087: C3          (RET)
    // -- Block 3 (0x400086) berakhir di sini --
    std::vector<uint8_t> text_data = { 0x55, 0x90, 0x74, 0x02, 0x90, 0xC3, 0x90, 0xC3 };
    header.insert(header.end(), text_data.begin(), text_data.end());
    header.resize(224, 0); // Padding ke shoff (224)

    // Section Header Table
    std::vector<uint8_t> sh_null(64, 0);
    std::vector<uint8_t> sh_str(64, 0); 
    std::vector<uint8_t> sh_text(64, 0);
    
    // String table data. ".text" harus di index 1
    std::vector<uint8_t> str_data = { 0x00, '.', 't', 'e', 'x', 't', 0x00 };
    uint64_t str_data_offset = 224 + (64 * 3); // shoff + sh_null + sh_str + sh_text

    // SH 1 (String table)
    *(uint32_t*)&sh_str[0] = 0; // sh_name
    *(uint32_t*)&sh_str[4] = 3; // sh_type
    *(uint64_t*)&sh_str[16] = 0; // sh_addr
    *(uint64_t*)&sh_str[24] = str_data_offset; // sh_offset
    *(uint64_t*)&sh_str[32] = str_data.size(); // sh_size

    // sh_name harus 1
    *(uint32_t*)&sh_text[0] = 1; // sh_name (offset 1 di strtab -> ".text")
    *(uint32_t*)&sh_text[4] = 1; // sh_type (PROGBITS)
    *(uint64_t*)&sh_text[8] = 0x6; // sh_flags (ALLOC|EXEC)
    *(uint64_t*)&sh_text[16] = 0x400080; // sh_addr
    *(uint64_t*)&sh_text[24] = 128; // sh_offset
    *(uint64_t*)&sh_text[32] = text_data.size(); // sh_size

    header.insert(header.end(), sh_null.begin(), sh_null.end());
    header.insert(header.end(), sh_str.begin(), sh_str.end());
    header.insert(header.end(), sh_text.begin(), sh_text.end());
    
    // Tulis data string table
    header.insert(header.end(), str_data.begin(), str_data.end());

    file.write(reinterpret_cast<char*>(header.data()), header.size());
    file.close();
}


int main() {
    std::string test_file = "test_cfg.bin";
    create_dummy_elf_file_cfg(test_file);

    std::cout << "[TEST] Mulai testGenerateCFG..." << std::endl;
    
    std::string dot_output = generateCFG(test_file);
    
    // Debugging: Cetak output DOT
    // std::cout << "--- Output DOT ---\n" << dot_output << "\n------------------\n";

    // Cek dasar
    assert(dot_output.find("digraph {") != std::string::npos); 
    assert(dot_output.find("error") == std::string::npos);
    std::cout << "  [PASS] 'digraph {' ditemukan." << std::endl;

    // Cek Node (Blok) - Cek konten label
    assert(dot_output.find("PUSH RBP") != std::string::npos); // Blok 1
    assert(dot_output.find("0x400084: NOP") != std::string::npos); // Blok 2
    assert(dot_output.find("0x400086: NOP") != std::string::npos); // Blok 3
    std::cout << "  [PASS] Semua 3 blok (label) ditemukan." << std::endl;

    // Cek Edge (Panah)
    // Cukup cek apakah ada panah (->)
    assert(dot_output.find("->") != std::string::npos);
    std::cout << "  [PASS] Edge (->) ditemukan." << std::endl;
    
    std::remove(test_file.c_str());
    std::cout << "[TEST] testGenerateCFG SELESAI." << std::endl;
    return 0;
}