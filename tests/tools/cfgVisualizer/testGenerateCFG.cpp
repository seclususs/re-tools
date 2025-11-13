#include "retools_advanced.h"
#include "retools_types.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <string>
#include <cstdio>


struct ElfSection {
    std::string name;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t type;
};

void create_dummy_elf_file_cfg(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
        0x01, 0x00, 0x40, 0x00, 0x03, 0x00, 0x01, 0x00
    };
    std::vector<uint8_t> pheader = {
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    header.insert(header.end(), pheader.begin(), pheader.end());
    header.resize(128, 0);
    std::vector<uint8_t> text_data = { 0x55, 0x90, 0x74, 0x02, 0x90, 0xC3, 0x90, 0xC3 };
    header.insert(header.end(), text_data.begin(), text_data.end());
    header.resize(224, 0);
    std::vector<uint8_t> sh_null(64, 0);
    std::vector<uint8_t> sh_str(64, 0); 
    std::vector<uint8_t> sh_text(64, 0);
    std::vector<uint8_t> str_data = { 0x00, '.', 't', 'e', 'x', 't', 0x00 };
    uint64_t str_data_offset = 224 + (64 * 3);
    *(uint32_t*)&sh_str[0] = 0;
    *(uint32_t*)&sh_str[4] = 3;
    *(uint64_t*)&sh_str[16] = 0;
    *(uint64_t*)&sh_str[24] = str_data_offset;
    *(uint64_t*)&sh_str[32] = str_data.size();
    *(uint32_t*)&sh_text[0] = 1;
    *(uint32_t*)&sh_text[4] = 1;
    *(uint64_t*)&sh_text[8] = 0x6;
    *(uint64_t*)&sh_text[16] = 0x400080;
    *(uint64_t*)&sh_text[24] = 128;
    *(uint64_t*)&sh_text[32] = text_data.size();
    header.insert(header.end(), sh_null.begin(), sh_null.end());
    header.insert(header.end(), sh_str.begin(), sh_str.end());
    header.insert(header.end(), sh_text.begin(), sh_text.end());
    header.insert(header.end(), str_data.begin(), str_data.end());
    file.write(reinterpret_cast<char*>(header.data()), header.size());
    file.close();
}

int main() {
    std::string test_file = "test_cfg.bin";
    create_dummy_elf_file_cfg(test_file);
    std::cout << "[TEST] Mulai testGenerateCFG..." << std::endl;
    char* dot_output_ptr = c_generateCFG_rs(test_file.c_str());
    assert(dot_output_ptr != nullptr);
    std::string dot_output(dot_output_ptr);
    c_freeString(dot_output_ptr);
    assert(dot_output.find("digraph") != std::string::npos);
    assert(dot_output.find("error") == std::string::npos);
    std::cout << "  [PASS] 'digraph' ditemukan." << std::endl;
    assert(dot_output.find("PUSH RBP") != std::string::npos);
    assert(dot_output.find("0x400084: NOP") != std::string::npos);
    assert(dot_output.find("0x400086: NOP") != std::string::npos);
    std::cout << "  [PASS] Semua 3 blok (label) ditemukan." << std::endl;
    assert(dot_output.find("->") != std::string::npos);
    std::cout << "  [PASS] Edge (->) ditemukan." << std::endl;
    std::remove(test_file.c_str());
    std::cout << "[TEST] testGenerateCFG SELESAI." << std::endl;
    return 0;
}