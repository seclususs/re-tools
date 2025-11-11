#include "cfg.h"
#include "parser.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <string>

// Helper
void create_dummy_elf_file_cfg(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    // Header ELF64
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x40, 0x00, 0x02, 0x00, 0x01, 0x00
    };
    // Program Header (LOAD .text)
    std::vector<uint8_t> pheader = {
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    header.insert(header.end(), pheader.begin(), pheader.end());
    header.resize(128, 0); // Padding ke .text offset
    
    // .text section data: 
    // 0x55       (PUSH RBP)
    // 0x48 0x89 0xE5 (MOV RBP, RSP)
    // 0x90       (NOP)
    // 0xC3       (RET)
    // 0x90       (NOP) - block 2
    // 0x90       (NOP)
    // 0xC3       (RET) - block 2
    std::vector<uint8_t> text_data = { 0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3, 0x90, 0x90, 0xC3 };
    header.insert(header.end(), text_data.begin(), text_data.end());
    header.resize(224, 0); // Padding ke shoff

    // Section Header Table
    std::vector<uint8_t> sh_null(64, 0);
    std::vector<uint8_t> sh_str(64, 0); 
    std::vector<uint8_t> sh_text(64, 0);
    
    *(uint32_t*)&sh_text[0] = 1; // sh_name (offset 1 di strtab)
    *(uint32_t*)&sh_text[4] = 1; // sh_type (PROGBITS)
    *(uint64_t*)&sh_text[8] = 0x6; // sh_flags (ALLOC|EXEC)
    *(uint64_t*)&sh_text[16] = 0x400080; // sh_addr
    *(uint64_t*)&sh_text[24] = 128; // sh_offset
    *(uint64_t*)&sh_text[32] = text_data.size(); // sh_size

    header.insert(header.end(), sh_null.begin(), sh_null.end());
    header.insert(header.end(), sh_str.begin(), sh_str.end());
    header.insert(header.end(), sh_text.begin(), sh_text.end());
    
    // String table data (\0.text\0)
    std::vector<uint8_t> str_data = { 0x00, '.', 't', 'e', 'x', 't', 0x00 };
    header.insert(header.end(), str_data.begin(), str_data.end());

    file.write(reinterpret_cast<char*>(header.data()), header.size());
    file.close();
}


int main() {
    std::string test_file = "test_cfg.bin";
    create_dummy_elf_file_cfg(test_file);

    std::cout << "[TEST] Mulai testGenerateCFG..." << std::endl;
    
    std::string dot_output = generateCFG(test_file);
    std::cout << "--- Output DOT ---\n" << dot_output << "\n------------------\n";

    // Cek apakah berisi node BBlock yang diharapkan
    // Alamat VAddr .text = 0x400080
    assert(dot_output.find("BBlock_0x400080") != std::string::npos);
    // Blok 1 (PUSH, MOV, NOP, RET) = 1 + 3 + 1 + 1 = 6 bytes
    // Blok 2 mulai di 0x400080 + 6 = 0x400086
    assert(dot_output.find("BBlock_0x400086") != std::string::npos);
    
    // Cek apakah berisi mnemonic
    assert(dot_output.find("PUSH rbp") != std::string::npos);
    assert(dot_output.find("MOV rbp rsp") != std::string::npos);
    assert(dot_output.find("RET") != std::string::npos);

    std::cout << "  [PASS] Output DOT berisi node dan instruksi yang diharapkan." << std::endl;

    std::remove(test_file.c_str());
    std::cout << "[TEST] testGenerateCFG SELESAI." << std::endl;
    return 0;
}