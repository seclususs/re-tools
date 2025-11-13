#include "retools_advanced.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>


struct ElfSection {
    std::string name;
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t type;
};

void create_dummy_elf_file(const std::string& filename, uint8_t entry_byte) {
    std::ofstream file(filename, std::ios::binary);
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00,
        0x3E, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x00,
        0x38, 0x00,
        0x01, 0x00,
        0x40, 0x00,
        0x03, 0x00,
        0x01, 0x00
    };
    header.resize(64, 0);
    std::vector<uint8_t> pheader = {
        0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    pheader.resize(56, 0);
    header.insert(header.end(), pheader.begin(), pheader.end());
    header.resize(128, 0);
    std::vector<uint8_t> text_data = { 0x90, entry_byte, 0x90, 0xC3 };
    header.insert(header.end(), text_data.begin(), text_data.end());
    header.resize(160, 0);
    std::vector<uint8_t> sh_null(64, 0);
    std::vector<uint8_t> sh_str(64, 0); 
    std::vector<uint8_t> sh_text(64, 0);
    std::vector<uint8_t> str_data = { 0x00, '.', 't', 'e', 'x', 't', 0x00 };
    uint64_t str_data_offset = 160 + (64 * 3);
    *(uint32_t*)&sh_str[0] = 0;
    *(uint32_t*)&sh_str[4] = 3;
    *(uint64_t*)&sh_str[8] = 0;
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
    std::string file1 = "test_diff_1.bin";
    std::string file2 = "test_diff_2.bin";
    std::string file3 = "test_diff_3.bin";
    create_dummy_elf_file(file1, 0x90);
    create_dummy_elf_file(file2, 0x90);
    create_dummy_elf_file(file3, 0x55);
    std::cout << "[TEST] Mulai testDiffBinary..." << std::endl;
    const int MAX_DIFF_RESULTS = 128;
    std::vector<C_DiffResult> results_buffer(MAX_DIFF_RESULTS);
    int count1 = c_diffBinary_rs(file1.c_str(), file2.c_str(), results_buffer.data(), MAX_DIFF_RESULTS);
    assert(count1 > 0);
    assert(std::strcmp(results_buffer[0].functionName, ".text") == 0);
    assert(results_buffer[0].status == 0); // 0 = MATCHED
    std::cout << "  [PASS] Perbandingan file identik (fallback .text MATCHED) OK." << std::endl;
    int count2 = c_diffBinary_rs(file1.c_str(), file3.c_str(), results_buffer.data(), MAX_DIFF_RESULTS);
    assert(count2 > 0);
    assert(std::strcmp(results_buffer[0].functionName, ".text") == 0);
    assert(results_buffer[0].status == 1);
    std::cout << "  [PASS] Perbandingan file berbeda (fallback .text MODIFIED) OK." << std::endl;
    std::remove(file1.c_str());
    std::remove(file2.c_str());
    std::remove(file3.c_str());
    std::cout << "[TEST] testDiffBinary SELESAI." << std::endl;
    return 0;
}