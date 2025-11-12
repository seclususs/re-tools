#include "parser.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <cstring>

void create_dummy_elf(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    // Header ELF64 minimalis palsu
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, // Magic, 64-bit, LE, ver
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Pad
        0x02, 0x00, // Type: EXEC
        0x3E, 0x00, // Machine: x86-64 (62)
        0x01, 0x00, 0x00, 0x00, // Version
        0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, // Entry point: 0x12345678
    };
    // Padding sisa header
    header.resize(64, 0); 
    std::vector<uint8_t> dummy_data(100, 0xAA);
    header.insert(header.end(), dummy_data.begin(), dummy_data.end());

    file.write(reinterpret_cast<char*>(header.data()), header.size());
    file.close();
}

int main() {
    std::string test_file = "test_dummy.elf";
    create_dummy_elf(test_file);
    long expected_file_size = 64 + 100;

    std::cout << "[TEST] Mulai testParseHeaderElf..." << std::endl;
    
    // Panggil fungsi C-ABI
    C_ElfHeader hdr = c_parseHeaderElf(test_file.c_str());

    if (hdr.valid) {
        std::cout << "  [PASS] Header valid (valid=1)." << std::endl;
        
        // Cek magic string
        if (std::strcmp(hdr.magic, "ELF") == 0) {
             std::cout << "  [PASS] Magic string match: " << hdr.magic << std::endl;
        } else {
             std::cout << "  [FAIL] Magic string mismatch: " << hdr.magic << ", diharapkan: ELF" << std::endl;
             return 1;
        }

        // Cek entry point
        if (hdr.entry_point == 0x12345678) {
             std::cout << "  [PASS] Entry point match: 0x" << std::hex << hdr.entry_point << std::endl;
        } else {
             std::cout << "  [FAIL] Entry point mismatch: 0x" << std::hex << hdr.entry_point << std::endl;
             return 1;
        }
        
        // Cek machine type
        if (hdr.machine == 0x3E) { // 62
             std::cout << "  [PASS] Machine type match (AMD64)" << std::endl;
        } else {
             std::cout << "  [FAIL] Machine type mismatch: " << std::dec << hdr.machine << std::endl;
             return 1;
        }

        // Cek file size
        if (hdr.ukuran_file_size == expected_file_size) {
             std::cout << "  [PASS] Ukuran file match: " << std::dec << hdr.ukuran_file_size << std::endl;
        } else {
             std::cout << "  [FAIL] Ukuran file mismatch: " << std::dec << hdr.ukuran_file_size << ", diharapkan: " << expected_file_size << std::endl;
             return 1;
        }

    } else {
        std::cout << "  [FAIL] Header tidak valid (valid=0)" << std::endl;
        return 1;
    }

    std::remove(test_file.c_str());
    std::cout << "[TEST] testParseHeaderElf SELESAI." << std::endl;
    return 0;
}