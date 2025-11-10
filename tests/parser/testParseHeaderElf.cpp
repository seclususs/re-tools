#include "parser.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>

void create_dummy_elf(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    // Header ELF64 minimalis palsu
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, // Magic, 64-bit, LE, ver
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Pad
        0x02, 0x00, // Type: EXEC
        0x3E, 0x00, // Machine: x86-64
        0x01, 0x00, 0x00, 0x00, // Version
        0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, // Entry point: 0x12345678
    };
    // Padding sisa header agar ukuran valid minimal
    header.resize(64, 0); 
    file.write(reinterpret_cast<char*>(header.data()), header.size());
    file.close();
}

int main() {
    std::string test_file = "test_dummy.elf";
    create_dummy_elf(test_file);

    std::cout << "[TEST] Mulai testParseHeaderElf..." << std::endl;
    ElfHeader hdr = parseHeaderElf(test_file);

    if (hdr.valid) {
        std::cout << "  [PASS] Magic valid: " << hdr.magic << std::endl;
        // Cek little endian pembacaan
        if (hdr.entry_point == 0x12345678) {
             std::cout << "  [PASS] Entry point match: 0x" << std::hex << hdr.entry_point << std::endl;
        } else {
             std::cout << "  [FAIL] Entry point mismatch: 0x" << std::hex << hdr.entry_point << std::endl;
             return 1;
        }
        if (hdr.machine == 0x3E) {
             std::cout << "  [PASS] Machine type match (AMD64)" << std::endl;
        } else {
             std::cout << "  [FAIL] Machine type mismatch" << std::endl;
             return 1;
        }
    } else {
        std::cout << "  [FAIL] Header tidak valid" << std::endl;
        return 1;
    }

    std::remove(test_file.c_str());
    std::cout << "[TEST] testParseHeaderElf SELESAI." << std::endl;
    return 0;
}