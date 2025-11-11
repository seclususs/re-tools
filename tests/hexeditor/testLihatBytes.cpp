#include "hexeditor.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>

void create_dummy_file(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    // 00 01 02 ... 0F 10 ...
    std::vector<uint8_t> data;
    for (int i = 0; i < 256; ++i) {
        data.push_back(static_cast<uint8_t>(i));
    }
    file.write(reinterpret_cast<char*>(data.data()), data.size());
    file.close();
}

int main() {
    std::string test_file = "test_hex.bin";
    create_dummy_file(test_file);

    std::cout << "[TEST] Mulai testLihatBytes..." << std::endl;

    // Baca 5 bytes pertama dari offset 0
    std::string hex_str = lihatBytes(test_file, 0, 5);
    std::string expected1 = "00 01 02 03 04";
    if (hex_str == expected1) {
        std::cout << "  [PASS] Offset 0, Length 5 match: " << hex_str << std::endl;
    } else {
        std::cout << "  [FAIL] Offset 0, Length 5 mismatch. Got: " << hex_str << ", Expected: " << expected1 << std::endl;
        return 1;
    }

    // Baca 4 bytes dari offset 10 (0x0A)
    hex_str = lihatBytes(test_file, 10, 4);
    std::string expected2 = "0A 0B 0C 0D";
    if (hex_str == expected2) {
        std::cout << "  [PASS] Offset 10, Length 4 match: " << hex_str << std::endl;
    } else {
        std::cout << "  [FAIL] Offset 10, Length 4 mismatch. Got: " << hex_str << ", Expected: " << expected2 << std::endl;
        return 1;
    }
    
    // Test ubahBytes
    std::vector<uint8_t> patch = { 0xDE, 0xAD, 0xBE, 0xEF };
    bool success = ubahBytes(test_file, 0, patch);
    if (!success) {
        std::cout << "  [FAIL] ubahBytes gagal" << std::endl;
        return 1;
    }
    hex_str = lihatBytes(test_file, 0, 6);
    std::string expected3 = "DE AD BE EF 04 05";
    if (hex_str == expected3) {
        std::cout << "  [PASS] ubahBytes sukses diverifikasi" << std::endl;
    } else {
        std::cout << "  [FAIL] Verifikasi ubahBytes gagal. Got: " << hex_str << ", Expected: " << expected3 << std::endl;
        return 1;
    }
    
    std::remove(test_file.c_str());
    std::cout << "[TEST] testLihatBytes SELESAI." << std::endl;
    return 0;
}