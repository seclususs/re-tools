#include "retools_static.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>

void create_dummy_file(const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    std::vector<uint8_t> data;
    for (int i = 0; i < 256; ++i) {
        data.push_back(static_cast<uint8_t>(i));
    }
    file.write(reinterpret_cast<char*>(data.data()), data.size());
    file.close();
}

std::string panggilLihatBytes(const std::string& filename, int offset, int length) {
    int buffer_size = length * 3 + 1;
    std::vector<char> buffer(buffer_size, 0);
    int result = c_lihatBytes(filename.c_str(), offset, length, buffer.data(), buffer_size);
    if (result == 0) {
        return std::string(buffer.data());
    } else {
        return "ERROR";
    }
}

int main() {
    std::string test_file = "test_hex.bin";
    create_dummy_file(test_file);
    std::cout << "[TEST] Mulai testLihatBytes..." << std::endl;
    std::string hex_str = panggilLihatBytes(test_file, 0, 5);
    std::string expected1 = "00 01 02 03 04";
    if (hex_str == expected1) {
        std::cout << "  [PASS] Offset 0, Length 5 match: " << hex_str << std::endl;
    } else {
        std::cout << "  [FAIL] Offset 0, Length 5 mismatch. Got: " << hex_str << ", Expected: " << expected1 << std::endl;
        std::remove(test_file.c_str());
        return 1;
    }
    hex_str = panggilLihatBytes(test_file, 10, 4);
    std::string expected2 = "0A 0B 0C 0D";
    if (hex_str == expected2) {
        std::cout << "  [PASS] Offset 10, Length 4 match: " << hex_str << std::endl;
    } else {
        std::cout << "  [FAIL] Offset 10, Length 4 mismatch. Got: " << hex_str << ", Expected: " << expected2 << std::endl;
        std::remove(test_file.c_str());
        return 1;
    }
    std::vector<uint8_t> patch = { 0xDE, 0xAD, 0xBE, 0xEF };
    int success = c_ubahBytes(test_file.c_str(), 0, patch.data(), patch.size());
    if (success != 1) {
        std::cout << "  [FAIL] c_ubahBytes gagal" << std::endl;
        std::remove(test_file.c_str());
        return 1;
    }
    hex_str = panggilLihatBytes(test_file, 0, 6);
    std::string expected3 = "DE AD BE EF 04 05";
    if (hex_str == expected3) {
        std::cout << "  [PASS] ubahBytes sukses diverifikasi" << std::endl;
    } else {
        std::cout << "  [FAIL] Verifikasi ubahBytes gagal. Got: " << hex_str << ", Expected: " << expected3 << std::endl;
        std::remove(test_file.c_str());
        return 1;
    }
    std::remove(test_file.c_str());
    std::cout << "[TEST] testLihatBytes SELESAI." << std::endl;
    return 0;
}