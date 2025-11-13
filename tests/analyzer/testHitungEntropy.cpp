#include "retools_static.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <cmath>
#include <cstdio>

void create_entropy_file(const std::string& filename, bool random) {
    std::ofstream file(filename, std::ios::binary);
    std::vector<uint8_t> data;
    if (random) {
        for (int i = 0; i < 1024; ++i) {
            data.push_back(static_cast<uint8_t>(i % 256));
        }
    } else {
        for (int i = 0; i < 1024; ++i) {
            data.push_back(0xAA);
        }
    }
    file.write(reinterpret_cast<char*>(data.data()), data.size());
    file.close();
}

int main() {
    std::string file_zero = "test_entropy_zero.bin";
    std::string file_high = "test_entropy_high.bin";
    create_entropy_file(file_zero, false);
    create_entropy_file(file_high, true);
    std::cout << "[TEST] Mulai testHitungEntropy..." << std::endl;
    const int MAX_ENTROPIES = 256;
    std::vector<double> entropy_buffer(MAX_ENTROPIES);
    int count1 = c_hitungEntropy_rs(file_zero.c_str(), 512, entropy_buffer.data(), MAX_ENTROPIES);
    assert(count1 == 2);
    if (std::fabs(entropy_buffer[0]) < 0.001 && std::fabs(entropy_buffer[1]) < 0.001) {
        std::cout << "  [PASS] Entropy 0.0 terdeteksi" << std::endl;
    } else {
        std::cout << "  [FAIL] Entropy 0.0 salah. Got: " << entropy_buffer[0] << ", " << entropy_buffer[1] << std::endl;
        std::remove(file_zero.c_str());
        std::remove(file_high.c_str());
        return 1;
    }
    int count2 = c_hitungEntropy_rs(file_high.c_str(), 1024, entropy_buffer.data(), MAX_ENTROPIES);
    assert(count2 == 1);
    if (std::fabs(entropy_buffer[0] - 8.0) < 0.001) {
        std::cout << "  [PASS] Entropy 8.0 terdeteksi" << std::endl;
    } else {
        std::cout << "  [FAIL] Entropy 8.0 salah. Got: " << entropy_buffer[0] << std::endl;
        std::remove(file_zero.c_str());
        std::remove(file_high.c_str());
        return 1;
    }
    std::remove(file_zero.c_str());
    std::remove(file_high.c_str());
    std::cout << "[TEST] testHitungEntropy SELESAI." << std::endl;
    return 0;
}