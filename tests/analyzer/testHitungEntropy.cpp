#include "analyzer.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <cmath>

void create_entropy_file(const std::string& filename, bool random) {
    std::ofstream file(filename, std::ios::binary);
    std::vector<uint8_t> data;
    if (random) {
        // Data "random" (sebenarnya cuma urutan 0-255 berulang)
        for (int i = 0; i < 1024; ++i) {
            data.push_back(static_cast<uint8_t>(i % 256));
        }
    } else {
        // Data entropy 0
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
    create_entropy_file(file_zero, false); // Entropy 0
    create_entropy_file(file_high, true);  // Entropy 8 (ideal)

    std::cout << "[TEST] Mulai testHitungEntropy..." << std::endl;

    // Entropy 0 (Blok 512)
    std::vector<double> entropies = hitungEntropy(file_zero, 512);
    // Harus ada 2 blok (1024 / 512)
    assert(entropies.size() == 2);
    
    // Cek apakah mendekati 0
    if (std::fabs(entropies[0]) < 0.001 && std::fabs(entropies[1]) < 0.001) {
        std::cout << "  [PASS] Entropy 0.0 terdeteksi" << std::endl;
    } else {
        std::cout << "  [FAIL] Entropy 0.0 salah. Got: " << entropies[0] << ", " << entropies[1] << std::endl;
        return 1;
    }

    // Entropy tinggi (Blok 1024)
    entropies = hitungEntropy(file_high, 1024);
    assert(entropies.size() == 1);
    
    // Cek apakah mendekati 8 (ideal)
    if (std::fabs(entropies[0] - 8.0) < 0.001) {
        std::cout << "  [PASS] Entropy 8.0 terdeteksi" << std::endl;
    } else {
        std::cout << "  [FAIL] Entropy 8.0 salah. Got: " << entropies[0] << std::endl;
        return 1;
    }

    std::remove(file_zero.c_str());
    std::remove(file_high.c_str());
    std::cout << "[TEST] testHitungEntropy SELESAI." << std::endl;
    return 0;
}