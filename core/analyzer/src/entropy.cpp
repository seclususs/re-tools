#include "analyzer.h"
#include <fstream>
#include <vector>
#include <map>
#include <cmath>

double calculate_entropy_for_block(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;

    std::map<uint8_t, int> counts;
    for (uint8_t b : data) {
        counts[b]++;
    }

    double entropy = 0.0;
    double data_size = static_cast<double>(data.size());

    for (auto const& [key, val] : counts) {
        double p_x = static_cast<double>(val) / data_size;
        if (p_x > 0) {
            entropy -= p_x * std::log2(p_x);
        }
    }
    return entropy;
}

std::vector<double> hitungEntropy(const std::string& filename, int blockSize) {
    std::vector<double> entropies;
    std::ifstream file(filename, std::ios::binary);
    if (!file || blockSize <= 0) return entropies;

    std::vector<uint8_t> buffer(blockSize);
    
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), blockSize);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read == 0) break;

        // Resize buffer ke jumlah byte yang sebenarnya dibaca
        std::vector<uint8_t> block_data(buffer.begin(), buffer.begin() + bytes_read);
        entropies.push_back(calculate_entropy_for_block(block_data));
    }

    return entropies;
}

// C-Wrapper
extern "C" {
    int c_hitungEntropy(const char* filename, int blockSize, double* out_entropies, int max_entropies) {
        std::vector<double> results = hitungEntropy(std::string(filename), blockSize);

        if (results.size() > static_cast<size_t>(max_entropies)) {
            return -1; // Buffer tidak cukup
        }

        for (size_t i = 0; i < results.size(); ++i) {
            out_entropies[i] = results[i];
        }
        return results.size();
    }
}