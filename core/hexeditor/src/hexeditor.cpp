#include "hexeditor.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iterator>
#include <algorithm>
#include <cstring>

// Implementasi C++
std::string lihatBytes(const std::string& filename, int offset, int length) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return "ERROR: File tidak bisa dibuka";

    file.seekg(offset, std::ios::beg);
    if (!file) return "ERROR: Gagal seek offset";

    std::vector<uint8_t> buffer(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);
    // Mendapatkan jumlah bytes yang *sebenarnya* terbaca
    std::streamsize bytes_read = file.gcount();
    buffer.resize(bytes_read);

    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < buffer.size(); ++i) {
        ss << std::setw(2) << static_cast<int>(buffer[i]);
        if (i < buffer.size() - 1) ss << " ";
    }
    return ss.str();
}

bool ubahBytes(const std::string& filename, int offset, const std::vector<uint8_t>& data) {
    // Buka file dalam mode read+write binary, tanpa truncate
    std::fstream file(filename, std::ios::binary | std::ios::in | std::ios::out);
    if (!file) return false;

    file.seekp(offset, std::ios::beg);
    if (!file) return false; // Gagal seek

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    return !file.fail(); // Return true jika penulisan sukses
}

std::vector<int> cariPattern(const std::string& filename, const std::vector<uint8_t>& pattern) {
    std::vector<int> offsets;
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file || pattern.empty()) return offsets;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> file_data(size);
    if (!file.read(reinterpret_cast<char*>(file_data.data()), size)) {
        return offsets; // Gagal baca file
    }

    auto it = file_data.begin();
    auto end = file_data.end();
    
    while (true) {
        it = std::search(it, end, pattern.begin(), pattern.end());
        if (it == end) {
            break; // Tidak ditemukan lagi
        }
        
        offsets.push_back(std::distance(file_data.begin(), it));
        it++; // Lanjut cari dari byte selanjutnya
    }

    return offsets;
}

// Implementasi C Interface
extern "C" {
    int c_lihatBytes(const char* filename, int offset, int length, char* out_buffer, int out_buffer_size) {
        std::string result = lihatBytes(std::string(filename), offset, length);
        if (result.length() >= static_cast<size_t>(out_buffer_size)) {
            return -1; // Buffer terlalu kecil
        }
        std::strncpy(out_buffer, result.c_str(), out_buffer_size - 1);
        out_buffer[out_buffer_size - 1] = '\0'; // Pastikan null-terminated
        return 0;
    }

    int c_ubahBytes(const char* filename, int offset, const uint8_t* data, int data_len) {
        std::vector<uint8_t> vec_data(data, data + data_len);
        bool success = ubahBytes(std::string(filename), offset, vec_data);
        return success ? 1 : 0;
    }

    int c_cariPattern(const char* filename, const uint8_t* pattern, int pattern_len, int* out_offsets, int max_offsets) {
        std::vector<uint8_t> vec_pattern(pattern, pattern + pattern_len);
        std::vector<int> results = cariPattern(std::string(filename), vec_pattern);

        if (results.size() > static_cast<size_t>(max_offsets)) {
            return -1; // Buffer tidak cukup
        }

        for (size_t i = 0; i < results.size(); ++i) {
            out_offsets[i] = results[i];
        }
        return results.size();
    }
}