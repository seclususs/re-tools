#include "analyzer.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <nlohmann/json.hpp>

bool isPrintableAscii_cpp(char c) {
    return (c >= 32 && c <= 126);
}

std::vector<std::string> extractStrings(const std::string& filename, int minLength) {
    // Implementasi C++ lama.
    // Demi konsistensi, fungsi C++ ini sekarang juga akan memanggil Rust,
    // tapi ia akan mem-parsing JSON yang dikembalikan oleh Rust.
    // Tidak efisien, tapi menjaga C++ API tetap fungsional.
    
    std::vector<std::string> strings;
    char* json_str_c = c_getStringsList_rs(filename.c_str(), minLength);
    if (!json_str_c) return strings;

    try {
        // Gunakan nlohmann::json untuk parse
        // Format JSON: [ { "offset": 0, "content": "string1" }, ... ]
        nlohmann::json j = nlohmann::json::parse(json_str_c);
        if (j.is_array()) {
            for (const auto& item : j) {
                if (item.is_object() && item.contains("content")) {
                    strings.push_back(item["content"]);
                }
            }
        }
    } catch (...) {
        // Gagal parse JSON, tidak apa-apa
    }
    
    c_freeString(json_str_c); // Bebaskan string dari Rust
    return strings;
}


// C-Wrapper (JSON approach)
extern "C" {
    int c_extractStrings(const char* filename, int minLength, char* out_buffer, int out_buffer_size) {
        
        // Panggil fungsi C-ABI Rust
        char* json_str_rust = c_getStringsList_rs(filename, minLength);
        if (!json_str_rust) {
             strncpy(out_buffer, "[]", out_buffer_size - 1);
             out_buffer[out_buffer_size - 1] = '\0';
             return 0;
        }
        
        // Salin hasilnya ke buffer C++
        size_t json_len = std::strlen(json_str_rust);
        if (json_len >= static_cast<size_t>(out_buffer_size)) {
            c_freeString(json_str_rust); // Bebaskan memori
            return -1; // Buffer tidak cukup
        }

        std::strncpy(out_buffer, json_str_rust, out_buffer_size - 1);
        out_buffer[out_buffer_size - 1] = '\0';
        
        // Bebaskan string yang dialokasi Rust
        c_freeString(json_str_rust);
        
        return 0; // Sukses
    }
}