#include "analyzer.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <regex>
#include <cstring>

std::vector<std::string> deteksiPattern(const std::string& filename, const std::string& regex_str) {
    std::vector<std::string> matches;
    
    // Baca seluruh file ke string (hati-hati untuk file besar)
    std::ifstream file(filename, std::ios::binary); 
    if (!file) return matches;
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string file_content = buffer.str();

    try {
        std::regex r(regex_str);
        std::smatch sm;

        // Cari semua match (bukan hanya yang pertama)
        std::string::const_iterator search_start(file_content.cbegin());
        while (std::regex_search(search_start, file_content.cend(), sm, r)) {
            matches.push_back(sm[0]); // sm[0] adalah seluruh match
            search_start = sm.suffix().first; // Lanjutkan pencarian dari akhir match
        }
    } catch (const std::regex_error& e) {
        // Gagal compile regex, kembalikan list kosong
        (void)e; // suppress unused variable
        return matches;
    }

    return matches;
}

// C-Wrapper (JSON approach)
extern "C" {
    int c_deteksiPattern(const char* filename, const char* regex_str, char* out_buffer, int out_buffer_size) {
        std::vector<std::string> results = deteksiPattern(std::string(filename), std::string(regex_str));

        // Logika JSON stringify yang sama seperti c_extractStrings
        std::stringstream json_ss;
        json_ss << "[";
        for (size_t i = 0; i < results.size(); ++i) {
            std::string s = results[i];
            std::string escaped_s;
            for (char c : s) {
                if (c == '"') escaped_s += "\\\"";
                else if (c == '\\') escaped_s += "\\\\";
                else if (c == '\n') escaped_s += "\\n";
                else if (c == '\r') escaped_s += "\\r";
                else if (c == '\t') escaped_s += "\\t";
                else if (c < 32 || c == 127) escaped_s += " "; 
                else escaped_s += c;
            }

            json_ss << "\"" << escaped_s << "\"";
            if (i < results.size() - 1) json_ss << ", ";
        }
        json_ss << "]";

        std::string json_result = json_ss.str();
        if (json_result.length() >= static_cast<size_t>(out_buffer_size)) {
            return -1; // Buffer terlalu kecil
        }

        std::strncpy(out_buffer, json_result.c_str(), out_buffer_size - 1);
        out_buffer[out_buffer_size - 1] = '\0';
        return 0;
    }
}