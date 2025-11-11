#include "analyzer.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>

bool isPrintableAscii(char c) {
    return (c >= 32 && c <= 126); // Karakter printable ASCII
}

std::vector<std::string> extractStrings(const std::string& filename, int minLength) {
    std::vector<std::string> strings;
    std::ifstream file(filename, std::ios::binary);
    if (!file) return strings;

    std::stringstream current_string;
    char c;
    int count = 0;

    while (file.get(c)) {
        if (isPrintableAscii(c)) {
            current_string.put(c);
            count++;
        } else {
            if (count >= minLength) {
                strings.push_back(current_string.str());
            }
            current_string.str(""); // Clear stringstream
            current_string.clear();
            count = 0;
        }
    }

    // Cek string terakhir di EOF
    if (count >= minLength) {
        strings.push_back(current_string.str());
    }

    return strings;
}

// C-Wrapper (JSON approach)
extern "C" {
    int c_extractStrings(const char* filename, int minLength, char* out_buffer, int out_buffer_size) {
        std::vector<std::string> results = extractStrings(std::string(filename), minLength);
        
        std::stringstream json_ss;
        json_ss << "[";
        for (size_t i = 0; i < results.size(); ++i) {
            // Escape simple JSON (hanya " dan \)
            std::string s = results[i];
            std::string escaped_s;
            for (char c : s) {
                if (c == '"') escaped_s += "\\\"";
                else if (c == '\\') escaped_s += "\\\\";
                // Simplifikasi: abaikan karakter non-printable lain di JSON string
                else if (c >= 0 && c < 32) escaped_s += " "; 
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