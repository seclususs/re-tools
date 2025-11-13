#include "binary_diff.h"
#include "parser.h"
#include <fstream>
#include <map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <cstdint>


std::vector<DiffResult> diffBinary(const std::string& file1, const std::string& file2) {
    // Fungsi ini hanya wrapper tipis ke C-ABI Rust
    std::vector<DiffResult> results;
    
    const int MAX_RESULTS = 4096;
    std::vector<C_DiffResult> c_buffer(MAX_RESULTS);

    int count = c_diffBinary_rs(file1.c_str(), file2.c_str(), c_buffer.data(), MAX_RESULTS);

    if (count < 0) {
        // Gagal, kembalikan hasil kosong
        return results;
    }

    // Konversi C_DiffResult ke DiffResult (C++)
    for (int i = 0; i < count; ++i) {
        results.push_back({
            std::string(c_buffer[i].functionName),
            c_buffer[i].addressFile1,
            c_buffer[i].addressFile2,
            static_cast<DiffResult::Status>(c_buffer[i].status)
        });
    }
    return results;
}

// Implementasi C Interface
extern "C" {
    int c_diffBinary(const char* file1, const char* file2, C_DiffResult* out_results, int max_results) {
        
        // Panggil implementasi C-ABI Rust BARU
        return c_diffBinary_rs(file1, file2, out_results, max_results);
    }
}