#include <iostream>
#include "cfg.h"
#include "parser.h"
#include "disasm.h"
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <map>

/**
 * @brief Implementasi generateCFG.
 */
std::string generateCFG(const std::string& filename) {
    // Panggil C-ABI Rust
    char* dot_str_c = c_generateCFG_rs(filename.c_str());
    if (!dot_str_c) {
        return "digraph G { error [label=\"Gagal alokasi di Rust\"]; }";
    }
    
    std::string dot_str_cpp(dot_str_c);
    
    // Bebaskan string dari Rust
    c_freeString(dot_str_c);
    
    return dot_str_cpp;
}

// Implementasi C Interface
extern "C" {
    int c_generateCFG(const char* filename, char* out_buffer, int out_buffer_size) {
        
        // Panggil C-ABI Rust
        char* result_rust = c_generateCFG_rs(filename);
        if (!result_rust) {
            return -1; // Gagal di Rust
        }

        size_t result_len = std::strlen(result_rust);
        if (result_len >= static_cast<size_t>(out_buffer_size)) {
            c_freeString(result_rust);
            return -1; // Buffer terlalu kecil
        }
        
        std::strncpy(out_buffer, result_rust, out_buffer_size - 1);
        out_buffer[out_buffer_size - 1] = '\0';
        
        c_freeString(result_rust);
        return 0;
    }
}