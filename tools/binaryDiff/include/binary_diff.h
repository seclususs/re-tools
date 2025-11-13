#ifndef RETOOLS_BINARY_DIFF_H
#define RETOOLS_BINARY_DIFF_H

#include <string>
#include <vector>
#include <cstdint>

// Struktur untuk hasil diff
struct DiffResult {
    enum Status {
        MATCHED,  // Cocok
        MODIFIED, // Berbeda
        REMOVED,  // Ada di file 1, tidak di file 2
        ADDED     // Ada di file 2, tidak di file 1
    };
    
    std::string functionName;
    uint64_t addressFile1;
    uint64_t addressFile2;
    Status status;
};

/**
 * @brief Membandingkan fungsi/basic block antara dua file binary.
 * @param file1 Path ke file binary pertama.
 * @param file2 Path ke file binary kedua.
 * @return List hasil perbandingan.
 */
std::vector<DiffResult> diffBinary(const std::string& file1, const std::string& file2);


// C Interface untuk Python
extern "C" {
    struct C_DiffResult {
        char functionName[128];
        uint64_t addressFile1;
        uint64_t addressFile2;
        int status; // 0=Matched, 1=Modified, 2=Removed, 3=Added
    };

    /**
     * @brief C-wrapper for diffBinary.
     * @param file1 Path file 1.
     * @param file2 Path file 2.
     * @param out_results Buffer untuk menyimpan hasil.
     * @param max_results Ukuran maksimum buffer out_results.
     * @return Jumlah hasil yang ditemukan, atau -1 jika buffer tidak cukup.
     */
    int c_diffBinary(const char* file1, const char* file2, C_DiffResult* out_results, int max_results);
    
    /**
     * @brief Implementasi penuh diffBinary di Rust.
     */
    int c_diffBinary_rs(const char* file1, const char* file2, C_DiffResult* out_results, int max_results);
}

#endif // RETOOLS_BINARY_DIFF_H