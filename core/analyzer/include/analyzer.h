#ifndef RETOOLS_ANALYZER_H
#define RETOOLS_ANALYZER_H

#include <string>
#include <vector>
#include <cstdint>


/**
 * @brief Mengekstrak string (ASCII/UTF-8) dari file binary.
 * @param filename Path ke file.
 * @param minLength Panjang minimum string yang diekstrak.
 * @return List berisi string yang ditemukan.
 */
std::vector<std::string> extractStrings(const std::string& filename, int minLength);

/**
 * @brief Menghitung entropy per blok dari sebuah file.
 * @param filename Path ke file.
 * @param blockSize Ukuran blok (misal: 1024 bytes).
 * @return List berisi nilai entropy (0.0 - 8.0) untuk setiap blok.
 */
std::vector<double> hitungEntropy(const std::string& filename, int blockSize);

/**
 * @brief Mendeteksi pattern menggunakan regex terhadap isi file (dibaca sebagai teks).
 * @param filename Path ke file.
 * @param regex_str String regex (C++ std::regex).
 * @return List berisi string yang cocok (match) dengan regex.
 */
std::vector<std::string> deteksiPattern(const std::string& filename, const std::string& regex_str);

// C Interface untuk Python
extern "C" {
    
    // C-Wrapper untuk extractStrings
    // Mengembalikan list of strings itu rumit. Return JSON string.
    // [ "string1", "string2", "string3" ]
    int c_extractStrings(const char* filename, int minLength, char* out_buffer, int out_buffer_size);

    // C-Wrapper untuk hitungEntropy
    // Mengembalikan list of doubles
    int c_hitungEntropy(const char* filename, int blockSize, double* out_entropies, int max_entropies);

    // C-Wrapper untuk deteksiPattern
    // Sama seperti extractStrings, kita kembalikan sebagai JSON string
    int c_deteksiPattern(const char* filename, const char* regex_str, char* out_buffer, int out_buffer_size);
}

#endif // RETOOLS_ANALYZER_H