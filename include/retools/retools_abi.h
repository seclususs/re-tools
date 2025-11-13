#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Struct untuk Header
typedef struct C_HeaderInfo {
    int32_t valid;       // 1 jika valid, 0 jika tidak
    char format[64];     // "ELF", "PE", "Mach-O", "Unknown"
    char arch[64];       // "x86-64", "x86", "AArch64", "ARM", "Unknown"
    uint16_t bits;       // 32 atau 64
    uint64_t entry_point;
    uint64_t machine_id; // Nilai mentah
    int32_t is_lib;      // 1 jika file adalah shared library, 0 jika bukan
    uint64_t file_size;
} C_HeaderInfo;

// Struct untuk Section
typedef struct C_SectionInfo {
    char name[128]; // Nama section
    uint64_t addr;
    uint64_t size;
    uint64_t offset; // File offset
    uint32_t tipe;   // Tipe section
} C_SectionInfo;

// Struct untuk Symbol
typedef struct C_SymbolInfo {
    char name[128]; // Nama simbol
    uint64_t addr;
    uint64_t size;
    char symbol_type[64]; // "FUNC", "OBJECT", "NOTYPE", dll.
    char bind[64];        // "GLOBAL", "LOCAL", "WEAK", dll.
} C_SymbolInfo;

/**
 * @brief Mengisi struct C_HeaderInfo dengan data dari header file.
 *
 * @param filename Path ke file binary.
 * @param out_header Pointer ke struct C_HeaderInfo yang akan diisi.
 * @return 0 jika sukses, -1 jika gagal.
 */
int32_t c_getBinaryHeader(const char* filename, C_HeaderInfo* out_header);

/**
 * @brief Mengisi buffer dengan array C_SectionInfo dari file.
 *
 * @param filename Path ke file binary.
 * @param out_buffer Pointer ke array C_SectionInfo.
 * @param max_count Jumlah maksimum struct yang bisa ditampung buffer.
 * @return Jumlah section yang diisi, atau -1 jika buffer terlalu kecil.
 */
int32_t c_getDaftarSections(const char* filename, C_SectionInfo* out_buffer, int32_t max_count);

/**
 * @brief Mengisi buffer dengan array C_SymbolInfo dari file.
 *
 * @param filename Path ke file binary.
 * @param out_buffer Pointer ke array C_SymbolInfo.
 * @param max_count Jumlah maksimum struct yang bisa ditampung buffer.
 * @return Jumlah simbol yang diisi, atau -1 jika buffer terlalu kecil.
 */
int32_t c_getDaftarSimbol(const char* filename, C_SymbolInfo* out_buffer, int32_t max_count);

#ifdef __cplusplus
} // extern "C"
#endif