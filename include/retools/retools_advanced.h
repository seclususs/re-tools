/**
 * @file retools_advanced.h
 * @brief [ID] Header untuk fungsionalitas Analisis Statis Tingkat Tinggi.
 *        [EN] Header for High-Level Static Analysis functionality.
 * @details [ID] Menggabungkan tools canggih seperti Binary Diff dan CFG Generator.
 *          [EN] Combines advanced tools like Binary Diff and CFG Generator.
 * @author Seclususs
 * @date 2025-11-13
 * https://github.com/seclususs/retools
 */

#ifndef RETOOLS_ADVANCED_H
#define RETOOLS_ADVANCED_H

#include "retools_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===================================================================================
// === BINARY DIFF ===
// ===================================================================================

/**
 * @struct C_DiffResult
 * @brief [ID] Struktur C-ABI untuk menyimpan satu hasil perbandingan.
 *        [EN] C-ABI structure to store a single diff result.
 */
struct C_DiffResult {
    char functionName[128];
    uint64_t addressFile1;
    uint64_t addressFile2;
    int status; // 0=Matched, 1=Modified, 2=Removed, 3=Added
};

/**
 * @brief [ID] Membandingkan dua file binary dan mengembalikan perbedaannya.
 *        [EN] Compares two binary files and returns the differences.
 * @param file1 [ID] Nama file pertama yang akan dibandingkan.
 *              [EN] First filename to be compared.
 * @param file2 [ID] Nama file kedua.
 *              [EN] Second filename.
 * @param out_results [ID] Pointer ke buffer output untuk menyimpan hasil `C_DiffResult`.
 *                    [EN] Pointer to the output buffer to store `C_DiffResult` results.
 * @param max_results [ID] Ukuran maksimum buffer `out_results`.
 *                    [EN] The maximum size of the `out_results` buffer.
 * @return [ID] Jumlah hasil yang ditulis, -1 jika gagal.
 *         [EN] The number of results written, -1 on failure.
 */
int c_diffBinary_rs(const char* file1, const char* file2, struct C_DiffResult* out_results, int max_results);


// ===================================================================================
// === CONTROL FLOW GRAPH (CFG) ===
// ===================================================================================

/**
 * @brief [ID] Membuat Control Flow Graph (CFG) dari file.
 *        [EN] Generates a Control Flow Graph (CFG) from a file.
 * @param filename [ID] Nama file target yang akan dibuatkan CFG.
 *                 [EN] Target filename to generate a CFG for.
 * @return [ID] Pointer ke string format DOT. Harus dibebaskan dengan `c_freeString`.
 *         [EN] Pointer to a DOT format string. Must be freed with `c_freeString`.
 */
char* c_generateCFG_rs(const char* filename);


#ifdef __cplusplus
}
#endif

#endif // RETOOLS_ADVANCED_H