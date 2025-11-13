/**
 * @file retools_types.h
 * @brief [ID] Header untuk definisi tipe data C-ABI umum dan utilitas.
 *        [EN] Header for common C-ABI type definitions and utilities.
 * @details [ID] File ini berisi alias tipe data dasar dan fungsi utilitas (seperti free) yang digunakan di seluruh C-API.
 *          [EN] This file contains basic type aliases and utility functions (like free) used across the C-API.
 * @note [ID] Tipe-tipe ini menjamin konsistensi ukuran data antara C/C++ dan Rust.
 *       [EN] These types guarantee data size consistency between C/C++ and Rust.
 * @author Seclususs
 * @date 2025-11-13
 * https://github.com/seclususs/retools
 */

#ifndef RETOOLS_TYPES_H
#define RETOOLS_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// === Tipe Data Dasar ===

/**
 * @name Tipe Data Primitif
 * @brief [ID] Alias tipe data C-ABI untuk integer dengan ukuran tetap.
 *        [EN] C-ABI type aliases for fixed-size integers.
 * @{
 */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
/** @} */

/**
 * @enum RT_Status
 * @brief [ID] Kode status error (saat ini tidak digunakan secara aktif, preferensi -1/0).
 *        [EN] Error status codes (currently not actively used, preferring -1/0).
 */
typedef enum {
    RT_SUKSES = 0,
    RT_GAGAL_UMUM = -1,
    RT_INVALID_PARAMETER = -2,
    RT_MEMORI_PENUH = -3,
    RT_FILE_TIDAK_DITEMUKAN = -4,
    RT_BELUM_DIIMPLEMENTASIKAN = -99
} RT_Status;

/**
 * @typedef RT_Handle
 * @brief [ID] Tipe handle opaque untuk state internal (seperti state debugger).
 *        [EN] Opaque handle type for internal state (like the debugger state).
 */
typedef void* RT_Handle;


// === Utilitas Umum ===

/**
 * @brief [ID] Membebaskan memori string yang dialokasikan oleh Rust.
 *        [EN] Frees string memory allocated by Rust.
 * @param ptr [ID] Pointer string yang dikembalikan dari fungsi C-API (misal `c_getStringsList_rs` atau `c_generateCFG_rs`).
 *            [EN] String pointer returned from a C-API function (e.g., `c_getStringsList_rs` or `c_generateCFG_rs`).
 */
void c_freeString(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_TYPES_H