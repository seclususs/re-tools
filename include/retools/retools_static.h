/**
 * @brief Static analysis, parsing, and scanning API.
 * @author Seclususs
 * @date 2025-11-19
 */

#ifndef RETOOLS_STATIC_H
#define RETOOLS_STATIC_H

#include "retools_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===================================================================================
// === BINARY PARSING ===
// ===================================================================================

/**
 * @brief Parses the binary header (ELF/PE/Mach-O) into JSON.
 *
 * @param ptr_jalur_raw Path to the binary file.
 * @return JSON string with header info. Caller must free using `c_freeString`.
 */
char* c_parseHeader_json(const char* ptr_jalur_raw);

/**
 * @brief Parses a raw binary file with a specific architecture.
 *
 * @param ptr_jalur_raw Path to the file.
 * @param val_arch_id Architecture ID.
 * @param va_basis Base virtual address.
 * @return JSON string with header info. Caller must free using `c_freeString`.
 */
char* c_parseHeaderRaw_json(const char* ptr_jalur_raw, int val_arch_id, u64 va_basis);

/**
 * @brief Parses section headers into JSON.
 * @return JSON string list of sections. Caller must free using `c_freeString`.
 */
char* c_parseSeksi_json(const char* ptr_jalur_raw);

/**
 * @brief Parses the symbol table into JSON.
 * @return JSON string list of symbols. Caller must free using `c_freeString`.
 */
char* c_parseSimbol_json(const char* ptr_jalur_raw);

/**
 * @brief Parses imported functions into JSON.
 * @return JSON string list of imports. Caller must free using `c_freeString`.
 */
char* c_parseImpor_json(const char* ptr_jalur_raw);

/**
 * @brief Parses exported functions into JSON.
 * @return JSON string list of exports. Caller must free using `c_freeString`.
 */
char* c_parseEkspor_json(const char* ptr_jalur_raw);

/**
 * @brief Parses ELF dynamic tags into JSON.
 * @return JSON string list of tags. Caller must free using `c_freeString`.
 */
char* c_parseElfDyn_json(const char* ptr_jalur_raw);


// ===================================================================================
// === SCANNERS & ANALYZERS ===
// ===================================================================================

/**
 * @brief Extracts ASCII and Unicode strings.
 * @param len_min Minimum string length.
 * @return JSON string list of found strings. Caller must free using `c_freeString`.
 */
char* c_scanString_rs(const char* ptr_jalur_raw, int len_min);

/**
 * @brief Calculates file entropy per block.
 * @param sz_blok Block size in bytes.
 * @return JSON array of entropy values. Caller must free using `c_freeString`.
 */
char* c_calcEntropy_json(const char* ptr_jalur_raw, int sz_blok);

/**
 * @brief Scans the file using a Regex pattern.
 * @param ptr_buf_luaran Buffer to store JSON result.
 * @param sz_buf_maks Size of the buffer.
 * @return 0 on success, -1 on failure.
 */
int c_scanPola_rs(const char* ptr_jalur_raw, const char* ptr_pola_regex, char* ptr_buf_luaran, int sz_buf_maks);

/**
 * @brief Scans the file using YARA rules.
 * @return JSON string of matches. Caller must free using `c_freeString`.
 */
char* c_scanYara_rs(const char* ptr_jalur_raw, const char* ptr_aturan_yara);

/**
 * @brief Scans for known cryptographic constants.
 * @return JSON string of results. Caller must free using `c_freeString`.
 */
char* c_scanKripto_json(const char* ptr_jalur_raw);

/**
 * @brief Heuristically detects packed sections based on entropy.
 * @param ambang_entropy Entropy threshold (e.g., 7.0).
 * @return JSON string of suspicious sections. Caller must free using `c_freeString`.
 */
char* c_scanPacker(const char* ptr_jalur_raw, double ambang_entropy);

/**
 * @brief Identifies library functions using signatures.
 * @return JSON string of matched functions. Caller must free using `c_freeString`.
 */
char* c_scanLib(const char* ptr_jalur_raw, const char* ptr_json_sig);

/**
 * @brief Analyzes data cross-references (X-Refs).
 * @param va_data Virtual address of the data.
 * @return JSON string list of accessing instructions. Caller must free using `c_freeString`.
 */
char* c_scanAksesData_json(const char* ptr_jalur_raw, u64 va_data);

/**
 * @brief Analyzes function callers.
 * @param va_fungsi Virtual address of the function.
 * @return JSON string list of calling addresses. Caller must free using `c_freeString`.
 */
char* c_scanPenelepon_json(const char* ptr_jalur_raw, u64 va_fungsi);


// ===================================================================================
// === HEX EDITOR ===
// ===================================================================================

/**
 * @brief Reads bytes and formats them as a hex string.
 * @return 0 on success, -1 on failure.
 */
int c_readBytes_hex(const char* ptr_jalur_raw, int off_posisi, int len_baca, char* ptr_buf_hex, int sz_buf_maks);

/**
 * @brief Patches the binary file.
 * @return 1 on success, 0 on failure.
 */
int c_writeBytes(const char* ptr_jalur_raw, int off_posisi, const u8* ptr_data_baru, int len_data);

/**
 * @brief Scans for a byte pattern.
 * @return JSON string list of offsets. Caller must free using `c_freeString`.
 */
char* c_scanPolaBytes_json(const char* ptr_jalur_raw, const u8* ptr_pola, int len_pola);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_STATIC_H