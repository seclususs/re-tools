/**
 * @file retools_static.h
 * @brief [ID] Header untuk fungsionalitas Analisis Statis.
 *        [EN] Header for Static Analysis functionality.
 * @details [ID] Menggabungkan parsing, disassembler, hex editing, dan analisis file dasar.
 *          [EN] Combines parsing, disassembly, hex editing, and basic file analysis.
 * @author Seclususs
 * @date 2025-11-13
 * https://github.com/seclususs/retools
 */

#ifndef RETOOLS_STATIC_H
#define RETOOLS_STATIC_H

#include "retools_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===================================================================================
// === PARSER ===
// ===================================================================================

/**
 * @struct C_HeaderInfo
 * @brief [ID] Struktur C-ABI untuk menyimpan informasi header dasar (ELF/PE/Mach-O).
 *        [EN] C-ABI structure to store basic header information (ELF/PE/Mach-O).
 */
typedef struct C_HeaderInfo {
    int32_t valid;
    char format[64];
    char arch[64];
    uint16_t bits;
    uint64_t entry_point;
    uint64_t machine_id;
    int32_t is_lib;
    uint64_t file_size;
} C_HeaderInfo;

/**
 * @struct C_SectionInfo
 * @brief [ID] Struktur C-ABI untuk menyimpan informasi section (ELF).
 *        [EN] C-ABI structure to store section information (ELF).
 */
typedef struct C_SectionInfo {
    char name[128];
    uint64_t addr;
    uint64_t size;
    uint64_t offset;
    uint32_t tipe;
} C_SectionInfo;

/**
 * @struct C_SymbolInfo
 * @brief [ID] Struktur C-ABI untuk menyimpan informasi simbol (ELF).
 *        [EN] C-ABI structure to store symbol information (ELF).
 */
typedef struct C_SymbolInfo {
    char name[128];
    uint64_t addr;
    uint64_t size;
    char symbol_type[64];
    char bind[64];
} C_SymbolInfo;

/**
 * @brief [ID] Mengambil informasi header (ELF/PE/Mach-O) dari file.
 *        [EN] Retrieves header information (ELF/PE/Mach-O) from a file.
 * @param filename [ID] Nama file target yang akan di-parse.
 *                 [EN] Target filename to be parsed.
 * @param out_header [ID] Pointer ke struktur `C_HeaderInfo` untuk diisi dengan hasil.
 *                   [EN] Pointer to a `C_HeaderInfo` structure to be filled with the results.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] Returns 0 on success, -1 on failure.
 */
int32_t c_getBinaryHeader(const char* filename, C_HeaderInfo* out_header);

/**
 * @brief [ID] Mengambil daftar section dari file ELF.
 *        [EN] Retrieves the section list from an ELF file.
 * @param filename [ID] Nama file target (ELF) yang akan di-parse.
 *                 [EN] Target filename (ELF) to be parsed.
 * @param out_buffer [ID] Pointer ke buffer output untuk menyimpan hasil `C_SectionInfo`.
 *                   [EN] Pointer to the output buffer to store `C_SectionInfo` results.
 * @param max_count [ID] Ukuran maksimum buffer `out_buffer`.
 *                  [EN] The maximum size of the `out_buffer` buffer.
 * @return [ID] Jumlah section yang ditulis, -1 jika gagal.
 *         [EN] The number of sections written, -1 on failure.
 */
int32_t c_getDaftarSections(const char* filename, C_SectionInfo* out_buffer, int32_t max_count);

/**
 * @brief [ID] Mengambil daftar simbol dari file ELF.
 *        [EN] Retrieves the symbol list from an ELF file.
 * @param filename [ID] Nama file target (ELF) yang akan di-parse.
 *                 [EN] Target filename (ELF) to be parsed.
 * @param out_buffer [ID] Pointer ke buffer output untuk menyimpan hasil `C_SymbolInfo`.
 *                   [EN] Pointer to the output buffer to store `C_SymbolInfo` results.
 * @param max_count [ID] Ukuran maksimum buffer `out_buffer`.
 *                  [EN] The maximum size of the `out_buffer` buffer.
 * @return [ID] Jumlah simbol yang ditulis, -1 jika gagal.
 *         [EN] The number of symbols written, -1 on failure.
 */
int32_t c_getDaftarSimbol(const char* filename, C_SymbolInfo* out_buffer, int32_t max_count);


// ===================================================================================
// === DISASSEMBLER ===
// ===================================================================================

/**
 * @enum ArsitekturDisasm
 * @brief [ID] Enum C-ABI untuk menentukan arsitektur disassembler.
 *        [EN] C-ABI enum to specify the disassembler architecture.
 */
typedef enum ArsitekturDisasm {
    ARCH_UNKNOWN = 0,
    ARCH_X86_32 = 1,
    ARCH_X86_64 = 2,
    ARCH_ARM_32 = 3,
    ARCH_ARM_64 = 4
} ArsitekturDisasm;

/**
 * @struct C_Instruksi
 * @brief [ID] Struktur C-ABI untuk menyimpan hasil decode satu instruksi.
 *        [EN] C-ABI structure to store the result of decoding one instruction.
 */
struct C_Instruksi {
    char mnemonic_instruksi[32];
    char str_operand[64];
    int ukuran;
    int valid;
};

/**
 * @brief [ID] Mendecode satu instruksi dari buffer bytes.
 *        [EN] Decodes a single instruction from a byte buffer.
 * @param bytes [ID] Pointer ke data binary.
 *              [EN] Pointer to the binary data.
 * @param len [ID] Panjang total data binary.
 *            [EN] Total length of the binary data.
 * @param offset [ID] Offset di dalam `bytes` untuk mulai decode.
 *               [EN] Offset within `bytes` to start decoding.
 * @param instruction_base_va [ID] Alamat virtual (VA) dari instruksi, untuk kalkulasi relatif.
 *                            [EN] Virtual address (VA) of the instruction, for relative calculations.
 * @param arch [ID] Arsitektur target (enum `ArsitekturDisasm`).
 *             [EN] Target architecture (enum `ArsitekturDisasm`).
 * @return [ID] Struktur `C_Instruksi` yang berisi hasil decode.
 *         [EN] A `C_Instruksi` structure containing the decode result.
 */
struct C_Instruksi c_decodeInstruksi(
    const uint8_t* bytes, 
    size_t len, 
    size_t offset, 
    uint64_t instruction_base_va,
    ArsitekturDisasm arch
);


// ===================================================================================
// === ANALYZER ===
// ===================================================================================

/**
 * @brief [ID] Mengekstrak daftar string dari file (format JSON).
 *        [EN] Extracts a list of strings from the file (JSON format).
 * @param filename [ID] Nama file target yang akan dianalisis.
 *                 [EN] Target filename to be analyzed.
 * @param minLength [ID] Panjang string minimum untuk diekstrak.
 *                  [EN] The minimum string length to extract.
 * @return [ID] Pointer ke string JSON. Harus dibebaskan dengan `c_freeString`.
 *         [EN] Pointer to a JSON string. Must be freed with `c_freeString`.
 */
char* c_getStringsList_rs(const char* filename, int minLength);

/**
 * @brief [ID] Menghitung entropy file per blok.
 *        [EN] Calculates the file's entropy per block.
 * @param filename [ID] Nama file target yang akan dianalisis.
 *                 [EN] Target filename to be analyzed.
 * @param blockSize [ID] Ukuran setiap blok untuk dianalisis.
 *                  [EN] The size of each block to analyze.
 * @param out_entropies [ID] Pointer ke buffer output untuk menyimpan hasil entropy (array double).
 *                      [EN] Pointer to the output buffer to store entropy results (array of doubles).
 * @param max_entropies [ID] Ukuran maksimum buffer `out_entropies`.
 *                      [EN] The maximum size of the `out_entropies` buffer.
 * @return [ID] Jumlah blok entropy yang ditulis, -1 jika gagal.
 *         [EN] The number of entropy blocks written, -1 on failure.
 */
int c_hitungEntropy_rs(const char* filename, int blockSize, double* out_entropies, int max_entropies);

/**
 * @brief [ID] Mendeteksi pattern menggunakan regex pada file.
 *        [EN] Detects patterns using regex on the file.
 * @param filename [ID] Nama file target yang akan dianalisis.
 *                 [EN] Target filename to be analyzed.
 * @param regex_str [ID] String regex untuk mencari.
 *                  [EN] The regex string to search for.
 * @param out_buffer [ID] Buffer untuk menyimpan hasil (format JSON).
 *                   [EN] Buffer to store the results (JSON format).
 * @param out_buffer_size [ID] Ukuran `out_buffer`.
 *                        [EN] The size of `out_buffer`.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] 0 on success, -1 on failure.
 */
int c_deteksiPattern_rs(const char* filename, const char* regex_str, char* out_buffer, int out_buffer_size);


// ===================================================================================
// === HEX EDITOR ===
// ===================================================================================

/**
 * @brief [ID] Membaca bytes dari file dan mengembalikannya sebagai string hex.
 *        [EN] Reads bytes from a file and returns them as a hex string.
 * @param filename [ID] Nama file target yang akan dibaca.
 *                 [EN] Target filename to be read.
 * @param offset [ID] Offset di file untuk mulai membaca.
 *               [EN] Offset in the file to start reading.
 * @param length [ID] Jumlah bytes yang akan dibaca.
 *               [EN] Number of bytes to read.
 * @param out_buffer [ID] Buffer untuk menyimpan string hex (misal "00 01 02").
 *                   [EN] Buffer to store the hex string (e.g., "00 01 02").
 * @param out_buffer_size [ID] Ukuran `out_buffer`.
 *                        [EN] The size of `out_buffer`.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] 0 on success, -1 on failure.
 */
int c_lihatBytes(const char* filename, int offset, int length, char* out_buffer, int out_buffer_size);

/**
 * @brief [ID] Menimpa bytes di file pada offset tertentu.
 *        [EN] Overwrites bytes in a file at a specific offset.
 * @param filename [ID] Nama file target yang akan diubah.
 *                 [EN] Target filename to be modified.
 * @param offset [ID] Offset di file untuk mulai menulis.
 *               [EN] Offset in the file to start writing.
 * @param data [ID] Pointer ke data (bytes) yang akan ditulis.
 *             [EN] Pointer to the data (bytes) to be written.
 * @param data_len [ID] Panjang data yang akan ditulis.
 *                 [EN] The length of the data to be written.
 * @return [ID] 1 jika sukses, 0 jika gagal.
 *         [EN] 1 on success, 0 on failure.
 */
int c_ubahBytes(const char* filename, int offset, const uint8_t* data, int data_len);

/**
 * @brief [ID] Mencari pattern (array byte) di dalam file.
 *        [EN] Searches for a byte pattern within a file.
 * @param filename [ID] Nama file target yang akan dicari.
 *                 [EN] Target filename to be searched.
 * @param pattern [ID] Pointer ke pattern bytes yang dicari.
 *                [EN] Pointer to the byte pattern to search for.
 * @param pattern_len [ID] Panjang pattern.
 *                    [EN] The length of the pattern.
 * @param out_offsets [ID] Buffer output (array int) untuk menyimpan offset yang ditemukan.
 *                    [EN] Output buffer (array of ints) to store found offsets.
 * @param max_offsets [ID] Ukuran maksimum buffer `out_offsets`.
 *                    [EN] The maximum size of the `out_offsets` buffer.
 * @return [ID] Jumlah offset yang ditemukan, -1 jika gagal.
 *         [EN] The number of offsets found, -1 on failure.
 */
int c_cariPattern(const char* filename, const uint8_t* pattern, int pattern_len, int* out_offsets, int max_offsets);


#ifdef __cplusplus
}
#endif

#endif // RETOOLS_STATIC_H