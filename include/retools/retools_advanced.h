/**
 * @brief Advanced Analysis API (IR, Data Flow, Decompiler).
 * @details Provides high-level analysis capabilities including IR lifting,
 * optimization, data flow analysis, and decompilation.
 * @author Seclususs
 * @date 2025-11-19
 */

#ifndef RETOOLS_ADVANCED_H
#define RETOOLS_ADVANCED_H

#include "retools_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===================================================================================
// === INTERMEDIATE REPRESENTATION (IR) ===
// ===================================================================================

/**
 * @brief Supported architectures.
 */
typedef enum ArsitekturDisasm {
    ARCH_UNKNOWN = 0,
    ARCH_X86_32 = 1,
    ARCH_X86_64 = 2,
    ARCH_ARM_32 = 3,
    ARCH_ARM_64 = 4,
    ARCH_RISCV_32 = 5,
    ARCH_RISCV_64 = 6,
    ARCH_MIPS_32 = 7,
    ARCH_MIPS_64 = 8
} ArsitekturDisasm;

/**
 * @brief Decoded instruction details.
 */
typedef struct C_Instruksi {
    char mnemonic_instruksi[32];
    char str_operand[64];
    int ukuran;
    int valid;
} C_Instruksi;

/**
 * @brief Decodes a single machine instruction.
 */
C_Instruksi c_parseInstruksi(
    const u8* ptr_kode_raw,
    size_t len_buffer,
    size_t off_kursor,
    u64 va_basis_instr,
    ArsitekturDisasm enum_arch
);

/**
 * @brief Lifts machine code to Intermediate Representation (IR).
 * @return JSON string representing IR. Caller must free using `c_freeString`.
 */
char* c_liftInstruksi(
    const u8* ptr_kode_raw,
    size_t len_buffer,
    size_t off_kursor,
    u64 va_basis_instr,
    ArsitekturDisasm enum_arch
);

/**
 * @brief Optimizes the IR of a binary.
 * @return JSON string of optimized IR. Caller must free using `c_freeString`.
 */
char* c_calcOptimasi(const char* ptr_jalur_raw);


// ===================================================================================
// === DATA FLOW ANALYSIS ===
// ===================================================================================

/**
 * @brief Performs Liveness Analysis.
 * @return JSON string (LiveIn/LiveOut sets). Caller must free using `c_freeString`.
 */
char* c_getLivenessAnalysis_json(const char* ptr_path_raw);

/**
 * @brief Performs Reaching Definitions Analysis.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* c_getReachingDefs_json(const char* ptr_path_raw);

/**
 * @brief Generates Def-Use Chains.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* c_getDefUseChains_json(const char* ptr_path_raw);

/**
 * @brief Generates Use-Def Chains.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* c_getUseDefChains_json(const char* ptr_path_raw);

/**
 * @brief Performs Value Set Analysis (VSA).
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* c_getValueSetAnalysis_json(const char* ptr_path_raw);

/**
 * @brief Infers variable types based on access patterns.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* c_getTipeInference_json(const char* ptr_path_raw);

/**
 * @brief Checks for static memory access violations.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* c_getMemoryAccessCheck_json(const char* ptr_path_raw);


// ===================================================================================
// === HIGH-LEVEL TOOLS ===
// ===================================================================================

/**
 * @brief Performs a structural binary diff.
 * @return JSON string of diff results. Caller must free using `c_freeString`.
 */
char* c_calcDiffBiner_json(const char* ptr_path1_raw, const char* ptr_path2_raw);

/**
 * @brief Generates a Control Flow Graph (CFG) in DOT format.
 * @return DOT format string. Caller must free using `c_freeString`.
 */
char* c_createCFG(const char* ptr_jalur_raw);

/**
 * @brief Decompiles a function to pseudocode.
 * @return Pseudocode string. Caller must free using `c_freeString`.
 */
char* c_createPseudocode(const char* ptr_jalur_raw, u64 va_fungsi);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_ADVANCED_H