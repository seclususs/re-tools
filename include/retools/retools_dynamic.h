/**
 * @file retools_dynamic.h
 * @brief [ID] Header untuk fungsionalitas Analisis Dinamis (Debugger/Tracer).
 *        [EN] Header for Dynamic Analysis functionality (Debugger/Tracer).
 * @details [ID] File ini berisi deklarasi fungsi dan struktur data C-ABI untuk analisis dinamis (debugger).
 *          [EN] This file contains C-ABI function and data structure declarations for dynamic analysis (debugger).
 * @author Seclususs
 * @date 2025-11-13
 * @see https://github.com/seclususs/retools
 */

#ifndef RETOOLS_DYNAMIC_H
#define RETOOLS_DYNAMIC_H

#include "retools_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===================================================================================
// === TRACER / DEBUGGER ===
// ===================================================================================

/**
 * @struct C_Registers
 * @brief [ID] Struktur C-ABI untuk menyimpan register CPU (x86_64).
 *        [EN] C-ABI structure to store CPU registers (x86_64).
 */
typedef struct C_Registers {
    u64 rax;
    u64 rbx;
    u64 rcx;
    u64 rdx;
    u64 rsi;
    u64 rdi;
    u64 rbp;
    u64 rsp;
    u64 r8;
    u64 r9;
    u64 r10;
    u64 r11;
    u64 r12;
    u64 r13;
    u64 r14;
    u64 r15;
    u64 rip;
    u64 eflags;
} C_Registers;

/**
 * @enum DebugEventTipe
 * @brief [ID] Enum C-ABI untuk tipe event debugger.
 *        [EN] C-ABI enum for debugger event types.
 */
typedef enum DebugEventTipe {
    EVENT_UNKNOWN = 0,
    EVENT_BREAKPOINT = 1,
    EVENT_SINGLE_STEP = 2,
    EVENT_PROSES_EXIT = 3
} DebugEventTipe;

/**
 * @struct C_DebugEvent
 * @brief [ID] Struktur C-ABI untuk menyimpan data event debugger.
 *        [EN] C-ABI structure to store debugger event data.
 */
typedef struct C_DebugEvent {
    DebugEventTipe tipe;
    int pid_thread;
    u64 info_alamat;
} C_DebugEvent;

/**
 * @brief [ID] Melakukan attach ke proses yang sedang berjalan.
 *        [EN] Attaches to a running process.
 * @param pid [ID] PID dari proses target.
 *            [EN] The PID of the target process.
 * @return [ID] Handle internal ke state debugger (`RT_Handle`), NULL jika gagal.
 *         [EN] An internal handle to the debugger state (`RT_Handle`), NULL on failure.
 */
RT_Handle rt_attachProses(int pid);

/**
 * @brief [ID] Melakukan detach dari proses dan membersihkan state.
 *        [EN] Detaches from the process and cleans up the state.
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 */
void rt_detachProses(RT_Handle handle);

/**
 * @brief [ID] Membaca memori dari proses yang di-debug.
 *        [EN] Reads memory from the debugged process.
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @param addr [ID] Alamat virtual untuk dibaca.
 *             [EN] The virtual address to read from.
 * @param out_buffer [ID] Buffer untuk menyimpan data yang dibaca.
 *                   [EN] Buffer to store the read data.
 * @param size [ID] Jumlah byte yang akan dibaca.
 *             [EN] The number of bytes to read.
 * @return [ID] Jumlah byte yang berhasil dibaca, -1 jika gagal.
 *         [EN] The number of bytes successfully read, -1 on failure.
 */
int rt_bacaMemory(RT_Handle handle, u64 addr, u8* out_buffer, int size);

/**
 * @brief [ID] Menulis memori ke proses yang di-debug.
 *        [EN] Writes memory to the debugged process.
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @param addr [ID] Alamat virtual untuk ditulisi.
 *             [EN] The virtual address to write to.
 * @param data [ID] Pointer ke data yang akan ditulis.
 *             [EN] Pointer to the data to be written.
 * @param size [ID] Jumlah byte yang akan ditulis.
 *             [EN] The number of bytes to write.
 * @return [ID] Jumlah byte yang berhasil ditulis, -1 jika gagal.
 *         [EN] The number of bytes successfully written, -1 on failure.
 */
int rt_tulisMemory(RT_Handle handle, u64 addr, const u8* data, int size);

/**
 * @brief [ID] Menyetel software breakpoint (0xCC) di alamat tertentu.
 *        [EN] Sets a software breakpoint (0xCC) at a specific address.
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @param addr [ID] Alamat virtual untuk menyetel breakpoint.
 *             [EN] The virtual address to set the breakpoint at.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] 0 on success, -1 on failure.
 */
int rt_setBreakpoint(RT_Handle handle, u64 addr);

/**
 * @brief [ID] Melakukan eksekusi satu instruksi (single step).
 *        [EN] Executes a single instruction (single step).
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] 0 on success, -1 on failure.
 */
int rt_singleStep(RT_Handle handle);

/**
 * @brief [ID] Mengambil register CPU saat ini dari thread terakhir.
 *        [EN] Gets the current CPU registers from the last event's thread.
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @param out_registers [ID] Pointer ke struktur `C_Registers` untuk diisi.
 *                      [EN] Pointer to a `C_Registers` structure to be filled.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] 0 on success, -1 on failure.
 */
int rt_getRegisters(RT_Handle handle, C_Registers* out_registers);

/**
 * @brief [ID] Menyetel register CPU untuk thread terakhir.
 *        [EN] Sets the CPU registers for the last event's thread.
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @param registers [ID] Pointer ke struktur `C_Registers` yang berisi nilai baru.
 *                  [EN] Pointer to a `C_Registers` structure containing the new values.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] 0 on success, -1 on failure.
 */
int rt_setRegisters(RT_Handle handle, const C_Registers* registers);

/**
 * @brief [ID] Melanjutkan eksekusi proses.
 *        [EN] Continues the execution of the process.
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @return [ID] 0 jika sukses, -1 jika gagal.
 *         [EN] 0 on success, -1 on failure.
 */
int rt_continueProses(RT_Handle handle);

/**
 * @brief [ID] Menunggu event debugger selanjutnya (blocking).
 *        [EN] Waits for the next debugger event (blocking).
 * @param handle [ID] Handle (`RT_Handle`) yang didapat dari `rt_attachProses`.
 *               [EN] The handle (`RT_Handle`) obtained from `rt_attachProses`.
 * @param event_out [ID] Pointer ke struktur `C_DebugEvent` untuk diisi.
 *                  [EN] Pointer to a `C_DebugEvent` structure to be filled.
 * @return [ID] 0 jika event diterima, -1 jika gagal.
 *         [EN] 0 if an event was received, -1 on failure.
 */
int rt_tungguEvent(RT_Handle handle, C_DebugEvent* event_out);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_DYNAMIC_H