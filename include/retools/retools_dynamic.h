/**
 * @brief Dynamic Analysis and Debugging API.
 * @author Seclususs
 * @date 2025-11-19
 */

#ifndef RETOOLS_DYNAMIC_H
#define RETOOLS_DYNAMIC_H

#include "retools_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ===================================================================================
// === DATA STRUCTURES ===
// ===================================================================================

/**
 * @brief CPU register state (x86_64).
 */
typedef struct C_Registers {
    u64 rax; u64 rbx; u64 rcx; u64 rdx;
    u64 rsi; u64 rdi; u64 rbp; u64 rsp;
    u64 r8;  u64 r9;  u64 r10; u64 r11;
    u64 r12; u64 r13; u64 r14; u64 r15;
    u64 rip; u64 eflags;
} C_Registers;

/**
 * @brief Types of debug events.
 */
typedef enum DebugEventTipe {
    EVENT_UNKNOWN = 0,
    EVENT_BREAKPOINT = 1,
    EVENT_SINGLE_STEP = 2,
    EVENT_PROSES_EXIT = 3,
    EVENT_THREAD_BARU = 4,
    EVENT_THREAD_EXIT = 5,
    EVENT_SYSCALL_ENTRY = 6,
    EVENT_SYSCALL_EXIT = 7,
    EVENT_MODUL_LOAD = 8
} DebugEventTipe;

/**
 * @brief Debug event details.
 */
typedef struct C_DebugEvent {
    DebugEventTipe tipe;
    int pid_thread;
    u64 info_alamat;
} C_DebugEvent;


// ===================================================================================
// === PROCESS CONTROL ===
// ===================================================================================

/**
 * @brief Attaches to a running process.
 * @return Debugger handle or NULL on failure.
 */
RT_Handle rt_attachProses(int id_pid_target);

/**
 * @brief Detaches and cleans up the debugger session.
 */
void rt_detachProses(RT_Handle ptr_handle);

/**
 * @brief Continues process execution.
 * @return 0 on success, -1 on failure.
 */
int rt_continueProses(RT_Handle ptr_handle);

/**
 * @brief Executes a single instruction.
 * @return 0 on success, -1 on failure.
 */
int rt_stepInstruksi(RT_Handle ptr_handle);

/**
 * @brief Waits for a debug event (blocking).
 * @param ptr_event_out Pointer to store event details.
 * @return 0 on success, -1 on failure.
 */
int rt_waitEvent(RT_Handle ptr_handle, C_DebugEvent* ptr_event_out);


// ===================================================================================
// === MEMORY & REGISTERS ===
// ===================================================================================

/**
 * @brief Reads memory from the target process.
 * @return Number of bytes read, or -1 on failure.
 */
int rt_readMemori(RT_Handle ptr_handle, u64 va_target, u8* ptr_buf_hasil, int sz_baca);

/**
 * @brief Writes memory to the target process.
 * @return Number of bytes written, or -1 on failure.
 */
int rt_writeMemori(RT_Handle ptr_handle, u64 va_target, const u8* ptr_sumber_data, int sz_tulis);

/**
 * @brief Reads CPU registers for the current thread.
 * @return 0 on success, -1 on failure.
 */
int rt_readRegister(RT_Handle ptr_handle, C_Registers* ptr_reg_luaran);

/**
 * @brief Writes CPU registers for the current thread.
 * @return 0 on success, -1 on failure.
 */
int rt_writeRegister(RT_Handle ptr_handle, const C_Registers* ptr_reg_in);


// ===================================================================================
// === BREAKPOINTS ===
// ===================================================================================

/**
 * @brief Sets a Software Breakpoint (INT 3).
 */
int rt_insertTitikHentiSw(RT_Handle ptr_handle, u64 va_target);

/**
 * @brief Removes a Software Breakpoint.
 */
int rt_removeTitikHentiSw(RT_Handle ptr_handle, u64 va_target);

/**
 * @brief Sets a Hardware Breakpoint (DRx).
 * @param id_urutan Slot index (0-3).
 */
int rt_insertTitikHentiHw(RT_Handle ptr_handle, u64 va_target, int id_urutan);

/**
 * @brief Removes a Hardware Breakpoint.
 */
int rt_removeTitikHentiHw(RT_Handle ptr_handle, int id_urutan);


// ===================================================================================
// === ADVANCED INFO ===
// ===================================================================================

/**
 * @brief Retrieves list of threads in JSON.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* rt_listThread_json(RT_Handle ptr_handle);

/**
 * @brief Retrieves memory regions in JSON.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* rt_readRegionMemori_json(RT_Handle ptr_handle);

/**
 * @brief Toggles system call tracing.
 */
int rt_setTraceSyscall(RT_Handle ptr_handle, bool is_aktif);

/**
 * @brief Retrieves last syscall info in JSON.
 * @return JSON string. Caller must free using `c_freeString`.
 */
char* rt_readInfoSyscall_json(RT_Handle ptr_handle, int id_thread);

// ===================================================================================
// === HYBRID ANALYSIS ===
// ===================================================================================

/**
 * @brief Performs Smart/Hybrid analysis by resolving dynamic jumps.
 * @details Traces the binary for `max_langkah` instructions to resolve
 * indirect branches, then refines the CFG and VSA results.
 *
 * @param ptr_jalur_biner Path to the binary file.
 * @param pid_target PID of the running process to attach to.
 * @param max_langkah Maximum instructions to trace.
 * @return JSON string containing coverage and iteration stats. Caller must free using `c_freeString`.
 */
char* rt_resolveDynamic(const char* ptr_jalur_biner, int pid_target, int max_langkah);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_DYNAMIC_H