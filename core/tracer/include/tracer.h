#ifndef RETOOLS_TRACER_H
#define RETOOLS_TRACER_H

#include "retools/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Struct C-ABI untuk menyimpan register (x86_64)
 */
typedef struct C_Registers {
    // General Purpose
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
    // Instruction Pointer
    u64 rip;
    // Flags
    u64 eflags;
} C_Registers;

/**
 * @brief Enum C-ABI untuk tipe event debugger
 */
typedef enum DebugEventTipe {
    EVENT_UNKNOWN = 0,
    EVENT_BREAKPOINT = 1,
    EVENT_SINGLE_STEP = 2,
    EVENT_PROSES_EXIT = 3
} DebugEventTipe;

/**
 * @brief Struct C-ABI untuk hasil event debugger
 */
typedef struct C_DebugEvent {
    DebugEventTipe tipe;
    int pid_thread;
    u64 info_alamat; // Alamat breakpoint/exception
} C_DebugEvent;

/**
 * @brief Melakukan attach ke proses yang ada berdasarkan PID.
 * @param pid Process ID target.
 * @return RT_Handle (handle debugger) jika sukses, NULL jika gagal.
 * Handle ini harus dibebaskan menggunakan rt_detachProses.
 */
RT_Handle rt_attachProses(int pid);

/**
 * @brief Melakukan detach dari proses yang di-debug.
 * @param handle Handle yang didapat dari rt_attachProses.
 */
void rt_detachProses(RT_Handle handle);

/**
 * @brief Membaca memori dari proses yang di-debug.
 * @param handle Handle debugger.
 * @param addr Alamat memori yang ingin dibaca.
 * @param out_buffer Buffer untuk menyimpan data yang dibaca.
 * @param size Jumlah byte yang ingin dibaca.
 * @return Jumlah byte yang berhasil dibaca, atau -1 jika gagal.
 */
int rt_bacaMemory(RT_Handle handle, u64 addr, u8* out_buffer, int size);

/**
 * @brief Menulis memori ke proses yang di-debug.
 * @param handle Handle debugger.
 * @param addr Alamat memori yang ingin ditulis.
 * @param data Buffer yang berisi data untuk ditulis.
 * @param size Jumlah byte yang ingin ditulis.
 * @return Jumlah byte yang berhasil ditulis, atau -1 jika gagal.
 */
int rt_tulisMemory(RT_Handle handle, u64 addr, const u8* data, int size);

/**
 * @brief Menyetel software breakpoint (0xCC / INT3) di alamat tertentu.
 * @param handle Handle debugger.
 * @param addr Alamat untuk menyetel breakpoint.
 * @return 0 jika sukses, -1 jika gagal.
 */
int rt_setBreakpoint(RT_Handle handle, u64 addr);

/**
 * @brief Melanjutkan eksekusi proses untuk satu instruksi (single step).
 * @param handle Handle debugger.
 * @return 0 jika sukses, -1 jika gagal.
 */
int rt_singleStep(RT_Handle handle);

/**
 * @brief (DEPRECATED) Fungsi lama, gunakan rt_tungguEvent.
 */
int rt_traceSyscall(int pid);

/**
 * @brief Membaca register CPU dari thread utama/event terakhir.
 * @param handle Handle debugger.
 * @param out_registers Pointer ke struct C_Registers untuk diisi.
 * @return 0 jika sukses, -1 jika gagal.
 */
int rt_getRegisters(RT_Handle handle, C_Registers* out_registers);

/**
 * @brief Menulis register CPU ke thread utama/event terakhir.
 * @param handle Handle debugger.
 * @param registers Pointer ke struct C_Registers yang berisi data baru.
 * @return 0 jika sukses, -1 jika gagal.
 */
int rt_setRegisters(RT_Handle handle, const C_Registers* registers);

/**
 * @brief Melanjutkan eksekusi proses (continue).
 * @param handle Handle debugger.
 * @return 0 jika sukses, -1 jika gagal.
 */
int rt_continueProses(RT_Handle handle);

/**
 * @brief Menunggu event debugger berikutnya (blocking).
 * Fungsi ini secara otomatis menangani logika breakpoint (restore, step, re-insert).
 * @param handle Handle debugger.
 * @param event_out Pointer ke C_DebugEvent untuk diisi.
 * @return 0 jika sukses, -1 jika gagal.
 */
int rt_tungguEvent(RT_Handle handle, C_DebugEvent* event_out);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_TRACER_H