#ifndef RETOOLS_TRACER_H
#define RETOOLS_TRACER_H

#include "retools/types.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief Mulai melacak syscall (Linux: PTRACE_SYSCALL).
 * Fungsi ini mungkin akan 'block' menunggu syscall berikutnya.
 * @param pid Process ID target (mungkin perlu attach baru).
 * @return Status, 0 jika sukses.
 */
int rt_traceSyscall(int pid);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_TRACER_H