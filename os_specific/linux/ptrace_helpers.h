#ifdef __linux__
#ifndef RETOOLS_PTRACE_HELPERS_H
#define RETOOLS_PTRACE_HELPERS_H

#include "retools/types.h"
#include <unistd.h>

// Helper ptrace untuk membaca/menulis blok data,
// karena PEEK/POKE hanya bekerja word-by-word.

/**
 * @brief Membaca blok memori menggunakan PTRACE_PEEKDATA
 */
bool ptrace_read_memory(pid_t pid, u64 addr, u8* out, int size);

/**
 * @brief Menulis blok memori menggunakan PTRACE_POKEDATA
 */
bool ptrace_write_memory(pid_t pid, u64 addr, const u8* data, int size);

#endif // RETOOLS_PTRACE_HELPERS_H
#endif // __linux__