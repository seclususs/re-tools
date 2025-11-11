#ifndef RETOOLS_TRACER_INTERNAL_H
#define RETOOLS_TRACER_INTERNAL_H

#include "retools/types.h"
#include <map>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

// Struktur internal yang disimpan di RT_Handle
struct DebuggerState {
    int pid;
    bool attached;
    
#ifdef _WIN32
    HANDLE hProcess;
#else
    // pid sudah cukup untuk ptrace
#endif
    // Menyimpan byte asli di alamat breakpoint
    std::map<u64, u8> breakpoints;
};

/**
 * @brief Primitif: Melakukan attach platform-spesifik.
 * Menginisialisasi handle di DebuggerState.
 */
bool platform_attach(DebuggerState* state);

/**
 * @brief Primitif: Melakukan detach platform-spesifik.
 * Membersihkan handle di DebuggerState.
 */
void platform_detach(DebuggerState* state);

/**
 * @brief Primitif: Membaca memori.
 */
int platform_bacaMemory(DebuggerState* state, u64 addr, u8* out, int size);

/**
 * @brief Primitif: Menulis memori.
 */
int platform_tulisMemory(DebuggerState* state, u64 addr, const u8* data, int size);

/**
 * @brief Primitif: Single step.
 */
int platform_singleStep(DebuggerState* state);

/**
 * @brief Primitif: Trace syscall.
 */
int platform_traceSyscall(int pid);


#endif // RETOOLS_TRACER_INTERNAL_H