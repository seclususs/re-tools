#include "tracer.h"
#include "tracer_internal.h"
#include <iostream>
#include <cstring>

// Implementasi C API (wrapper logika)
RT_Handle rt_attachProses(int pid) {
    DebuggerState* state = new (std::nothrow) DebuggerState();
    if (!state) return NULL;
    
    state->pid = pid;
    state->attached = false;

    if (platform_attach(state)) {
        state->attached = true;
        return (RT_Handle)state;
    } else {
        delete state;
        return NULL;
    }
}

void rt_detachProses(RT_Handle handle) {
    if (!handle) return;
    DebuggerState* state = (DebuggerState*)handle;
    
    // Kembalikan semua breakpoint sebelum detach
    for (auto const& [addr, orig_byte] : state->breakpoints) {
        u8 byte = orig_byte;
        platform_tulisMemory(state, addr, &byte, 1);
    }
    state->breakpoints.clear();

    if (state->attached) {
        platform_detach(state);
    }
    
    delete state;
}

int rt_bacaMemory(RT_Handle handle, u64 addr, u8* out_buffer, int size) {
    if (!handle || !out_buffer || size <= 0) return -1;
    DebuggerState* state = (DebuggerState*)handle;
    if (!state->attached) return -1;
    
    return platform_bacaMemory(state, addr, out_buffer, size);
}

int rt_tulisMemory(RT_Handle handle, u64 addr, const u8* data, int size) {
    if (!handle || !data || size <= 0) return -1;
    DebuggerState* state = (DebuggerState*)handle;
    if (!state->attached) return -1;

    return platform_tulisMemory(state, addr, data, size);
}

int rt_setBreakpoint(RT_Handle handle, u64 addr) {
    if (!handle) return -1;
    DebuggerState* state = (DebuggerState*)handle;
    if (state->breakpoints.count(addr)) {
        // Breakpoint sudah ada
        return 0;
    }

    // Baca byte asli
    u8 orig_byte;
    if (platform_bacaMemory(state, addr, &orig_byte, 1) != 1) {
        return -1; // Gagal baca
    }

    // Simpan byte asli
    state->breakpoints[addr] = orig_byte;

    // Tulis 0xCC (INT3)
    u8 int3 = 0xCC;
    if (platform_tulisMemory(state, addr, &int3, 1) != 1) {
        // Gagal, kembalikan byte asli
        state->breakpoints.erase(addr);
        return -1;
    }

    return 0;
}

int rt_singleStep(RT_Handle handle) {
    if (!handle) return -1;
    DebuggerState* state = (DebuggerState*)handle;
    return platform_singleStep(state);
}

int rt_traceSyscall(int pid) {
    // Fungsi ini standalone, tidak menggunakan state handle
    return platform_traceSyscall(pid);
}