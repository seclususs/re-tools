#ifdef __linux__

#include "tracer_internal.h"
#include "ptrace_helpers.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>

bool platform_attach(DebuggerState* state) {
    if (ptrace(PTRACE_ATTACH, state->pid, NULL, NULL) == -1) {
        perror("Linux: PTRACE_ATTACH gagal");
        return false;
    }
    // Tunggu proses target berhenti (SIGSTOP)
    int status;
    waitpid(state->pid, &status, 0);
    if (WIFSTOPPED(status)) {
        return true;
    }
    return false;
}

void platform_detach(DebuggerState* state) {
    ptrace(PTRACE_DETACH, state->pid, NULL, NULL);
}

int platform_bacaMemory(DebuggerState* state, u64 addr, u8* out, int size) {
    if (ptrace_read_memory(state->pid, addr, out, size)) {
        return size;
    }
    return -1;
}

int platform_tulisMemory(DebuggerState* state, u64 addr, const u8* data, int size) {
    if (ptrace_write_memory(state->pid, addr, data, size)) {
        return size;
    }
    return -1;
}

int platform_singleStep(DebuggerState* state) {
    if (ptrace(PTRACE_SINGLESTEP, state->pid, NULL, NULL) == -1) {
        perror("Linux: PTRACE_SINGLESTEP gagal");
        return -1;
    }
    // Tunggu proses target (setelah 1 instruksi)
    int status;
    waitpid(state->pid, &status, 0);
    return WIFSTOPPED(status) ? 0 : -1;
}

int platform_traceSyscall(int pid) {
    // Implementasi: attach, PTRACE_SYSCALL, dan tunggu
    // Ini adalah fungsi 'blocking'
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("Linux: PTRACE_ATTACH (syscall) gagal");
        return -1;
    }
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) return -1;

    std::cout << "Melacak syscall untuk PID " << pid << ". (Tekan Ctrl+C untuk berhenti)" << std::endl;

    while (true) {
        // Tunggu syscall enter
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status)) break;
        // Ambil register (syscall number, args) - (di luar cakupan 'minimal')
        // ... ptrace(PTRACE_GETREGS, ...) ...
        
        // Tunggu syscall exit
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, &status, 0);
        if (!WIFSTOPPED(status)) break;
        // Ambil register (return value)
        // ... ptrace(PTRACE_GETREGS, ...) ...
        
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

#endif // __linux__