#ifdef _WIN32

#include "tracer_internal.h"
#include "winapi_helpers.h"
#include <iostream>

bool platform_attach(DebuggerState* state) {
    EnableDebugPrivilege();

    // Untuk Read/WriteMemory, hanya perlu OpenProcess
    // Untuk single step/breakpoint (via debug loop), perlu DebugActiveProcess
    // Gunakan OpenProcess untuk R/W memori minimal
    
    state->hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        state->pid
    );
    
    if (state->hProcess == NULL) {
        std::cerr << "WinAPI: OpenProcess gagal, error: " << GetLastError() << std::endl;
        return false;
    }
    
    // TODO: Untuk single step/trace, perlu `DebugActiveProcess(state->pid)`
    // dan sebuah thread debug loop (WaitForDebugEvent).
    // Untuk saat ini biarkan non-fungsional di Windows.
    
    return true;
}

void platform_detach(DebuggerState* state) {
    if (state->hProcess != NULL) {
        CloseHandle(state->hProcess);
        state->hProcess = NULL;
    }
    // TODO: `DebugActiveProcessStop(state->pid)` jika menggunakannya.
}

int platform_bacaMemory(DebuggerState* state, u64 addr, u8* out, int size) {
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(state->hProcess, (LPCVOID)addr, out, (SIZE_T)size, &bytesRead)) {
        return (int)bytesRead;
    }
    return -1;
}

int platform_tulisMemory(DebuggerState* state, u64 addr, const u8* data, int size) {
    SIZE_T bytesWritten = 0;
    if (WriteProcessMemory(state->hProcess, (LPVOID)addr, data, (SIZE_T)size, &bytesWritten)) {
        return (int)bytesWritten;
    }
    return -1;
}

int platform_singleStep(DebuggerState* state) {
    // Implementasi Windows Debug API (DebugActiveProcess, WaitForDebugEvent,
    // set TRAP_FLAG, ContinueDebugEvent) sangat rumit.
    std::cerr << "PERINGATAN: singleStep() belum diimplementasikan di Windows" << std::endl;
    return -1; // Belum diimplementasikan
}

int platform_traceSyscall(int pid) {
    // Implementasi Windows (ETW) sangat rumit.
    std::cerr << "PERINGATAN: traceSyscall() belum diimplementasikan di Windows" << std::endl;
    return -1; // Belum diimplementasikan
}

#endif // _WIN32