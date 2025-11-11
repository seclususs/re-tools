#include "tracer.h"
#include <iostream>
#include <cassert>

#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#endif

// Fungsi untuk membuat proses anak (target)
int create_target_process() {
#ifdef _WIN32
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Buat proses yang 'sleep' (ping localhost 10 detik)
    char cmd[] = "ping 127.0.0.1 -n 10"; 
    
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)pi.dwProcessId;
#else
    pid_t pid = fork();
    if (pid == 0) {
        // Proses anak
        // Diam selama 10 detik
        execlp("sleep", "sleep", "10", NULL);
        _exit(1); // Jika execlp gagal
    } else {
        // Proses induk
        return pid;
    }
#endif
}

void cleanup_target_process(int pid) {
#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
#else
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
#endif
}

int main() {
    std::cout << "[TEST] Memulai testAttachProses..." << std::endl;

    int target_pid = create_target_process();
    if (target_pid <= 0) {
        std::cerr << "  [FAIL] Gagal membuat proses target." << std::endl;
        return 1;
    }
    std::cout << "  [INFO] Proses target dibuat dengan PID: " << target_pid << std::endl;
    
#ifdef _WIN32
    // Windows perlu waktu sedikit agar prosesnya stabil
    Sleep(500);
#else
    // Linux juga perlu waktu (meski attach akan menunggunya)
    usleep(100 * 1000); // 100ms
#endif


    // Test Attach
    RT_Handle handle = rt_attachProses(target_pid);
    if (handle) {
        std::cout << "  [PASS] rt_attachProses sukses." << std::endl;
    } else {
        std::cerr << "  [FAIL] rt_attachProses gagal." << std::endl;
        cleanup_target_process(target_pid);
        return 1;
    }

    // Test Detach
    rt_detachProses(handle);
    std::cout << "  [PASS] rt_detachProses sukses." << std::endl;

    cleanup_target_process(target_pid);
    std::cout << "[TEST] testAttachProses SELESAI." << std::endl;
    return 0;
}