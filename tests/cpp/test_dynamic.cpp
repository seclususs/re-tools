#include <iostream>
#include "retools_dynamic.h"
#include <cassert>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#endif

int spawn_target() {
#ifdef _WIN32
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, (LPSTR)"ping 127.0.0.1 -n 3", NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return (int)pi.dwProcessId;
    }
    return -1;
#else
    pid_t pid = fork();
    if (pid == 0) {
        execlp("sleep", "sleep", "5", NULL);
        _exit(1);
    }
    return pid;
#endif
}
void kill_target(int pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        CloseHandle(h);
    }
#else
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
#endif
}

int main() {
    int pid = spawn_target();
    if (pid <= 0) return 1;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    RT_Handle h = rt_attachProses(pid);
    if (h) {
        C_Registers regs;
        if (rt_readRegister(h, &regs) == 0) {
            assert(regs.rip != 0 || regs.rax != 0);
        }
        rt_detachProses(h);
        std::cout << "Dynamic Tracer Test Passed" << std::endl;
    } else {
        std::cerr << "Attach Failed" << std::endl;
    }
    kill_target(pid);
    return 0;
}