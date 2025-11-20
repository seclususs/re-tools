#include <iostream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

extern "C" int secret_calculation(int input) {
    int key = 0x55AA;
    if (input % 2 == 0) {
        return (input ^ key) + 1;
    } else {
        return (input ^ key) - 1;
    }
}

int g_secret_data = 1337;

int main() {
    const char* secret_message = "ReTools_Secret_Flag_XYZ123";
    std::cout << "=========================================" << std::endl;
    std::cout << "   DUMMY TARGET FOR RETOOLS TESTING      " << std::endl;
    std::cout << "=========================================" << std::endl;
    #ifdef _WIN32
    int pid = _getpid();
    #else
    int pid = getpid();
    #endif
    std::cout << "[INFO] Process PID: " << pid << std::endl;
    std::cout << "[INFO] Address of 'secret_calculation': " << (void*)&secret_calculation << std::endl;
    std::cout << "[INFO] Secret string stored in memory." << std::endl;
    std::cout << "[INFO] Program running... (CTRL+C to stop)" << std::endl;
    std::cout << "-----------------------------------------" << std::endl;
    int counter = 0;
    while (true) {
        int result = secret_calculation(counter);
        g_secret_data += result;
        std::cout << "Loop #" << counter << " | Result: 0x" << std::hex << result << std::dec << "\r" << std::flush;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        counter++;
    }
    return 0;
}