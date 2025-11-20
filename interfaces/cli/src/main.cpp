#include <iostream>
#include <fstream>
#include "cli_engine.h"
#include "cli_repl.h"
#include "cli_utils.h"

void suppress_stderr() {
#ifdef _WIN32
    FILE* trash;
    freopen_s(&trash, "NUL", "w", stderr);
#else
    freopen("/dev/null", "w", stderr);
#endif
}

int main(int argc, char* argv[]) {
    std::ios::sync_with_stdio(false);
    suppress_stderr();
    CliEngine engine;
    bool interactive = true;
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "--headless") {
            interactive = false;
        } else if (arg == "--help") {
            std::cout << "ReTools CLI" << std::endl;
            return 0;
        }
    }
    if (interactive) {
        try {
            CliRepl repl(engine);
            repl.run();
        } catch (const std::exception& e) {
            #ifdef _WIN32
            FILE* console;
            freopen_s(&console, "CONOUT$", "w", stderr);
            #else
            freopen("/dev/tty", "w", stderr);
            #endif
            std::cerr << "[FATAL ERROR] UI Crash: " << e.what() << std::endl;
        }
    } else {
        std::cout << "Headless mode not implemented yet." << std::endl;
    }
    return 0;
}