#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include "cli_engine.h"
#include "cli_repl.h"
#include "cli_utils.h"

void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " [options] <mode> <args...>" << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  -i, --interactive  : Start interactive shell (REPL)" << std::endl;
    std::cerr << "Modes (Non-interactive):" << std::endl;
    std::cerr << "  hybrid    : <binary_path> --pid <pid> [--steps <count>]" << std::endl;
    std::cerr << "  security  : <binary_path>" << std::endl;
    std::cerr << "  forensics : <binary_path> [--diff <second_binary>]" << std::endl;
}

int main(int argc, char* argv[]) {
    CliEngine engine;
    if (argc > 1 && (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interactive") == 0)) {
        CliRepl repl(engine);
        repl.run();
        return 0;
    }
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }
    std::string mode = argv[1];
    std::string binary_path = argv[2];
    engine.print_banner();
    if (mode == "hybrid") {
        int pid = -1;
        int steps = 1000;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--pid" && i + 1 < argc) {
                pid = std::stoi(argv[++i]);
            } else if (arg == "--steps" && i + 1 < argc) {
                steps = std::stoi(argv[++i]);
            }
        }
        if (pid == -1) {
            CliUtils::log(LogLevel::ERROR, "--pid is required for hybrid analysis.");
            return 1;
        }
        engine.handle_hybrid_analysis(binary_path, pid, steps);
    } else if (mode == "security") {
        engine.handle_security_analysis(binary_path);
    } else if (mode == "forensics") {
        std::string diff_target = "";
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--diff" && i + 1 < argc) {
                diff_target = argv[++i];
            }
        }
        engine.handle_forensics_analysis(binary_path, diff_target);
    } else {
        CliUtils::log(LogLevel::ERROR, "Unknown mode: " + mode);
        print_usage(argv[0]);
        return 1;
    }
    return 0;
}