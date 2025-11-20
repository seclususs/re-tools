#include "cli_repl.h"
#include "cli_utils.h"
#include <iostream>
#include <vector>

CliRepl::CliRepl(CliEngine& engine) : engine(engine), running(false) {}

void CliRepl::run() {
    running = true;
    CliUtils::clear_screen();
    engine.print_banner();
    CliUtils::log(LogLevel::INFO, "Entering Interactive Mode. Type 'help' for commands.");
    std::string line;
    while (running) {
        std::cout << "\nretools> ";
        if (!std::getline(std::cin, line)) {
            break;
        }
        if (line.empty()) continue;
        process_command(line);
    }
}

void CliRepl::process_command(const std::string& line) {
    auto args = CliUtils::split_args(line);
    if (args.empty()) return;
    std::string cmd = args[0];
    if (cmd == "exit" || cmd == "quit") {
        running = false;
        CliUtils::log(LogLevel::INFO, "Exiting ReTools...");
    } else if (cmd == "clear") {
        CliUtils::clear_screen();
        engine.print_banner();
    } else if (cmd == "help") {
        show_help();
    } else if (cmd == "hybrid") {
        handle_hybrid_cmd(args);
    } else if (cmd == "security") {
        handle_security_cmd(args);
    } else if (cmd == "forensics") {
        handle_forensics_cmd(args);
    } else {
        CliUtils::log(LogLevel::ERROR, "Unknown command: " + cmd);
    }
}

void CliRepl::show_help() {
    CliUtils::print_header("Available Commands");
    CliUtils::print_kv("hybrid", "<file> <pid> [steps]");
    CliUtils::print_kv("security", "<file>");
    CliUtils::print_kv("forensics", "<file> [diff_target]");
    CliUtils::print_kv("clear", "Clear screen");
    CliUtils::print_kv("exit", "Exit shell");
}

void CliRepl::handle_hybrid_cmd(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        CliUtils::log(LogLevel::WARNING, "Usage: hybrid <binary_path> <pid> [max_steps]");
        return;
    }
    std::string path = args[1];
    int pid = 0;
    int steps = 1000;
    try {
        pid = std::stoi(args[2]);
        if (args.size() >= 4) {
            steps = std::stoi(args[3]);
        }
        engine.handle_hybrid_analysis(path, pid, steps);
    } catch (...) {
        CliUtils::log(LogLevel::ERROR, "Invalid PID or Steps value.");
    }
}

void CliRepl::handle_security_cmd(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        CliUtils::log(LogLevel::WARNING, "Usage: security <binary_path>");
        return;
    }
    engine.handle_security_analysis(args[1]);
}

void CliRepl::handle_forensics_cmd(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        CliUtils::log(LogLevel::WARNING, "Usage: forensics <binary_path> [diff_path]");
        return;
    }
    std::string diff_target = "";
    if (args.size() >= 3) {
        diff_target = args[2];
    }
    engine.handle_forensics_analysis(args[1], diff_target);
}