#include "cli_utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>

const std::string CliUtils::RESET = "\033[0m";
const std::string CliUtils::RED = "\033[31m";
const std::string CliUtils::GREEN = "\033[32m";
const std::string CliUtils::YELLOW = "\033[33m";
const std::string CliUtils::BLUE = "\033[34m";
const std::string CliUtils::CYAN = "\033[36m";
const std::string CliUtils::BOLD = "\033[1m";

void CliUtils::log(LogLevel level, const std::string& message) {
    switch (level) {
        case LogLevel::INFO:
            std::cout << BLUE << "[*] " << RESET << message << std::endl;
            break;
        case LogLevel::SUCCESS:
            std::cout << GREEN << "[+] " << RESET << message << std::endl;
            break;
        case LogLevel::WARNING:
            std::cout << YELLOW << "[!] " << RESET << message << std::endl;
            break;
        case LogLevel::ERROR:
            std::cerr << RED << "[-] " << RESET << message << std::endl;
            break;
        case LogLevel::DEBUG:
            std::cout << CYAN << "[D] " << RESET << message << std::endl;
            break;
    }
}

void CliUtils::print_header(const std::string& title) {
    std::cout << std::endl << BOLD << "=== " << title << " ===" << RESET << std::endl;
}

void CliUtils::print_kv(const std::string& key, const std::string& value) {
    std::cout << std::left << std::setw(20) << key << ": " << value << std::endl;
}
std::vector<std::string> CliUtils::split_args(const std::string& input) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(input);
    while (std::getline(tokenStream, token, ' ')) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

void CliUtils::clear_screen() {
    std::cout << "\033[2J\033[1;1H";
}