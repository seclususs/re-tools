#include "cli_utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>

std::deque<LogEntry> CliUtils::log_buffer;
std::mutex CliUtils::log_mutex;

void CliUtils::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    std::time_t now = std::time(nullptr);
    char time_buf[10];
    std::strftime(time_buf, sizeof(time_buf), "%H:%M:%S", std::localtime(&now));
    log_buffer.push_back({level, message, std::string(time_buf)});
    if (log_buffer.size() > MAX_LOG_SIZE) {
        log_buffer.pop_front();
    }
}

std::vector<LogEntry> CliUtils::get_logs() {
    std::lock_guard<std::mutex> lock(log_mutex);
    return std::vector<LogEntry>(log_buffer.begin(), log_buffer.end());
}

void CliUtils::print_header(const std::string& title) {
    std::cout << "=== " << title << " ===" << std::endl;
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