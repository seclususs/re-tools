#ifndef RETOOLS_CLI_UTILS_H
#define RETOOLS_CLI_UTILS_H

#include <string>
#include <vector>
#include <deque>
#include <mutex>

enum class LogLevel {
    INFO,
    SUCCESS,
    WARNING,
    ERROR,
    DEBUG
};

struct LogEntry {
    LogLevel level;
    std::string message;
    std::string timestamp;
};

class CliUtils {
public:
    static void log(LogLevel level, const std::string& message);
    static std::vector<LogEntry> get_logs();
    static void print_header(const std::string& title);
    static void clear_screen();
    static std::vector<std::string> split_args(const std::string& input);

private:
    static std::deque<LogEntry> log_buffer;
    static std::mutex log_mutex;
    static const size_t MAX_LOG_SIZE = 100;
};

#endif