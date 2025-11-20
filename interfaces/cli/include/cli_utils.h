#ifndef RETOOLS_CLI_UTILS_H
#define RETOOLS_CLI_UTILS_H

#include <string>
#include <vector>

enum class LogLevel {
    INFO,
    SUCCESS,
    WARNING,
    ERROR,
    DEBUG
};

class CliUtils {
public:
    static void log(LogLevel level, const std::string& message);
    static void print_header(const std::string& title);
    static void print_kv(const std::string& key, const std::string& value);
    static std::vector<std::string> split_args(const std::string& input);
    static void clear_screen();

private:
    static const std::string RESET;
    static const std::string RED;
    static const std::string GREEN;
    static const std::string YELLOW;
    static const std::string BLUE;
    static const std::string CYAN;
    static const std::string BOLD;
};

#endif