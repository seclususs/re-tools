#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Utils {

    // Logging
    void logInfo(const std::string& message);
    void logWarning(const std::string& message);
    void logError(const std::string& message);

    // File I/O
    std::string readFile(const std::string& filePath);
    bool writeFile(const std::string& filePath, const std::string& content);
    
    // Formatting
    std::string toHex(uint64_t value);

    // Add other common utilities
    // enum classLogLevel { INFO, WARN, ERROR };
    // ...

} // namespace Utils