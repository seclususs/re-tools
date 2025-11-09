#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace Utils {

    void logInfo(const std::string& message) {
        std::cout << "[INFO] " << message << std::endl;
    }

    void logWarning(const std::string& message) {
        std::cerr << "[WARN] " << message << std::endl;
    }

    void logError(const std::string& message) {
        std::cerr << "[ERROR] " << message << std::endl;
    }

    std::string readFile(const std::string& filePath) {
        // Stub implementation
        std::ifstream file(filePath);
        if (!file.is_open()) {
            logError("Failed to read file: " + filePath);
            return "";
        }
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    bool writeFile(const std::string& filePath, const std::string& content) {
        // Stub implementation
        std::ofstream file(filePath);
        if (!file.is_open()) {
            logError("Failed to write file: " + filePath);
            return false;
        }
        file << content;
        return true;
    }
    
    std::string toHex(uint64_t value) {
        std::stringstream ss;
        ss << std::hex << value;
        return ss.str();
    }

} // namespace Utils