#include "utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

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

    // Function to remove whitespace and newlines from the beginning and end of a string
    std::string trim(const std::string& str) {
        const std::string whitespace = " \t\n\r\f\v";
        
        // Trim from right (end)
        size_t end = str.find_last_not_of(whitespace);
        if (end == std::string::npos) { // String contains only whitespace
            return "";
        }
        std::string s = str.substr(0, end + 1);
        
        // Trim from left (start)
        size_t start = s.find_first_not_of(whitespace);
        return s.substr(start);
    }

} // namespace Utils