#pragma once

#include <string>
#include <vector>
#include <cstdint>


struct Section {
    std::string name;
    uint64_t address;
    uint64_t size;
    // ... other properties
};

struct Symbol {
    std::string name;
    uint64_t address;
    // ... other properties
};

class BinaryParser {
public:
    BinaryParser(const std::string& path);
    ~BinaryParser();

    /**
     * @brief Loads and parses the binary file.
     * @return True on success, false on failure.
     */
    bool loadBinary();

    /**
     * @brief Retrieves all sections from the binary.
     * @return A vector of Section objects.
     */
    std::vector<Section> getSections();

    /**
     * @brief Retrieves all symbols from the binary.
     * @return A vector of Symbol objects.
     */
    std::vector<Symbol> getSymbols();

private:
    std::string filePath;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    
    // Private helper methods for parsing (e.g., ELF, PE)
    // void parseELF();
    // void parsePE();
};