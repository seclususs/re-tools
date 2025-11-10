#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

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

namespace LIEF {
    class Binary;
}

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

    /**
     * @brief Reads and returns the raw bytes from a specific section.
     * @param sectionName The name of the section (e.g., ".text").
     * @return A vector of bytes for that section, or an empty vector if not found.
     */
    std::vector<uint8_t> getSectionData(const std::string& sectionName);


private:
    std::string filePath;
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::unique_ptr<LIEF::Binary> parsedBinary;
};