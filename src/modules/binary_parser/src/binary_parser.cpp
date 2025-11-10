#include "binary_parser.h"
#include "utils.h"
#include <LIEF/LIEF.hpp>
#include <memory>
#include <iterator>


BinaryParser::BinaryParser(const std::string& path) : filePath(path) {
    // Constructor
}

// std::unique_ptr with a forward-declared type (LIEF::Binary) in the header.
BinaryParser::~BinaryParser() = default;

bool BinaryParser::loadBinary() {
    Utils::logInfo("[BinaryParser] Loading binary with LIEF: " + filePath);
    
    if (filePath.empty()) {
        Utils::logError("[BinaryParser] File path is empty.");
        return false;
    }

    // Use LIEF Parser to parse the file.
    // LIEF::Parser::parse returns a std::unique_ptr<LIEF::Binary>
    parsedBinary = LIEF::Parser::parse(filePath);

    if (!parsedBinary) {
        Utils::logError("[BinaryParser] LIEF failed to parse the binary: " + filePath);
        return false;
    }

    // Clear any old data
    sections.clear();
    symbols.clear();

    // Populate std::vector<Section>
    Utils::logInfo("[BinaryParser] Populating sections...");
    for (const LIEF::Section& sec : parsedBinary->sections()) {
        sections.push_back({
            sec.name(),
            sec.virtual_address(),
            sec.size()
        });
    }

    // Populate std::vector<Symbol>
    Utils::logInfo("[BinaryParser] Populating symbols...");
    for (const LIEF::Symbol& sym : parsedBinary->symbols()) {
        if (!sym.name().empty()) {
             symbols.push_back({
                sym.name(),
                sym.value()
            });
        }
    }
    
    Utils::logInfo("[BinaryParser] Successfully loaded " + std::to_string(sections.size()) + " sections and " + std::to_string(symbols.size()) + " symbols.");
    return true; 
}

std::vector<Section> BinaryParser::getSections() {
    Utils::logInfo("[BinaryParser] Retrieving sections.");
    return sections;
}

std::vector<Symbol> BinaryParser::getSymbols() {
    Utils::logInfo("[BinaryParser] Retrieving symbols.");
    return symbols;
}

/**
 * @brief Reads and returns the raw bytes from a specific section.
 * @param sectionName The name of the section (e.g., ".text").
 * @return A vector of bytes for that section, or an empty vector if not found.
 */
std::vector<uint8_t> BinaryParser::getSectionData(const std::string& sectionName) {
    if (!parsedBinary) {
        Utils::logError("[BinaryParser] Binary not loaded. Call loadBinary() first.");
        return {};
    }

    const LIEF::Section* foundSection = nullptr;
    for (const LIEF::Section& sec : parsedBinary->sections()) {
        if (sec.name() == sectionName) {
            foundSection = &sec;
            break;
        }
    }

    if (!foundSection) {
        Utils::logWarning("[BinaryParser] Section not found: " + sectionName);
        return {};
    }

    // Get the section's content as a LIEF::span<const uint8_t>
    LIEF::span<const uint8_t> content = foundSection->content();

    // Copy the data from the LIEF::span into a std::vector<uint8_t>
    return std::vector<uint8_t>(content.begin(), content.end());
}