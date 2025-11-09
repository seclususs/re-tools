#include "binary_parser.h"
#include "utils.h"

BinaryParser::BinaryParser(const std::string& path) : filePath(path) {
    // Constructor
}

BinaryParser::~BinaryParser() {
    // Destructor
}

bool BinaryParser::loadBinary() {
    Utils::logInfo("[BinaryParser] Loading binary: " + filePath);
    
    if (filePath.empty()) {
        return false;
    }
    
    sections.push_back({".text", 0x1000, 4096});
    sections.push_back({".data", 0x2000, 1024});
    symbols.push_back({"_start", 0x1000});
    symbols.push_back({"main", 0x1050});
    
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