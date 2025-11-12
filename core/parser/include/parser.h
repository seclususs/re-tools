#ifndef RETOOLS_PARSER_H
#define RETOOLS_PARSER_H

#include <string>
#include <vector>
#include <cstdint>


// C Interface
extern "C" {
    
    /**
     * @brief Parse header generik (ELF, PE, Mach-O) dan return sebagai JSON string.
     * @param filename Path ke file binary.
     * @return Pointer ke string JSON. Panggil c_freeJsonString() untuk membebaskan.
     */
    char* c_parseBinaryHeader(const char* filename);

    /**
     * @brief Parse ELF sections dan return sebagai JSON string.
     * @param filename Path ke file binary.
     * @return Pointer ke string JSON. Panggil c_freeJsonString() untuk membebaskan.
     */
    char* c_parseSectionsElf(const char* filename);

    /**
     * @brief Parse ELF symbols (static + dynamic) dan return sebagai JSON string.
     * @param filename Path ke file binary.
     * @return Pointer ke string JSON. Panggil c_freeJsonString() untuk membebaskan.
     */
    char* c_parseSymbolsElf(const char* filename);

    /**
     * @brief Membebaskan memori string JSON yang dialokasikan oleh Rust.
     * @param s Pointer string yang dikembalikan dari c_parseSectionsElf/c_parseSymbolsElf.
     */
    void c_freeJsonString(char* s);
    
} // extern "C"

#endif // RETOOLS_PARSER_H