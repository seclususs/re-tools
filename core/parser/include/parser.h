#ifndef RETOOLS_PARSER_H
#define RETOOLS_PARSER_H

#include <string>
#include <vector>
#include <cstdint>


// C Interface
extern "C" {
    // Wrapper untuk ctypes
    struct C_ElfHeader {
        char magic[5];
        uint64_t entry_point;
        uint16_t machine;
        uint16_t section_count;
        int valid;
        uint64_t ukuran_file_size;
        uint64_t padding; 
    };

    /**
     * @brief Parse header ELF.
     */
    C_ElfHeader c_parseHeaderElf(const char* filename);
}

#endif // RETOOLS_PARSER_H