#ifndef RETOOLS_DISASM_H
#define RETOOLS_DISASM_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>


// Struct C++
struct InstruksiDecoded {
    std::string mnemonic;
    std::vector<std::string> operands;
    int size;
    bool valid;
};

// C Interface
extern "C" {
    // Enum untuk arsitektur
    typedef enum ArsitekturDisasm {
        ARCH_UNKNOWN = 0,
        ARCH_X86_32 = 1,
        ARCH_X86_64 = 2,
        ARCH_ARM_32 = 3,
        ARCH_ARM_64 = 4
    } ArsitekturDisasm;

    // Struct C-ABI
    struct C_Instruksi {
        char mnemonic_instruksi[32]; // Nama mnemonic
        char str_operand[64];    // String operand
        int ukuran;              // Ukuran instruksi
        int valid;             // 1 kalo valid
    };

    // Deklarasi fungsi C-ABI
    C_Instruksi c_decodeInstruksi(
        const uint8_t* bytes, 
        size_t len, 
        size_t offset, 
        ArsitekturDisasm arch
    );
}

#endif // RETOOLS_DISASM_H