#ifndef RETOOLS_DISASM_H
#define RETOOLS_DISASM_H

#include <string>
#include <vector>
#include <cstdint>


struct InstruksiDecoded {
    std::string mnemonic;
    std::vector<std::string> operands;
    int size;
    bool valid;
};

// Fungsi disassembler
InstruksiDecoded decodeInstruksi(const std::vector<uint8_t>& bytes, int offset);

// C Interface untuk Python
extern "C" {
    struct C_Instruksi {
        char mnemonic[32];
        char op_str[64];
        int size;
        int valid;
    };

    C_Instruksi c_decodeInstruksi(const uint8_t* bytes, int len, int offset);
}

#endif // RETOOLS_DISASM_H