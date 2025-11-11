#include "disasm.h"
#include <sstream>
#include <iomanip>
#include <cstring>

// Helper format hex
inline std::string to_hex_str(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << val;
    return ss.str();
}

InstruksiDecoded decodeInstruksi(const std::vector<uint8_t>& bytes, int offset) {
    InstruksiDecoded instr;
    instr.valid = false;
    instr.size = 0;

    if (offset >= static_cast<int>(bytes.size())) return instr;

    uint8_t opcode = bytes[offset];

    // Disassembler Subset Minimal x86_64
    switch (opcode) {
        case 0x90: // NOP
            instr.mnemonic = "NOP";
            instr.size = 1;
            instr.valid = true;
            break;
        case 0xC3: // RET
            instr.mnemonic = "RET";
            instr.size = 1;
            instr.valid = true;
            break;
        case 0xCC: // INT 3
            instr.mnemonic = "INT3";
            instr.size = 1;
            instr.valid = true;
            break;
        case 0x55: // PUSH RBP
            instr.mnemonic = "PUSH";
            instr.operands.push_back("rbp");
            instr.size = 1;
            instr.valid = true;
            break;
        case 0x5D: // POP RBP
            instr.mnemonic = "POP";
            instr.operands.push_back("rbp");
            instr.size = 1;
            instr.valid = true;
            break;
        case 0x48: // Prefix REX.W
            if (offset + 1 < bytes.size()) {
                uint8_t next_op = bytes[offset + 1];
                if (next_op == 0x89) { // MOV r/m64, r64
                     if (offset + 2 < bytes.size()) {
                         uint8_t modrm = bytes[offset + 2];
                         if (modrm == 0xE5) { // ModR/M untuk RSP, RBP
                             instr.mnemonic = "MOV";
                             instr.operands.push_back("rbp");
                             instr.operands.push_back("rsp");
                             instr.size = 3; // 48 89 E5
                             instr.valid = true;
                         }
                     }
                }
            }
            break;
        case 0xB8: // MOV EAX, imm32 (simplifikasi, aslinya tergantung mode)
            if (offset + 4 < bytes.size()) {
                instr.mnemonic = "MOV";
                instr.operands.push_back("eax");
                uint32_t imm = *reinterpret_cast<const uint32_t*>(&bytes[offset+1]);
                instr.operands.push_back(to_hex_str(imm));
                instr.size = 5;
                instr.valid = true;
            }
            break;
        default:
            // Instruksi tidak dikenal di subset ini
            instr.mnemonic = "(unknown)";
            instr.size = 1;
            instr.valid = false;
            break;
    }

    return instr;
}

extern "C" {
    C_Instruksi c_decodeInstruksi(const uint8_t* bytes_ptr, int len, int offset) {
        std::vector<uint8_t> vec_bytes(bytes_ptr, bytes_ptr + len);
        InstruksiDecoded cpp_instr = decodeInstruksi(vec_bytes, offset);

        C_Instruksi c_instr;
        std::strncpy(c_instr.mnemonic, cpp_instr.mnemonic.c_str(), 31);
        c_instr.mnemonic[31] = '\0';
        
        std::string op_joined;
        for (size_t i = 0; i < cpp_instr.operands.size(); ++i) {
            op_joined += cpp_instr.operands[i];
            if (i < cpp_instr.operands.size() - 1) op_joined += ", ";
        }
        std::strncpy(c_instr.op_str, op_joined.c_str(), 63);
        c_instr.op_str[63] = '\0';

        c_instr.size = cpp_instr.size;
        c_instr.valid = cpp_instr.valid ? 1 : 0;

        return c_instr;
    }
}