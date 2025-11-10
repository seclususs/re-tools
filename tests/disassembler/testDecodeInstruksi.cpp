#include "disasm.h"
#include <iostream>
#include <vector>
#include <cassert>

void assert_instr(const InstruksiDecoded& ins, const std::string& mne, int sz) {
    if (!ins.valid) {
        std::cerr << "  [FAIL] Instruksi tidak valid, diharapkan: " << mne << std::endl;
        exit(1);
    }
    if (ins.mnemonic != mne) {
        std::cerr << "  [FAIL] Mnemonic salah: " << ins.mnemonic << ", diharapkan: " << mne << std::endl;
        exit(1);
    }
    if (ins.size != sz) {
        std::cerr << "  [FAIL] Ukuran salah untuk " << mne << ": " << ins.size << ", diharapkan: " << sz << std::endl;
        exit(1);
    }
    std::cout << "  [PASS] " << mne << " OK" << std::endl;
}

int main() {
    std::cout << "[TEST] Mulai testDecodeInstruksi..." << std::endl;

    // Kode mesin sampel: PUSH RBP; MOV RBP, RSP; NOP; RET
    std::vector<uint8_t> code = { 0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3 };

    InstruksiDecoded ins;
    int offset = 0;

    // 0x55 -> PUSH RBP
    ins = decodeInstruksi(code, offset);
    assert_instr(ins, "PUSH", 1);
    offset += ins.size;

    // 0x48 0x89 0xE5 -> MOV RBP, RSP
    ins = decodeInstruksi(code, offset);
    assert_instr(ins, "MOV", 3);
    assert(ins.operands.size() == 2 && ins.operands[0] == "rbp" && ins.operands[1] == "rsp");
    offset += ins.size;

    // 0x90 -> NOP
    ins = decodeInstruksi(code, offset);
    assert_instr(ins, "NOP", 1);
    offset += ins.size;

    // 0xC3 -> RET
    ins = decodeInstruksi(code, offset);
    assert_instr(ins, "RET", 1);

    std::cout << "[TEST] testDecodeInstruksi SELESAI." << std::endl;
    return 0;
}