#include "disasm.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <sstream>
#include <algorithm>
#include <cctype>

/**
 * @brief Helper untuk panggil C-ABI Rust dan konversi hasilnya ke C++ struct
 */
InstruksiDecoded panggilDanKonversi(const std::vector<uint8_t>& bytes, int offset, ArsitekturDisasm arch) {
    
    // Panggil C-ABI Rust
    C_Instruksi c_instr = c_decodeInstruksi(
        bytes.data(),
        bytes.size(),
        static_cast<size_t>(offset),
        arch // Teruskan arsitektur
    );

    // Konversi C_Instruksi (C struct) ke InstruksiDecoded (C++ struct)
    InstruksiDecoded instr;
    instr.valid = (c_instr.valid != 0);
    instr.size = c_instr.ukuran;

    if (instr.valid) {
        // Konversi mnemonic ke UPPERCASE
        std::string temp_mne(c_instr.mnemonic_instruksi);
        std::transform(temp_mne.begin(), temp_mne.end(), std::back_inserter(instr.mnemonic), ::toupper);

        // Parsing string operand (Capstone format: "op1, op2")
        std::string ops(c_instr.str_operand);
        if (!ops.empty()) {
            std::stringstream ss(ops);
            std::string single_op;
            while (std::getline(ss, single_op, ',')) {
                // Trim spasi
                size_t first = single_op.find_first_not_of(' ');
                if (std::string::npos == first) {
                    if (!single_op.empty()) instr.operands.push_back(single_op);
                } else {
                    size_t last = single_op.find_last_not_of(' ');
                    instr.operands.push_back(single_op.substr(first, (last - first + 1)));
                }
            }
        }
    } else {
        instr.mnemonic = "(unknown)";
        if (instr.size == 0) instr.size = 1; // Hindari infinite loop
    }
    
    return instr;
}

// Fungsi assert helper
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

void testX86_64() {
    std::cout << "[TEST] Menjalankan tes X86_64..." << std::endl;
    // Kode mesin sampel: PUSH RBP; MOV RBP, RSP; NOP; RET
    std::vector<uint8_t> code = { 0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3 };
    ArsitekturDisasm arch = ARCH_X86_64;

    InstruksiDecoded ins;
    int offset = 0;

    // 0x55 -> PUSH RBP
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "PUSH", 1);
    assert(ins.operands.size() == 1 && ins.operands[0] == "rbp");
    offset += ins.size;

    // 0x48 0x89 0xE5 -> MOV RBP, RSP
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "MOV", 3);
    assert(ins.operands.size() == 2 && ins.operands[0] == "rbp" && ins.operands[1] == "rsp");
    offset += ins.size;

    // 0x90 -> NOP
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "NOP", 1);
    assert(ins.operands.empty());
    offset += ins.size;

    // 0xC3 -> RET
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "RET", 1);
    assert(ins.operands.empty());
}

void testAArch64() {
    std::cout << "[TEST] Menjalankan tes AArch64 (ARM_64)..." << std::endl;
    // Kode mesin: 
    // 0xD2800000 -> MOV X0, #0  (little-endian: 00 00 80 D2)
    // 0xF9400021 -> LDR X1, [X1] (little-endian: 21 00 40 F9)
    std::vector<uint8_t> code = { 0x00, 0x00, 0x80, 0xD2, 0x21, 0x00, 0x40, 0xF9 };
    ArsitekturDisasm arch = ARCH_ARM_64;

    InstruksiDecoded ins;
    int offset = 0;

    // MOV X0, #0
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "MOV", 4);
    assert(ins.operands.size() == 2 && ins.operands[0] == "x0" && ins.operands[1] == "#0");
    offset += ins.size;

    // LDR X1, [X1]
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "LDR", 4);
    assert(ins.operands.size() == 2 && ins.operands[0] == "x1" && ins.operands[1] == "[x1]");
    offset += ins.size;
}

void testARM32() {
    std::cout << "[TEST] Menjalankan tes ARM32..." << std::endl;
    // Kode mesin:
    // 0xE1A00000 -> MOV R0, R0 (little-endian: 00 00 A0 E1)
    // 0xE3A01001 -> MOV R1, #1 (little-endian: 01 10 A0 E3)
    std::vector<uint8_t> code = { 0x00, 0x00, 0xA0, 0xE1, 0x01, 0x10, 0xA0, 0xE3 };
    ArsitekturDisasm arch = ARCH_ARM_32;

    InstruksiDecoded ins;
    int offset = 0;

    // MOV R0, R0
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "MOV", 4);
    assert(ins.operands.size() == 2 && ins.operands[0] == "r0" && ins.operands[1] == "r0");
    offset += ins.size;

    // MOV R1, #1
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "MOV", 4);
    assert(ins.operands.size() == 2 && ins.operands[0] == "r1" && ins.operands[1] == "#1");
    offset += ins.size;
}

int main() {
    std::cout << "[TEST] Mulai testDecodeInstruksi (Multi-Arch)..." << std::endl;
    
    testX86_64();
    testAArch64();
    testARM32();

    std::cout << "[TEST] testDecodeInstruksi (Multi-Arch) SELESAI." << std::endl;
    return 0;
}