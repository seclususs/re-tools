#include "retools_static.h"
#include <iostream>
#include <vector>
#include <cassert>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <string>
#include <cstdlib>


struct InstruksiDecoded {
    bool valid;
    int size;
    std::string mnemonic;
    std::vector<std::string> operands;
};

InstruksiDecoded panggilDanKonversi(const std::vector<uint8_t>& bytes, int offset, ArsitekturDisasm arch) {
    uint64_t base_va = static_cast<uint64_t>(offset);
    C_Instruksi c_instr = c_decodeInstruksi(
        bytes.data(),
        bytes.size(),
        static_cast<size_t>(offset),
        base_va,
        arch
    );
    InstruksiDecoded instr;
    instr.valid = (c_instr.valid != 0);
    instr.size = c_instr.ukuran;
    if (instr.valid) {
        std::string temp_mne(c_instr.mnemonic_instruksi);
        std::transform(temp_mne.begin(), temp_mne.end(), std::back_inserter(instr.mnemonic), ::toupper);
        std::string ops(c_instr.str_operand);
        if (!ops.empty()) {
            std::stringstream ss(ops);
            std::string single_op;
            while (std::getline(ss, single_op, ',')) {
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
        if (instr.size == 0) instr.size = 1;
    }
    return instr;
}

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
    std::vector<uint8_t> code = { 0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3 };
    ArsitekturDisasm arch = ARCH_X86_64;
    InstruksiDecoded ins;
    int offset = 0;
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "PUSH", 1);
    assert(ins.operands.size() == 1 && ins.operands[0] == "rbp");
    offset += ins.size;
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "MOV", 3);
    assert(ins.operands.size() == 2 && ins.operands[0] == "rbp" && ins.operands[1] == "rsp");
    offset += ins.size;
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "NOP", 1);
    assert(ins.operands.empty());
    offset += ins.size;
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "RET", 1);
    assert(ins.operands.empty());
}

void testAArch64() {
    std::cout << "[TEST] Menjalankan tes AArch64 (ARM_64)..." << std::endl;
    std::vector<uint8_t> code = { 0x00, 0x00, 0x80, 0xD2, 0x21, 0x00, 0x40, 0xF9 };
    ArsitekturDisasm arch = ARCH_ARM_64;
    InstruksiDecoded ins;
    int offset = 0;
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "MOV", 4);
    assert(ins.operands.size() == 2 && ins.operands[0] == "x0" && ins.operands[1] == "#0");
    offset += ins.size;
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "LDR", 4);
    assert(ins.operands.size() == 2 && ins.operands[0] == "x1" && ins.operands[1] == "[x1]");
    offset += ins.size;
}

void testARM32() {
    std::cout << "[TEST] Menjalankan tes ARM32..." << std::endl;
    std::vector<uint8_t> code = { 0x00, 0x00, 0xA0, 0xE1, 0x01, 0x10, 0xA0, 0xE3 };
    ArsitekturDisasm arch = ARCH_ARM_32;
    InstruksiDecoded ins;
    int offset = 0;
    ins = panggilDanKonversi(code, offset, arch);
    assert_instr(ins, "MOV", 4);
    assert(ins.operands.size() == 2 && ins.operands[0] == "r0" && ins.operands[1] == "r0");
    offset += ins.size;
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