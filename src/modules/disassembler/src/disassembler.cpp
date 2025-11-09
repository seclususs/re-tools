#include "disassembler.h"
#include "utils.h"
// #include <capstone/capstone.h>

Disassembler::Disassembler(const std::string& arch, const std::string& mode)
    : arch(arch), mode(mode), cs_handle(nullptr) {
    // Stub: Initialize Capstone
    // csh handle;
    // if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    //     cs_handle = nullptr;
    // } else {
    //     cs_handle = (void*)handle;
    // }
    Utils::logInfo("[Disassembler] Initialized for " + arch + " " + mode + "bit.");
}

Disassembler::~Disassembler() {
    // Stub: Close Capstone
    // if (cs_handle) {
    //     cs_close((csh*)&cs_handle);
    // }
}

bool Disassembler::disassembleBytes(const std::vector<uint8_t>& bytes, uint64_t startAddress) {
    // Stub implementation
    Utils::logInfo("[Disassembler] Disassembling " + std::to_string(bytes.size()) + " bytes.");
    
    // Populate with dummy data
    instructions.push_back({0x1000, "push", "rbp"});
    instructions.push_back({0x1001, "mov", "rbp, rsp"});
    instructions.push_back({0x1004, "mov", "eax, 0x1"});
    instructions.push_back({0x1009, "pop", "rbp"});
    instructions.push_back({0x100a, "ret", ""});

    return true;
}

std::vector<Instruction> Disassembler::getInstructions() {
    // Stub implementation
    return instructions;
}