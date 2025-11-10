#include "disassembler.h"
#include "utils.h"
#include <capstone/capstone.h>

Disassembler::Disassembler(const std::string& arch, const std::string& mode)
    : arch(arch), mode(mode), cs_handle(nullptr) {
    
    // Convert arch and mode strings to Capstone enums
    cs_arch capstone_arch;
    cs_mode capstone_mode;

    if (arch == "x86") {
        capstone_arch = CS_ARCH_X86;
    } else if (arch == "arm") {
        capstone_arch = CS_ARCH_ARM;
    } else if (arch == "arm64") {
        capstone_arch = CS_ARCH_ARM64;
    } else {
        Utils::logError("[Disassembler] Unsupported architecture: " + arch);
        cs_handle = nullptr;
        return;
    }

    if (mode == "32") {
        capstone_mode = CS_MODE_32;
    } else if (mode == "64") {
        capstone_mode = CS_MODE_64;
    } else {
        Utils::logError("[Disassembler] Unsupported mode: " + mode);
        cs_handle = nullptr;
        return;
    }

    // Initialize Capstone
    csh handle;
    cs_err err = cs_open(capstone_arch, capstone_mode, &handle);
    if (err != CS_ERR_OK) {
        Utils::logError("[Disassembler] Failed to initialize Capstone: " + std::string(cs_strerror(err)));
        cs_handle = nullptr;
    } else {
        cs_handle = (void*)handle; // Store handle as void*
        Utils::logInfo("[Disassembler] Successfully initialized for " + arch + " " + mode + "bit.");
    }
}

Disassembler::~Disassembler() {
    // Close Capstone handle if valid
    if (cs_handle) {
        csh handle = (csh)cs_handle; // Cast back void* to csh
        cs_close(&handle);
        Utils::logInfo("[Disassembler] Capstone handle closed.");
    }
}

bool Disassembler::disassembleBytes(const std::vector<uint8_t>& bytes, uint64_t startAddress) {
    if (!cs_handle) {
        Utils::logError("[Disassembler] Capstone handle is invalid. Initialization may have failed.");
        return false;
    }

    csh handle = (csh)cs_handle; // Cast void* to csh
    cs_insn* insn; // Capstone will allocate an array of instructions
    size_t count;  // Number of disassembled instructions

    // Clear old instructions
    instructions.clear();

    // Call core cs_disasm function
    count = cs_disasm(handle, 
                      bytes.data(),    // Pointer to the byte buffer
                      bytes.size(),    // Size of the buffer
                      startAddress,    // Virtual address of the first byte
                      0,               // 0 to disassemble all instructions
                      &insn);          // Pointer to receive instruction array

    if (count > 0) {
        Utils::logInfo("[Disassembler] Successfully disassembled " + std::to_string(count) + " instructions.");

        // Iterate through the found instructions
        for (size_t i = 0; i < count; i++) {
            instructions.push_back({
                insn[i].address,
                std::string(insn[i].mnemonic),
                std::string(insn[i].op_str)
            });
        }
        
        // Free memory allocated by cs_disasm
        cs_free(insn, count);
        return true;

    } else {
        cs_err err = cs_errno(handle);
        if (err != CS_ERR_OK) {
             Utils::logError("[Disassembler] Failed to disassemble. Capstone error: " + std::string(cs_strerror(err)));
        } else {
             Utils::logInfo("[Disassembler] No instructions found or buffer empty.");
             return true; 
        }
        return false;
    }
}

std::vector<Instruction> Disassembler::getInstructions() {
    return instructions;
}