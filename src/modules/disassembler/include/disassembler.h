#pragma once

#include <string>
#include <vector>
#include <cstdint>


struct Instruction {
    uint64_t address;
    std::string mnemonic;
    std::string op_str; // Operands
};

class Disassembler {
public:
    Disassembler(const std::string& arch, const std::string& mode);
    ~Disassembler();

    /**
     * @brief Disassembles a raw buffer of bytes.
     * @param bytes The raw byte buffer.
     * @param startAddress The virtual address of the first byte.
     * @return True on success, false on failure.
     */
    bool disassembleBytes(const std::vector<uint8_t>& bytes, uint64_t startAddress);

    /**
     * @brief Retrieves the disassembled instructions.
     * @return A vector of Instruction objects.
     */
    std::vector<Instruction> getInstructions();

private:
    std::string arch; // e.g., "x86"
    std::string mode; // e.g., "64"
    std::vector<Instruction> instructions;

    // Handle for the Capstone engine
    void* cs_handle; // Using void* to avoid including capstone.h here
};