#pragma once

#include <string>
#include <vector>
#include "disassembler.h"

class PromptBuilder {
public:
    PromptBuilder();
    
    /**
     * @brief Builds a analysis prompt from a list of instructions.
     * @param instructions The vector of disassembled instructions.
     * @return A formatted prompt string for the LLM.
     */
    std::string buildPromptFromInstructions(const std::vector<Instruction>& instructions);

    /**
     * @brief Sanitizes a string to prevent prompt injection or formatting issues.
     * @param input The raw string.
     * @return A sanitized string.
     */
    std::string sanitizePrompt(const std::string& input);

private:
    std::string templateStr;
};