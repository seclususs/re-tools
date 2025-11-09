// src/modules/prompt_builder/src/prompt_builder.cpp
#include "prompt_builder.h"
#include "utils.h"

PromptBuilder::PromptBuilder() {
    templateStr = "Analyze the following assembly code for potential vulnerabilities. "
                  "Provide a summary of the function's purpose.\n\n"
                  "--- CODE ---\n{CODE}\n--- END CODE ---";
}

std::string PromptBuilder::buildPromptFromInstructions(const std::vector<Instruction>& instructions) {
    Utils::logInfo("[PromptBuilder] Building prompt from " + std::to_string(instructions.size()) + " instructions.");
    
    std::string codeBlock;
    for (const auto& inst : instructions) {
        codeBlock += "0x" + Utils::toHex(inst.address) + ":\t" + inst.mnemonic + "\t" + inst.op_str + "\n";
    }

    // Replace {CODE} in template
    std::string prompt = templateStr;
    size_t pos = prompt.find("{CODE}");
    if (pos != std::string::npos) {
        prompt.replace(pos, 6, codeBlock);
    }
    
    return sanitizePrompt(prompt);
}

std::string PromptBuilder::sanitizePrompt(const std::string& input) {
    return input;
}