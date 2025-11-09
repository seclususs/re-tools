#include <iostream>
#include <memory>

#include "binary_parser.h"
#include "disassembler.h"
#include "prompt_builder.h"
#include "llm_client.h"
#include "reporting.h"
#include "utils.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        Utils::logError("Usage: re_assistant <path_to_binary>");
        return 1;
    }

    std::string binaryPath = argv[1];
    Utils::logInfo("Starting analysis of: " + binaryPath);

    // Binary Parser
    auto parser = std::make_unique<BinaryParser>(binaryPath);
    if (!parser->loadBinary()) {
        Utils::logError("Failed to load binary.");
        return 1;
    }
    auto sections = parser->getSections();
    Utils::logInfo("Found " + std::to_string(sections.size()) + " sections.");

    // Disassembler
    auto disassembler = std::make_unique<Disassembler>("x86", "64");
    // std::vector<uint8_t> text_section_bytes = ...
    // disassembler->disassembleBytes(text_section_bytes);
    auto instructions = disassembler->getInstructions();

    // Prompt Builder
    auto promptBuilder = std::make_unique<PromptBuilder>();
    std::string prompt = promptBuilder->buildPromptFromInstructions(instructions);

    // LLM Client
    auto llmClient = std::make_unique<LLMClient>("YOUR_API_KEY");
    // std::string analysis = llmClient->sendPrompt(prompt);

    // Reporting
    auto reporter = std::make_unique<Reporter>("analysis_report");
    // reporter->setData(analysis);
    reporter->printCLI();
    // reporter->exportJSON();

    Utils::logInfo("Analysis complete.");

    return 0;
}