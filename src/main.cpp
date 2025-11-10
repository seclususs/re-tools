#include <iostream>
#include <memory>
#include <string>
#include <cstdlib>

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
        Utils::logError("Failed to load or parse binary.");
        return 1;
    }
    auto sections = parser->getSections();
    Utils::logInfo("Found " + std::to_string(sections.size()) + " sections.");

    // Get the .text section data and its virtual address
    std::vector<uint8_t> text_section_bytes = parser->getSectionData(".text");
    if (text_section_bytes.empty()) {
        Utils::logError("Could not find or read .text section. Disassembly may fail.");
        // You might want to continue or stop here, depending on use case
    }

    uint64_t textAddress = 0;
    for (const auto& sec : sections) {
        if (sec.name == ".text") {
            textAddress = sec.address;
            break;
        }
    }
    Utils::logInfo(".text section found at address 0x" + Utils::toHex(textAddress) + " with size " + std::to_string(text_section_bytes.size()) + " bytes.");


    // Disassembler
    auto disassembler = std::make_unique<Disassembler>("x86", "64"); 
    if (!disassembler->disassembleBytes(text_section_bytes, textAddress)) {
         Utils::logError("Failed to disassemble .text section.");
         return 1;
    }
    auto instructions = disassembler->getInstructions();
    Utils::logInfo("Disassembled " + std::to_string(instructions.size()) + " instructions.");

    // Prompt Builder
    auto promptBuilder = std::make_unique<PromptBuilder>();
    std::string prompt = promptBuilder->buildPromptFromInstructions(instructions);
    // Utils::logInfo("Generated Prompt:\n" + prompt); // (can be very large)

    // LLM Client
    const char* apiKeyEnv = std::getenv("API_KEY_ENV_VAR");
    std::string apiKey = apiKeyEnv ? std::string(apiKeyEnv) : "API_KEY_FALLBACK";
    
    if(apiKey == "YOUR_API_KEY_FALLBACK" || apiKey.empty()) {
        Utils::logWarning("API Key not set. Using stubbed response.");
        Utils::logWarning("Set YOUR_API_KEY_ENV_VAR environment variable.");
    }

    auto llmClient = std::make_unique<LLMClient>(apiKey);
    std::string analysis = llmClient->sendPrompt(prompt);

    // Reporting
    auto reporter = std::make_unique<Reporter>("analysis_report");
    reporter->setData(analysis);
    reporter->printCLI();
    reporter->exportJSON();

    Utils::logInfo("Analysis complete.");

    return 0;
}