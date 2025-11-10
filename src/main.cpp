#include <iostream>
#include <memory>
#include <string>
#include <cstdlib>
#include <fstream>

#include "binary_parser.h"
#include "disassembler.h"
#include "prompt_builder.h"
#include "llm_client.h"
#include "reporting.h"
#include "utils.h"

// Helper function to read .env file
std::string getApiKeyFromEnvFile() {
    std::ifstream envFile(".env");
    if (!envFile.is_open()) {
        Utils::logInfo("[Main] .env file not found. Checking environment variables.");
        return "";
    }

    Utils::logInfo("[Main] Reading .env file...");
    std::string line;
    std::string key = "GEMINI_API_KEY=";
    while (std::getline(envFile, line)) {
        line = Utils::trim(line);
        if (line.rfind(key, 0) == 0) {
            return Utils::trim(line.substr(key.length()));
        }
    }
    return "";
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        Utils::logError("Usage: re_tools <path_to_binary>");
        return 1;
    }

    std::string binaryPath = argv[1];
    Utils::logInfo("Starting analysis of: " + binaryPath);

    std::string apiKey;
    
    const char* apiKeyEnv = std::getenv("GEMINI_API_KEY");
    if (apiKeyEnv != nullptr && !std::string(apiKeyEnv).empty()) {
        apiKey = std::string(apiKeyEnv);
        Utils::logInfo("GEMINI_API_KEY loaded from Environment Variable.");
    } else {
        apiKey = getApiKeyFromEnvFile();
        if (!apiKey.empty()) {
            Utils::logInfo("GEMINI_API_KEY loaded from .env file.");
        }
    }

    if (apiKey.empty()) {
        Utils::logError("API Key not set.");
        Utils::logError("Please set the 'GEMINI_API_KEY' environment variable");
        Utils::logError("OR create a '.env' file in the project root with content:");
        Utils::logError("GEMINI_API_KEY=YOUR_KEY_HERE");
        return 1; 
    }

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

    // LLM Client
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