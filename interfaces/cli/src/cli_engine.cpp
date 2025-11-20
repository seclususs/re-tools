#include "cli_engine.h"
#include <iostream>
#include <iomanip>

CliEngine::CliEngine() {}
CliEngine::~CliEngine() {}

void CliEngine::print_banner() {
    std::cout << "=============================================" << std::endl;
    std::cout << "          ReTools Binary Analysis            " << std::endl;
    std::cout << "=============================================" << std::endl;
}

void CliEngine::print_json_result(char* json_ptr, const std::string& label) {
    if (json_ptr) {
        std::cout << "[" << label << "] Result:" << std::endl;
        std::cout << json_ptr << std::endl;
        c_freeString(json_ptr);
    } else {
        char* err = rt_get_last_error_message();
        if (err) {
            std::cerr << "[" << label << "] Error: " << err << std::endl;
            c_freeString(err);
        } else {
            std::cerr << "[" << label << "] Unknown Error" << std::endl;
        }
    }
    std::cout << "---------------------------------------------" << std::endl;
}

void CliEngine::print_error(const std::string& message) {
    std::cerr << "[ERROR] " << message << std::endl;
}

void CliEngine::handle_hybrid_analysis(const std::string& binary_path, int pid, int max_steps) {
    std::cout << "[*] Starting Hybrid Analysis..." << std::endl;
    std::cout << "    Target: " << binary_path << std::endl;
    std::cout << "    PID: " << pid << std::endl;
    char* dyn_result = rt_resolveDynamic(binary_path.c_str(), pid, max_steps);
    print_json_result(dyn_result, "Dynamic Resolution");
    std::cout << "[*] Generating Enhanced Pseudocode..." << std::endl;
    u64 entry_point = 0; 
    char* header_json = c_parseHeader_json(binary_path.c_str());
    if (header_json) {
        c_freeString(header_json); 
    }
    char* pseudo_code = c_createPseudocode(binary_path.c_str(), entry_point);
    if (pseudo_code) {
        std::cout << pseudo_code << std::endl;
        c_freeString(pseudo_code);
    } else {
        char* err = rt_get_last_error_message();
        if (err) {
            std::cerr << "Decompilation failed: " << err << std::endl;
            c_freeString(err);
        }
    }
}

void CliEngine::handle_security_analysis(const std::string& binary_path) {
    std::cout << "[*] Starting Proactive Security Analysis..." << std::endl;
    char* vsa_res = c_getValueSetAnalysis_json(binary_path.c_str());
    print_json_result(vsa_res, "Value Set Analysis (VSA)");
    char* mem_check = c_getMemoryAccessCheck_json(binary_path.c_str());
    print_json_result(mem_check, "Memory Bounds Check");
    char* liveness = c_getLivenessAnalysis_json(binary_path.c_str());
    print_json_result(liveness, "Variable Liveness");
    std::cout << "[*] Static Taint Sources Identification (Heuristic)..." << std::endl;
    char* imports = c_parseImpor_json(binary_path.c_str());
    print_json_result(imports, "Potential Sink Candidates");
}

void CliEngine::handle_forensics_analysis(const std::string& binary_path, const std::string& diff_target) {
    std::cout << "[*] Starting Forensics Analysis..." << std::endl;
    char* crypto_res = c_scanKripto_json(binary_path.c_str());
    print_json_result(crypto_res, "Cryptographic Signatures");
    char* packer_res = c_scanPacker(binary_path.c_str(), 7.0);
    print_json_result(packer_res, "Packer Detection");
    if (!diff_target.empty()) {
        std::cout << "[*] Performing Structural Binary Diffing..." << std::endl;
        std::cout << "    Source A: " << binary_path << std::endl;
        std::cout << "    Source B: " << diff_target << std::endl;
        char* diff_res = c_calcDiffBiner_json(binary_path.c_str(), diff_target.c_str());
        print_json_result(diff_res, "Binary Diff");
    }
}