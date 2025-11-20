#ifndef RETOOLS_CLI_ENGINE_H
#define RETOOLS_CLI_ENGINE_H

#include <string>
#include <vector>
#include "retools_static.h"
#include "retools_dynamic.h"
#include "retools_advanced.h"

class CliEngine {
public:
    CliEngine();
    ~CliEngine();

    void print_banner();
    void handle_hybrid_analysis(const std::string& binary_path, int pid, int max_steps);
    void handle_security_analysis(const std::string& binary_path);
    void handle_forensics_analysis(const std::string& binary_path, const std::string& diff_target = "");
    
private:
    void print_json_result(char* json_ptr, const std::string& label);
    void print_error(const std::string& message);
};

#endif