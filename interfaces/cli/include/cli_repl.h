#ifndef RETOOLS_CLI_REPL_H
#define RETOOLS_CLI_REPL_H

#include "cli_engine.h"
#include <string>

class CliRepl {
public:
    CliRepl(CliEngine& engine);
    void run();

private:
    CliEngine& engine;
    bool running;
    
    void process_command(const std::string& line);
    void show_help();
    void handle_hybrid_cmd(const std::vector<std::string>& args);
    void handle_security_cmd(const std::vector<std::string>& args);
    void handle_forensics_cmd(const std::vector<std::string>& args);
};

#endif