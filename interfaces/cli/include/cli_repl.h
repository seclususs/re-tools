#ifndef RETOOLS_CLI_REPL_H
#define RETOOLS_CLI_REPL_H

#include "cli_engine.h"
#include <string>
#include <vector>
#include <memory>

class CliRepl {
public:
    CliRepl(CliEngine& engine);
    void run();

private:
    CliEngine& engine;
};

#endif