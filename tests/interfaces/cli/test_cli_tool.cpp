#include <iostream>
#include <cstdlib>
#include <cassert>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <cstdint>
#include <cstdio>

#ifdef _WIN32
const std::string CLI_PATH = "retools_cli.exe";
#else
const std::string CLI_PATH = "retools_cli";
#endif

std::string create_dummy_file_cli() {
    std::string filename = "cli_test_dummy.bin";
    std::ofstream f(filename, std::ios::binary);
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00,
        0x3E, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    header.resize(64, 0);
    f.write(reinterpret_cast<const char*>(header.data()), header.size());
    f.write("ini_string_cli_satu", 20);
    f.write("ini_string_cli_dua", 19);
    f.close();
    return filename;
}

std::string exec(const std::string& cmd) {
    std::string temp_file = "cli_test_output.tmp";
    std::string cmd_platform = cmd;
    #ifdef _WIN32
        std::replace(cmd_platform.begin(), cmd_platform.end(), '/', '\\');
    #endif
    std::string full_cmd = cmd_platform + " > " + temp_file;
    int ret_code = std::system(full_cmd.c_str());
    std::ifstream f(temp_file);
    std::stringstream buffer;
    buffer << f.rdbuf();
    f.close();
    std::remove(temp_file.c_str());
    if (ret_code == 0) {
        return buffer.str();
    } else {
        return "COMMAND_FAILED_WITH_CODE_" + std::to_string(ret_code);
    }
}

void test_cli_parse(const std::string& dummy_file) {
    std::cout << "[TEST] CLI: parse header" << std::endl;
    std::string cmd = CLI_PATH + " parse header " + dummy_file;
    std::string output = exec(cmd);
    assert(output.find("COMMAND_FAILED") == std::string::npos);
    assert(output.find("\"format\": \"ELF\"") != std::string::npos);
    assert(output.find("\"entry_point\": 4194368") != std::string::npos);
    std::cout << "  [PASS] parse header" << std::endl;
}

void test_cli_analyze(const std::string& dummy_file) {
    std::cout << "[TEST] CLI: analyze strings" << std::endl;
    std::string cmd = CLI_PATH + " analyze strings " + dummy_file;
    std::string output = exec(cmd);
    assert(output.find("COMMAND_FAILED") == std::string::npos);
    assert(output.find("Strings (JSON format):") != std::string::npos);
    assert(output.find("\"ini_string_cli_satu\"") != std::string::npos);
    assert(output.find("\"ini_string_cli_dua\"") != std::string::npos);
    std::cout << "  [PASS] analyze strings (JSON output)" << std::endl;
}

void test_cli_pipeline(const std::string& dummy_file) {
    std::cout << "[TEST] CLI: pipeline" << std::endl;
    std::string cmd = CLI_PATH + " pipeline " + dummy_file;
    std::string output = exec(cmd);
    assert(output.find("COMMAND_FAILED") == std::string::npos);
    assert(output.find("\"file\": \"cli_test_dummy.bin\"") != std::string::npos);
    assert(output.find("\"valid\": true") != std::string::npos);
    assert(output.find("\"ini_string_cli_satu\"") != std::string::npos);
    assert(output.find("\"entropy\":") != std::string::npos);
    std::cout << "  [PASS] pipeline" << std::endl;
}

int main() {
    std::cout << "Memulai Tes CLI..." << std::endl;
    std::string dummy = create_dummy_file_cli();
    try {
        test_cli_parse(dummy);
        test_cli_analyze(dummy);
        test_cli_pipeline(dummy);
    } catch (const std::exception& e) {
        std::cerr << "[FAIL] Exception: " << e.what() << std::endl;
        std::remove(dummy.c_str());
        return 1;
    } catch (...) {
        std::cerr << "[FAIL] Unknown assertion." << std::endl;
        std::remove(dummy.c_str());
        return 1;
    }
    std::remove(dummy.c_str());
    std::cout << "Semua Tes CLI Selesai." << std::endl;
    return 0;
}