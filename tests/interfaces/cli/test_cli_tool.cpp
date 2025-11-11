#include <iostream>
#include <cstdlib>
#include <cassert>
#include <string>
#include <fstream>
#include <sstream>

const std::string CLI_PATH = "./retools_cli"; 

// Helper untuk membuat file palsu
std::string create_dummy_file_cli() {
    std::string filename = "cli_test_dummy.bin";
    std::ofstream f(filename, std::ios::binary);
    // Data palsu: Magic ELF dan string
    f.write("\x7F\x45\x4C\x46\x02\x01\x01\x00", 8); // ELF64
    f.write("\x00\x00\x00\x00\x00\x00\x00\x00", 8);
    f.write("\x02\x00\x3E\x00", 4); // EXEC, AMD64
    f.write("\x01\x00\x00\x00", 4);
    f.write("\x40\x00\x40\x00\x00\x00\x00\x00", 8); // Entry
    f.write("ini_string_cli_satu", 20);
    f.write("ini_string_cli_dua", 19);
    f.close();
    return filename;
}

// Helper untuk menjalankan command dan menangkap stdout
std::string exec(const std::string& cmd) {
    // Arahkan stdout ke file temporer
    std::string temp_file = "cli_test_output.tmp";
    std::string full_cmd = cmd + " > " + temp_file;
    
    int ret_code = std::system(full_cmd.c_str());
    
    // Baca file temporer
    std::ifstream f(temp_file);
    std::stringstream buffer;
    buffer << f.rdbuf();
    f.close();
    
    // Hapus file temporer
    std::remove(temp_file.c_str());
    
    // Kembalikan 0 jika sukses
    if (ret_code == 0) {
        return buffer.str();
    } else {
        // Kembalikan error
        return "COMMAND_FAILED_WITH_CODE_" + std::to_string(ret_code);
    }
}

void test_cli_parse(const std::string& dummy_file) {
    std::cout << "[TEST] CLI: parse header" << std::endl;
    std::string cmd = CLI_PATH + " parse header " + dummy_file;
    std::string output = exec(cmd);
    
    assert(output.find("COMMAND_FAILED") == std::string::npos);
    assert(output.find("Magic: ELF") != std::string::npos);
    assert(output.find("Entry: 0x400040") != std::string::npos);
    std::cout << "  [PASS] parse header" << std::endl;
}

void test_cli_analyze(const std::string& dummy_file) {
    std::cout << "[TEST] CLI: analyze strings" << std::endl;
    std::string cmd = CLI_PATH + " analyze strings " + dummy_file;
    std::string output = exec(cmd);
    
    assert(output.find("COMMAND_FAILED") == std::string::npos);
    assert(output.find("ini_string_cli_satu") != std::string::npos);
    assert(output.find("ini_string_cli_dua") != std::string::npos);
    std::cout << "  [PASS] analyze strings" << std::endl;
}

void test_cli_pipeline(const std::string& dummy_file) {
    std::cout << "[TEST] CLI: pipeline" << std::endl;
    std::string cmd = CLI_PATH + " pipeline " + dummy_file;
    std::string output = exec(cmd);

    assert(output.find("COMMAND_FAILED") == std::string::npos);
    // Cek output JSON
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