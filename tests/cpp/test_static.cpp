#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <cstring>
#include <string>
#include "retools_static.h"
#include "retools_advanced.h"
#include "retools_types.h"

void create_dummy_elf(const std::string& filename) {
    std::ofstream f(filename, std::ios::binary);
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    header.resize(64, 0);
    f.write(reinterpret_cast<const char*>(header.data()), header.size());
    f.write("\x90\x90\xC3", 3); 
    std::string s = "TestString";
    f.write(s.c_str(), s.size());
    f.close();
}

void test_parser(const std::string& file) {
    char* json = c_parseHeader_json(file.c_str());
    assert(json != nullptr);
    std::string s(json);
    c_freeString(json);
    assert(s.find("ELF") != std::string::npos);
    assert(s.find("64") != std::string::npos);
}

void test_analyzer(const std::string& file) {
    char* json = c_scanString_rs(file.c_str(), 4);
    assert(json != nullptr);
    std::string s(json);
    c_freeString(json);
    assert(s.find("TestString") != std::string::npos);

    json = c_calcEntropy_json(file.c_str(), 256);
    assert(json != nullptr);
    c_freeString(json);
}

void test_hexeditor(const std::string& file) {
    char buf[100];
    int res = c_readBytes_hex(file.c_str(), 0, 4, buf, 100);
    assert(res == 0);
    assert(std::string(buf) == "7F 45 4C 46");
}

void test_advanced(const std::string& file) {
    char* cfg = c_createCFG(file.c_str());
    assert(cfg != nullptr);
    std::string s(cfg);
    c_freeString(cfg);
    assert(s.find("digraph") != std::string::npos);
}

int main() {
    std::string f = "test_dummy_static.bin";
    create_dummy_elf(f);
    try {
        test_parser(f);
        test_analyzer(f);
        test_hexeditor(f);
        test_advanced(f);
        std::cout << "All Static Tests Passed" << std::endl;
    } catch (...) {
        std::cerr << "Tests Failed" << std::endl;
        std::remove(f.c_str());
        return 1;
    }
    std::remove(f.c_str());
    return 0;
}