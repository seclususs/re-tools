#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include "retools_static.h"
#include "retools_types.h"

void print_and_free(char* json_ptr) {
    if (json_ptr) {
        std::cout << json_ptr << std::endl;
        c_freeString(json_ptr);
    } else {
        std::cerr << "Error: Received null pointer from API." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <module> <command> [args...]" << std::endl;
        return 1;
    }
    std::string module = argv[1];
    std::string command = argv[2];
    if (module == "parse") {
        if (argc < 4) return 1;
        if (command == "header") {
            print_and_free(c_parseHeader_json(argv[3]));
        } else if (command == "sections") {
            print_and_free(c_parseSeksi_json(argv[3]));
        } else if (command == "imports") {
            print_and_free(c_parseImpor_json(argv[3]));
        } else if (command == "exports") {
            print_and_free(c_parseEkspor_json(argv[3]));
        }
    } else if (module == "analyze") {
        if (argc < 4) return 1;
        if (command == "strings") {
            print_and_free(c_scanString_rs(argv[3], 4));
        } else if (command == "entropy") {
            print_and_free(c_calcEntropy_json(argv[3], 1024));
        } else if (command == "crypto") {
            print_and_free(c_scanKripto_json(argv[3]));
        } else if (command == "packer") {
            print_and_free(c_scanPacker(argv[3], 7.0));
        }
    } else if (module == "hex") {
        if (argc < 6) return 1;
        if (command == "view") {
            std::string file = argv[3];
            int offset = std::stoi(argv[4]);
            int len = std::stoi(argv[5]);
            std::vector<char> buf(len * 3 + 10);
            if (c_readBytes_hex(file.c_str(), offset, len, buf.data(), buf.size()) == 0) {
                std::cout << buf.data() << std::endl;
            } else {
                std::cerr << "Error reading bytes" << std::endl;
            }
        }
    } else {
        std::cerr << "Unknown module: " << module << std::endl;
        return 1;
    }
    return 0;
}