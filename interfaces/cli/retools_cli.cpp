/*
 * Contoh Penggunaan:
 * ./retools_cli parse header /bin/bash
 * ./retools_cli analyze strings /bin/bash
 * ./retools_cli pipeline /bin/bash
 */

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#include "parser.h"
#include "analyzer.h"
#include "disasm.h"
#include "hexeditor.h"

// Helper untuk print usage
void printUsage(const char* progName) {
    std::cerr << "Usage: " << progName << " <module> <command> [file_path] [options]" << std::endl;
    std::cerr << "Modules:" << std::endl;
    std::cerr << "  parse <command> [file]" << std::endl;
    std::cerr << "    header              : Tampilkan header (ELF, PE, Mach-O) sebagai JSON." << std::endl;
    std::cerr << "    sections            : Tampilkan ELF sections." << std::endl;
    std::cerr << "  analyze <command> [file]" << std::endl;
    std::cerr << "    strings             : Ekstrak strings." << std::endl;
    std::cerr << "    entropy             : Hitung entropy (blok 1024)." << std::endl;
    std::cerr << "  hex <command> [file] [offset] [len/data]" << std::endl;
    std::cerr << "    lihat [file] [off] [len] : Lihat bytes (hex)." << std::endl;
    std::cerr << "  pipeline [file]" << std::endl;
    std::cerr << "    (runs full analysis and outputs JSON)" << std::endl;
    std::cerr << std::endl;
}

// Implementasi
int handleParse(const std::vector<std::string>& args) {
    if (args.size() < 3) return -1;
    std::string command = args[1];
    std::string file_path = args[2];

    if (command == "header") {
        // Panggil C-ABI (return JSON)
        char* json_string = c_parseBinaryHeader(file_path.c_str());
        
        if (json_string == nullptr) {
            std::cerr << "Error: Gagal parse header (pointer null)." << std::endl;
            return 1;
        }
        
        std::cout << "Binary Header (JSON):" << std::endl;
        std::cout << json_string << std::endl;
        
        // Bebaskan string
        c_freeJsonString(json_string);
    
    } else if (command == "sections") {
         char* json_string = c_parseSectionsElf(file_path.c_str());
         if (json_string == nullptr) {
             std::cerr << "Error: Gagal parse sections (hanya support ELF)." << std::endl;
             return 1;
         }
         std::cout << "ELF Sections (JSON):" << std::endl;
         std::cout << json_string << std::endl;
         c_freeJsonString(json_string);
    } else {
        return -1;
    }
    return 0;
}

int handleAnalyze(const std::vector<std::string>& args) {
    if (args.size() < 3) return -1;
    std::string command = args[1];
    std::string file_path = args[2];

    if (command == "strings") {
        std::vector<std::string> strings = extractStrings(file_path, 4);
        std::cout << "Strings (min 4):" << std::endl;
        for (const auto& s : strings) {
            std::cout << "  " << s << std::endl;
        }
    } else if (command == "entropy") {
        std::vector<double> entropy = hitungEntropy(file_path, 1024);
        std::cout << "Entropy (per 1024 bytes):" << std::endl;
        for (size_t i = 0; i < entropy.size(); ++i) {
            std::cout << "  Block " << i << ": " << std::fixed << std::setprecision(4) << entropy[i] << std::endl;
        }
    } else {
        return -1;
    }
    return 0;
}

int handleHex(const std::vector<std::string>& args) {
    if (args.size() < 4) return -1; // hex lihat <file> <offset> <len>
    std::string command = args[1];
    std::string file_path = args[2];
    
    if (command == "lihat") {
        if (args.size() < 5) return -1;
        int offset = std::stoi(args[3]);
        int length = std::stoi(args[4]);
        std::string hex_str = lihatBytes(file_path, offset, length);
        std::cout << "Bytes at " << offset << " (len " << length << "):" << std::endl;
        std::cout << hex_str << std::endl;
    } else {
        return -1;
    }
    return 0;
}

// Helper escape JSON
std::string escapeJson(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') out += '\\';
        else if (c < 32 || c == 127) out += " ";
        else out += c;
    }
    out += "\"";
    return out;
}

int handlePipeline(const std::vector<std::string>& args) {
    if (args.size() < 2) return -1;
    std::string file_path = args[1];
    
    std::cout << "{" << std::endl;
    std::cout << "  \"file\": " << escapeJson(file_path) << "," << std::endl;

    // Parse
    char* json_header_ptr = c_parseBinaryHeader(file_path.c_str());
    if (json_header_ptr) {
        std::cout << "  \"header\": " << json_header_ptr << "," << std::endl;
        c_freeJsonString(json_header_ptr);
    } else {
        std::cout << "  \"header\": {\"valid\": false, \"error\": \"parse failed\"}," << std::endl;
    }

    // Analyze (Strings)
    std::vector<std::string> strings = extractStrings(file_path, 4);
    std::cout << "  \"strings\": [" << std::endl;
    for (size_t i = 0; i < strings.size(); ++i) {
        std::cout << "    " << escapeJson(strings[i]);
        if (i < strings.size() - 1) std::cout << ",";
        std::cout << std::endl;
    }
    std::cout << "  ]," << std::endl;
    
    // Analyze (Entropy)
    std::vector<double> entropy = hitungEntropy(file_path, 1024);
    std::cout << "  \"entropy\": [" << std::endl;
    for (size_t i = 0; i < entropy.size(); ++i) {
        std::cout << "    " << std::fixed << std::setprecision(4) << entropy[i];
        if (i < entropy.size() - 1) std::cout << ",";
        std::cout << std::endl;
    }
    std::cout << "  ]" << std::endl; // Koma terakhir dihilangkan
    
    std::cout << "}" << std::endl;
    return 0;
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    // Konversi argv ke vector<string>
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        args.push_back(std::string(argv[i]));
    }
    
    std::string module = args[0];
    int result = -1;

    try {
        if (module == "parse") {
            result = handleParse(args);
        } else if (module == "analyze") {
            result = handleAnalyze(args);
        } else if (module == "hex") {
            result = handleHex(args);
        } else if (module == "pipeline") {
            result = handlePipeline(args);
        } else {
            std::cerr << "Error: Modul '" << module << "' tidak dikenal." << std::endl;
            printUsage(argv[0]);
            return 1;
        }

        if (result == -1) {
            std::cerr << "Error: Argumen tidak valid untuk modul '" << module << "'." << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "FATAL ERROR: " << e.what() << std::endl;
        return 2;
    }

    return result;
}