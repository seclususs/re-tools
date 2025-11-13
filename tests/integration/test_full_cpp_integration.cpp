#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <string>
#include <cstring>

#include "parser.h"
#include "analyzer.h"
#include "disasm.h"
#include "cfg.h"
#include "binary_diff.h"

// Helper file dummy
std::string create_dummy_file_integration(const std::string& namaFile) {
    std::ofstream file(namaFile, std::ios::binary);
    
    // .text section data: PUSH RBP (0x55), RET (0xC3)
    std::vector<uint8_t> text_data = { 0x55, 0xC3 };

    // Header ELF64 minimalis palsu
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Magic, 64-bit, LE, ver
        0x02, 0x00, // Type: EXEC
        0x3E, 0x00, // Machine: x86-64 (62)
        0x01, 0x00, 0x00, 0x00, // Version
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry 0x400080
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Phoff 64
        0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Shoff 224
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, // Ehsize, Phentsize
        0x01, 0x00, 0x40, 0x00, 0x03, 0x00, 0x01, 0x00  // Phnum(1), Shentsize(64), Shnum(3), Shstrndx(1)
    };
    // Program Header (LOAD .text)
    std::vector<uint8_t> pheader = {
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // Type, Flags, Offset 128
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Offset 128
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Vaddr 0x400080
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // Paddr
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Filesz (2)
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Memsz (2)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // Align
    };
    header.insert(header.end(), pheader.begin(), pheader.end());
    header.resize(128, 0); // Padding ke .text offset
    
    header.insert(header.end(), text_data.begin(), text_data.end());
    
    // String data
    header.push_back(0x00);
    std::string str_test = "IniStringIntegrasiCpp";
    header.insert(header.end(), str_test.begin(), str_test.end());
    header.push_back(0x00);
    
    header.resize(224, 0); // Padding ke shoff

    // Section Header Table (Minimal)
    std::vector<uint8_t> sh_null(64, 0);
    std::vector<uint8_t> sh_str(64, 0); 
    std::vector<uint8_t> sh_text(64, 0);

    // Definisikan str_data agar ukurannya diketahui
    std::vector<uint8_t> str_data = { 0x00, '.', 't', 'e', 'x', 't', 0x00 };

    // SH 1 (String Table)
    *(uint32_t*)&sh_str[4] = 3; // sh_type (STRTAB)
    *(uint64_t*)&sh_str[32] = str_data.size(); // sh_size

    // SH 2 (.text)
    *(uint32_t*)&sh_text[0] = 1; // sh_name (index 1 di strtab)
    *(uint32_t*)&sh_text[4] = 1; // sh_type (PROGBITS)
    *(uint64_t*)&sh_text[8] = 0x6; // sh_flags (ALLOC|EXEC)
    *(uint64_t*)&sh_text[16] = 0x400080; // sh_addr
    *(uint64_t*)&sh_text[24] = 128; // sh_offset
    *(uint64_t*)&sh_text[32] = text_data.size(); // sh_size

    header.insert(header.end(), sh_null.begin(), sh_null.end());
    header.insert(header.end(), sh_str.begin(), sh_str.end());
    header.insert(header.end(), sh_text.begin(), sh_text.end());
    
    uint64_t str_data_offset = header.size();
    header.insert(header.end(), str_data.begin(), str_data.end());
    
    // Update offset string table di SH 1
    *(uint64_t*)&header[224 + 64 + 24] = str_data_offset; // shoff + sh_null + sh_str[offset]

    file.write(reinterpret_cast<char*>(header.data()), header.size());
    file.close();
    return namaFile;
}

void cleanup_file(const std::string& namaFile) {
    std::remove(namaFile.c_str());
}

int main() {
    std::cout << "[Integration Test C++] Dimulai..." << std::endl;
    std::string file_name = "cpp_integration_dummy.bin";
    create_dummy_file_integration(file_name);

    // Variabel hasil (campur)
    bool semuaTesLulus = true;

    try {
        // Test Parser
        std::cout << "  [TEST] Menjalankan Parser..." << std::endl;
        
        C_HeaderInfo header_info;
        std::memset(&header_info, 0, sizeof(C_HeaderInfo));
        
        int32_t res = c_getBinaryHeader(file_name.c_str(), &header_info);

        // Update assertions untuk C_HeaderInfo struct
        assert(res == 0); // Fungsi C-ABI harus return 0 (sukses)
        assert(header_info.valid == 1);
        assert(std::strcmp(header_info.format, "ELF") == 0);
        assert(header_info.machine_id == 62); // 62 adalah 0x3E (x86-64)
        std::cout << "    [PASS] Parser OK." << std::endl;

        // Test Analyzer (Strings)
        std::cout << "  [TEST] Menjalankan Analyzer (Strings)..." << std::endl;
        std::vector<std::string> extracted_strings = extractStrings(file_name, 5);
        assert(extracted_strings.size() >= 1);
        assert(extracted_strings[0] == "IniStringIntegrasiCpp");
        std::cout << "    [PASS] Analyzer (Strings) OK." << std::endl;
        
        // Test Analyzer (Entropy)
        std::cout << "  [TEST] Menjalankan Analyzer (Entropy)..." << std::endl;
        std::vector<double> entropy_list = hitungEntropy(file_name, 1024);
        assert(entropy_list.size() > 0);
        std::cout << "    [PASS] Analyzer (Entropy) OK." << std::endl;

        // Test Advanced Tool (CFG Visualizer)
        std::cout << "  [TEST] Menjalankan Advanced/CFG..." << std::endl;
        std::string dot_graph = generateCFG(file_name);
        // Debugging:
        // std::cout << "--- DOT Graph ---\n" << dot_graph << "\n-----------------\n";
        assert(dot_graph.find("error") == std::string::npos);
        assert(dot_graph.find("PUSH") != std::string::npos); 
        assert(dot_graph.find("RET") != std::string::npos);
        std::cout << "    [PASS] Advanced/CFG OK." << std::endl;
        
        // Test Advanced Tool (Binary Diff)
        std::cout << "  [TEST] Menjalankan Advanced/Diff..." << std::endl;
        std::vector<DiffResult> diff_results = diffBinary(file_name, file_name);
        assert(diff_results.size() > 0);
        assert(diff_results[0].functionName == ".text");
        assert(diff_results[0].status == DiffResult::MATCHED);
        std::cout << "    [PASS] Advanced/Diff (fallback .text) OK." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "  [FAIL] Test gagal dengan exception: " << e.what() << std::endl;
        semuaTesLulus = false;
    } catch (...) {
        std::cerr << "  [FAIL] Test gagal dengan unknown exception." << std::endl;
        semuaTesLulus = false;
    }

    cleanup_file(file_name);
    
    if (semuaTesLulus) {
        std::cout << "[Integration Test C++] Semua tes LULUS." << std::endl;
        return 0;
    } else {
        std::cout << "[Integration Test C++] Terdapat tes yang GAGAL." << std::endl;
        return 1;
    }
}