#include <iostream>
#include <fstream>
#include <vector>
#include <cassert>
#include <string>
#include <cstring>
#include <cstdio>

#include "retools_static.h"
#include "retools_advanced.h"
#include "retools_types.h"

std::string create_dummy_file_integration(const std::string& namaFile) {
    std::ofstream file(namaFile, std::ios::binary);
    std::vector<uint8_t> text_data = { 0x55, 0xC3 };
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00,
        0x3E, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
        0x01, 0x00, 0x40, 0x00, 0x03, 0x00, 0x01, 0x00
    };
    std::vector<uint8_t> pheader = {
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    header.insert(header.end(), pheader.begin(), pheader.end());
    header.resize(128, 0);
    header.insert(header.end(), text_data.begin(), text_data.end());
    header.push_back(0x00);
    std::string str_test = "IniStringIntegrasiCpp";
    header.insert(header.end(), str_test.begin(), str_test.end());
    header.push_back(0x00);
    header.resize(224, 0);
    std::vector<uint8_t> sh_null(64, 0);
    std::vector<uint8_t> sh_str(64, 0); 
    std::vector<uint8_t> sh_text(64, 0);
    std::vector<uint8_t> str_data = { 0x00, '.', 't', 'e', 'x', 't', 0x00 };
    *(uint32_t*)&sh_str[4] = 3;
    *(uint64_t*)&sh_str[32] = str_data.size();
    *(uint32_t*)&sh_text[0] = 1;
    *(uint32_t*)&sh_text[4] = 1;
    *(uint64_t*)&sh_text[8] = 0x6;
    *(uint64_t*)&sh_text[16] = 0x400080;
    *(uint64_t*)&sh_text[24] = 128;
    *(uint64_t*)&sh_text[32] = text_data.size();
    header.insert(header.end(), sh_null.begin(), sh_null.end());
    header.insert(header.end(), sh_str.begin(), sh_str.end());
    header.insert(header.end(), sh_text.begin(), sh_text.end());
    uint64_t str_data_offset = header.size();
    header.insert(header.end(), str_data.begin(), str_data.end());
    *(uint64_t*)&header[224 + 64 + 24] = str_data_offset;
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
    bool semuaTesLulus = true;
    try {
        std::cout << "  [TEST] Menjalankan Parser..." << std::endl;
        C_HeaderInfo header_info;
        std::memset(&header_info, 0, sizeof(C_HeaderInfo));
        int32_t res = c_getBinaryHeader(file_name.c_str(), &header_info);
        assert(res == 0);
        assert(header_info.valid == 1);
        assert(std::strcmp(header_info.format, "ELF") == 0);
        assert(header_info.machine_id == 62);
        std::cout << "    [PASS] Parser OK." << std::endl;
        std::cout << "  [TEST] Menjalankan Analyzer (Strings)..." << std::endl;
        char* json_strings_ptr = c_getStringsList_rs(file_name.c_str(), 5);
        assert(json_strings_ptr != nullptr);
        std::string json_strings(json_strings_ptr);
        c_freeString(json_strings_ptr);
        assert(json_strings.find("IniStringIntegrasiCpp") != std::string::npos);
        std::cout << "    [PASS] Analyzer (Strings) OK." << std::endl;
        std::cout << "  [TEST] Menjalankan Analyzer (Entropy)..." << std::endl;
        std::vector<double> entropy_buffer(10);
        int entropy_count = c_hitungEntropy_rs(file_name.c_str(), 1024, entropy_buffer.data(), 10);
        assert(entropy_count > 0);
        std::cout << "    [PASS] Analyzer (Entropy) OK." << std::endl;
        std::cout << "  [TEST] Menjalankan Advanced/CFG..." << std::endl;
        char* dot_graph_ptr = c_generateCFG_rs(file_name.c_str());
        assert(dot_graph_ptr != nullptr);
        std::string dot_graph(dot_graph_ptr);
        c_freeString(dot_graph_ptr);
        assert(dot_graph.find("error") == std::string::npos);
        assert(dot_graph.find("PUSH") != std::string::npos); 
        assert(dot_graph.find("RET") != std::string::npos);
        std::cout << "    [PASS] Advanced/CFG OK." << std::endl;
        std::cout << "  [TEST] Menjalankan Advanced/Diff..." << std::endl;
        std::vector<C_DiffResult> diff_buffer(128);
        int diff_count = c_diffBinary_rs(file_name.c_str(), file_name.c_str(), diff_buffer.data(), 128);
        assert(diff_count > 0);
        assert(std::strcmp(diff_buffer[0].functionName, ".text") == 0);
        assert(diff_buffer[0].status == 0);
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