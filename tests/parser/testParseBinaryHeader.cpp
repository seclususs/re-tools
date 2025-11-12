#include "parser.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <cstring>
#include <string>

// Helper untuk membuat file dummy
void create_dummy_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

// Dummy Header
std::vector<uint8_t> get_dummy_elf64() {
    // Header ELF64 minimalis (x86-64)
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, // Magic, 64-bit, LE, ver
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Pad
        0x02, 0x00, // Type: EXEC
        0x3E, 0x00, // Machine: x86-64 (62)
        0x01, 0x00, 0x00, 0x00, // Version
        0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, // Entry point: 0x12345678
    };
    header.resize(64, 0); 
    return header;
}

std::vector<uint8_t> get_dummy_pe32() {
    // Header PE32 minimalis (MZ + PE) (x86)
    std::vector<uint8_t> header(0x80, 0x00); // 128 bytes
    // MZ Header
    header[0] = 'M'; header[1] = 'Z';
    *(uint32_t*)&header[0x3C] = 0x80; // e_lfanew (offset ke PE)
    // PE Header
    header[0x80] = 'P'; header[0x81] = 'E'; header[0x82] = 0x00; header[0x83] = 0x00;
    // COFF Header
    *(uint16_t*)&header[0x84] = 0x014C; // Machine: I386
    *(uint16_t*)&header[0x86] = 2; // NumberOfSections
    // Optional Header
    *(uint16_t*)&header[0x98] = 0x010B; // Magic: PE32
    *(uint32_t*)&header[0xA0] = 0x1000; // AddressOfEntryPoint
    return header;
}

std::vector<uint8_t> get_dummy_macho64() {
    // Header Mach-O 64-bit (AArch64)
    std::vector<uint8_t> header = {
        0xCF, 0xFA, 0xED, 0xFE, // Magic: MH_MAGIC_64 (reversed)
        0x0C, 0x00, 0x00, 0x01, // Cputype: ARM64 (12 | 0x01000000)
        0x00, 0x00, 0x00, 0x80, // Cpusubtype
        0x02, 0x00, 0x00, 0x00, // Filetype: EXECUTE
    };
    header.resize(100, 0);
    return header;
}

// Helper untuk cek JSON
void check_json_result(char* json_ptr, const std::string& expected_format, const std::string& expected_arch) { // <-- FIX: Mengubah const char* ke char*
    assert(json_ptr != nullptr);
    std::string json_str(json_ptr);
    c_freeJsonString(json_ptr); // Selalu bebaskan memori

    std::cout << "  [INFO] Menerima JSON: " << json_str << std::endl;
    assert(json_str.find("\"valid\":true") != std::string::npos);
    assert(json_str.find(expected_format) != std::string::npos);
    assert(json_str.find(expected_arch) != std::string::npos);
}

int main() {
    std::string file_elf = "test_dummy.elf";
    std::string file_pe = "test_dummy.pe";
    std::string file_macho = "test_dummy.macho";

    create_dummy_file(file_elf, get_dummy_elf64());
    create_dummy_file(file_pe, get_dummy_pe32());
    create_dummy_file(file_macho, get_dummy_macho64());

    std::cout << "[TEST] Mulai testParseBinaryHeader (Multi-Format)..." << std::endl;
    
    // Test ELF
    std::cout << "[TEST] Parsing ELF..." << std::endl;
    char* json_elf = c_parseBinaryHeader(file_elf.c_str());
    check_json_result(json_elf, "\"format\":\"ELF\"", "\"arch\":\"x86-64\"");
    std::cout << "  [PASS] ELF OK." << std::endl;

    // Test PE
    std::cout << "[TEST] Parsing PE..." << std::endl;
    char* json_pe = c_parseBinaryHeader(file_pe.c_str());
    check_json_result(json_pe, "\"format\":\"PE\"", "\"arch\":\"x86\"");
    std::cout << "  [PASS] PE OK." << std::endl;

    // Test Mach-O
    std::cout << "[TEST] Parsing Mach-O..." << std::endl;
    char* json_macho = c_parseBinaryHeader(file_macho.c_str());
    check_json_result(json_macho, "\"format\":\"Mach-O\"", "\"arch\":\"ARM\"");
    std::cout << "  [PASS] Mach-O OK." << std::endl;

    std::remove(file_elf.c_str());
    std::remove(file_pe.c_str());
    std::remove(file_macho.c_str());
    std::cout << "[TEST] testParseBinaryHeader SELESAI." << std::endl;
    return 0;
}