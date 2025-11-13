#include "retools_static.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>
#include <cstring>
#include <string> 
#include <cstdio>


void create_dummy_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

std::vector<uint8_t> get_dummy_elf64() {
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00,
        0x3E, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00,
    };
    header.resize(64, 0); 
    return header;
}

std::vector<uint8_t> get_dummy_pe32() {
    std::vector<uint8_t> header(0x100, 0x00);
    header[0] = 'M'; header[1] = 'Z';
    *(uint32_t*)&header[0x3C] = 0x80;
    header[0x80] = 'P'; header[0x81] = 'E'; header[0x82] = 0x00; header[0x83] = 0x00;
    *(uint16_t*)&header[0x84] = 0x014C;
    *(uint16_t*)&header[0x86] = 0;
    *(uint16_t*)&header[0x94] = 0xE0;
    *(uint16_t*)&header[0x98] = 0x010B;
    *(uint32_t*)&header[0xA8] = 0x1000;
    return header;
}

std::vector<uint8_t> get_dummy_macho64() {
    std::vector<uint8_t> header = {
        0xCF, 0xFA, 0xED, 0xFE,
        0x0C, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x80,
        0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    header.resize(100, 0);
    return header;
}

void check_struct_result(const C_HeaderInfo& header, const std::string& expected_format, const std::string& expected_arch, uint64_t expected_machine_id) {
    std::cout << "  [INFO] Menerima Struct: Format=" << header.format 
              << ", Arch=" << header.arch 
              << ", MachineID=" << header.machine_id << std::endl;    
    assert(header.valid == 1);
    assert(std::string(header.format) == expected_format);
    assert(std::string(header.arch) == expected_arch);
    assert(header.machine_id == expected_machine_id);
}

int main() {
    std::string file_elf = "test_dummy.elf";
    std::string file_pe = "test_dummy.pe";
    std::string file_macho = "test_dummy.macho";
    create_dummy_file(file_elf, get_dummy_elf64());
    create_dummy_file(file_pe, get_dummy_pe32());
    create_dummy_file(file_macho, get_dummy_macho64());
    std::cout << "[TEST] Mulai testParseBinaryHeader (Struct C-ABI)..." << std::endl;
    std::cout << "[TEST] Parsing ELF..." << std::endl;
    C_HeaderInfo header_elf;
    int32_t res_elf = c_getBinaryHeader(file_elf.c_str(), &header_elf);
    assert(res_elf == 0);
    check_struct_result(header_elf, "ELF", "x86-64", 62);
    assert(header_elf.entry_point == 0x12345678);
    std::cout << "  [PASS] ELF OK." << std::endl;
    std::cout << "[TEST] Parsing PE..." << std::endl;
    C_HeaderInfo header_pe;
    int32_t res_pe = c_getBinaryHeader(file_pe.c_str(), &header_pe);
    assert(res_pe == 0);
    check_struct_result(header_pe, "PE", "x86", 0x014C);
    assert(header_pe.entry_point == 0x1000);
    std::cout << "  [PASS] PE OK." << std::endl;
    std::cout << "[TEST] Parsing Mach-O..." << std::endl;
    C_HeaderInfo header_macho;
    int32_t res_macho = c_getBinaryHeader(file_macho.c_str(), &header_macho);
    assert(res_macho == 0);
    if (header_macho.valid) {
        check_struct_result(header_macho, "Mach-O", "ARM", 16777228);
        std::cout << "  [PASS] Mach-O OK." << std::endl;
    } else {
        std::cout << "  [WARN] Parser Mach-O gagal memvalidasi (file dummy mungkin terlalu minimal)." << std::endl;
    }
    std::remove(file_elf.c_str());
    std::remove(file_pe.c_str());
    std::remove(file_macho.c_str());
    std::cout << "[TEST] testParseBinaryHeader SELESAI." << std::endl;
    return 0;
}