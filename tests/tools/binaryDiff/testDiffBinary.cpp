#include "binary_diff.h"
#include "parser.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <vector>

void create_dummy_elf_file(const std::string& filename, uint8_t entry_byte) {
    std::ofstream file(filename, std::ios::binary);
    // Header ELF64 minimalis palsu
    std::vector<uint8_t> header = {
        0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00, // Magic, 64-bit, LE, ver
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Pad
        0x02, 0x00, // Type: EXEC
        0x3E, 0x00, // Machine: x86-64
        0x01, 0x00, 0x00, 0x00, // Version
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Entry point (offset 64)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pgoff
        0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // shoff (offset 160)
        0x00, 0x00, 0x00, 0x00, // flags
        0x40, 0x00, // ehsize
        0x38, 0x00, // phentsize
        0x01, 0x00, // phnum
        0x40, 0x00, // shentsize
        0x02, 0x00, // shnum
        0x01, 0x00  // shstrndx
    };
    header.resize(64, 0); 
    
    // Program Header (dummy, menunjuk ke .text)
    std::vector<uint8_t> pheader = {
        0x01, 0x00, 0x00, 0x00, // type=LOAD
        0x05, 0x00, 0x00, 0x00, // flags=R+X
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // offset .text (128)
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // vaddr .text (0x400080)
        0x80, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // paddr
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // filesz (4 bytes)
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // memsz (4 bytes)
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // align
    };
    pheader.resize(56, 0);

    header.insert(header.end(), pheader.begin(), pheader.end()); // Header + PHeader
    header.resize(128, 0); // Padding ke offset .text

    // .text section data (NOP, RET)
    std::vector<uint8_t> text_data = { 0x90, entry_byte, 0x90, 0xC3 };
    header.insert(header.end(), text_data.begin(), text_data.end());
    header.resize(160, 0); // Padding ke shoff

    // Section Header Table
    // SH 0 (NULL)
    std::vector<uint8_t> sh_null(64, 0);
    // SH 1 (String table) - dummy
    std::vector<uint8_t> sh_str(64, 0); 
    // SH 2 (.text)
    std::vector<uint8_t> sh_text(64, 0);
    // sh_name (offset 1 di strtab)
    *(uint32_t*)&sh_text[0] = 1; 
    // sh_type (PROGBITS)
    *(uint32_t*)&sh_text[4] = 1;
    // sh_flags (ALLOC|EXEC)
    *(uint64_t*)&sh_text[8] = 0x6;
    // sh_addr (0x400080)
    *(uint64_t*)&sh_text[16] = 0x400080;
    // sh_offset (128)
    *(uint64_t*)&sh_text[24] = 128;
    // sh_size (4)
    *(uint64_t*)&sh_text[32] = 4;

    header.insert(header.end(), sh_null.begin(), sh_null.end());
    header.insert(header.end(), sh_str.begin(), sh_str.end());
    header.insert(header.end(), sh_text.begin(), sh_text.end());
    
    // String table data (\0.text\0)
    std::vector<uint8_t> str_data = { 0x00, '.', 't', 'e', 'x', 't', 0x00 };
    header.insert(header.end(), str_data.begin(), str_data.end());

    file.write(reinterpret_cast<char*>(header.data()), header.size());
    file.close();
}

int main() {
    std::string file1 = "test_diff_1.bin";
    std::string file2 = "test_diff_2.bin";
    std::string file3 = "test_diff_3.bin";

    create_dummy_elf_file(file1, 0x90); // .text = 90 90 90 C3
    create_dummy_elf_file(file2, 0x90); // .text = 90 90 90 C3 (Sama)
    create_dummy_elf_file(file3, 0x55); // .text = 90 55 90 C3 (Beda)

    std::cout << "[TEST] Mulai testDiffBinary..." << std::endl;

    // Test: File Sama
    std::vector<DiffResult> results1 = diffBinary(file1, file2);
    assert(results1.size() == 1);
    assert(results1[0].functionName == ".text");
    assert(results1[0].status == DiffResult::MATCHED);
    std::cout << "  [PASS] Perbandingan file identik sukses." << std::endl;

    // Test: File Beda
    std::vector<DiffResult> results2 = diffBinary(file1, file3);
    assert(results2.size() == 1);
    assert(results2[0].functionName == ".text");
    assert(results2[0].status == DiffResult::MODIFIED);
    std::cout << "  [PASS] Perbandingan file berbeda sukses." << std::endl;

    std::remove(file1.c_str());
    std::remove(file2.c_str());
    std::remove(file3.c_str());

    std::cout << "[TEST] testDiffBinary SELESAI." << std::endl;
    return 0;
}