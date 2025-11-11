#include "cfg.h"
#include "parser.h"
#include "disasm.h"
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

// Helper untuk membaca section .text
std::vector<uint8_t> get_text_section(const std::string& filename, uint64_t& base_addr) {
    std::vector<ElfSection> sections = parseSectionsElf(filename);
    for (const auto& s : sections) {
        if (s.name == ".text") {
            base_addr = s.addr;
            std::ifstream file(filename, std::ios::binary);
            if (!file) return {};
            file.seekg(s.offset, std::ios::beg);
            
            std::vector<uint8_t> data(s.size);
            file.read(reinterpret_cast<char*>(data.data()), s.size);
            return data;
        }
    }
    base_addr = 0;
    return {};
}

// Helper format hex
std::string to_hex_str(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::hex << val;
    return ss.str();
}

/**
 * Implementasi generateCFG.
 * Sangat sederhana karena disassembler 'core' terbatas.
 * Membuat basic block yang berakhir saat 'RET' (0xC3) ditemukan.
 */
std::string generateCFG(const std::string& filename) {
    uint64_t base_addr = 0;
    std::vector<uint8_t> text_data = get_text_section(filename, base_addr);
    if (text_data.empty()) return "digraph G { error [label=\"File tidak valid atau .text kosong\"]; }";

    std::stringstream dot;
    dot << "digraph G {\n";
    dot << "  node [shape=box, fontname=\"Courier\"];\n";

    int offset = 0;
    int bblock_count = 0;
    std::string current_bblock_id;

    std::stringstream bblock_content;
    uint64_t bblock_start_addr = 0;

    while (offset < static_cast<int>(text_data.size())) {
        if (current_bblock_id.empty()) {
            bblock_start_addr = base_addr + offset;
            current_bblock_id = "BBlock_" + to_hex_str(bblock_start_addr);
            bblock_content.str(""); // Clear content
            bblock_content.clear();
        }

        InstruksiDecoded instr = decodeInstruksi(text_data, offset);
        if (!instr.valid) {
            // Instruksi tidak dikenal, anggap akhir blok
            bblock_content << to_hex_str(base_addr + offset) << ": (unknown)\\n";
            offset += 1;
        } else {
             bblock_content << to_hex_str(base_addr + offset) << ": " << instr.mnemonic;
             for(const auto& op : instr.operands) {
                 bblock_content << " " << op;
             }
             bblock_content << "\\n";
             offset += instr.size;
        }

        // Cek akhir basic block
        // Disassembler saat ini hanya tahu 'RET'
        bool is_block_end = (!instr.valid) || (instr.mnemonic == "RET");
        
        if (is_block_end || offset >= static_cast<int>(text_data.size())) {
            // Tulis basic block ke DOT
            dot << "  " << current_bblock_id << " [label=\"" << bblock_content.str() << "\"];\n";
            
            // TODO: Tambahkan edges (panah)
            // Karena disasm tidak tahu JUMP/CALL, hanya perlu buat linear
            if (bblock_count > 0) {
                 std::string prev_bblock_id = "BBlock_" + to_hex_str(bblock_start_addr - 1); // Ini salah, perlu logic lebih
                 // dot << "  " << prev_bblock_id << " -> " << current_bblock_id << ";\n";
            }

            current_bblock_id = "";
            bblock_count++;
        }
    }

    dot << "}\n";
    return dot.str();
}

// Implementasi C Interface
extern "C" {
    int c_generateCFG(const char* filename, char* out_buffer, int out_buffer_size) {
        std::string result = generateCFG(std::string(filename));
        if (result.length() >= static_cast<size_t>(out_buffer_size)) {
            return -1; // Buffer terlalu kecil
        }
        std::strncpy(out_buffer, result.c_str(), out_buffer_size - 1);
        out_buffer[out_buffer_size - 1] = '\0'; // Pastikan null-terminated
        return 0;
    }
}