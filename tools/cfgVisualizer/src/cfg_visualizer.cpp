#include "cfg.h"
#include "parser.h"
#include "disasm.h"
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <cctype>

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
inline std::string to_hex_str(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << val;
    return ss.str();
}

/**
 * Implementasi generateCFG.
 * Panggil Rust C-ABI c_decodeInstruksi.
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

    const uint8_t* data_ptr = text_data.data();
    const size_t data_len = text_data.size();

    while (offset < static_cast<int>(data_len)) {
        if (current_bblock_id.empty()) {
            bblock_start_addr = base_addr + offset;
            current_bblock_id = "BBlock_" + to_hex_str(bblock_start_addr);
            bblock_content.str(""); // Clear content
            bblock_content.clear();
        }

        // Panggil C-ABI
        C_Instruksi c_instr = c_decodeInstruksi(data_ptr, data_len, static_cast<size_t>(offset));

        // Konversi C_Instruksi (C struct) ke InstruksiDecoded (C++ struct internal)
        InstruksiDecoded instr;
        instr.valid = (c_instr.valid != 0);
        instr.size = c_instr.ukuran;

        if (instr.valid) {
            // Konversi mnemonic ke UPPERCASE
            std::string temp_mne(c_instr.mnemonic_instruksi);
            std::transform(temp_mne.begin(), temp_mne.end(), std::back_inserter(instr.mnemonic), ::toupper);

            // Parsing string operand (Capstone format: "op1, op2")
            std::string ops(c_instr.str_operand);
            if (!ops.empty()) {
                std::stringstream ss(ops);
                std::string single_op;
                while (std::getline(ss, single_op, ',')) {
                    // Trim spasi
                    size_t first = single_op.find_first_not_of(' ');
                    if (std::string::npos == first) {
                        if (!single_op.empty()) instr.operands.push_back(single_op);
                    } else {
                        size_t last = single_op.find_last_not_of(' ');
                        instr.operands.push_back(single_op.substr(first, (last - first + 1)));
                    }
                }
            }
        } else {
            instr.mnemonic = "(unknown)";
            if (instr.size == 0) instr.size = 1; // Hindari infinite loop
        }

        if (!instr.valid) {
            // Instruksi gak dikenal, anggap akhir block
            bblock_content << to_hex_str(base_addr + offset) << ": (unknown)\\n";
            offset += instr.size; // Maju sesuai ukuran (atau 1)
        } else {
             bblock_content << to_hex_str(base_addr + offset) << ": " << instr.mnemonic;
             for(const auto& op : instr.operands) {
                 bblock_content << " " << op;
             }
             bblock_content << "\\n";
             offset += instr.size;
        }

        // Cek akhir basic block
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