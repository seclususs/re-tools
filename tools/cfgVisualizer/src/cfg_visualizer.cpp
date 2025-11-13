#include <iostream>
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
#include <map>

// Tipe data
struct InstruksiLokal {
    uint64_t address;
    std::string mnemonic;
    std::string op_str;
    int size;
    bool valid;
};

// Helper untuk membaca section .text menggunakan C-ABI
std::vector<uint8_t> get_text_section_data(const std::string& filename, uint64_t& base_addr) {
    base_addr = 0;
    
    const int MAX_SECTIONS = 256;
    std::vector<C_SectionInfo> buffer(MAX_SECTIONS);
    
    // Panggil fungsi C-ABI
    int32_t count = c_getDaftarSections(filename.c_str(), buffer.data(), MAX_SECTIONS);

    if (count < 0) {
        std::cerr << "Peringatan: Gagal get sections atau buffer tidak cukup." << std::endl;
        return {};
    }

    // Cari seksyen ".text"
    for (int i = 0; i < count; ++i) {
        const auto& c_sec = buffer[i];
        if (std::strcmp(c_sec.name, ".text") == 0) {
            base_addr = c_sec.addr;
            uint64_t offset = c_sec.offset;
            uint64_t size = c_sec.size;
            
            // Baca data dari file
            std::ifstream file(filename, std::ios::binary);
            if (!file || size == 0) return {};
            file.seekg(offset, std::ios::beg);
            
            std::vector<uint8_t> data(size);
            file.read(reinterpret_cast<char*>(data.data()), size);
            return data;
        }
    }
    
    return {}; // .text tidak ditemukan
}

// Helper format hex
inline std::string to_hex_str(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::hex << val;
    return ss.str();
}

// Helper parse target jump
uint64_t parseTargetAlamat(const std::string& op_str) {
    if (op_str.empty()) return 0;
    try {
        // Basis 0 akan otomatis mendeteksi "0x"
        return std::stoull(op_str, nullptr, 0); 
    } catch (...) {
        return 0;
    }
}

// Helper untuk decode C-ABI ke struct C++ lokal
InstruksiLokal decodeInstruksiLokal(const uint8_t* data_ptr, size_t data_len, size_t offset, uint64_t base_addr) {
    // Teruskan VA (base_addr + offset) ke fungsi disasm
    C_Instruksi c_instr = c_decodeInstruksi(
        data_ptr,
        data_len,
        offset,
        base_addr + offset, // VA aktual dari instruksi
        ARCH_X86_64 // Asumsi x86_64
    );
    
    InstruksiLokal instr;
    instr.address = base_addr + offset;
    instr.valid = (c_instr.valid != 0);
    instr.size = c_instr.ukuran;
    instr.op_str = "";

    if (instr.valid) {
        std::string temp_mne(c_instr.mnemonic_instruksi);
        std::transform(temp_mne.begin(), temp_mne.end(), std::back_inserter(instr.mnemonic), ::toupper);
        
        std::string ops(c_instr.str_operand);
        if (!ops.empty()) {
            // Ambil hanya operand pertama (untuk JZ, JMP, dll)
            instr.op_str = ops.substr(0, ops.find_first_of(','));
            // Trim spasi
            size_t first = instr.op_str.find_first_not_of(' ');
            if (std::string::npos != first) {
                 size_t last = instr.op_str.find_last_not_of(' ');
                 instr.op_str = instr.op_str.substr(first, (last - first + 1));
            }
        }
    } else {
        instr.mnemonic = "(unknown)";
        if (instr.size == 0) instr.size = 1;
    }
    return instr;
}

/**
 * @brief Implementasi generateCFG.
 */
std::string generateCFG(const std::string& filename) {
    uint64_t base_addr = 0;
    std::vector<uint8_t> text_data = get_text_section_data(filename, base_addr);
    if (text_data.empty()) {
        return "digraph G { error [label=\"File tidak valid atau .text kosong/gagal parse\"]; }";
    }

    const uint8_t* data_ptr = text_data.data();
    const size_t data_len = text_data.size();

    std::map<uint64_t, std::string> petaBlokLabel;
    std::vector<std::string> daftarEdge;
    // Set untuk melacak alamat yang merupakan target jump
    std::map<uint64_t, bool> targetJumps;
    targetJumps[base_addr] = true; // Alamat pertama selalu awal blok

    // Pass: Identifikasi semua target jump
    int temp_offset = 0;
    while (temp_offset < static_cast<int>(data_len)) {
        InstruksiLokal instr = decodeInstruksiLokal(data_ptr, data_len, temp_offset, base_addr);
        if (!instr.valid) {
            temp_offset += instr.size;
            continue;
        }
        
        std::string mne = instr.mnemonic;
        if (mne == "JMP" || mne == "JNE" || mne == "JZ" || mne == "CALL" || mne == "JNZ" || mne == "JE") {
            uint64_t alamatTarget = parseTargetAlamat(instr.op_str);
            if (alamatTarget != 0) {
                targetJumps[alamatTarget] = true;
            }
            // Alamat setelah jump juga awal blok baru (jika bukan JMP/CALL unconditional)
            if (mne != "JMP" && mne != "CALL") {
                 targetJumps[instr.address + instr.size] = true;
            }
        } else if (mne == "RET") {
            // Alamat setelah RET adalah awal blok baru (jika bisa di-decode)
            targetJumps[instr.address + instr.size] = true;
        }
        temp_offset += instr.size;
    }

    // Pass: Bangun blok
    int offset = 0;
    while (offset < static_cast<int>(data_len)) {
        uint64_t alamatMulaiBlok = base_addr + offset;
        std::stringstream kontenBlok;
        
        InstruksiLokal instr;
        bool akhirBlok = false;

        while (offset < static_cast<int>(data_len) && !akhirBlok) {
            instr = decodeInstruksiLokal(data_ptr, data_len, offset, base_addr);
            
            kontenBlok << to_hex_str(instr.address) << ": " << instr.mnemonic;
            if (!instr.op_str.empty()) {
                kontenBlok << " " << instr.op_str;
            }
            kontenBlok << "\\n"; 

            offset += instr.size; 

            std::string mne = instr.mnemonic;

            if (!instr.valid) {
                akhirBlok = true;
            } else if (mne == "RET") {
                akhirBlok = true;
            } else if (mne == "JMP" || mne == "JNE" || mne == "JZ" || mne == "CALL" || mne == "JNZ" || mne == "JE") {
                akhirBlok = true;
                uint64_t alamatTarget = parseTargetAlamat(instr.op_str);
                
                if (alamatTarget != 0) {
                    std::string edge = "  \"BBlock_" + to_hex_str(alamatMulaiBlok) + "\" -> \"BBlock_" + to_hex_str(alamatTarget) + "\";";
                    daftarEdge.push_back(edge);
                }

                if (mne != "JMP") {
                    uint64_t alamatFallthrough = base_addr + offset;
                    std::string edge = "  \"BBlock_" + to_hex_str(alamatMulaiBlok) + "\" -> \"BBlock_" + to_hex_str(alamatFallthrough) + "\";";
                    daftarEdge.push_back(edge);
                }
            }
            
            // Cek apakah instruksi *berikutnya* adalah target jump
            if (targetJumps.count(base_addr + offset)) {
                akhirBlok = true;
                // Jika blok saat ini tidak berakhir dengan JMP/RET, tambahkan edge fall-through
                if (mne != "JMP" && mne != "RET") {
                    std::string edge = "  \"BBlock_" + to_hex_str(alamatMulaiBlok) + "\" -> \"BBlock_" + to_hex_str(base_addr + offset) + "\";";
                    // Hindari duplikat edge fall-through
                    bool found = false;
                    for(const auto& e : daftarEdge) { if (e == edge) found = true; }
                    if (!found) daftarEdge.push_back(edge);
                }
            }
        }
        
        petaBlokLabel[alamatMulaiBlok] = kontenBlok.str();
    }

    std::stringstream dot;
    dot << "digraph G {\n";
    dot << "  node [shape=box, fontname=\"Courier\"];\n";

    for (auto const& [alamat, label] : petaBlokLabel) {
        dot << "  \"BBlock_" << to_hex_str(alamat) << "\" [label=\"" << label << "\"];\n";
    }

    for (const auto& edge_str : daftarEdge) {
        dot << edge_str << "\n";
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
        out_buffer[out_buffer_size - 1] = '\0';
        return 0;
    }
}