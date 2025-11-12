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

/**
 * @brief Helper "dirty" parser untuk ekstrak nilai dari string JSON.
 */
std::string extractJsonValue(const std::string& json_obj, const std::string& key_prefix, const std::string& suffix) {
    size_t start_pos = json_obj.find(key_prefix);
    if (start_pos == std::string::npos) return "";
    
    start_pos += key_prefix.length();
    
    size_t end_pos = json_obj.find_first_of(suffix, start_pos);
    if (end_pos == std::string::npos) return "";
    
    return json_obj.substr(start_pos, end_pos - start_pos);
}

// Helper untuk membaca section .text menggunakan C-ABI (parsing JSON)
std::vector<uint8_t> get_text_section_data(const std::string& filename, uint64_t& base_addr) {
    base_addr = 0;
    char* json_string = c_parseSectionsElf(filename.c_str());
    if (!json_string) {
        return {}; // Gagal parse atau tidak ada seksyen
    }
    
    std::string json_data(json_string);
    c_freeJsonString(json_string); // Bebaskan memori

    size_t pos = 0;
    // Cari seksyen ".text"
    while ((pos = json_data.find("\"name\":\".text\"", pos)) != std::string::npos) {
        // Temukan awal objek JSON
        size_t obj_start = json_data.rfind('{', pos);
        if (obj_start == std::string::npos) break;

        std::string obj_str = json_data.substr(obj_start);
        std::string addr_str = extractJsonValue(obj_str, "\"addr\":", ",}");
        std::string offset_str = extractJsonValue(obj_str, "\"offset\":", ",}");
        std::string size_str = extractJsonValue(obj_str, "\"size\":", ",}");

        if (!addr_str.empty() && !offset_str.empty() && !size_str.empty()) {
            try {
                base_addr = std::stoull(addr_str);
                uint64_t offset = std::stoull(offset_str);
                uint64_t size = std::stoull(size_str);
                
                // Baca data dari file
                std::ifstream file(filename, std::ios::binary);
                if (!file || size == 0) return {};
                file.seekg(offset, std::ios::beg);
                
                std::vector<uint8_t> data(size);
                file.read(reinterpret_cast<char*>(data.data()), size);
                return data;

            } catch (...) {
                return {}; // Gagal konversi
            }
        }
        pos++;
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
        // std::stoull dengan base 0 bisa auto-deteksi "0x"
        return std::stoull(op_str, nullptr, 0);
    } catch (...) {
        return 0; // Gagal parse
    }
}

// Helper untuk decode C-ABI ke struct C++ lokal
InstruksiLokal decodeInstruksiLokal(const uint8_t* data_ptr, size_t data_len, size_t offset, uint64_t base_addr) {
    C_Instruksi c_instr = c_decodeInstruksi(data_ptr, data_len, offset);
    
    InstruksiLokal instr;
    instr.address = base_addr + offset;
    instr.valid = (c_instr.valid != 0);
    instr.size = c_instr.ukuran;
    instr.op_str = "";

    if (instr.valid) {
        // Konversi mnemonic ke UPPERCASE
        std::string temp_mne(c_instr.mnemonic_instruksi);
        std::transform(temp_mne.begin(), temp_mne.end(), std::back_inserter(instr.mnemonic), ::toupper);
        
        // Salin operand string (hanya operand pertama jika ada)
        std::string ops(c_instr.str_operand);
        if (!ops.empty()) {
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
        if (instr.size == 0) instr.size = 1; // Hindari infinite loop
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

    // Peta untuk menyimpan label node DOT
    // Key: Alamat awal blok
    // Value: String label (konten)
    std::map<uint64_t, std::string> petaBlokLabel;
    
    // List untuk menyimpan string edge DOT
    std::vector<std::string> daftarEdge;

    int offset = 0;
    uint64_t alamatMulaiBlok = base_addr + offset;
    std::stringstream kontenBlok;

    while (offset < static_cast<int>(data_len)) {
        InstruksiLokal instr = decodeInstruksiLokal(data_ptr, data_len, offset, base_addr);

        // Tambahkan instruksi ke konten blok saat ini
        kontenBlok << to_hex_str(instr.address) << ": " << instr.mnemonic;
        if (!instr.op_str.empty()) {
            kontenBlok << " " << instr.op_str;
        }
        kontenBlok << "\\n"; // Newline untuk DOT

        offset += instr.size; // Maju ke instruksi berikutnya

        // Cek apakah instruksi ini adalah akhir dari basic block
        bool akhirBlok = false;
        std::string mne = instr.mnemonic;

        if (!instr.valid) {
            akhirBlok = true;
        } else if (mne == "RET") {
            akhirBlok = true;
        } else if (mne == "JMP" || mne == "JNE" || mne == "JZ" || mne == "CALL" || mne == "JNZ" || mne == "JE") {
            akhirBlok = true;
            uint64_t alamatTarget = parseTargetAlamat(instr.op_str);
            
            if (alamatTarget != 0) {
                // Tambahkan edge ke target jump/call
                std::string edge = "  \"BBlock_" + to_hex_str(alamatMulaiBlok) + "\" -> \"BBlock_" + to_hex_str(alamatTarget) + "\";";
                daftarEdge.push_back(edge);
            }

            if (mne != "JMP") {
                // JNE, JZ, CALL, dll. juga punya fall-through
                uint64_t alamatFallthrough = base_addr + offset;
                std::string edge = "  \"BBlock_" + to_hex_str(alamatMulaiBlok) + "\" -> \"BBlock_" + to_hex_str(alamatFallthrough) + "\";";
                daftarEdge.push_back(edge);
            }
        }
        
        // TODO: Deteksi jika offset berikutnya adalah target jump
        // (memerlukan 2 pass, saat ini 1 pass)

        if (akhirBlok || offset >= static_cast<int>(data_len)) {
            // Simpan blok yang sudah selesai
            petaBlokLabel[alamatMulaiBlok] = kontenBlok.str();
            
            // Siapkan untuk blok berikutnya
            kontenBlok.str("");
            kontenBlok.clear();
            alamatMulaiBlok = base_addr + offset;
        }
    }

    // Tulis sisa konten jika ada
    if (!kontenBlok.str().empty()) {
         petaBlokLabel[alamatMulaiBlok] = kontenBlok.str();
    }

    // Bangun string DOT final
    std::stringstream dot;
    dot << "digraph G {\n";
    dot << "  node [shape=box, fontname=\"Courier\"];\n";

    // Tulis semua node (blok)
    for (auto const& [alamat, label] : petaBlokLabel) {
        dot << "  \"BBlock_" << to_hex_str(alamat) << "\" [label=\"" << label << "\"];\n";
    }

    // Tulis semua edge
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
        out_buffer[out_buffer_size - 1] = '\0'; // Pastikan null-terminated
        return 0;
    }
}