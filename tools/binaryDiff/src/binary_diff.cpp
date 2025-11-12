#include "binary_diff.h"
#include "parser.h"
#include <fstream>
#include <map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>
#include <cstdint>

// Struct untuk menyimpan info fungsi dari simbol
struct SimbolFungsi {
    std::string name;
    uint64_t addr; // Virtual Address
    uint64_t size;
};

// Struct untuk menyimpan info seksyen (termasuk offset file)
struct InfoSeksyen {
    std::string name;
    uint64_t addr;   // Virtual Address
    uint64_t offset; // File Offset
    uint64_t size;
};

// Helper untuk membaca N bytes dari file di offset
std::vector<uint8_t> read_bytes_at(const std::string& filename, uint64_t offset, uint64_t size) {
    std::ifstream file(filename, std::ios::binary);
    if (!file || size == 0) return {};
    
    file.seekg(offset, std::ios::beg);
    if (!file) {
        // std::cerr << "Gagal seek ke offset " << offset << " di " << filename << std::endl;
        return {};
    }

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    std::streamsize bytes_read = file.gcount();
    
    if (bytes_read < 0) return {}; // Error
    if (static_cast<uint64_t>(bytes_read) < size) {
        data.resize(bytes_read);
    }
    return data;
}

/**
 * @brief Helper "dirty" parser untuk ekstrak nilai dari string JSON.
 * @param json_obj String objek JSON, misal: {"name":"foo","addr":123}
 * @param key_prefix Kunci yang dicari, misal: "\"name\":\""
 * @param suffix Karakter akhir value, misal: "\"" untuk string, "," atau "}" untuk angka
 * @return String nilai yang diekstrak.
 */
std::string extractJsonValue(const std::string& json_obj, const std::string& key_prefix, const std::string& suffix) {
    size_t start_pos = json_obj.find(key_prefix);
    if (start_pos == std::string::npos) return "";
    
    start_pos += key_prefix.length();
    
    size_t end_pos = json_obj.find_first_of(suffix, start_pos);
    if (end_pos == std::string::npos) return "";
    
    return json_obj.substr(start_pos, end_pos - start_pos);
}

// Helper untuk parse JSON string dari c_parseSymbolsElf
std::map<std::string, SimbolFungsi> parseSimbolFungsi(const std::string& filename) {
    std::map<std::string, SimbolFungsi> petaFungsi;
    char* json_string = c_parseSymbolsElf(filename.c_str());
    if (!json_string) {
        return petaFungsi; // Gagal parse atau tidak ada simbol
    }
    
    std::string json_data(json_string);
    c_freeJsonString(json_string); // Bebaskan memori

    size_t pos = 0;
    // Cari fungsi: "symbol_type":"FUNC"
    while ((pos = json_data.find("\"symbol_type\":\"FUNC\"", pos)) != std::string::npos) {
        // Temukan awal objek JSON
        size_t obj_start = json_data.rfind('{', pos);
        if (obj_start == std::string::npos) break;

        // Ekstrak string objek
        std::string obj_str = json_data.substr(obj_start);
        std::string name = extractJsonValue(obj_str, "\"name\":\"", "\"");
        std::string addr_str = extractJsonValue(obj_str, "\"addr\":", ",}");
        std::string size_str = extractJsonValue(obj_str, "\"size\":", ",}");

        if (!name.empty() && !addr_str.empty() && !size_str.empty()) {
            try {
                uint64_t addr = std::stoull(addr_str);
                uint64_t size = std::stoull(size_str);
                // Hanya tambahkan jika simbol punya nama dan ukuran
                if (!name.empty() && size > 0) {
                    petaFungsi[name] = {name, addr, size};
                }
            } catch (...) {
                // Gagal konversi string ke int, abaikan
            }
        }
        pos++; // Lanjut cari dari setelah "FUNC"
    }
    return petaFungsi;
}

// Helper untuk parse JSON string dari c_parseSectionsElf
std::map<std::string, InfoSeksyen> parseInfoSeksyen(const std::string& filename) {
    std::map<std::string, InfoSeksyen> petaSeksyen;
    char* json_string = c_parseSectionsElf(filename.c_str());
    if (!json_string) {
        return petaSeksyen;
    }

    std::string json_data(json_string);
    c_freeJsonString(json_string);

    size_t pos = 0;
    while ((pos = json_data.find("{\"name\":", pos)) != std::string::npos) {
        std::string obj_str = json_data.substr(pos);

        std::string name = extractJsonValue(obj_str, "\"name\":\"", "\"");
        std::string addr_str = extractJsonValue(obj_str, "\"addr\":", ",}");
        std::string offset_str = extractJsonValue(obj_str, "\"offset\":", ",}");
        std::string size_str = extractJsonValue(obj_str, "\"size\":", ",}");

        if (!name.empty() && !addr_str.empty() && !offset_str.empty() && !size_str.empty()) {
             try {
                petaSeksyen[name] = {
                    name,
                    std::stoull(addr_str),
                    std::stoull(offset_str),
                    std::stoull(size_str)
                };
             } catch (...) { }
        }
        pos++;
    }
    return petaSeksyen;
}

/**
 * @brief Mengkonversi Virtual Address (VA) ke File Offset
 * @param v_addr Alamat virtual fungsi/simbol
 * @param petaSeksyen Peta info seksyen dari file
 * @return Offset file, atau 0 jika tidak ditemukan
 */
uint64_t ambilOffsetFile(uint64_t v_addr, const std::map<std::string, InfoSeksyen>& petaSeksyen) {
    for (auto const& [nama, info] : petaSeksyen) {
        // Cek apakah v_addr ada di dalam seksyen ini
        if (v_addr >= info.addr && v_addr < (info.addr + info.size)) {
            // Hitung offset relatif dari awal seksyen
            uint64_t offset_relatif = v_addr - info.addr;
            // Tambahkan ke offset file seksyen
            return info.offset + offset_relatif;
        }
    }
    return 0; // Tidak ditemukan (atau v_addr 0)
}

/**
 * @brief Helper untuk logika fallback (section diffing)
 */
DiffResult diffSatuSeksyen(const std::string& file1, const std::map<std::string, InfoSeksyen>& sections1,
                           const std::string& file2, const std::map<std::string, InfoSeksyen>& sections2,
                           const std::string& namaSeksyen)
{
    auto it1 = sections1.find(namaSeksyen);
    auto it2 = sections2.find(namaSeksyen);

    if (it1 != sections1.end() && it2 != sections2.end()) {
        // Keduanya punya seksyen, bandingkan
        const auto& sec1 = it1->second;
        const auto& sec2 = it2->second;
        
        std::vector<uint8_t> data1 = read_bytes_at(file1, sec1.offset, sec1.size);
        std::vector<uint8_t> data2 = read_bytes_at(file2, sec2.offset, sec2.size);

        if (data1.empty() && data2.empty()) {
             return {namaSeksyen, sec1.addr, sec2.addr, DiffResult::MATCHED};
        }
        if (data1 == data2) {
            return {namaSeksyen, sec1.addr, sec2.addr, DiffResult::MATCHED};
        } else {
            return {namaSeksyen, sec1.addr, sec2.addr, DiffResult::MODIFIED};
        }
        
    } else if (it1 != sections1.end()) {
        return {namaSeksyen, it1->second.addr, 0, DiffResult::REMOVED};
    } else if (it2 != sections2.end()) {
        return {namaSeksyen, 0, it2->second.addr, DiffResult::ADDED};
    } else {
        // Keduanya tidak punya
        return {namaSeksyen, 0, 0, DiffResult::MATCHED}; // Atau bisa di-skip
    }
}

// Implementasi diffBinary
std::vector<DiffResult> diffBinary(const std::string& file1, const std::string& file2) {
    std::vector<DiffResult> results;
    
    // Coba parse simbol fungsi
    std::map<std::string, SimbolFungsi> petaFungsi1 = parseSimbolFungsi(file1);
    std::map<std::string, SimbolFungsi> petaFungsi2 = parseSimbolFungsi(file2);
    
    // Cek apakah kita berhasil parse simbol
    if (!petaFungsi1.empty() && !petaFungsi2.empty()) {
        // LOGIKA UTAMA: Symbol-based Diffing
        std::cout << "[INFO] Menjalankan diff berbasis simbol." << std::endl;
        
        // Perlu info seksyen untuk mapping VA ke Offset
        std::map<std::string, InfoSeksyen> seksyen1 = parseInfoSeksyen(file1);
        std::map<std::string, InfoSeksyen> seksyen2 = parseInfoSeksyen(file2);
        
        std::map<std::string, bool> processedFuncs; // Untuk melacak fungsi yg sudah dicek

        // Loop: Cek fungsi di file 1 (MATCHED, MODIFIED, REMOVED)
        for (auto const& [namaFungsi, simbol1] : petaFungsi1) {
            processedFuncs[namaFungsi] = true;
            auto it_file2 = petaFungsi2.find(namaFungsi);

            if (it_file2 == petaFungsi2.end()) {
                // Tidak ada di file 2 -> REMOVED
                results.push_back({namaFungsi, simbol1.addr, 0, DiffResult::REMOVED});
            } else {
                // Ada di kedua file, bandingkan bytecode
                const auto& simbol2 = it_file2->second;
                
                uint64_t offset1 = ambilOffsetFile(simbol1.addr, seksyen1);
                uint64_t offset2 = ambilOffsetFile(simbol2.addr, seksyen2);

                std::vector<uint8_t> bytes1 = read_bytes_at(file1, offset1, simbol1.size);
                std::vector<uint8_t> bytes2 = read_bytes_at(file2, offset2, simbol2.size);

                if (bytes1.empty() && bytes2.empty()) {
                    // Gagal baca, anggap sama
                     results.push_back({namaFungsi, simbol1.addr, simbol2.addr, DiffResult::MATCHED});
                } else if (bytes1 == bytes2) {
                    results.push_back({namaFungsi, simbol1.addr, simbol2.addr, DiffResult::MATCHED});
                } else {
                    results.push_back({namaFungsi, simbol1.addr, simbol2.addr, DiffResult::MODIFIED});
                }
            }
        }
        
        // Loop: Cek fungsi di file 2 (ADDED)
        for (auto const& [namaFungsi, simbol2] : petaFungsi2) {
            if (processedFuncs.find(namaFungsi) == processedFuncs.end()) {
                // Jika belum diproses, berarti ini fungsi baru -> ADDED
                results.push_back({namaFungsi, 0, simbol2.addr, DiffResult::ADDED});
            }
        }

    } else {
        // LOGIKA FALLBACK: Section-based Diffing
        // Parse seksyen
        std::map<std::string, InfoSeksyen> seksyen1 = parseInfoSeksyen(file1);
        std::map<std::string, InfoSeksyen> seksyen2 = parseInfoSeksyen(file2);

        // Bandingkan .text
        results.push_back(diffSatuSeksyen(file1, seksyen1, file2, seksyen2, ".text"));
    }

    return results;
}

// Implementasi C Interface
extern "C" {
    int c_diffBinary(const char* file1, const char* file2, C_DiffResult* out_results, int max_results) {
        std::vector<DiffResult> results = diffBinary(std::string(file1), std::string(file2));

        if (results.size() > static_cast<size_t>(max_results)) {
            return -1; // Buffer tidak cukup
        }

        for (size_t i = 0; i < results.size(); ++i) {
            std::strncpy(out_results[i].functionName, results[i].functionName.c_str(), 127);
            out_results[i].functionName[127] = '\0';
            out_results[i].addressFile1 = results[i].addressFile1;
            out_results[i].addressFile2 = results[i].addressFile2;
            out_results[i].status = static_cast<int>(results[i].status);
        }
        
        return static_cast<int>(results.size());
    }
}