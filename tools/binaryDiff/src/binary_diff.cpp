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

// Helper untuk membaca N bytes dari file di offset (Tidak berubah)
std::vector<uint8_t> read_bytes_at(const std::string& filename, uint64_t offset, uint64_t size) {
    std::ifstream file(filename, std::ios::binary);
    if (!file || size == 0) return {};
    
    file.seekg(offset, std::ios::beg);
    if (!file) {
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

// Helper untuk parse JSON string dari c_parseSymbolsElf
std::map<std::string, SimbolFungsi> parseSimbolFungsi(const std::string& filename) {
    std::map<std::string, SimbolFungsi> petaFungsi;
    
    // Alokasi buffer di stack atau vector
    const int MAX_SIMBOL = 4096;
    std::vector<C_SymbolInfo> buffer(MAX_SIMBOL);

    // Panggil fungsi C-ABI baru
    int32_t count = c_getDaftarSimbol(filename.c_str(), buffer.data(), MAX_SIMBOL);

    if (count < 0) {
        std::cerr << "Peringatan: Buffer simbol (max " << MAX_SIMBOL << ") tidak cukup atau gagal parse." << std::endl;
        return petaFungsi;
    }

    for (int i = 0; i < count; ++i) {
        const auto& c_sym = buffer[i];
        
        // Cek jika ini adalah FUNC
        if (std::strcmp(c_sym.symbol_type, "FUNC") == 0) {
            std::string name(c_sym.name);
            uint64_t size = c_sym.size;

            if (!name.empty() && size > 0) {
                petaFungsi[name] = {name, c_sym.addr, size};
            }
        }
    }
    return petaFungsi;
}

// Helper untuk parse JSON string dari c_parseSectionsElf
std::map<std::string, InfoSeksyen> parseInfoSeksyen(const std::string& filename) {
    std::map<std::string, InfoSeksyen> petaSeksyen;

    const int MAX_SECTIONS = 256;
    std::vector<C_SectionInfo> buffer(MAX_SECTIONS);
    
    // Panggil fungsi C-ABI baru
    int32_t count = c_getDaftarSections(filename.c_str(), buffer.data(), MAX_SECTIONS);

    if (count < 0) {
        std::cerr << "Peringatan: Buffer section (max " << MAX_SECTIONS << ") tidak cukup atau gagal parse." << std::endl;
        return petaSeksyen;
    }

    for (int i = 0; i < count; ++i) {
        const auto& c_sec = buffer[i];
        std::string name(c_sec.name);
        
        if (!name.empty()) {
             petaSeksyen[name] = {
                name,
                c_sec.addr,
                c_sec.offset,
                c_sec.size
            };
        }
    }
    return petaSeksyen;
}

/**
 * @brief Mengkonversi Virtual Address (VA) ke File Offset
 */
uint64_t ambilOffsetFile(uint64_t v_addr, const std::map<std::string, InfoSeksyen>& petaSeksyen) {
    for (auto const& [nama, info] : petaSeksyen) {
        if (v_addr >= info.addr && v_addr < (info.addr + info.size)) {
            uint64_t offset_relatif = v_addr - info.addr;
            return info.offset + offset_relatif;
        }
    }
    return 0;
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
        return {namaSeksyen, 0, 0, DiffResult::MATCHED};
    }
}

// Implementasi diffBinary
std::vector<DiffResult> diffBinary(const std::string& file1, const std::string& file2) {
    std::vector<DiffResult> results;
    
    std::map<std::string, SimbolFungsi> petaFungsi1 = parseSimbolFungsi(file1);
    std::map<std::string, SimbolFungsi> petaFungsi2 = parseSimbolFungsi(file2);
    
    if (!petaFungsi1.empty() && !petaFungsi2.empty()) {
        std::cout << "[INFO] Menjalankan diff berbasis simbol." << std::endl;
        
        std::map<std::string, InfoSeksyen> seksyen1 = parseInfoSeksyen(file1);
        std::map<std::string, InfoSeksyen> seksyen2 = parseInfoSeksyen(file2);
        
        std::map<std::string, bool> processedFuncs;

        for (auto const& [namaFungsi, simbol1] : petaFungsi1) {
            processedFuncs[namaFungsi] = true;
            auto it_file2 = petaFungsi2.find(namaFungsi);

            if (it_file2 == petaFungsi2.end()) {
                results.push_back({namaFungsi, simbol1.addr, 0, DiffResult::REMOVED});
            } else {
                const auto& simbol2 = it_file2->second;
                uint64_t offset1 = ambilOffsetFile(simbol1.addr, seksyen1);
                uint64_t offset2 = ambilOffsetFile(simbol2.addr, seksyen2);
                std::vector<uint8_t> bytes1 = read_bytes_at(file1, offset1, simbol1.size);
                std::vector<uint8_t> bytes2 = read_bytes_at(file2, offset2, simbol2.size);

                if (bytes1.empty() && bytes2.empty()) {
                     results.push_back({namaFungsi, simbol1.addr, simbol2.addr, DiffResult::MATCHED});
                } else if (bytes1 == bytes2) {
                    results.push_back({namaFungsi, simbol1.addr, simbol2.addr, DiffResult::MATCHED});
                } else {
                    results.push_back({namaFungsi, simbol1.addr, simbol2.addr, DiffResult::MODIFIED});
                }
            }
        }
        
        for (auto const& [namaFungsi, simbol2] : petaFungsi2) {
            if (processedFuncs.find(namaFungsi) == processedFuncs.end()) {
                results.push_back({namaFungsi, 0, simbol2.addr, DiffResult::ADDED});
            }
        }

    } else {
        std::map<std::string, InfoSeksyen> seksyen1 = parseInfoSeksyen(file1);
        std::map<std::string, InfoSeksyen> seksyen2 = parseInfoSeksyen(file2);
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