#include "binary_diff.h"
#include "parser.h"
#include <fstream>
#include <map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <iostream>

// Helper untuk membaca N bytes dari file di offset
std::vector<uint8_t> read_bytes_at(const std::string& filename, uint64_t offset, uint64_t size) {
    std::ifstream file(filename, std::ios::binary);
    if (!file || size == 0) return {};
    
    file.seekg(offset, std::ios::beg);
    if (!file) return {};

    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    std::streamsize bytes_read = file.gcount();
    
    if (bytes_read < static_cast<std::streamsize>(size)) {
        data.resize(bytes_read);
    }
    return data;
}

// Implementasi sederhana diffBinary
// Membandingkan simbol ELF (jika ada)
std::vector<DiffResult> diffBinary(const std::string& file1, const std::string& file2) {
    std::vector<DiffResult> results;
    
    // Parse simbol dari kedua file
    // NOTE: parseSymbolElf di 'core' adalah stub. 
    // Implementasi ini berpura-pura parseSymbolElf mengembalikan simbol.
    
    std::vector<ElfSection> sections1 = parseSectionsElf(file1);
    std::vector<ElfSection> sections2 = parseSectionsElf(file2);

    std::map<std::string, ElfSection> map1, map2;
    for (const auto& s : sections1) {
        if (!s.name.empty()) map1[s.name] = s;
    }
    for (const auto& s : sections2) {
        if (!s.name.empty()) map2[s.name] = s;
    }

    // Bandingkan section .text (sebagai ganti fungsi)
    std::string target_name = ".text";
    
    auto it1 = map1.find(target_name);
    auto it2 = map2.find(target_name);

    if (it1 != map1.end() && it2 != map2.end()) {
        // Keduanya punya .text, bandingkan
        std::vector<uint8_t> data1 = read_bytes_at(file1, it1->second.offset, it1->second.size);
        std::vector<uint8_t> data2 = read_bytes_at(file2, it2->second.offset, it2->second.size);

        DiffResult res;
        res.functionName = target_name;
        res.addressFile1 = it1->second.addr;
        res.addressFile2 = it2->second.addr;
        
        if (data1 == data2) {
            res.status = DiffResult::MATCHED;
        } else {
            res.status = DiffResult::MODIFIED;
        }
        results.push_back(res);
        
    } else if (it1 != map1.end()) {
        results.push_back({target_name, it1->second.addr, 0, DiffResult::REMOVED});
    } else if (it2 != map2.end()) {
        results.push_back({target_name, 0, it2->second.addr, DiffResult::ADDED});
    }

    // TODO: Idealnya, ini akan mengulang semua fungsi, bukan hanya .text
    // for (const auto& [name, sym1] : map1) {
    //    ... bandingkan dengan map2 ...
    // }

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