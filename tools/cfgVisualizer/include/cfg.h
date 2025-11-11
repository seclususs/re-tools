#ifndef RETOOLS_CFG_H
#define RETOOLS_CFG_H

#include <string>

/**
 * @brief Menganalisis file binary dan menghasilkan representasi CFG
 * (Control Flow Graph) dalam format DOT (Graphviz).
 * @param filename Path ke file binary.
 * @return String berisi konten file .dot.
 */
std::string generateCFG(const std::string& filename);

// C Interface untuk Python
extern "C" {
    /**
     * @brief C-wrapper untuk generateCFG.
     * @param filename Path file.
     * @param out_buffer Buffer untuk menyimpan string DOT output.
     * @param out_buffer_size Ukuran buffer output.
     * @return 0 jika sukses, -1 jika error (misal buffer terlalu kecil).
     */
    int c_generateCFG(const char* filename, char* out_buffer, int out_buffer_size);
}

#endif // RETOOLS_CFG_H