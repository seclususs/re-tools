#ifndef RETOOLS_HEXEDITOR_H
#define RETOOLS_HEXEDITOR_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * @brief Membaca sebagian bytes dari file dan mengembalikan representasi heksadesimal.
 * @param filename Path ke file.
 * @param offset Posisi awal baca.
 * @param length Jumlah bytes yang ingin dibaca.
 * @return String heksadesimal (misal: "4D 5A 90 00...")
 */
std::string lihatBytes(const std::string& filename, int offset, int length);

/**
 * @brief Mengubah bytes pada offset tertentu di dalam file.
 * @param filename Path ke file.
 * @param offset Posisi untuk mulai menulis.
 * @param data Data bytes yang akan ditulis.
 * @return true jika sukses, false jika gagal.
 */
bool ubahBytes(const std::string& filename, int offset, const std::vector<uint8_t>& data);

/**
 * @brief Mencari pattern bytes di dalam file.
 * @param filename Path ke file.
 * @param pattern Pattern bytes yang dicari.
 * @return List berisi offset (posisi) di mana pattern ditemukan.
 */
std::vector<int> cariPattern(const std::string& filename, const std::vector<uint8_t>& pattern);

// C Interface untuk Python
// perlu helper struct untuk mengembalikan list/vector
extern "C" {
    /**
     * @brief C-wrapper untuk lihatBytes.
     * @param filename Path file.
     * @param offset Posisi awal.
     * @param length Jumlah bytes.
     * @param out_buffer Buffer untuk menyimpan string hex output.
     * @param out_buffer_size Ukuran buffer output.
     * @return 0 jika sukses, -1 jika error (misal buffer terlalu kecil).
     */
    int c_lihatBytes(const char* filename, int offset, int length, char* out_buffer, int out_buffer_size);

    /**
     * @brief C-wrapper untuk ubahBytes.
     * @param filename Path file.
     * @param offset Posisi tulis.
     * @param data Pointer ke data bytes.
     * @param data_len Panjang data bytes.
     * @return 1 jika sukses, 0 jika gagal.
     */
    int c_ubahBytes(const char* filename, int offset, const uint8_t* data, int data_len);

    /**
     * @brief C-wrapper untuk cariPattern.
     * @param filename Path file.
     * @param pattern Pointer ke pattern bytes.
     * @param pattern_len Panjang pattern.
     * @param out_offsets Buffer untuk menyimpan hasil offsets (list of int).
     * @param max_offsets Ukuran maksimum buffer out_offsets.
     * @return Jumlah offset yang ditemukan (bisa 0), atau -1 jika error.
     */
    int c_cariPattern(const char* filename, const uint8_t* pattern, int pattern_len, int* out_offsets, int max_offsets);
}

#endif // RETOOLS_HEXEDITOR_H