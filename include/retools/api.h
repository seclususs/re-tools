#ifndef RETOOLS_API_H
#define RETOOLS_API_H

#include "types.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Inisialisasi global library re-tools.
 * Harus dipanggil sebelum fungsi lainnya.
 */
RT_Status rt_inisialisasiUtama(void);

/**
 * @brief Membersihkan resource global saat aplikasi selesai.
 */
void rt_bersihkanUtama(void);

/* Mikir dulu, mungkin untuk Parser nanti */
// RT_Handle rt_bukaFileBinary(const char* path);
// RT_Status rt_tutupFileBinary(RT_Handle handle);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_API_H