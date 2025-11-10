#ifndef RETOOLS_COMMON_H
#define RETOOLS_COMMON_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Makro utilitas
#define RT_UNUSED(x) (void)(x)

// Deklarasi fungsi utility umum (logging, versi, dll)

/**
 * @brief Mengambil versi library saat ini.
 * @return String versi (misal: "0.1.0-alpha")
 */
const char* rt_ambilVersi(void);

/**
 * @brief Fungsi logging sederhana.
 * @param level Level log (0=Info, 1=Warning, 2=Error)
 * @param pesan Pesan yang akan dicetak
 */
void rt_catatLog(int level, const char* pesan);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_COMMON_H