#ifndef RETOOLS_TYPES_H
#define RETOOLS_TYPES_H

#include <stdint.h>
#include <stddef.h>


typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef enum {
    RT_SUKSES = 0,
    RT_GAGAL_UMUM = -1,
    RT_INVALID_PARAMETER = -2,
    RT_MEMORI_PENUH = -3,
    RT_FILE_TIDAK_DITEMUKAN = -4,
    RT_BELUM_DIIMPLEMENTASIKAN = -99
} RT_Status;

typedef void* RT_Handle;

#endif // RETOOLS_TYPES_H