/**
 * @brief Core type definitions and utility functions for the library.
 * @author Seclususs
 * @date 2025-11-19
 */

#ifndef RETOOLS_TYPES_H
#define RETOOLS_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ===================================================================================
// === TYPE DEFINITIONS ===
// ===================================================================================

/** @name Fixed-width Integers
 * Standardized integer types for FFI compatibility.
 * @{ */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
/** @} */

/**
 * @brief Opaque handle for internal objects (e.g., debugger session).
 */
typedef void* RT_Handle;


// ===================================================================================
// === UTILITIES ===
// ===================================================================================

/**
 * @brief Frees a string allocated by the library.
 *
 * @note Must be called for every `char*` returned by the API to prevent memory leaks.
 *
 * @param ptr Pointer to the C-string to free.
 */
void c_freeString(char* ptr);

/**
 * @brief Retrieves the last error message on the current thread.
 *
 * Use this when an API function returns a failure code (e.g., -1 or NULL).
 *
 * @return Pointer to the error string. Caller must free using `c_freeString`.
 */
char* rt_get_last_error_message(void);

#ifdef __cplusplus
}
#endif

#endif // RETOOLS_TYPES_H