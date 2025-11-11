#ifdef _WIN32
#ifndef RETOOLS_WINAPI_HELPERS_H
#define RETOOLS_WINAPI_HELPERS_H

#include <windows.h>

/**
 * @brief Mencoba mengaktifkan SeDebugPrivilege
 * @return true jika sukses
 */
bool EnableDebugPrivilege();

#endif // RETOOLS_WINAPI_HELPERS_H
#endif // _WIN32