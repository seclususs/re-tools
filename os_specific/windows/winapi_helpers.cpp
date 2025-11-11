#ifdef _WIN32
#include "winapi_helpers.h"

bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bool bOk = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    CloseHandle(hToken);
    return bOk;
}

#endif // _WIN32