#ifdef __linux__

#include "ptrace_helpers.h"
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <iostream>
#include <cstring>

// Ukuran word di arsitektur ini
constexpr size_t WORD_SIZE = sizeof(long);

// Gunakan process_vm_readv/writev jika tersedia
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 15))
#define USE_PROCESS_VM_IOV
#endif

bool ptrace_read_memory(pid_t pid, u64 addr, u8* out, int size) {
#ifdef USE_PROCESS_VM_IOV
    struct iovec local_iov;
    struct iovec remote_iov;

    local_iov.iov_base = out;
    local_iov.iov_len = size;
    remote_iov.iov_base = (void*)addr;
    remote_iov.iov_len = size;

    ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    return nread == size;
#else
    // Fallback ke PTRACE_PEEKDATA (lambat)
    int i = 0;
    long word;
    u8* out_ptr = out;
    
    for (i = 0; i < size; i += WORD_SIZE) {
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + i), NULL);
        if (errno != 0) return false;

        int bytes_to_copy = std::min((int)WORD_SIZE, size - i);
        std::memcpy(out_ptr, &word, bytes_to_copy);
        out_ptr += WORD_SIZE;
    }
    return true;
#endif
}

bool ptrace_write_memory(pid_t pid, u64 addr, const u8* data, int size) {
#ifdef USE_PROCESS_VM_IOV
    struct iovec local_iov;
    struct iovec remote_iov;

    local_iov.iov_base = (void*)data; // const_cast
    local_iov.iov_len = size;
    remote_iov.iov_base = (void*)addr;
    remote_iov.iov_len = size;

    ssize_t nwritten = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    return nwritten == size;
#else
    // Fallback ke PTRACE_POKEDATA (lambat)
    int i = 0;
    long word;
    const u8* data_ptr = data;

    for (i = 0; i < size; i += WORD_SIZE) {
        int bytes_to_copy = std::min((int)WORD_SIZE, size - i);
        if (bytes_to_copy < WORD_SIZE) {
            // Read-Modify-Write untuk word terakhir (parsial)
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + i), NULL);
            if (errno != 0) return false;
            std::memcpy(&word, data_ptr, bytes_to_copy);
        } else {
            std::memcpy(&word, data_ptr, WORD_SIZE);
        }

        if (ptrace(PTRACE_POKEDATA, pid, (void*)(addr + i), word) != 0) {
            return false;
        }
        data_ptr += WORD_SIZE;
    }
    return true;
#endif
}

#endif // __linux__