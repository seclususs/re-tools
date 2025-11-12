use libc::{c_int, c_ulonglong, c_uchar};
use std::collections::HashMap;
use std::ffi::c_void as rt_Handle;
use std::ptr::null_mut;

// Tipe C-ABI
#[allow(non_camel_case_types)]
type u64 = c_ulonglong;
#[allow(non_camel_case_types)]
type u8 = c_uchar;

#[repr(C)]
struct StateDebuggerInternal {
    pid_target: c_int,
    attached_status: bool,
    // Menyimpan byte asli di alamat breakpoint
    breakpoints_map: HashMap<u64, u8>,

    // Data spesifik platform
    #[cfg(windows)]
    handle_proses: windows_sys::Win32::Foundation::HANDLE,
}

/// Helper untuk mengkonversi *mut rt_Handle ke &mut StateDebuggerInternal
unsafe fn ambil_state<'a>(handle: *mut rt_Handle) -> Option<&'a mut StateDebuggerInternal> {
    if handle.is_null() {
        return None;
    }
    // Operasi ini memerlukan blok unsafe
    unsafe { (handle as *mut StateDebuggerInternal).as_mut() }
}

// Implementasi C-ABI
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_attachProses(pid_target_proses: c_int) -> *mut rt_Handle {

    unsafe {
        // Buat state di heap
        let state_debugger_box = Box::new(StateDebuggerInternal {
            pid_target: pid_target_proses,
            attached_status: false,
            breakpoints_map: HashMap::new(),
            #[cfg(windows)]
            handle_proses: 0, // INVALID_HANDLE_VALUE
        });

        // Ubah ke pointer mentah
        let state_ptr = Box::into_raw(state_debugger_box);

        // Panggil platform attach
        let attach_sukses: bool;

        #[cfg(target_os = "linux")]
        { attach_sukses = platform_linux::impl_platform_attach(state_ptr.as_mut().unwrap()); }

        #[cfg(windows)]
        { attach_sukses = platform_windows::impl_platform_attach(state_ptr.as_mut().unwrap()); }

        #[cfg(not(any(target_os = "linux", windows)))]
        { attach_sukses = platform_unsupported::impl_platform_attach(); }

        if attach_sukses {
            (*state_ptr).attached_status = true;
            state_ptr as *mut rt_Handle
        } else {
            // Gagal, bebaskan memori
            let _ = Box::from_raw(state_ptr);
            null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_detachProses(handle: *mut rt_Handle) {

    unsafe {
        let Some(state_data) = ambil_state(handle) else { return };

        // Kembalikan semua breakpoint sebelum detach
        let bps_to_restore: Vec<(u64, u8)> = state_data.breakpoints_map.iter().map(|(&k, &v)| (k, v)).collect();
        for (addr, orig_byte) in bps_to_restore {
            let data_byte = [orig_byte];
            #[cfg(target_os = "linux")]
            platform_linux::impl_platform_tulisMemory(state_data, addr, data_byte.as_ptr(), 1);
            #[cfg(windows)]
            platform_windows::impl_platform_tulisMemory(state_data, addr, data_byte.as_ptr(), 1);
        }
        state_data.breakpoints_map.clear();

        if state_data.attached_status {
            #[cfg(target_os = "linux")]
            platform_linux::impl_platform_detach(state_data);
            #[cfg(windows)]
            platform_windows::impl_platform_detach(state_data);
        }

        // Bebaskan memori Box
        let _ = Box::from_raw(handle as *mut StateDebuggerInternal);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_bacaMemory(handle: *mut rt_Handle, addr: u64, out_buffer: *mut u8, size: c_int) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if out_buffer.is_null() || size <= 0 { return -1; }
        if !state_data.attached_status { return -1; }

        #[cfg(target_os = "linux")]
        { return platform_linux::impl_platform_bacaMemory(state_data, addr, out_buffer, size); }

        #[cfg(windows)]
        { return platform_windows::impl_platform_bacaMemory(state_data, addr, out_buffer, size); }

        #[cfg(not(any(target_os = "linux", windows)))]
        { return platform_unsupported::impl_platform_bacaMemory(); }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_tulisMemory(handle: *mut rt_Handle, addr: u64, data: *const u8, size: c_int) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if data.is_null() || size <= 0 { return -1; }
        if !state_data.attached_status { return -1; }

        #[cfg(target_os = "linux")]
        { return platform_linux::impl_platform_tulisMemory(state_data, addr, data, size); }

        #[cfg(windows)]
        { return platform_windows::impl_platform_tulisMemory(state_data, addr, data, size); }

        #[cfg(not(any(target_os = "linux", windows)))]
        { return platform_unsupported::impl_platform_tulisMemory(); }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setBreakpoint(handle: *mut rt_Handle, addr: u64) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if state_data.breakpoints_map.contains_key(&addr) {
            return 0; // Breakpoint sudah ada
        }

        // Baca byte asli
        let mut orig_byte: u8 = 0;
        let bytes_dibaca = rt_bacaMemory(handle, addr, &mut orig_byte, 1);
        if bytes_dibaca != 1 {
            return -1; // Gagal baca
        }

        // Simpan byte asli
        state_data.breakpoints_map.insert(addr, orig_byte);

        // Tulis 0xCC (INT3)
        let int3_byte: u8 = 0xCC;
        let bytes_ditulis = rt_tulisMemory(handle, addr, &int3_byte, 1);
        if bytes_ditulis != 1 {
            // Gagal, kembalikan
            state_data.breakpoints_map.remove(&addr);
            // Coba kembalikan byte asli
            rt_tulisMemory(handle, addr, &orig_byte, 1);
            return -1;
        }
        0 // Sukses
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_singleStep(handle: *mut rt_Handle) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };

        #[cfg(target_os = "linux")]
        { return platform_linux::impl_platform_singleStep(state_data); }

        #[cfg(windows)]
        { return platform_windows::impl_platform_singleStep(state_data); }
        
        #[cfg(not(any(target_os = "linux", windows)))]
        { return platform_unsupported::impl_platform_singleStep(); }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_traceSyscall(pid: c_int) -> c_int {
    unsafe {
        // Fungsi ini standalone, tidak menggunakan state handle

        #[cfg(target_os = "linux")]
        { return platform_linux::impl_platform_traceSyscall(pid); }

        #[cfg(windows)]
        { return platform_windows::impl_platform_traceSyscall(pid); }

        #[cfg(not(any(target_os = "linux", windows)))]
        { return platform_unsupported::impl_platform_traceSyscall(); }
    }
}

/// Implementasi Linux
#[cfg(target_os = "linux")]
mod platform_linux {
    use super::{StateDebuggerInternal, u64, u8};
    use nix::sys::ptrace;
    use nix::sys::uio::{process_vm_readv, process_vm_writev, IoVec, RemoteIoVec};
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::Pid;
    use std::io::IoSliceMut;
    use std::os::raw::{c_int, c_void};

    pub unsafe fn impl_platform_attach(state_data: &mut StateDebuggerInternal) -> bool {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::attach(pid_target) {
            eprintln!("Linux: PTRACE_ATTACH gagal: {}", e);
            return false;
        }
        match waitpid(pid_target, None) {
            Ok(status) => matches!(status, WaitStatus::Stopped(_, nix::sys::signal::Signal::SIGSTOP)),
            Err(e) => {
                eprintln!("Linux: waitpid gagal setelah attach: {}", e);
                false
            }
        }
    }

    pub unsafe fn impl_platform_detach(state_data: &mut StateDebuggerInternal) {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::detach(pid_target, None) {
             eprintln!("Linux: PTRACE_DETACH gagal: {}", e);
        }
    }

    pub unsafe fn impl_platform_bacaMemory(state_data: &StateDebuggerInternal, addr: u64, out_buffer: *mut u8, size: c_int) -> c_int {
        let pid_target = Pid::from_raw(state_data.pid_target);
        let local_slice = std::slice::from_raw_parts_mut(out_buffer, size as usize);
        let mut local_iov = [IoSliceMut::new(local_slice)];
        let remote_iov = [RemoteIoVec {
            base: addr as usize,
            len: size as usize,
        }];

        match process_vm_readv(pid_target, &mut local_iov, &remote_iov) {
            Ok(bytes_read) => bytes_read as c_int,
            Err(_) => -1,
        }
    }

    pub unsafe fn impl_platform_tulisMemory(state_data: &StateDebuggerInternal, addr: u64, data: *const u8, size: c_int) -> c_int {
        let pid_target = Pid::from_raw(state_data.pid_target);
        let local_slice = std::slice::from_raw_parts(data, size as usize);
        let local_iov = [std::io::IoSlice::new(local_slice)];
        let remote_iov = [RemoteIoVec {
            base: addr as usize,
            len: size as usize,
        }];

        match process_vm_writev(pid_target, &local_iov, &remote_iov) {
            Ok(bytes_written) => bytes_written as c_int,
            Err(_) => -1,
        }
    }

    pub unsafe fn impl_platform_singleStep(state_data: &StateDebuggerInternal) -> c_int {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::step(pid_target, None) {
            eprintln!("Linux: PTRACE_SINGLESTEP gagal: {}", e);
            return -1;
        }
        match waitpid(pid_target, None) {
            Ok(status) => {
                if matches!(status, WaitStatus::Stopped(_, _)) { 0 } else { -1 }
            }
            Err(_) => -1,
        }
    }
    
    pub unsafe fn impl_platform_traceSyscall(pid_target_proses: c_int) -> c_int {
        let pid_target = Pid::from_raw(pid_target_proses);
        if ptrace::attach(pid_target).is_err() { return -1; }
        if waitpid(pid_target, None).is_err() { return -1; }

        println!("Melacak syscall untuk PID {} (Rust). (Tekan Ctrl+C untuk berhenti)", pid_target);

        loop {
            if ptrace::syscall(pid_target, None).is_err() { break; }
            if waitpid(pid_target, None).is_err() { break; }
            
            if ptrace::syscall(pid_target, None).is_err() { break; }
            if waitpid(pid_target, None).is_err() { break; }
        }
        
        ptrace::detach(pid_target, None).ok();
        0
    }
}

/// Implementasi Windows
#[cfg(windows)]
mod platform_windows {
    use super::{StateDebuggerInternal, u64, u8};
    use std::os::raw::{c_int, c_void};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, HANDLE, LUID};
    use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE};
    use windows_sys::Win32::Security::{AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};

    #[allow(non_snake_case)]
    unsafe fn impl_EnableDebugPrivilege_windows() -> bool {
        unsafe {
            let mut handle_token: HANDLE = 0;
            if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut handle_token) == 0 {
                return false;
            }

            let mut luid_debug: LUID = std::mem::zeroed();
            let debug_name = b"SeDebugPrivilege\0";
            if LookupPrivilegeValueA(null(), debug_name.as_ptr(), &mut luid_debug) == 0 {
                CloseHandle(handle_token);
                return false;
            }

            let mut token_privs: TOKEN_PRIVILEGES = std::mem::zeroed();
            token_privs.PrivilegeCount = 1;
            token_privs.Privileges[0].Luid = luid_debug;
            token_privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            let b_ok = AdjustTokenPrivileges(handle_token, FALSE, &token_privs, 0, null_mut(), null_mut());
            CloseHandle(handle_token);
            b_ok != 0
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn impl_platform_attach(state_data: &mut StateDebuggerInternal) -> bool {
        unsafe {
            impl_EnableDebugPrivilege_windows(); // Coba aktifkan
                
            let handle_proses = OpenProcess(
                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                FALSE, // bInheritHandle
                state_data.pid_target as u32,
            );
            
            if handle_proses == 0 { // 0 adalah NULL
                eprintln!("WinAPI: OpenProcess gagal, error: {}", GetLastError());
                return false;
            }
            state_data.handle_proses = handle_proses;
            true
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn impl_platform_detach(state_data: &mut StateDebuggerInternal) {
        unsafe {
            if state_data.handle_proses != 0 {
                CloseHandle(state_data.handle_proses);
                state_data.handle_proses = 0;
            }
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn impl_platform_bacaMemory(state_data: &StateDebuggerInternal, addr: u64, out_buffer: *mut u8, size: c_int) -> c_int {
        unsafe {
            let mut bytes_dibaca: usize = 0;
            if ReadProcessMemory(
                state_data.handle_proses,
                addr as *const c_void,
                out_buffer as *mut c_void,
                size as usize,
                &mut bytes_dibaca,
            ) != 0 {
                bytes_dibaca as c_int
            } else {
                -1
            }
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn impl_platform_tulisMemory(state_data: &StateDebuggerInternal, addr: u64, data: *const u8, size: c_int) -> c_int {
        unsafe {
            let mut bytes_ditulis: usize = 0;
            if WriteProcessMemory(
                state_data.handle_proses,
                addr as *mut c_void,
                data as *const c_void,
                size as usize,
                &mut bytes_ditulis,
            ) != 0 {
                bytes_ditulis as c_int
            } else {
                -1
            }
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn impl_platform_singleStep(_state_data: &StateDebuggerInternal) -> c_int {
        eprintln!("PERINGATAN (Rust): singleStep() belum diimplementasikan di Windows");
        -1 // Belum diimplementasikan
    }

    #[allow(non_snake_case)]
    pub unsafe fn impl_platform_traceSyscall(_pid: c_int) -> c_int {
        eprintln!("PERINGATAN (Rust): traceSyscall() belum diimplementasikan di Windows");
        -1 // Belum diimplementasikan
    }
}

/// Implementasi Stub/Fallback
#[cfg(not(any(target_os = "linux", windows)))]
mod platform_unsupported {
    use std::os::raw::{c_int, c_void};
    use super::{u64, u8};

    fn print_unsupported() {
        eprintln!("PERINGATAN (Rust): Fungsi tracer tidak didukung di OS ini.");
    }
    
    pub unsafe fn impl_platform_attach() -> bool { print_unsupported(); false }
    pub unsafe fn impl_platform_detach() { print_unsupported(); }
    pub unsafe fn impl_platform_bacaMemory() -> c_int { print_unsupported(); -1 }
    pub unsafe fn impl_platform_tulisMemory() -> c_int { print_unsupported(); -1 }
    pub unsafe fn impl_platform_singleStep() -> c_int { print_unsupported(); -1 }
    pub unsafe fn impl_platform_traceSyscall() -> c_int { print_unsupported(); -1 }
}