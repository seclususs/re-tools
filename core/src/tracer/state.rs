use super::types::{u64, u8};
use libc::c_int;
use std::collections::HashMap;
use std::ffi::c_void as rt_Handle;

/// State internal yang disimpan di heap untuk setiap sesi debugger.
#[repr(C)]
pub struct StateDebuggerInternal {
    pub pid_target: c_int,
    pub attached_status: bool,
    // Menyimpan byte asli di alamat breakpoint
    pub breakpoints_map: HashMap<u64, u8>,

    // Data spesifik Windows
    #[cfg(windows)]
    pub handle_proses: windows_sys::Win32::Foundation::HANDLE,
    // Menyimpan thread ID dari event terakhir, untuk Get/SetThreadContext
    #[cfg(windows)]
    pub last_event_thread_id: u32,
    // Menyimpan alamat BP yang sedang ditangani (untuk flow single-step)
    #[cfg(windows)]
    pub handling_breakpoint_alamat: Option<u64>,
}

/// Helper untuk mengkonversi *mut rt_Handle ke &mut StateDebuggerInternal
pub unsafe fn ambil_state<'a>(handle: *mut rt_Handle) -> Option<&'a mut StateDebuggerInternal> {
    if handle.is_null() {
        return None;
    }
    // Operasi memerlukan blok unsafe
    unsafe { (handle as *mut StateDebuggerInternal).as_mut() }
}