use super::types::{u64, u8};
use libc::c_int;
use std::collections::HashMap;
use std::ffi::c_void as RtHandle;

#[repr(C)]
pub struct StateDebuggerInternal {
    pub pid_target: c_int,
    pub attached_status: bool,
    pub breakpoints_map: HashMap<u64, u8>,
    #[cfg(windows)]
    pub handle_proses: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    pub last_event_thread_id: u32,
    #[cfg(windows)]
    pub handling_breakpoint_alamat: Option<u64>,
}

pub unsafe fn ambil_state<'a>(handle: *mut RtHandle) -> Option<&'a mut StateDebuggerInternal> {
    if handle.is_null() {
        return None;
    }
    unsafe { (handle as *mut StateDebuggerInternal).as_mut() }
}