//! Author: [Seclususs](https://github.com/seclususs)

#![allow(unsafe_op_in_unsafe_fn)]

use crate::error::{set_last_error, ReToolsError};
use crate::logic::tracer::{self, Debugger};
use crate::logic::tracer::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};

use libc::{c_char, c_int, c_void};
use serde_json;
use std::ffi::CString;
use std::ptr::null_mut;
use std::slice;

type RtHandle = c_void;

#[inline(always)]
unsafe fn ambil_debugger<'a>(handle: *mut RtHandle) -> Option<&'a mut Debugger> {
    if handle.is_null() {
        set_last_error(ReToolsError::Generic(
            "Handle tracer tidak valid (null)".to_string(),
        ));
        return None;
    }
    (handle as *mut Debugger).as_mut()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_attachProses(pid_target_proses: c_int) -> *mut RtHandle {
    match tracer::new_debugger(pid_target_proses) {
        Ok(debugger) => {
            let handle = Box::into_raw(Box::new(debugger));
            handle as *mut RtHandle
        }
        Err(e) => {
            set_last_error(e);
            null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_detachProses(handle: *mut RtHandle) {
    let Some(debugger) = (handle as *mut Debugger).as_mut() else {
        return;
    };
    if let Err(e) = debugger.detach() {
        set_last_error(e);
    }
    let _ = Box::from_raw(handle as *mut Debugger);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_bacaMemory(
    handle: *mut RtHandle,
    addr: u64,
    out_buffer: *mut u8,
    size: c_int,
) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if out_buffer.is_null() || size <= 0 {
        set_last_error(ReToolsError::Generic(
            "rt_bacaMemory: buffer output tidak valid atau size <= 0".to_string(),
        ));
        return -1;
    }
    match debugger.baca_memory(addr, size) {
        Ok(bytes) => {
            let bytes_to_copy = bytes.len().min(size as usize);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buffer, bytes_to_copy);
            bytes_to_copy as c_int
        }
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_tulisMemory(
    handle: *mut RtHandle,
    addr: u64,
    data: *const u8,
    size: c_int,
) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if data.is_null() || size <= 0 {
        set_last_error(ReToolsError::Generic(
            "rt_tulisMemory: data input tidak valid atau size <= 0".to_string(),
        ));
        return -1;
    }
    let data_slice = slice::from_raw_parts(data, size as usize);
    match debugger.tulis_memory(addr, data_slice) {
        Ok(bytes_written) => bytes_written as c_int,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setSoftwareBreakpoint(handle: *mut RtHandle, addr: u64) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    match debugger.set_software_breakpoint(addr) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_removeSoftwareBreakpoint(handle: *mut RtHandle, addr: u64) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    match debugger.remove_software_breakpoint(addr) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setHardwareBreakpoint(
    handle: *mut RtHandle,
    addr: u64,
    index: c_int,
) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if !(0..=3).contains(&index) {
        set_last_error(ReToolsError::Generic(
            "Indeks hardware breakpoint harus 0-3".to_string(),
        ));
        return -1;
    }
    match debugger.set_hardware_breakpoint(addr, index as usize) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_removeHardwareBreakpoint(handle: *mut RtHandle, index: c_int) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if !(0..=3).contains(&index) {
        set_last_error(ReToolsError::Generic(
            "Indeks hardware breakpoint harus 0-3".to_string(),
        ));
        return -1;
    }
    match debugger.remove_hardware_breakpoint(index as usize) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_singleStep(handle: *mut RtHandle) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    match debugger.single_step() {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_getRegisters(
    handle: *mut RtHandle,
    out_registers: *mut C_Registers,
) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if out_registers.is_null() {
        set_last_error(ReToolsError::Generic(
            "rt_getRegisters: out_registers adalah null".to_string(),
        ));
        return -1;
    }
    match debugger.get_registers() {
        Ok(regs) => {
            *out_registers = regs;
            0
        }
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setRegisters(
    handle: *mut RtHandle,
    registers: *const C_Registers,
) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if registers.is_null() {
        set_last_error(ReToolsError::Generic(
            "rt_setRegisters: registers adalah null".to_string(),
        ));
        return -1;
    }
    match debugger.set_registers(&*registers) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_continueProses(handle: *mut RtHandle) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    match debugger.continue_proses() {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_tungguEvent(
    handle: *mut RtHandle,
    event_out: *mut C_DebugEvent,
) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if event_out.is_null() {
        set_last_error(ReToolsError::Generic(
            "rt_tungguEvent: event_out adalah null".to_string(),
        ));
        return -1;
    }
    (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
    (*event_out).pid_thread = 0;
    (*event_out).info_alamat = 0;
    match debugger.tunggu_event(event_out) {
        Ok(code) => code,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_listSemuaThreads_json(handle: *mut RtHandle) -> *mut c_char {
    let error_json = CString::new("[]").unwrap().into_raw();
    let Some(debugger) = ambil_debugger(handle) else {
        return error_json;
    };
    match debugger.list_semua_threads() {
        Ok(threads) => match serde_json::to_string(&threads) {
            Ok(json_str) => CString::new(json_str).unwrap_or_default().into_raw(),
            Err(e) => {
                set_last_error(ReToolsError::Generic(e.to_string()));
                error_json
            }
        },
        Err(e) => {
            set_last_error(e);
            error_json
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_getMemoryRegions_json(handle: *mut RtHandle) -> *mut c_char {
    let error_json = CString::new("[]").unwrap().into_raw();
    let Some(debugger) = ambil_debugger(handle) else {
        return error_json;
    };
    match debugger.get_memory_regions() {
        Ok(regions) => match serde_json::to_string(&regions) {
            Ok(json_str) => CString::new(json_str).unwrap_or_default().into_raw(),
            Err(e) => {
                set_last_error(ReToolsError::Generic(e.to_string()));
                error_json
            }
        },
        Err(e) => {
            set_last_error(e);
            error_json
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setPelacakanSyscall(handle: *mut RtHandle, enable: bool) -> c_int {
    let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    match debugger.set_pelacakan_syscall(enable) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_getInfoSyscall_json(
    handle: *mut RtHandle,
    pid_thread: c_int,
) -> *mut c_char {
    let error_json = CString::new("{}").unwrap().into_raw();
    let Some(debugger) = ambil_debugger(handle) else {
        return error_json;
    };
    match debugger.get_info_syscall(pid_thread) {
        Ok(info) => match serde_json::to_string(&info) {
            Ok(json_str) => CString::new(json_str).unwrap_or_default().into_raw(),
            Err(e) => {
                set_last_error(ReToolsError::Generic(e.to_string()));
                error_json
            }
        },
        Err(e) => {
            set_last_error(e);
            error_json
        }
    }
}