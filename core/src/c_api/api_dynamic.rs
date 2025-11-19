//! Author: [Seclususs](https://github.com/seclususs)

#![allow(unsafe_op_in_unsafe_fn)]

use crate::error::{set_err_last, ReToolsError};
use crate::logic::tracer::{self, Debugger};
use crate::logic::tracer::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use crate::logic::hybrid::SmartAnalyzer;

use libc::{c_char, c_int, c_void};
use serde_json;
use std::ffi::{CStr, CString};
use std::ptr::null_mut;
use std::slice;

type RtHandle = c_void;

#[inline(always)]
unsafe fn ambil_debugger<'a>(ptr_handle: *mut RtHandle) -> Option<&'a mut Debugger> {
    if ptr_handle.is_null() {
        set_err_last(ReToolsError::Generic(
            "Handle tracer tidak valid (null)".to_string(),
        ));
        return None;
    }
    unsafe { (ptr_handle as *mut Debugger).as_mut() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_attachProses(id_pid_target: c_int) -> *mut RtHandle {
    let result = std::panic::catch_unwind(|| {
        match tracer::new_debugger(id_pid_target) {
            Ok(obj_debugger) => {
                let ptr_handle_sesi = Box::into_raw(Box::new(obj_debugger));
                ptr_handle_sesi as *mut RtHandle
            }
            Err(e) => {
                set_err_last(e);
                null_mut()
            }
        }
    });
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_attachProses".to_string()));
            null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_detachProses(ptr_handle: *mut RtHandle) {
    if ptr_handle.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        unsafe {
            let Some(obj_debugger) = (ptr_handle as *mut Debugger).as_mut() else {
                return;
            };
            if let Err(e) = obj_debugger.detach_sasaran() {
                set_err_last(e);
            }
            let _ = Box::from_raw(ptr_handle as *mut Debugger);
        }
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_readMemori(
    ptr_handle: *mut RtHandle,
    va_target: u64,
    ptr_buf_hasil: *mut u8,
    sz_baca: c_int,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        if ptr_buf_hasil.is_null() || sz_baca <= 0 {
            set_err_last(ReToolsError::Generic(
                "rt_bacaMemory: buffer output tidak valid atau size <= 0".to_string(),
            ));
            return -1;
        }
        match obj_debugger.read_memori(va_target, sz_baca) {
            Ok(vec_bytes) => {
                let sz_salin = vec_bytes.len().min(sz_baca as usize);
                unsafe {
                    std::ptr::copy_nonoverlapping(vec_bytes.as_ptr(), ptr_buf_hasil, sz_salin);
                }
                sz_salin as c_int
            }
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_readMemori".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_writeMemori(
    ptr_handle: *mut RtHandle,
    va_target: u64,
    ptr_sumber_data: *const u8,
    sz_tulis: c_int,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        if ptr_sumber_data.is_null() || sz_tulis <= 0 {
            set_err_last(ReToolsError::Generic(
                "rt_tulisMemory: data input tidak valid atau size <= 0".to_string(),
            ));
            return -1;
        }
        let slice_data = unsafe { slice::from_raw_parts(ptr_sumber_data, sz_tulis as usize) };
        match obj_debugger.write_memori(va_target, slice_data) {
            Ok(sz_tertulis) => sz_tertulis as c_int,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_writeMemori".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_insertTitikHentiSw(ptr_handle: *mut RtHandle, va_target: u64) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        match obj_debugger.set_titik_henti_sw(va_target) {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_insertTitikHentiSw".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_removeTitikHentiSw(ptr_handle: *mut RtHandle, va_target: u64) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        match obj_debugger.remove_titik_henti_sw(va_target) {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_removeTitikHentiSw".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_insertTitikHentiHw(
    ptr_handle: *mut RtHandle,
    va_target: u64,
    id_urutan: c_int,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        if !(0..=3).contains(&id_urutan) {
            set_err_last(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
            return -1;
        }
        match obj_debugger.set_titik_henti_hw(va_target, id_urutan as usize) {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_insertTitikHentiHw".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_removeTitikHentiHw(ptr_handle: *mut RtHandle, id_urutan: c_int) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        if !(0..=3).contains(&id_urutan) {
            set_err_last(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
            return -1;
        }
        match obj_debugger.remove_titik_henti_hw(id_urutan as usize) {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_removeTitikHentiHw".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_stepInstruksi(ptr_handle: *mut RtHandle) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        match obj_debugger.step_instruksi() {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_stepInstruksi".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_readRegister(
    ptr_handle: *mut RtHandle,
    ptr_reg_luaran: *mut C_Registers,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        if ptr_reg_luaran.is_null() {
            set_err_last(ReToolsError::Generic(
                "rt_getRegisters: out_registers adalah null".to_string(),
            ));
            return -1;
        }
        match obj_debugger.get_register() {
            Ok(val_reg) => {
                unsafe { *ptr_reg_luaran = val_reg; }
                0
            }
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_readRegister".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_writeRegister(
    ptr_handle: *mut RtHandle,
    ptr_reg_in: *const C_Registers,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        if ptr_reg_in.is_null() {
            set_err_last(ReToolsError::Generic(
                "rt_setRegisters: registers adalah null".to_string(),
            ));
            return -1;
        }
        match obj_debugger.set_register(unsafe { &*ptr_reg_in }) {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_writeRegister".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_continueProses(ptr_handle: *mut RtHandle) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        match obj_debugger.continue_proses() {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_continueProses".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_waitEvent(
    ptr_handle: *mut RtHandle,
    ptr_event_out: *mut C_DebugEvent,
) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        if ptr_event_out.is_null() {
            set_err_last(ReToolsError::Generic(
                "rt_tungguEvent: event_out adalah null".to_string(),
            ));
            return -1;
        }
        unsafe {
            (*ptr_event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
            (*ptr_event_out).pid_thread = 0;
            (*ptr_event_out).info_alamat = 0;
        }
        match obj_debugger.wait_event(ptr_event_out) {
            Ok(val_kode) => val_kode,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_waitEvent".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_listThread_json(ptr_handle: *mut RtHandle) -> *mut c_char {
    let ptr_str_error = CString::new("[]").unwrap().into_raw();
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return ptr_str_error;
        };
        match obj_debugger.list_thread() {
            Ok(vec_thread) => match serde_json::to_string(&vec_thread) {
                Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
                Err(e) => {
                    set_err_last(ReToolsError::Generic(e.to_string()));
                    ptr_str_error
                }
            },
            Err(e) => {
                set_err_last(e);
                ptr_str_error
            }
        }
    });
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_listThread_json".to_string()));
            ptr_str_error
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_readRegionMemori_json(ptr_handle: *mut RtHandle) -> *mut c_char {
    let ptr_str_error = CString::new("[]").unwrap().into_raw();
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return ptr_str_error;
        };
        match obj_debugger.get_region_memori() {
            Ok(vec_region) => match serde_json::to_string(&vec_region) {
                Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
                Err(e) => {
                    set_err_last(ReToolsError::Generic(e.to_string()));
                    ptr_str_error
                }
            },
            Err(e) => {
                set_err_last(e);
                ptr_str_error
            }
        }
    });
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_readRegionMemori_json".to_string()));
            ptr_str_error
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setTraceSyscall(ptr_handle: *mut RtHandle, is_aktif: bool) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return -1;
        };
        match obj_debugger.set_trace_syscall(is_aktif) {
            Ok(_) => 0,
            Err(e) => {
                set_err_last(e);
                -1
            }
        }
    });
    match result {
        Ok(val) => val,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_setTraceSyscall".to_string()));
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_readInfoSyscall_json(
    ptr_handle: *mut RtHandle,
    id_thread: c_int,
) -> *mut c_char {
    let ptr_str_error = CString::new("{}").unwrap().into_raw();
    let result = std::panic::catch_unwind(|| {
        let Some(obj_debugger) = (unsafe { ambil_debugger(ptr_handle) }) else {
            return ptr_str_error;
        };
        match obj_debugger.get_info_syscall(id_thread) {
            Ok(obj_info) => match serde_json::to_string(&obj_info) {
                Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
                Err(e) => {
                    set_err_last(ReToolsError::Generic(e.to_string()));
                    ptr_str_error
                }
            },
            Err(e) => {
                set_err_last(e);
                ptr_str_error
            }
        }
    });
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_readInfoSyscall_json".to_string()));
            ptr_str_error
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_resolveDynamic(
    ptr_jalur_biner: *const c_char,
    pid_target: c_int,
    max_langkah: c_int,
) -> *mut c_char {
    let ptr_json_error = CString::new("{}").unwrap().into_raw();
    if ptr_jalur_biner.is_null() {
        set_err_last(ReToolsError::Generic("Path binary null".to_string()));
        return ptr_json_error;
    }
    let result = std::panic::catch_unwind(|| {
        let str_jalur = match unsafe { CStr::from_ptr(ptr_jalur_biner) }.to_str() {
            Ok(s) => s,
            Err(e) => {
                set_err_last(ReToolsError::Generic(e.to_string()));
                return ptr_json_error;
            }
        };
        match SmartAnalyzer::new(str_jalur) {
            Ok(mut analyzer) => {
                match analyzer.run_smart_analysis(pid_target, max_langkah as usize) {
                    Ok(hasil) => {
                        let mut peta_hasil = std::collections::HashMap::new();
                        peta_hasil.insert("dynamic_coverage", hasil.dynamic_coverage);
                        peta_hasil.insert("iteration_count", hasil.iteration_count);
                        match serde_json::to_string(&peta_hasil) {
                            Ok(s) => CString::new(s).unwrap_or_default().into_raw(),
                            Err(e) => {
                                set_err_last(ReToolsError::Generic(e.to_string()));
                                ptr_json_error
                            }
                        }
                    },
                    Err(e) => {
                        set_err_last(e);
                        ptr_json_error
                    }
                }
            },
            Err(e) => {
                set_err_last(e);
                ptr_json_error
            }
        }
    });
    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_err_last(ReToolsError::Generic("Panic di rt_resolveDynamic".to_string()));
            ptr_json_error
        }
    }
}