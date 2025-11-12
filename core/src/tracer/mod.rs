#[cfg(target_os = "linux")]
mod platform_linux;

#[cfg(not(any(target_os = "linux", windows)))]
mod platform_unsupported;

#[cfg(windows)]
mod platform_windows;

mod state;
mod types;

use state::{ambil_state, StateDebuggerInternal};
use types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use libc::c_int;
use std::collections::HashMap;
use std::ffi::c_void as rt_Handle;
use std::ptr::null_mut;

// Implementasi C-ABI Publik
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_attachProses(pid_target_proses: c_int) -> *mut rt_Handle {
    unsafe {
        // Buat state di heap
        let state_debugger_box = Box::new(StateDebuggerInternal {
            pid_target: pid_target_proses,
            attached_status: false,
            breakpoints_map: HashMap::new(),

            #[cfg(windows)]
            last_event_thread_id: 0,
            #[cfg(windows)]
            handle_proses: 0, // INVALID_HANDLE_VALUE
            #[cfg(windows)]
            handling_breakpoint_alamat: None,
        });

        // Ubah ke pointer mentah
        let state_ptr = Box::into_raw(state_debugger_box);

        // Panggil platform attach
        let attach_sukses: bool;

        #[cfg(target_os = "linux")]
        {
            attach_sukses = platform_linux::impl_platform_attach(state_ptr.as_mut().unwrap());
        }
        #[cfg(windows)]
        {
            attach_sukses = platform_windows::impl_platform_attach(state_ptr.as_mut().unwrap());
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            attach_sukses = platform_unsupported::impl_platform_attach(state_ptr as *mut _);
        }

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
        let bps_to_restore: Vec<(u64, u8)> =
            state_data.breakpoints_map.iter().map(|(&k, &v)| (k, v)).collect();
        for (addr, orig_byte) in bps_to_restore {
            let data_byte = [orig_byte];
            #[cfg(target_os = "linux")]
            platform_linux::impl_platform_tulis_memory(state_data, addr, data_byte.as_ptr(), 1);
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
pub unsafe extern "C" fn rt_bacaMemory(
    handle: *mut rt_Handle,
    addr: u64,
    out_buffer: *mut u8,
    size: c_int,
) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if out_buffer.is_null() || size <= 0 {
            return -1;
        }
        if !state_data.attached_status {
            return -1;
        }

        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_baca_memory(state_data, addr, out_buffer, size);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_bacaMemory(state_data, addr, out_buffer, size);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return platform_unsupported::impl_platform_baca_memory();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_tulisMemory(
    handle: *mut rt_Handle,
    addr: u64,
    data: *const u8, // <-- Beda: *const u8
    size: c_int,
) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if data.is_null() || size <= 0 {
            // <-- Beda: data.is_null()
            return -1;
        }
        if !state_data.attached_status {
            return -1;
        }

        #[cfg(target_os = "linux")]
        {
            // Panggil 'tulis'
            return platform_linux::impl_platform_tulis_memory(state_data, addr, data, size);
        }
        #[cfg(windows)]
        {
            // Panggil 'tulis'
            return platform_windows::impl_platform_tulisMemory(state_data, addr, data, size);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            // Panggil 'tulis'
            return platform_unsupported::impl_platform_tulis_memory();
        }
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
        {
            return platform_linux::impl_platform_single_step(state_data);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_singleStep(state_data);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return platform_unsupported::impl_platform_single_step();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_getRegisters(
    handle: *mut rt_Handle,
    out_registers: *mut C_Registers,
) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if out_registers.is_null() {
            return -1;
        }

        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_get_registers(state_data, out_registers);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_getRegisters(state_data, out_registers);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return platform_unsupported::impl_platform_get_registers();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setRegisters(
    handle: *mut rt_Handle,
    registers: *const C_Registers,
) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if registers.is_null() {
            return -1;
        }

        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_set_registers(state_data, registers);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_setRegisters(state_data, registers);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return platform_unsupported::impl_platform_set_registers();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_continueProses(handle: *mut rt_Handle) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };

        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_continue_proses(state_data);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_continueProses(state_data);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return platform_unsupported::impl_platform_continue_proses();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_tungguEvent(
    handle: *mut rt_Handle,
    event_out: *mut C_DebugEvent,
) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if event_out.is_null() {
            return -1;
        }

        // Default event
        (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
        (*event_out).pid_thread = 0;
        (*event_out).info_alamat = 0;

        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_tunggu_event(state_data, event_out);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_tungguEvent(state_data, event_out);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return platform_unsupported::impl_platform_tunggu_event();
        }
    }
}