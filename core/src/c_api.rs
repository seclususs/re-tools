#![allow(unsafe_op_in_unsafe_fn)]

use crate::logic::static_analysis::analyzer::{
    c_deteksi_pattern_rs, c_get_strings_list, c_hitung_entropy_rs,
};
use crate::logic::static_analysis::cfg::c_generate_cfg_rs;
use crate::logic::static_analysis::diff::{c_diff_binary_rs, C_DiffResult};
use crate::logic::static_analysis::disasm::{logic_decode_instruksi, ArsitekturDisasm, C_Instruksi};
use crate::logic::static_analysis::hexeditor::{c_cari_pattern, c_lihat_bytes, c_ubah_bytes};
use crate::logic::static_analysis::parser::{
    c_get_binary_header, c_get_daftar_sections, c_get_daftar_simbol, C_HeaderInfo, C_SectionInfo,
    C_SymbolInfo,
};

#[cfg(target_os = "linux")]
use crate::logic::tracer::platform_linux;
#[cfg(not(any(target_os = "linux", windows)))]
use crate::logic::tracer::platform_unsupported;
#[cfg(windows)]
use crate::logic::tracer::platform_windows;

use crate::logic::tracer::state::{ambil_state, StateDebuggerInternal};
use crate::logic::tracer::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use crate::utils::c_free_string;

use libc::{c_char, c_int, c_void};
use std::collections::HashMap;
use std::ptr::null_mut;


#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_decodeInstruksi(
    ptr_data: *const u8,
    len_data: usize,
    offset: usize,
    instruction_base_va: u64,
    arch: ArsitekturDisasm,
) -> C_Instruksi {
    logic_decode_instruksi(ptr_data, len_data, offset, instruction_base_va, arch)
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getBinaryHeader(
    file_path_c: *const c_char,
    out_header: *mut C_HeaderInfo,
) -> c_int {
    unsafe { c_get_binary_header(file_path_c, out_header) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSections(
    file_path_c: *const c_char,
    out_buffer: *mut C_SectionInfo,
    max_count: c_int,
) -> c_int {
    unsafe { c_get_daftar_sections(file_path_c, out_buffer, max_count) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSimbol(
    file_path_c: *const c_char,
    out_buffer: *mut C_SymbolInfo,
    max_count: c_int,
) -> c_int {
    unsafe { c_get_daftar_simbol(file_path_c, out_buffer, max_count) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getStringsList_rs(
    file_path_c: *const c_char,
    min_length: c_int,
) -> *mut c_char {
    unsafe { c_get_strings_list(file_path_c, min_length) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_hitungEntropy_rs(
    file_path_c: *const c_char,
    block_size: c_int,
    out_entropies: *mut f64,
    max_entropies: c_int,
) -> c_int {
    unsafe { c_hitung_entropy_rs(file_path_c, block_size, out_entropies, max_entropies) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_deteksiPattern_rs(
    file_path_c: *const c_char,
    regex_str_c: *const c_char,
    out_buffer: *mut c_char,
    out_buffer_size: c_int,
) -> c_int {
    unsafe { c_deteksi_pattern_rs(file_path_c, regex_str_c, out_buffer, out_buffer_size) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_diffBinary_rs(
    file1_c: *const c_char,
    file2_c: *const c_char,
    out_results: *mut C_DiffResult,
    max_results: c_int,
) -> c_int {
    unsafe { c_diff_binary_rs(file1_c, file2_c, out_results, max_results) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_generateCFG_rs(filename_c: *const c_char) -> *mut c_char {
    unsafe { c_generate_cfg_rs(filename_c) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_freeString(ptr: *mut c_char) {
    unsafe {
        c_free_string(ptr);
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_lihatBytes(
    filename: *const c_char,
    offset: c_int,
    length: c_int,
    out_buffer: *mut c_char,
    out_buffer_size: c_int,
) -> c_int {
    unsafe { c_lihat_bytes(filename, offset, length, out_buffer, out_buffer_size) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_ubahBytes(
    filename: *const c_char,
    offset: c_int,
    data: *const u8,
    data_len: c_int,
) -> c_int {
    unsafe { c_ubah_bytes(filename, offset, data, data_len) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_cariPattern(
    filename: *const c_char,
    pattern: *const u8,
    pattern_len: c_int,
    out_offsets: *mut c_int,
    max_offsets: c_int,
) -> c_int {
    unsafe { c_cari_pattern(filename, pattern, pattern_len, out_offsets, max_offsets) }
}

type RtHandle = c_void;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_attachProses(pid_target_proses: c_int) -> *mut RtHandle {
    unsafe {
        let state_debugger_box = Box::new(StateDebuggerInternal {
            pid_target: pid_target_proses,
            attached_status: false,
            breakpoints_map: HashMap::new(),
            #[cfg(windows)]
            last_event_thread_id: 0,
            #[cfg(windows)]
            handle_proses: 0,
            #[cfg(windows)]
            handling_breakpoint_alamat: None,
        });
        let state_ptr = Box::into_raw(state_debugger_box);
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
            attach_sukses = platform_unsupported::impl_platform_attach(state_ptr.as_mut().unwrap());
        }
        if attach_sukses {
            (*state_ptr).attached_status = true;
            state_ptr as *mut RtHandle
        } else {
            let _ = Box::from_raw(state_ptr);
            null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_detachProses(handle: *mut RtHandle) {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return };
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
            #[cfg(not(any(target_os = "linux", windows)))]
            platform_unsupported::impl_platform_detach(state_data);
        }
        let _ = Box::from_raw(handle as *mut StateDebuggerInternal);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_bacaMemory(
    handle: *mut RtHandle,
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
    handle: *mut RtHandle,
    addr: u64,
    data: *const u8,
    size: c_int,
) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if data.is_null() || size <= 0 {
            return -1;
        }
        if !state_data.attached_status {
            return -1;
        }
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_tulis_memory(state_data, addr, data, size);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_tulisMemory(state_data, addr, data, size);
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            return platform_unsupported::impl_platform_tulis_memory();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setBreakpoint(handle: *mut RtHandle, addr: u64) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if state_data.breakpoints_map.contains_key(&addr) {
            return 0;
        }
        let mut orig_byte: u8 = 0;
        let bytes_dibaca = rt_bacaMemory(handle, addr, &mut orig_byte, 1);
        if bytes_dibaca != 1 {
            return -1;
        }
        state_data.breakpoints_map.insert(addr, orig_byte);
        let int3_byte: u8 = 0xCC;
        let bytes_ditulis = rt_tulisMemory(handle, addr, &int3_byte, 1);
        if bytes_ditulis != 1 {
            state_data.breakpoints_map.remove(&addr);
            rt_tulisMemory(handle, addr, &orig_byte, 1);
            return -1;
        }
        0 
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_singleStep(handle: *mut RtHandle) -> c_int {
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
    handle: *mut RtHandle,
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
    handle: *mut RtHandle,
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
pub unsafe extern "C" fn rt_continueProses(handle: *mut RtHandle) -> c_int {
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
    handle: *mut RtHandle,
    event_out: *mut C_DebugEvent,
) -> c_int {
    unsafe {
        let Some(state_data) = ambil_state(handle) else { return -1 };
        if event_out.is_null() {
            return -1;
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logic::static_analysis::disasm::ArsitekturDisasm;
    use std::ffi::CStr;
    #[test]
    fn test_disasm_rust_side_x86_64() {
        let code: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        let ptr = code.as_ptr();
        let len = code.len();
        let arch = ArsitekturDisasm::ARCH_X86_64;
        let base_va: u64 = 0x1000;
        let insn1 = unsafe { c_decodeInstruksi(ptr, len, 0, base_va, arch) };
        assert_eq!(insn1.valid, 1);
        assert_eq!(insn1.ukuran, 1);
        assert_eq!(
            unsafe { CStr::from_ptr(insn1.mnemonic_instruksi.as_ptr()).to_str().unwrap() },
            "push"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(insn1.str_operand.as_ptr()).to_str().unwrap() },
            "rbp"
        );
        let insn2 = unsafe { c_decodeInstruksi(ptr, len, 1, base_va + 1, arch) };
        assert_eq!(insn2.valid, 1);
        assert_eq!(insn2.ukuran, 3);
        assert_eq!(
            unsafe { CStr::from_ptr(insn2.mnemonic_instruksi.as_ptr()).to_str().unwrap() },
            "mov"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(insn2.str_operand.as_ptr()).to_str().unwrap() },
            "rbp, rsp"
        );
    }
}