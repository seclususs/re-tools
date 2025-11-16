#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
use crate::logic::tracer::platform_linux;
#[cfg(target_os = "macos")]
use crate::logic::tracer::platform_macos;
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
use crate::logic::tracer::platform_unsupported;
#[cfg(windows)]
use crate::logic::tracer::platform_windows;

use crate::logic::static_analysis::analyzer::{
    c_deteksi_pattern_rs, c_get_strings_list, c_hitung_entropy_rs, c_scan_yara_rs,
};
use crate::logic::static_analysis::binary::Binary;
use crate::logic::static_analysis::cfg::c_generate_cfg_rs;
use crate::logic::static_analysis::diff::c_diff_binary_rs;
use crate::logic::static_analysis::disasm::{logic_decode_instruksi, ArsitekturDisasm, C_Instruksi};
use crate::logic::static_analysis::hexeditor::{c_cari_pattern, c_lihat_bytes, c_ubah_bytes};
use crate::logic::static_analysis::parser::{
    c_get_binary_header, c_get_daftar_sections, c_get_daftar_simbol, C_DiffResult, C_HeaderInfo,
    C_SectionInfo, C_SymbolInfo,
};
use crate::logic::tracer::state::{ambil_state, StateDebuggerInternal};
use crate::logic::tracer::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use crate::utils::{c_free_string, strncpy_rs};
use crate::error::ReToolsError;
use crate::logic::ir::lifter::angkat_blok_instruksi;

use libc::{c_char, c_int, c_void};
use log::{debug, error, warn};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::ptr::null_mut;
use std::slice;


#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct C_ElfDynamicInfo {
    pub tag_name: [c_char; 64],
    pub value: u64,
}

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
pub unsafe extern "C" fn c_getIrForInstruksi(
    ptr_data: *const u8,
    len_data: usize,
    offset: usize,
    instruction_base_va: u64,
    arch: ArsitekturDisasm,
) -> *mut c_char {
    if offset >= len_data {
        return CString::new("[]").unwrap().into_raw();
    }
    let data_slice = unsafe { slice::from_raw_parts(ptr_data, len_data) };
    let code_slice = &data_slice[offset..];
    let ir_result = angkat_blok_instruksi(code_slice, instruction_base_va, arch);
    let json_result = match ir_result {
        Ok((_size, ir_vec)) => {
            serde_json::to_string(&ir_vec).unwrap_or_else(|e| format!("Error: {}", e))
        },
        Err(e) => format!("Error: {}", e)
    };
    CString::new(json_result).unwrap_or_default().into_raw()
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
pub unsafe extern "C" fn c_getDaftarDynamicElf(
    file_path_c: *const c_char,
    out_buffer: *mut C_ElfDynamicInfo,
    max_count: c_int,
) -> c_int {
    if out_buffer.is_null() || max_count <= 0 {
        error!("Buffer output invalid atau max_count <= 0");
        return -1;
    }
    let path_str_result = CStr::from_ptr(file_path_c).to_str();
    let binary_result = match path_str_result {
        Ok(path_str) => Binary::load(path_str),
        Err(e) => Err(ReToolsError::from(e)),
    };
    match binary_result {
        Ok(binary) => {
            let entries = &binary.elf_dynamic_info;
            if entries.len() > max_count as usize {
                warn!(
                    "Jumlah dynamic entries ({}) melebihi max_count ({})",
                    entries.len(),
                    max_count
                );
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);
            for (i, entry) in entries.iter().enumerate() {
                let out_item = &mut out_slice[i];
                strncpy_rs(&entry.tag_name, &mut out_item.tag_name);
                out_item.value = entry.value;
            }
            entries.len() as c_int
        }
        Err(e) => {
            error!("Gagal load binary di c_getDaftarDynamicElf: {}", e);
            -1
        }
    }
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
pub unsafe extern "C" fn c_scanYara_rs(
    file_path_c: *const c_char,
    yara_rules_c: *const c_char,
) -> *mut c_char {
    unsafe { c_scan_yara_rs(file_path_c, yara_rules_c) }
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
    debug!("rt_attachProses dipanggil untuk PID: {}", pid_target_proses);
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
        let attach_sukses: bool = {
            #[cfg(target_os = "linux")]
            {
                platform_linux::impl_platform_attach(state_ptr.as_mut().unwrap())
            }
            #[cfg(target_os = "macos")]
            {
                platform_macos::impl_platform_attach(state_ptr.as_mut().unwrap())
            }
            #[cfg(windows)]
            {
                platform_windows::impl_platform_attach(state_ptr.as_mut().unwrap())
            }
            #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
            {
                platform_unsupported::impl_platform_attach(state_ptr.as_mut().unwrap())
            }
        };
        if attach_sukses {
            debug!("Attach ke PID {} berhasil", pid_target_proses);
            (*state_ptr).attached_status = true;
            state_ptr as *mut RtHandle
        } else {
            error!("Attach ke PID {} gagal", pid_target_proses);
            let _ = Box::from_raw(state_ptr);
            null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_detachProses(handle: *mut RtHandle) {
    debug!("rt_detachProses dipanggil");
    unsafe {
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_detachProses: handle tidak valid");
            return;
        };
        let bps_to_restore: Vec<(u64, u8)> = state_data
            .breakpoints_map
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();
        debug!("Merestore {} breakpoints", bps_to_restore.len());
        for (addr, orig_byte) in bps_to_restore {
            let data_byte = [orig_byte];
            #[cfg(target_os = "linux")]
            platform_linux::impl_platform_tulis_memory(state_data, addr, data_byte.as_ptr(), 1);
            #[cfg(target_os = "macos")]
            platform_macos::impl_platform_tulis_memory(state_data, addr, data_byte.as_ptr(), 1);
            #[cfg(windows)]
            platform_windows::impl_platform_tulisMemory(state_data, addr, data_byte.as_ptr(), 1);
        }
        state_data.breakpoints_map.clear();
        if state_data.attached_status {
            #[cfg(target_os = "linux")]
            platform_linux::impl_platform_detach(state_data);
            #[cfg(target_os = "macos")]
            platform_macos::impl_platform_detach(state_data);
            #[cfg(windows)]
            platform_windows::impl_platform_detach(state_data);
            #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
            platform_unsupported::impl_platform_detach(state_data);
            debug!("Detach platform-specific selesai");
        }
        let _ = Box::from_raw(handle as *mut StateDebuggerInternal);
        debug!("State debugger dibebaskan");
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
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_bacaMemory: handle tidak valid");
            return -1;
        };
        if out_buffer.is_null() || size <= 0 {
            error!("rt_bacaMemory: buffer output tidak valid atau size <= 0");
            return -1;
        }
        if !state_data.attached_status {
            error!("rt_bacaMemory: proses tidak ter-attach");
            return -1;
        }
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_baca_memory(state_data, addr, out_buffer, size);
        }
        #[cfg(target_os = "macos")]
        {
            return platform_macos::impl_platform_baca_memory(state_data, addr, out_buffer, size);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_bacaMemory(state_data, addr, out_buffer, size);
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_tulisMemory: handle tidak valid");
            return -1;
        };
        if data.is_null() || size <= 0 {
            error!("rt_tulisMemory: data input tidak valid atau size <= 0");
            return -1;
        }
        if !state_data.attached_status {
            error!("rt_tulisMemory: proses tidak ter-attach");
            return -1;
        }
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_tulis_memory(state_data, addr, data, size);
        }
        #[cfg(target_os = "macos")]
        {
            return platform_macos::impl_platform_tulis_memory(state_data, addr, data, size);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_tulisMemory(state_data, addr, data, size);
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        {
            return platform_unsupported::impl_platform_tulis_memory();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_setBreakpoint(handle: *mut RtHandle, addr: u64) -> c_int {
    debug!("rt_setBreakpoint dipanggil pada alamat: 0x{:x}", addr);
    unsafe {
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_setBreakpoint: handle tidak valid");
            return -1;
        };
        if state_data.breakpoints_map.contains_key(&addr) {
            debug!("Breakpoint sudah ada di 0x{:x}", addr);
            return 0;
        }
        let mut orig_byte: u8 = 0;
        let bytes_dibaca = rt_bacaMemory(handle, addr, &mut orig_byte, 1);
        if bytes_dibaca != 1 {
            error!("Gagal membaca byte asli di 0x{:x}", addr);
            return -1;
        }
        state_data.breakpoints_map.insert(addr, orig_byte);
        let int3_byte: u8 = 0xCC;
        let bytes_ditulis = rt_tulisMemory(handle, addr, &int3_byte, 1);
        if bytes_ditulis != 1 {
            error!("Gagal menulis INT3 di 0x{:x}", addr);
            state_data.breakpoints_map.remove(&addr);
            rt_tulisMemory(handle, addr, &orig_byte, 1);
            return -1;
        }
        debug!("Breakpoint berhasil diset di 0x{:x}", addr);
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_singleStep(handle: *mut RtHandle) -> c_int {
    debug!("rt_singleStep dipanggil");
    unsafe {
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_singleStep: handle tidak valid");
            return -1;
        };
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_single_step(state_data);
        }
        #[cfg(target_os = "macos")]
        {
            return platform_macos::impl_platform_single_step(state_data);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_singleStep(state_data);
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_getRegisters: handle tidak valid");
            return -1;
        };
        if out_registers.is_null() {
            error!("rt_getRegisters: out_registers adalah null");
            return -1;
        }
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_get_registers(state_data, out_registers);
        }
        #[cfg(target_os = "macos")]
        {
            return platform_macos::impl_platform_get_registers(state_data, out_registers);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_getRegisters(state_data, out_registers);
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_setRegisters: handle tidak valid");
            return -1;
        };
        if registers.is_null() {
            error!("rt_setRegisters: registers adalah null");
            return -1;
        }
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_set_registers(state_data, registers);
        }
        #[cfg(target_os = "macos")]
        {
            return platform_macos::impl_platform_set_registers(state_data, registers);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_setRegisters(state_data, registers);
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        {
            return platform_unsupported::impl_platform_set_registers();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_continueProses(handle: *mut RtHandle) -> c_int {
    debug!("rt_continueProses dipanggil");
    unsafe {
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_continueProses: handle tidak valid");
            return -1;
        };
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_continue_proses(state_data);
        }
        #[cfg(target_os = "macos")]
        {
            return platform_macos::impl_platform_continue_proses(state_data);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_continueProses(state_data);
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
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
    debug!("rt_tungguEvent: Menunggu event debug...");
    unsafe {
        let Some(state_data) = ambil_state(handle) else {
            error!("rt_tungguEvent: handle tidak valid");
            return -1;
        };
        if event_out.is_null() {
            error!("rt_tungguEvent: event_out adalah null");
            return -1;
        }
        (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
        (*event_out).pid_thread = 0;
        (*event_out).info_alamat = 0;
        #[cfg(target_os = "linux")]
        {
            return platform_linux::impl_platform_tunggu_event(state_data, event_out);
        }
        #[cfg(target_os = "macos")]
        {
            return platform_macos::impl_platform_tunggu_event(state_data, event_out);
        }
        #[cfg(windows)]
        {
            return platform_windows::impl_platform_tungguEvent(state_data, event_out);
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        {
            return platform_unsupported::impl_platform_tunggu_event();
        }
    }
}