#![allow(unsafe_op_in_unsafe_fn)]

use crate::logic::static_analysis::analyzer::{
    c_deteksiHeuristicPacker_rs, c_deteksi_pattern_rs, c_get_strings_list, c_hitung_entropy_rs,
    c_identifikasiFungsiLibrary_rs, c_scan_yara_rs,
};
use crate::logic::static_analysis::binary::Binary;
use crate::logic::static_analysis::cfg::c_generate_cfg_rs;
use crate::logic::static_analysis::diff::c_diff_binary_rs;
use crate::logic::static_analysis::disasm::{logic_decode_instruksi, ArsitekturDisasm, C_Instruksi};
use crate::logic::static_analysis::hexeditor::{c_cari_pattern, c_lihat_bytes, c_ubah_bytes};
use crate::logic::static_analysis::parser::{
    c_get_binary_header, c_get_daftar_exports, c_get_daftar_imports, c_get_daftar_sections,
    c_get_daftar_simbol, C_DiffResult, C_ElfDynamicInfo, C_ExportInfo, C_HeaderInfo, C_ImportInfo,
    C_SectionInfo, C_SymbolInfo,
};
use crate::logic::tracer::{self, Debugger};
use crate::logic::tracer::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use crate::utils::{c_free_string, strncpy_rs};
use crate::error::{set_last_error, get_last_error_message, ReToolsError};
use crate::logic::ir::lifter::angkat_blok_instruksi;

use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::ptr::null_mut;
use std::slice;


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
    let empty_json = CString::new("[]").unwrap().into_raw();
    if offset >= len_data {
        set_last_error(ReToolsError::Generic("Offset di luar batas".to_string()));
        return empty_json;
    }
    let data_slice = unsafe { slice::from_raw_parts(ptr_data, len_data) };
    let code_slice = &data_slice[offset..];
    let ir_result = angkat_blok_instruksi(code_slice, instruction_base_va, arch);
    let json_result = match ir_result {
        Ok((_size, ir_vec)) => {
            serde_json::to_string(&ir_vec).unwrap_or_else(|e| {
                set_last_error(ReToolsError::Generic(format!("JSON serialization error: {}", e)));
                "[]".to_string()
            })
        },
        Err(e) => {
            set_last_error(e);
            "[]".to_string()
        }
    };
    CString::new(json_result).unwrap_or_else(|_| {
        set_last_error(ReToolsError::Generic("Failed to create CString, possibly interior nulls".to_string()));
        CString::new("[]").unwrap()
    }).into_raw()
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
pub unsafe extern "C" fn c_getDaftarImports(
    file_path_c: *const c_char,
    out_buffer: *mut C_ImportInfo,
    max_count: c_int,
) -> c_int {
    unsafe { c_get_daftar_imports(file_path_c, out_buffer, max_count) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarExports(
    file_path_c: *const c_char,
    out_buffer: *mut C_ExportInfo,
    max_count: c_int,
) -> c_int {
    unsafe { c_get_daftar_exports(file_path_c, out_buffer, max_count) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarDynamicElf(
    file_path_c: *const c_char,
    out_buffer: *mut C_ElfDynamicInfo,
    max_count: c_int,
) -> c_int {
    if out_buffer.is_null() || max_count <= 0 {
        set_last_error(ReToolsError::Generic("Buffer output invalid atau max_count <= 0".to_string()));
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
                set_last_error(ReToolsError::Generic(format!(
                    "Jumlah dynamic entries ({}) melebihi max_count ({})",
                    entries.len(),
                    max_count
                )));
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
            set_last_error(e);
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
pub unsafe extern "C" fn c_deteksiHeuristicPacker(
    file_path_c: *const c_char,
    entropy_threshold: f64,
) -> *mut c_char {
    unsafe { c_deteksiHeuristicPacker_rs(file_path_c, entropy_threshold) }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_identifikasiFungsiLibrary(
    file_path_c: *const c_char,
    signatures_json_c: *const c_char,
) -> *mut c_char {
    unsafe { c_identifikasiFungsiLibrary_rs(file_path_c, signatures_json_c) }
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_get_last_error_message() -> *mut c_char {
    get_last_error_message()
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

#[inline(always)]
unsafe fn ambil_debugger<'a>(handle: *mut RtHandle) -> Option<&'a mut Debugger> {
    if handle.is_null() {
        set_last_error(ReToolsError::Generic("Handle tracer tidak valid (null)".to_string()));
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
        set_last_error(ReToolsError::Generic("rt_bacaMemory: buffer output tidak valid atau size <= 0".to_string()));
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
        set_last_error(ReToolsError::Generic("rt_tulisMemory: data input tidak valid atau size <= 0".to_string()));
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
pub unsafe extern "C" fn rt_setHardwareBreakpoint(handle: *mut RtHandle, addr: u64, index: c_int) -> c_int {
     let Some(debugger) = ambil_debugger(handle) else {
        return -1;
    };
    if !(0..=3).contains(&index) {
        set_last_error(ReToolsError::Generic("Indeks hardware breakpoint harus 0-3".to_string()));
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
        set_last_error(ReToolsError::Generic("Indeks hardware breakpoint harus 0-3".to_string()));
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
        set_last_error(ReToolsError::Generic("rt_getRegisters: out_registers adalah null".to_string()));
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
        set_last_error(ReToolsError::Generic("rt_setRegisters: registers adalah null".to_string()));
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
        set_last_error(ReToolsError::Generic("rt_tungguEvent: event_out adalah null".to_string()));
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