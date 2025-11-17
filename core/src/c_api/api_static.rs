#![allow(unsafe_op_in_unsafe_fn)]

use crate::error::{set_last_error, ReToolsError};
use crate::logic::static_analysis::analyzer::{
    deteksiHeuristicPacker_internal, deteksi_pattern_internal, ekstrak_strings_internal,
    getKodeAksesData_internal, getPeneleponFungsi_internal, hitung_entropy_internal,
    identifikasiFungsiLibrary_internal, scan_yara_internal, scan_crypto_constants_internal,
};
use crate::logic::static_analysis::cfg::buat_cfg;
use crate::logic::static_analysis::diff::diff_binary_internal;
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::static_analysis::hexeditor::{
    cari_pattern_internal, lihat_bytes_internal, ubah_bytes_internal,
};
use crate::logic::static_analysis::parser::Binary;
use crate::utils::strncpy_rs_from_bytes;

use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::slice;

unsafe fn c_load_binary_and_serialize<F, T>(
    file_path_c: *const c_char,
    f: F,
) -> *mut c_char
where
    F: FnOnce(&Binary) -> Result<T, ReToolsError>,
    T: serde::Serialize,
{
    let error_json = CString::new("[]").unwrap().into_raw();
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return error_json;
        }
    };
    let binary = match Binary::load(path_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(e);
            return error_json;
        }
    };
    match f(&binary) {
        Ok(data) => match serde_json::to_string(&data) {
            Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
            Err(e) => {
                set_last_error(ReToolsError::Generic(format!("Serialisasi JSON gagal: {}", e)));
                error_json
            }
        },
        Err(e) => {
            set_last_error(e);
            error_json
        }
    }
}

unsafe fn c_load_raw_binary_and_serialize<F, T>(
    file_path_c: *const c_char,
    arch_int: c_int,
    base_addr: u64,
    f: F,
) -> *mut c_char
where
    F: FnOnce(&Binary) -> Result<T, ReToolsError>,
    T: serde::Serialize,
{
    let error_json = CString::new("[]").unwrap().into_raw();
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return error_json;
        }
    };
    let arch = match arch_int {
        1 => ArsitekturDisasm::ARCH_X86_32,
        2 => ArsitekturDisasm::ARCH_X86_64,
        3 => ArsitekturDisasm::ARCH_ARM_32,
        4 => ArsitekturDisasm::ARCH_ARM_64,
        _ => ArsitekturDisasm::ARCH_UNKNOWN,
    };
    let binary = match Binary::load_raw(path_str, arch, base_addr) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(e);
            return error_json;
        }
    };
    match f(&binary) {
        Ok(data) => match serde_json::to_string(&data) {
            Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
            Err(e) => {
                set_last_error(ReToolsError::Generic(format!("Serialisasi JSON gagal: {}", e)));
                error_json
            }
        },
        Err(e) => {
            set_last_error(e);
            error_json
        }
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getRawBinaryHeader_json(
    file_path_c: *const c_char,
    arch_int: c_int,
    base_addr: u64,
) -> *mut c_char {
    c_load_raw_binary_and_serialize(file_path_c, arch_int, base_addr, |binary| Ok(binary.header))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getBinaryHeader_json(file_path_c: *const c_char) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| Ok(binary.header))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSections_json(file_path_c: *const c_char) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| Ok(binary.sections.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSimbol_json(file_path_c: *const c_char) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| Ok(binary.symbols.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarImports_json(file_path_c: *const c_char) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| Ok(binary.imports.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarExports_json(file_path_c: *const c_char) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| Ok(binary.exports.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarDynamicElf_json(file_path_c: *const c_char) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| Ok(binary.elf_dynamic_info.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getStringsList_rs(
    file_path_c: *const c_char,
    min_length: c_int,
) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| {
        ekstrak_strings_internal(binary, min_length as usize)
    })
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_hitungEntropy_json(
    file_path_c: *const c_char,
    block_size: c_int,
) -> *mut c_char {
    if block_size <= 0 {
        set_last_error(ReToolsError::Generic("Block size harus > 0".to_string()));
        return CString::new("[]").unwrap().into_raw();
    }
    c_load_binary_and_serialize(file_path_c, |binary| {
        hitung_entropy_internal(binary, block_size as usize)
    })
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_deteksiPattern_rs(
    file_path_c: *const c_char,
    regex_str_c: *const c_char,
    out_buffer: *mut c_char,
    out_buffer_size: c_int,
) -> c_int {
    if file_path_c.is_null()
        || regex_str_c.is_null()
        || out_buffer.is_null()
        || out_buffer_size <= 0
    {
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_deteksi_pattern_rs".to_string()));
        return -1;
    }
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    let regex_str = match CStr::from_ptr(regex_str_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    let binary = match Binary::load(path_str) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(e);
            return -1;
        }
    };
    let results = deteksi_pattern_internal(&binary, regex_str);
    let json_result_string = match results {
        Ok(matches) => {
            serde_json::to_string(&matches).unwrap_or_else(|e| format!("[\"Error serialisasi: {}\"]", e))
        }
        Err(e) => {
            set_last_error(e);
            "[]".to_string()
        }
    };
    let json_bytes = json_result_string.as_bytes();
    if json_bytes.len() >= out_buffer_size as usize {
        set_last_error(ReToolsError::Generic("Ukuran buffer output JSON tidak cukup".to_string()));
        return -1;
    }
    let out_slice = std::slice::from_raw_parts_mut(out_buffer, out_buffer_size as usize);
    strncpy_rs_from_bytes(json_bytes, out_slice);
    0
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanYara_rs(
    file_path_c: *const c_char,
    yara_rules_c: *const c_char,
) -> *mut c_char {
    let error_json = CString::new("[]").unwrap().into_raw();
    let yara_rules_str = match CStr::from_ptr(yara_rules_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return error_json;
        }
    };
    c_load_binary_and_serialize(file_path_c, |binary| {
        scan_yara_internal(binary, yara_rules_str)
    })
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanCryptoConstants_json(
    file_path_c: *const c_char,
) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| {
        scan_crypto_constants_internal(binary)
    })
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_deteksiHeuristicPacker(
    file_path_c: *const c_char,
    entropy_threshold: f64,
) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| {
        deteksiHeuristicPacker_internal(binary, entropy_threshold)
    })
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_identifikasiFungsiLibrary(
    file_path_c: *const c_char,
    signatures_json_c: *const c_char,
) -> *mut c_char {
    let error_json = CString::new("[]").unwrap().into_raw();
    let signatures_json = match CStr::from_ptr(signatures_json_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return error_json;
        }
    };
    c_load_binary_and_serialize(file_path_c, |binary| {
        identifikasiFungsiLibrary_internal(binary, signatures_json)
    })
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_diffBinary_json(
    file1_c: *const c_char,
    file2_c: *const c_char,
) -> *mut c_char {
    let error_json = CString::new("[]").unwrap().into_raw();
    let path_str1 = match CStr::from_ptr(file1_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return error_json;
        }
    };
    let path_str2 = match CStr::from_ptr(file2_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return error_json;
        }
    };
    match diff_binary_internal(path_str1, path_str2) {
        Ok(results) => match serde_json::to_string(&results) {
            Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
            Err(e) => {
                set_last_error(ReToolsError::Generic(format!("Serialisasi JSON gagal: {}", e)));
                error_json
            }
        },
        Err(e_str) => {
            set_last_error(ReToolsError::Generic(e_str));
            error_json
        }
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_buatCFG(filename_c: *const c_char) -> *mut c_char {
    let error_dot = "digraph G {{ error [label=\"Koneksi error\"]; }}";
    let path_str = match CStr::from_ptr(filename_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return CString::new(error_dot.replace("Koneksi error", "Invalid Path UTF-8"))
                .unwrap()
                .into_raw();
        }
    };
    let binary_result = Binary::load(path_str);
    let dot_result = match binary_result {
        Ok(binary) => match buat_cfg(&binary) {
            Ok(dot) => dot,
            Err(e) => {
                let err_msg = e.to_string();
                set_last_error(e);
                format!("digraph G {{ error [label=\"{}\"]; }}", err_msg)
            }
        },
        Err(e) => {
            let err_msg = e.to_string();
            set_last_error(e);
            format!("digraph G {{ error [label=\"{}\"]; }}", err_msg)
        }
    };
    CString::new(dot_result).unwrap_or_default().into_raw()
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
    if filename.is_null()
        || out_buffer.is_null()
        || out_buffer_size <= 0
        || offset < 0
        || length < 0
    {
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_lihat_bytes".to_string()));
        return -1;
    }
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    match lihat_bytes_internal(path_str, offset as u64, length as usize) {
        Ok(hex_str) => {
            let hex_bytes = hex_str.as_bytes();
            if hex_bytes.len() >= out_buffer_size as usize {
                set_last_error(ReToolsError::Generic("Buffer output hex tidak cukup".to_string()));
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_buffer, out_buffer_size as usize);
            strncpy_rs_from_bytes(hex_bytes, out_slice);
            0
        }
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_ubahBytes(
    filename: *const c_char,
    offset: c_int,
    data: *const u8,
    data_len: c_int,
) -> c_int {
    if filename.is_null() || data.is_null() || offset < 0 || data_len <= 0 {
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_ubah_bytes".to_string()));
        return -1;
    }
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    let data_slice = slice::from_raw_parts(data, data_len as usize);
    match ubah_bytes_internal(path_str, offset as u64, data_slice) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_last_error(e);
            0
        }
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_cariPattern_json(
    filename: *const c_char,
    pattern: *const u8,
    pattern_len: c_int,
) -> *mut c_char {
    let error_json = CString::new("[]").unwrap().into_raw();
    if filename.is_null() || pattern.is_null() || pattern_len <= 0 {
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_cari_pattern_json".to_string()));
        return error_json;
    }
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return error_json;
        }
    };
    let pattern_slice = slice::from_raw_parts(pattern, pattern_len as usize);
    match cari_pattern_internal(path_str, pattern_slice) {
        Ok(results) => match serde_json::to_string(&results) {
            Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
            Err(e) => {
                set_last_error(ReToolsError::Generic(format!("Serialisasi JSON gagal: {}", e)));
                error_json
            }
        },
        Err(e) => {
            set_last_error(e);
            error_json
        }
    }
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getKodeAksesData_json(
    file_path_c: *const c_char,
    data_address: u64,
) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| {
        getKodeAksesData_internal(binary, data_address)
    })
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getPeneleponFungsi_json(
    file_path_c: *const c_char,
    function_address: u64,
) -> *mut c_char {
    c_load_binary_and_serialize(file_path_c, |binary| {
        getPeneleponFungsi_internal(binary, function_address)
    })
}