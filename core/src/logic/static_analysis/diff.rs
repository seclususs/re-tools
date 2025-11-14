use libc::{c_char, c_int};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::Path;
use std::slice;

use crate::c_api::{c_getDaftarSections, c_getDaftarSimbol};
use crate::error::ReToolsError;
use crate::logic::static_analysis::parser::{C_SectionInfo, C_SymbolInfo};
use crate::utils::strncpy_rs;


#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct C_DiffResult {
    pub function_name: [c_char; 128],
    pub address_file1: u64,
    pub address_file2: u64,
    pub status: c_int,
}

#[derive(Debug)]
pub struct DiffResultInternal {
    pub function_name: String,
    pub address_file1: u64,
    pub address_file2: u64,
    pub status: String,
}

const STATUS_MATCHED: c_int = 0;
const STATUS_MODIFIED: c_int = 1;
const STATUS_REMOVED: c_int = 2;
const STATUS_ADDED: c_int = 3;

#[derive(Debug, Clone)]
struct InternalSymbol {
    addr: u64,
    size: u64,
}

#[derive(Debug, Clone)]
struct InternalSection {
    addr: u64,
    offset: u64,
    size: u64,
}

fn get_symbols_internal(
    filename_c: *const c_char,
) -> Result<HashMap<String, InternalSymbol>, ReToolsError> {
    let mut symbols_map = HashMap::new();
    let mut buffer: Vec<C_SymbolInfo> = vec![
        C_SymbolInfo {
            name: [0; 128],
            addr: 0,
            size: 0,
            symbol_type: [0; 64],
            bind: [0; 64],
        };
        4096
    ];
    let count = unsafe { c_getDaftarSimbol(filename_c, buffer.as_mut_ptr(), buffer.len() as c_int) };
    if count < 0 {
        warn!(
            "c_getDaftarSimbol gagal atau buffer penuh (count: {})",
            count
        );
        return Err(ReToolsError::ParseError(
            "Gagal parse simbol (buffer penuh atau file error)".to_string(),
        ));
    }
    debug!("Memproses {} simbol", count);
    for sym in &buffer[..count as usize] {
        let sym_type = unsafe { CStr::from_ptr(sym.symbol_type.as_ptr()).to_str().unwrap_or("") };
        if sym_type == "FUNC" && sym.size > 0 {
            if let Ok(name) = unsafe { CStr::from_ptr(sym.name.as_ptr()).to_str() } {
                symbols_map.insert(
                    name.to_string(),
                    InternalSymbol {
                        addr: sym.addr,
                        size: sym.size,
                    },
                );
            }
        }
    }
    info!("Ditemukan {} simbol FUNC", symbols_map.len());
    Ok(symbols_map)
}

fn get_sections_internal(
    filename_c: *const c_char,
) -> Result<HashMap<String, InternalSection>, ReToolsError> {
    let mut sections_map = HashMap::new();
    let mut buffer: Vec<C_SectionInfo> = vec![
        C_SectionInfo {
            name: [0; 128],
            addr: 0,
            size: 0,
            offset: 0,
            tipe: 0,
        };
        256
    ];
    let count = unsafe { c_getDaftarSections(filename_c, buffer.as_mut_ptr(), buffer.len() as c_int) };
    if count < 0 {
        warn!(
            "c_getDaftarSections gagal atau buffer penuh (count: {})",
            count
        );
        return Err(ReToolsError::ParseError("Gagal parse sections".to_string()));
    }
    debug!("Memproses {} sections", count);
    for sec in &buffer[..count as usize] {
        if let Ok(name) = unsafe { CStr::from_ptr(sec.name.as_ptr()).to_str() } {
            sections_map.insert(
                name.to_string(),
                InternalSection {
                    addr: sec.addr,
                    offset: sec.offset,
                    size: sec.size,
                },
            );
        }
    }
    Ok(sections_map)
}

fn read_bytes_at_internal(
    filename_c: *const c_char,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, ReToolsError> {
    let path_str = unsafe { CStr::from_ptr(filename_c).to_str()? };
    let mut file = fs::File::open(Path::new(path_str))?;
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0; size as usize];
    file.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn va_to_offset(va: u64, sections: &HashMap<String, InternalSection>) -> Option<u64> {
    for (_, sec) in sections {
        if va >= sec.addr && va < (sec.addr + sec.size) {
            let relative_offset = va - sec.addr;
            return Some(sec.offset + relative_offset);
        }
    }
    None
}

fn compare_bytes(bytes1: Result<Vec<u8>, ReToolsError>, bytes2: Result<Vec<u8>, ReToolsError>) -> c_int {
    match (bytes1, bytes2) {
        (Ok(b1), Ok(b2)) => {
            if b1 == b2 {
                STATUS_MATCHED
            } else {
                STATUS_MODIFIED
            }
        }
        _ => STATUS_MODIFIED,
    }
}

unsafe fn diff_fallback_by_section(
    file1_c: *const c_char,
    file2_c: *const c_char,
    sections1: &HashMap<String, InternalSection>,
    sections2: &HashMap<String, InternalSection>,
    section_name: &str,
) -> Option<C_DiffResult> {
    info!("Menjalankan fallback diff pada section: {}", section_name);
    let sec1 = sections1.get(section_name);
    let sec2 = sections2.get(section_name);
    let mut result = C_DiffResult {
        function_name: [0; 128],
        address_file1: 0,
        address_file2: 0,
        status: STATUS_MODIFIED,
    };
    strncpy_rs(section_name, &mut result.function_name);
    match (sec1, sec2) {
        (Some(s1), Some(s2)) => {
            result.address_file1 = s1.addr;
            result.address_file2 = s2.addr;
            let bytes1 = read_bytes_at_internal(file1_c, s1.offset, s1.size);
            let bytes2 = read_bytes_at_internal(file2_c, s2.offset, s2.size);
            result.status = compare_bytes(bytes1, bytes2);
            Some(result)
        }
        (Some(s1), None) => {
            result.address_file1 = s1.addr;
            result.status = STATUS_REMOVED;
            Some(result)
        }
        (None, Some(s2)) => {
            result.address_file2 = s2.addr;
            result.status = STATUS_ADDED;
            Some(result)
        }
        (None, None) => None,
    }
}

pub fn diff_binary_internal(
    file1_path: &str,
    file2_path: &str,
) -> Result<Vec<DiffResultInternal>, String> {
    info!("Mulai diff binary: {} vs {}", file1_path, file2_path);
    let c_file1 = CString::new(file1_path).map_err(|e| e.to_string())?;
    let c_file2 = CString::new(file2_path).map_err(|e| e.to_string())?;
    const MAX_RESULTS: usize = 4096;
    let mut c_results_buffer: Vec<C_DiffResult> = vec![
        C_DiffResult {
            function_name: [0; 128],
            address_file1: 0,
            address_file2: 0,
            status: 0,
        };
        MAX_RESULTS
    ];
    let count = unsafe {
        c_diff_binary_rs(
            c_file1.as_ptr(),
            c_file2.as_ptr(),
            c_results_buffer.as_mut_ptr(),
            MAX_RESULTS as c_int,
        )
    };
    if count < 0 {
        error!("c_diff_binary_rs gagal (count: {})", count);
        return Err("Gagal menjalankan diff di Rust (buffer penuh atau error)".to_string());
    }
    info!("Diff selesai, {} hasil ditemukan", count);
    let status_map = ["Matched", "Modified", "Removed", "Added", "Unknown"];
    let mut rust_results: Vec<DiffResultInternal> = Vec::new();
    for i in 0..(count as usize) {
        let res = &c_results_buffer[i];
        let func_name = unsafe { CStr::from_ptr(res.function_name.as_ptr()).to_str().unwrap_or("") };
        let status_str = status_map
            .get(res.status as usize)
            .unwrap_or(&status_map[4]);
        rust_results.push(DiffResultInternal {
            function_name: func_name.to_string(),
            address_file1: res.address_file1,
            address_file2: res.address_file2,
            status: status_str.to_string(),
        });
    }
    Ok(rust_results)
}

pub unsafe fn c_diff_binary_rs(
    file1_c: *const c_char,
    file2_c: *const c_char,
    out_results: *mut C_DiffResult,
    max_results: c_int,
) -> c_int {
    if out_results.is_null() || max_results <= 0 {
        error!("Invalid arguments untuk c_diff_binary_rs");
        return -1;
    }
    unsafe {
        let out_slice = slice::from_raw_parts_mut(out_results, max_results as usize);
        let (symbols1, symbols2, sections1, sections2) =
            match (
                get_symbols_internal(file1_c),
                get_symbols_internal(file2_c),
                get_sections_internal(file1_c),
                get_sections_internal(file2_c),
            ) {
                (Ok(s1), Ok(s2), Ok(sec1), Ok(sec2)) => (s1, s2, sec1, sec2),
                (Err(e), _, _, _) | (_, Err(e), _, _) | (_, _, Err(e), _) | (_, _, _, Err(e)) => {
                    error!("Gagal mendapatkan info simbol/section: {}", e);
                    return -1;
                }
            };
        let mut results: Vec<C_DiffResult> = Vec::new();
        let mut processed_names: HashMap<String, bool> = HashMap::new();
        debug!("Membandingkan simbol dari file 1...");
        for (name, sym1) in &symbols1 {
            processed_names.insert(name.clone(), true);
            let mut result_entry = C_DiffResult {
                function_name: [0; 128],
                address_file1: sym1.addr,
                address_file2: 0,
                status: STATUS_REMOVED,
            };
            strncpy_rs(name, &mut result_entry.function_name);
            if let Some(sym2) = symbols2.get(name) {
                result_entry.address_file2 = sym2.addr;
                let offset1 = va_to_offset(sym1.addr, &sections1);
                let offset2 = va_to_offset(sym2.addr, &sections2);
                let bytes1 =
                    offset1.map_or(Err(ReToolsError::Generic("VA not found".to_string())), |off| {
                        read_bytes_at_internal(file1_c, off, sym1.size)
                    });
                let bytes2 =
                    offset2.map_or(Err(ReToolsError::Generic("VA not found".to_string())), |off| {
                        read_bytes_at_internal(file2_c, off, sym2.size)
                    });
                result_entry.status = compare_bytes(bytes1, bytes2);
            }
            results.push(result_entry);
        }
        debug!("Mencari simbol yang ditambah di file 2...");
        for (name, sym2) in &symbols2 {
            if !processed_names.contains_key(name) {
                let mut result_entry = C_DiffResult {
                    function_name: [0; 128],
                    address_file1: 0,
                    address_file2: sym2.addr,
                    status: STATUS_ADDED,
                };
                strncpy_rs(name, &mut result_entry.function_name);
                results.push(result_entry);
            }
        }
        if results.is_empty() {
            warn!("Tidak ada simbol fungsi yang ditemukan, menjalankan fallback diff .text");
            if let Some(fallback_result) =
                diff_fallback_by_section(file1_c, file2_c, &sections1, &sections2, ".text")
            {
                results.push(fallback_result);
            }
        }
        if results.len() > max_results as usize {
            error!(
                "Jumlah hasil diff ({}) melebihi max_results ({})",
                results.len(),
                max_results
            );
            return -1;
        }
        for (i, res) in results.iter().enumerate() {
            out_slice[i] = *res;
        }
        results.len() as c_int
    }
}