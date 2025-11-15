use libc::{c_char, c_int};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::ffi::CStr;
use std::slice;

use crate::error::ReToolsError;
use crate::logic::static_analysis::binary::{Binary, SectionInfo, SymbolInfo};
use crate::logic::static_analysis::parser::C_DiffResult;
use crate::utils::strncpy_rs;


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

fn read_bytes_at_internal(
    file_bytes: &[u8],
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, ReToolsError> {
    let start = offset as usize;
    let end = start.saturating_add(size as usize);

    if start > file_bytes.len() || end > file_bytes.len() {
        warn!(
            "Read bytes OOB: offset {} + size {} > total {}",
            offset,
            size,
            file_bytes.len()
        );
        return Err(ReToolsError::Generic("Read di luar batas".to_string()));
    }
    Ok(file_bytes[start..end].to_vec())
}

fn va_to_offset(va: u64, sections: &[SectionInfo]) -> Option<u64> {
    for sec in sections {
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

fn diff_fallback_by_section(
    binary1: &Binary,
    binary2: &Binary,
    section_name: &str,
) -> Option<C_DiffResult> {
    info!("Menjalankan fallback diff pada section: {}", section_name);
    let sec1 = binary1.sections.iter().find(|s| s.name == section_name);
    let sec2 = binary2.sections.iter().find(|s| s.name == section_name);
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
            let bytes1 = read_bytes_at_internal(&binary1.file_bytes, s1.offset, s1.size);
            let bytes2 = read_bytes_at_internal(&binary2.file_bytes, s2.offset, s2.size);
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

fn perform_diff_logic(
    binary1: &Binary,
    binary2: &Binary,
) -> Result<Vec<C_DiffResult>, ReToolsError> {
    let symbols1_map: HashMap<String, &SymbolInfo> = binary1
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "FUNC" && s.size > 0)
        .map(|s| (s.name.clone(), s))
        .collect();
    let symbols2_map: HashMap<String, &SymbolInfo> = binary2
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "FUNC" && s.size > 0)
        .map(|s| (s.name.clone(), s))
        .collect();
    info!(
        "Membandingkan {} simbol FUNC dari file 1 vs {} simbol FUNC dari file 2",
        symbols1_map.len(),
        symbols2_map.len()
    );
    let mut results: Vec<C_DiffResult> = Vec::new();
    let mut processed_names: HashMap<String, bool> = HashMap::new();
    debug!("Membandingkan simbol dari file 1...");
    for (name, sym1) in &symbols1_map {
        processed_names.insert(name.clone(), true);
        let mut result_entry = C_DiffResult {
            function_name: [0; 128],
            address_file1: sym1.addr,
            address_file2: 0,
            status: STATUS_REMOVED,
        };
        strncpy_rs(name, &mut result_entry.function_name);
        if let Some(sym2) = symbols2_map.get(name) {
            result_entry.address_file2 = sym2.addr;
            let offset1 = va_to_offset(sym1.addr, &binary1.sections);
            let offset2 = va_to_offset(sym2.addr, &binary2.sections);
            let bytes1 =
                offset1.map_or(Err(ReToolsError::Generic("VA not found".to_string())), |off| {
                    read_bytes_at_internal(&binary1.file_bytes, off, sym1.size)
                });
            let bytes2 =
                offset2.map_or(Err(ReToolsError::Generic("VA not found".to_string())), |off| {
                    read_bytes_at_internal(&binary2.file_bytes, off, sym2.size)
                });
            result_entry.status = compare_bytes(bytes1, bytes2);
        }
        results.push(result_entry);
    }
    debug!("Mencari simbol yang ditambah di file 2...");
    for (name, sym2) in &symbols2_map {
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
        if let Some(fallback_result) = diff_fallback_by_section(binary1, binary2, ".text") {
            results.push(fallback_result);
        }
    }
    Ok(results)
}

pub fn diff_binary_internal(
    file1_path: &str,
    file2_path: &str,
) -> Result<Vec<DiffResultInternal>, String> {
    info!("Mulai diff binary: {} vs {}", file1_path, file2_path);
    let binary1 = Binary::load(file1_path).map_err(|e| e.to_string())?;
    let binary2 = Binary::load(file2_path).map_err(|e| e.to_string())?;
    let c_results = perform_diff_logic(&binary1, &binary2).map_err(|e| e.to_string())?;
    info!("Diff selesai, {} hasil ditemukan", c_results.len());
    let status_map = ["Matched", "Modified", "Removed", "Added", "Unknown"];
    let mut rust_results: Vec<DiffResultInternal> = Vec::new();
    for res in &c_results {
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
    let path_str1 = match CStr::from_ptr(file1_c).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let path_str2 = match CStr::from_ptr(file2_c).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let binary1 = match Binary::load(path_str1) {
        Ok(b) => b,
        Err(e) => {
            error!("Gagal load binary 1: {}", e);
            return -1;
        }
    };
    let binary2 = match Binary::load(path_str2) {
        Ok(b) => b,
        Err(e) => {
            error!("Gagal load binary 2: {}", e);
            return -1;
        }
    };
    let results = match perform_diff_logic(&binary1, &binary2) {
        Ok(r) => r,
        Err(e) => {
            error!("Gagal perform_diff_logic: {}", e);
            return -1;
        }
    };
    if results.len() > max_results as usize {
        error!(
            "Jumlah hasil diff ({}) melebihi max_results ({})",
            results.len(),
            max_results
        );
        return -1;
    }
    let out_slice = slice::from_raw_parts_mut(out_results, max_results as usize);
    for (i, res) in results.iter().enumerate() {
        out_slice[i] = *res;
    }
    results.len() as c_int
}