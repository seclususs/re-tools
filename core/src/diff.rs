use crate::parser::{C_SectionInfo, C_SymbolInfo};
use crate::utils::strncpy_rs;
use libc::{c_char, c_int};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::path::Path;
use std::slice;

// Impor C-ABI
unsafe extern "C" {
    fn c_getDaftarSections(
        filename: *const c_char,
        out_buffer: *mut C_SectionInfo,
        max_count: c_int,
    ) -> c_int;
    fn c_getDaftarSimbol(
        filename: *const c_char,
        out_buffer: *mut C_SymbolInfo,
        max_count: c_int,
    ) -> c_int;
}

/// Struct C-ABI
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct C_DiffResult {
    pub function_name: [c_char; 128],
    pub address_file1: u64,
    pub address_file2: u64,
    pub status: c_int, // 0=Matched, 1=Modified, 2=Removed, 3=Added
}

const STATUS_MATCHED: c_int = 0;
const STATUS_MODIFIED: c_int = 1;
const STATUS_REMOVED: c_int = 2;
const STATUS_ADDED: c_int = 3;

/// Struct internal untuk menyimpan info simbol
#[derive(Debug, Clone)]
struct InternalSymbol {
    addr: u64,
    size: u64,
}

/// Struct internal untuk menyimpan info section
#[derive(Debug, Clone)]
struct InternalSection {
    addr: u64,
    offset: u64,
    size: u64,
}

/// Helper untuk memanggil c_getDaftarSimbol dari Rust
fn get_symbols_internal(
    filename_c: *const c_char,
) -> Result<HashMap<String, InternalSymbol>, &'static str> {
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
    ]; // Alokasi buffer
    
    // Panggil C-ABI
    let count = unsafe { c_getDaftarSimbol(filename_c, buffer.as_mut_ptr(), buffer.len() as c_int) };
    if count < 0 {
        return Err("Gagal parse simbol (buffer penuh atau file error)");
    }

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
    Ok(symbols_map)
}

/// Helper untuk memanggil c_getDaftarSections dari Rust
fn get_sections_internal(
    filename_c: *const c_char,
) -> Result<HashMap<String, InternalSection>, &'static str> {
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

    // Panggil C-ABI
    let count = unsafe { c_getDaftarSections(filename_c, buffer.as_mut_ptr(), buffer.len() as c_int) };
    if count < 0 {
        return Err("Gagal parse sections");
    }

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

/// Helper untuk baca bytes dari file
fn read_bytes_at_internal(
    filename_c: *const c_char,
    offset: u64,
    size: u64,
) -> Option<Vec<u8>> {
    let path_str = unsafe { CStr::from_ptr(filename_c).to_str().ok()? };
    let mut file = fs::File::open(Path::new(path_str)).ok()?;
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut buffer = vec![0; size as usize];
    file.read_exact(&mut buffer).ok()?;
    Some(buffer)
}

/// Helper: Konversi VA ke File Offset
fn va_to_offset(va: u64, sections: &HashMap<String, InternalSection>) -> Option<u64> {
    for (_, sec) in sections {
        if va >= sec.addr && va < (sec.addr + sec.size) {
            let relative_offset = va - sec.addr;
            return Some(sec.offset + relative_offset);
        }
    }
    None
}

/// C-ABI: c_diffBinary_rs
pub unsafe fn c_diff_binary_rs(
    file1_c: *const c_char,
    file2_c: *const c_char,
    out_results: *mut C_DiffResult,
    max_results: c_int,
) -> c_int {
    unsafe {
        let symbols1 = match get_symbols_internal(file1_c) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let symbols2 = match get_symbols_internal(file2_c) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let sections1 = match get_sections_internal(file1_c) {
            Ok(s) => s,
            Err(_) => return -1,
        };
        let sections2 = match get_sections_internal(file2_c) {
            Ok(s) => s,
            Err(_) => return -1,
        };

        let mut results: Vec<C_DiffResult> = Vec::new();
        let mut processed_names: HashMap<String, bool> = HashMap::new();

        // Loop: Cek file1 -> file2
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
                // Ada di kedua file, bandingkan bytes
                result_entry.address_file2 = sym2.addr;
                let offset1 = va_to_offset(sym1.addr, &sections1);
                let offset2 = va_to_offset(sym2.addr, &sections2);

                if let (Some(off1), Some(off2)) = (offset1, offset2) {
                    let bytes1 = read_bytes_at_internal(file1_c, off1, sym1.size);
                    let bytes2 = read_bytes_at_internal(file2_c, off2, sym2.size);

                    if bytes1 == bytes2 {
                        result_entry.status = STATUS_MATCHED;
                    } else {
                        result_entry.status = STATUS_MODIFIED;
                    }
                } else {
                    result_entry.status = STATUS_MODIFIED; // Gagal map offset
                }
            }
            results.push(result_entry);
        }

        // Loop: Cek file2 (Added)
        for (name, sym2) in &symbols2 {
            if !processed_names.contains_key(name) {
                // Hanya ada di file 2
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

        // Salin hasil ke buffer C
        if results.len() > max_results as usize {
            return -1; // Buffer tidak cukup
        }
        let out_slice = slice::from_raw_parts_mut(out_results, max_results as usize);
        for (i, res) in results.iter().enumerate() {
            out_slice[i] = *res;
        }

        results.len() as c_int
    }
}