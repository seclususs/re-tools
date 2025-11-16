use libc::{c_char, c_int};
use log::{debug, info};
use std::collections::HashMap;
use std::ffi::CStr;
use std::slice;

use crate::error::{set_last_error, ReToolsError};
use crate::logic::static_analysis::binary::{Binary, SectionInfo, SymbolInfo};
use crate::logic::static_analysis::parser::C_DiffResult;
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::ir::lifter::angkat_blok_instruksi;
use crate::logic::ir::instruction::IrInstruction;
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

fn va_to_offset(va: u64, sections: &[SectionInfo]) -> Option<u64> {
    for sec in sections {
        if va >= sec.addr && va < (sec.addr + sec.size) {
            let relative_offset = va - sec.addr;
            return Some(sec.offset + relative_offset);
        }
    }
    None
}

fn get_arch_from_binary(binary: &Binary) -> ArsitekturDisasm {
    match (binary.header.arch, binary.header.bits) {
        ("x86-64", 64) => ArsitekturDisasm::ARCH_X86_64,
        ("x86", 32) => ArsitekturDisasm::ARCH_X86_32,
        ("AArch64", 64) => ArsitekturDisasm::ARCH_ARM_64,
        ("ARM", 32) => ArsitekturDisasm::ARCH_ARM_32,
        _ => ArsitekturDisasm::ARCH_X86_64,
    }
}

fn lift_function_to_ir(
    binary: &Binary,
    sym: &SymbolInfo,
    arch: ArsitekturDisasm,
) -> Result<Vec<IrInstruction>, ReToolsError> {
    let func_va = sym.addr;
    let func_size = sym.size;
    if func_size == 0 {
        return Ok(Vec::new());
    }
    let func_offset = va_to_offset(func_va, &binary.sections)
        .ok_or_else(|| ReToolsError::Generic(format!("VA 0x{:x} tidak ditemukan di sections", func_va)))?;
    let start = func_offset as usize;
    let end = start.saturating_add(func_size as usize);
    if start > binary.file_bytes.len() || end > binary.file_bytes.len() {
        return Err(ReToolsError::Generic(format!("Simbol 0x{:x} di luar batas file", func_va)));
    }
    let func_bytes = &binary.file_bytes[start..end];
    let mut all_irs = Vec::new();
    let mut current_offset = 0;
    while current_offset < func_bytes.len() {
        let current_va = func_va + current_offset as u64;
        let (size, irs) = match angkat_blok_instruksi(&func_bytes[current_offset..], current_va, arch) {
            Ok((size, ir_vec)) if size > 0 => (size, ir_vec),
            _ => (1, vec![IrInstruction::Undefined]),
        };
        all_irs.extend(irs);
        current_offset += size;
        if size == 0 {
            break;
        }
    }
    Ok(all_irs)
}

fn compare_ir_sequences(
    irs1_res: Result<Vec<IrInstruction>, ReToolsError>,
    irs2_res: Result<Vec<IrInstruction>, ReToolsError>,
) -> c_int {
    match (irs1_res, irs2_res) {
        (Ok(irs1), Ok(irs2)) => {
            if irs1 == irs2 {
                STATUS_MATCHED
            } else {
                STATUS_MODIFIED
            }
        }
        _ => STATUS_MODIFIED,
    }
}

fn perform_diff_logic(
    binary1: &Binary,
    binary2: &Binary,
) -> Result<Vec<C_DiffResult>, ReToolsError> {
    let arch1 = get_arch_from_binary(binary1);
    let arch2 = get_arch_from_binary(binary2);
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
        "Membandingkan (IR-based) {} simbol FUNC dari file 1 vs {} simbol FUNC dari file 2",
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
        let irs1 = lift_function_to_ir(binary1, sym1, arch1);
        if let Some(sym2) = symbols2_map.get(name) {
            result_entry.address_file2 = sym2.addr;
            let irs2 = lift_function_to_ir(binary2, sym2, arch2);
            result_entry.status = compare_ir_sequences(irs1, irs2);
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
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_diff_binary_rs".to_string()));
        return -1;
    }
    let path_str1 = match CStr::from_ptr(file1_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    let path_str2 = match CStr::from_ptr(file2_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    let binary1 = match Binary::load(path_str1) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(e);
            return -1;
        }
    };
    let binary2 = match Binary::load(path_str2) {
        Ok(b) => b,
        Err(e) => {
            set_last_error(e);
            return -1;
        }
    };
    let results = match perform_diff_logic(&binary1, &binary2) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(e);
            return -1;
        }
    };
    if results.len() > max_results as usize {
        set_last_error(ReToolsError::Generic(format!(
            "Jumlah hasil diff ({}) melebihi max_results ({})",
            results.len(),
            max_results
        )));
        return -1;
    }
    let out_slice = slice::from_raw_parts_mut(out_results, max_results as usize);
    for (i, res) in results.iter().enumerate() {
        out_slice[i] = *res;
    }
    results.len() as c_int
}