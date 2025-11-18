//! Author: [Seclususs](https://github.com/seclususs)

#![allow(unsafe_op_in_unsafe_fn)]

use crate::error::{set_last_error, ReToolsError};
use crate::logic::ir::lifter::angkat_blok_instruksi;
use crate::logic::ir::optimization::IrOptimizer;
use crate::logic::static_analysis::cfg::bangun_cfg_internal;
use crate::logic::static_analysis::disasm::{decode_satu_instruksi, ArsitekturDisasm, C_Instruksi};
use crate::logic::static_analysis::parser::Binary;
use crate::logic::tracer::types::u8;

use libc::c_char;
use std::ffi::{CStr, CString};
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
    decode_satu_instruksi(ptr_data, len_data, offset, instruction_base_va, arch)
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
        }
        Err(e) => {
            set_last_error(e);
            "[]".to_string()
        }
    };
    CString::new(json_result)
        .unwrap_or_else(|_| {
            set_last_error(ReToolsError::Generic("Failed to create CString, possibly interior nulls".to_string()));
            CString::new("[]").unwrap()
        })
        .into_raw()
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_optimizeIrCfg(
    file_path_c: *const c_char,
) -> *mut c_char {
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

    let mut cfg = match bangun_cfg_internal(&binary) {
        Ok(g) => g,
        Err(e) => {
            set_last_error(e);
            return error_json;
        }
    };

    let mut optimizer = IrOptimizer::new();
    optimizer.jalankan_optimasi(&mut cfg);

    let mut result_map = std::collections::HashMap::new();
    for node_idx in cfg.node_indices() {
        let block = &cfg[node_idx];
        let instrs: Vec<_> = block.instructions.iter().flat_map(|(_, irs)| irs.clone()).collect();
        result_map.insert(block.va_start, instrs);
    }

    match serde_json::to_string(&result_map) {
        Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
        Err(e) => {
            set_last_error(ReToolsError::Generic(format!("JSON error: {}", e)));
            error_json
        }
    }
}