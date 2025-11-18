//! Author: [Seclususs](https://github.com/seclususs)

#![allow(unsafe_op_in_unsafe_fn)]

use crate::error::{set_err_last, ReToolsError};
use crate::logic::ir::lifter::lift_blok_instr;
use crate::logic::ir::optimization::IrOptimizer;
use crate::logic::static_analysis::cfg::build_cfg_internal;
use crate::logic::static_analysis::disasm::{decode_instr_single, ArsitekturDisasm, C_Instruksi};
use crate::logic::static_analysis::parser::Binary;
use crate::logic::tracer::types::u8;

use libc::c_char;
use std::ffi::{CStr, CString};
use std::slice;

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseInstruksi(
    ptr_kode_raw: *const u8,
    len_buffer: usize,
    off_kursor: usize,
    va_basis_instr: u64,
    enum_arch: ArsitekturDisasm,
) -> C_Instruksi {
    decode_instr_single(ptr_kode_raw, len_buffer, off_kursor, va_basis_instr, enum_arch)
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_liftInstruksi(
    ptr_kode_raw: *const u8,
    len_buffer: usize,
    off_kursor: usize,
    va_basis_instr: u64,
    enum_arch: ArsitekturDisasm,
) -> *mut c_char {
    let ptr_json_kosong = CString::new("[]").unwrap().into_raw();
    if off_kursor >= len_buffer {
        set_err_last(ReToolsError::Generic("Offset di luar batas".to_string()));
        return ptr_json_kosong;
    }
    let slice_data = unsafe { slice::from_raw_parts(ptr_kode_raw, len_buffer) };
    let slice_kode = &slice_data[off_kursor..];
    let res_ir = lift_blok_instr(slice_kode, va_basis_instr, enum_arch);
    let str_hasil_json = match res_ir {
        Ok((_size, vec_ir)) => {
            serde_json::to_string(&vec_ir).unwrap_or_else(|e| {
                set_err_last(ReToolsError::Generic(format!("JSON serialization error: {}", e)));
                "[]".to_string()
            })
        }
        Err(e) => {
            set_err_last(e);
            "[]".to_string()
        }
    };
    CString::new(str_hasil_json)
        .unwrap_or_else(|_| {
            set_err_last(ReToolsError::Generic("Failed to create CString, possibly interior nulls".to_string()));
            CString::new("[]").unwrap()
        })
        .into_raw()
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_calcOptimasi(
    ptr_jalur_raw: *const c_char,
) -> *mut c_char {
    let ptr_json_error = CString::new("[]").unwrap().into_raw();
    let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_json_error;
		}
	};
    let obj_biner = match Binary::load(str_jalur_sumber) {
        Ok(b) => b,
        Err(e) => {
            set_err_last(e);
            return ptr_json_error;
        }
    };
    let mut graf_cfg = match build_cfg_internal(&obj_biner) {
        Ok(g) => g,
        Err(e) => {
            set_err_last(e);
            return ptr_json_error;
        }
    };
    let mut obj_optimizer = IrOptimizer::new();
    obj_optimizer.run_pass_opt(&mut graf_cfg);
    let mut peta_hasil = std::collections::HashMap::new();
    for idx_simpul in graf_cfg.node_indices() {
        let obj_blok = &graf_cfg[idx_simpul];
        let vec_instr: Vec<_> = obj_blok.instructions.iter().flat_map(|(_, irs)| irs.clone()).collect();
        peta_hasil.insert(obj_blok.va_start, vec_instr);
    }
    match serde_json::to_string(&peta_hasil) {
        Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
        Err(e) => {
            set_err_last(ReToolsError::Generic(format!("JSON error: {}", e)));
            ptr_json_error
        }
    }
}