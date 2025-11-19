//! Author: [Seclususs](https://github.com/seclususs)

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::ffi::CStr;

use super::api_static::convert_err_py;
use crate::logic::ir::lifter::lift_blok_instr;
use crate::logic::ir::optimization::IrOptimizer;
use crate::logic::static_analysis::cfg::build_cfg_internal;
use crate::logic::static_analysis::parser::Binary;
use crate::logic::static_analysis::disasm::{decode_instr_single, ArsitekturDisasm};

#[pyfunction(name = "decodeInstruksi")]
fn wrap_decode_instr(
    py: Python,
    bytes_data: &Bound<'_, PyBytes>,
    off_set: usize,
    id_arch: u32,
    va_basis: u64,
) -> PyResult<Py<PyAny>> {
    let slice_bytes = bytes_data.as_bytes();
    let len_data = slice_bytes.len();
    let ptr_data = slice_bytes.as_ptr();
    let arch = match id_arch {
        1 => ArsitekturDisasm::ARCH_X86_32,
        2 => ArsitekturDisasm::ARCH_X86_64,
        3 => ArsitekturDisasm::ARCH_ARM_32,
        4 => ArsitekturDisasm::ARCH_ARM_64,
        5 => ArsitekturDisasm::ARCH_RISCV_32,
        6 => ArsitekturDisasm::ARCH_RISCV_64,
        7 => ArsitekturDisasm::ARCH_MIPS_32,
        8 => ArsitekturDisasm::ARCH_MIPS_64,
        _ => ArsitekturDisasm::ARCH_UNKNOWN,
    };
    let c_instr = decode_instr_single(ptr_data, len_data, off_set, va_basis, arch);
    let dict = PyDict::new(py);
    dict.set_item("valid", c_instr.valid != 0)?;
    dict.set_item("size", c_instr.ukuran)?;
    if c_instr.valid != 0 {
        let mnemonic =
            unsafe { CStr::from_ptr(c_instr.mnemonic_instruksi.as_ptr()).to_str().unwrap_or("") };
        let op_str =
            unsafe { CStr::from_ptr(c_instr.str_operand.as_ptr()).to_str().unwrap_or("") };
        dict.set_item("mnemonic", mnemonic.to_uppercase())?;
        dict.set_item("operands", op_str)?;
    } else {
        dict.set_item("mnemonic", "INVALID")?;
        dict.set_item("operands", "")?;
    }
    Ok(dict.into())
}

#[pyfunction(name = "getIrForInstruksi")]
fn wrap_lift_ir(
    py: Python,
    bytes_data: &Bound<'_, PyBytes>,
    off_set: usize,
    id_arch: u32,
    va_basis: u64,
) -> PyResult<Py<PyAny>> {
    let slice_bytes = bytes_data.as_bytes();
    if off_set >= slice_bytes.len() {
        return Err(PyValueError::new_err("Offset di luar batas"));
    }
    let code_slice = &slice_bytes[off_set..];
    let arch = match id_arch {
        1 => ArsitekturDisasm::ARCH_X86_32,
        2 => ArsitekturDisasm::ARCH_X86_64,
        3 => ArsitekturDisasm::ARCH_ARM_32,
        4 => ArsitekturDisasm::ARCH_ARM_64,
        5 => ArsitekturDisasm::ARCH_RISCV_32,
        6 => ArsitekturDisasm::ARCH_RISCV_64,
        7 => ArsitekturDisasm::ARCH_MIPS_32,
        8 => ArsitekturDisasm::ARCH_MIPS_64,
        _ => ArsitekturDisasm::ARCH_UNKNOWN,
    };
    match lift_blok_instr(code_slice, va_basis, arch) {
        Ok((_size, ir_vec)) => {
            let json_str = serde_json::to_string(&ir_vec)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let json_module = PyModule::import(py, "json")?;
            let py_json = json_module.getattr("loads")?.call1((json_str,))?;
            Ok(py_json.into())
        }
        Err(e) => Err(convert_err_py(e)),
    }
}

#[pyfunction(name = "optimizeIrCfg")]
fn wrap_calc_opt(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
    let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
    let mut cfg = build_cfg_internal(&binary, None).map_err(convert_err_py)?;
    let mut optimizer = IrOptimizer::new();
    optimizer.run_pass_opt(&mut cfg);
    let mut result_map = std::collections::HashMap::new();
    for node_idx in cfg.node_indices() {
        let block = &cfg[node_idx];
        let instrs: Vec<_> = block.instructions.iter().flat_map(|(_, irs)| irs.clone()).collect();
        result_map.insert(block.va_start, instrs);
    }
    let json_str = serde_json::to_string(&result_map)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let json_module = PyModule::import(py, "json")?;
    let py_json = json_module.getattr("loads")?.call1((json_str,))?;
    Ok(py_json.into())
}

pub fn init_modul_ir(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(wrap_decode_instr, m)?)?;
    m.add_function(wrap_pyfunction!(wrap_lift_ir, m)?)?;
    m.add_function(wrap_pyfunction!(wrap_calc_opt, m)?)?;
    Ok(())
}