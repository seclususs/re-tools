use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::ffi::CStr;

use super::api_static::map_err_to_py;
use crate::logic::ir::lifter::angkat_blok_instruksi;
use crate::logic::static_analysis::disasm::{decode_satu_instruksi, ArsitekturDisasm};


#[pyfunction(name = "decodeInstruksi")]
fn decode_instruksi_py(
    py: Python,
    byte_data: &Bound<'_, PyBytes>,
    offset: usize,
    arch_int: u32,
    base_va: u64,
) -> PyResult<PyObject> {
    let bytes_slice = byte_data.as_bytes();
    let len_data = bytes_slice.len();
    let ptr_data = bytes_slice.as_ptr();
    let arch = match arch_int {
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
    let c_instr = decode_satu_instruksi(ptr_data, len_data, offset, base_va, arch);
    let dict = PyDict::new_bound(py);
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
    Ok(dict.to_object(py))
}

#[pyfunction(name = "getIrForInstruksi")]
fn get_ir_for_instruksi_py(
    py: Python,
    byte_data: &Bound<'_, PyBytes>,
    offset: usize,
    arch_int: u32,
    base_va: u64,
) -> PyResult<PyObject> {
    let bytes_slice = byte_data.as_bytes();
    if offset >= bytes_slice.len() {
        return Err(PyValueError::new_err("Offset di luar batas"));
    }
    let code_slice = &bytes_slice[offset..];
    let arch = match arch_int {
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
    match angkat_blok_instruksi(code_slice, base_va, arch) {
        Ok((_size, ir_vec)) => {
            let json_str = serde_json::to_string(&ir_vec)
                .map_err(|e| PyValueError::new_err(e.to_string()))?;
            let json_module = PyModule::import_bound(py, "json")?;
            let py_json = json_module.getattr("loads")?.call1((json_str,))?;
            Ok(py_json.to_object(py))
        }
        Err(e) => Err(map_err_to_py(e)),
    }
}

pub fn register_ir_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(decode_instruksi_py, m)?)?;
    m.add_function(wrap_pyfunction!(get_ir_for_instruksi_py, m)?)?;
    Ok(())
}