use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use std::ffi::CStr;

use crate::logic::static_analysis::analyzer::{
    deteksi_pattern_internal, ekstrak_strings_internal, hitung_entropy_internal,
};
use crate::logic::static_analysis::cfg::generate_cfg_internal;
use crate::logic::static_analysis::diff::diff_binary_internal;
use crate::logic::static_analysis::disasm::{logic_decode_instruksi, ArsitekturDisasm};
use crate::logic::static_analysis::hexeditor::{
    cari_pattern_internal, lihat_bytes_internal, ubah_bytes_internal,
};
use crate::logic::static_analysis::parser::parse_header_info_internal;

#[pyfunction(name = "parseHeaderInfo")]
fn parse_header_info_py(py: Python, file_path: &str) -> PyResult<PyObject> {
    match parse_header_info_internal(file_path) {
        Ok(header_info) => {
            let dict = PyDict::new_bound(py);
            dict.set_item("valid", header_info.valid)?;
            dict.set_item("format", header_info.format)?;
            dict.set_item("arch", header_info.arch)?;
            dict.set_item("bits", header_info.bits)?;
            dict.set_item("entry_point", header_info.entry_point)?;
            dict.set_item("machine_id", header_info.machine_id)?;
            dict.set_item("is_lib", header_info.is_lib)?;
            dict.set_item("file_size", header_info.file_size)?;
            Ok(dict.to_object(py))
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(e)),
    }
}

#[pyfunction(name = "ekstrakStrings")]
fn ekstrak_strings_py(py: Python, file_path: &str, min_length: usize) -> PyResult<PyObject> {
    match ekstrak_strings_internal(file_path, min_length) {
        Ok(strings_info) => {
            let py_strings: Vec<String> = strings_info.into_iter().map(|s| s.content).collect();
            Ok(py_strings.to_object(py))
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string())),
    }
}

#[pyfunction(name = "hitungEntropy")]
fn hitung_entropy_py(_py: Python, file_path: &str, block_size: usize) -> PyResult<Vec<f64>> {
    match hitung_entropy_internal(file_path, block_size) {
        Ok(results) => Ok(results),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string())),
    }
}

#[pyfunction(name = "deteksiPattern")]
fn deteksi_pattern_py(_py: Python, file_path: &str, regex_str: &str) -> PyResult<Vec<String>> {
    match deteksi_pattern_internal(file_path, regex_str) {
        Ok(matches) => Ok(matches),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

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
        _ => ArsitekturDisasm::ARCH_UNKNOWN,
    };
    let c_instr = logic_decode_instruksi(ptr_data, len_data, offset, base_va, arch);
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

#[pyfunction(name = "generateCFG")]
fn generate_cfg_py(_py: Python, file_path: &str) -> PyResult<String> {
    match generate_cfg_internal(file_path) {
        Ok(dot_str) => Ok(dot_str),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

#[pyfunction(name = "diffBinary")]
fn diff_binary_py(py: Python, file1: &str, file2: &str) -> PyResult<Vec<PyObject>> {
    match diff_binary_internal(file1, file2) {
        Ok(results) => {
            let mut py_results: Vec<PyObject> = Vec::new();
            for res in results {
                let dict = PyDict::new_bound(py);
                dict.set_item("functionName", res.function_name)?;
                dict.set_item("addressFile1", format!("0x{:x}", res.address_file1))?;
                dict.set_item("addressFile2", format!("0x{:x}", res.address_file2))?;
                dict.set_item("status", res.status)?;
                py_results.push(dict.to_object(py));
            }
            Ok(py_results)
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(e)),
    }
}

#[pyfunction(name = "lihatBytes")]
fn lihat_bytes_py(_py: Python, filename: &str, offset: u64, length: usize) -> PyResult<String> {
    match lihat_bytes_internal(filename, offset, length) {
        Ok(s) => Ok(s),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string())),
    }
}

#[pyfunction(name = "ubahBytes")]
fn ubah_bytes_py(
    _py: Python,
    filename: &str,
    offset: u64,
    data: &Bound<'_, PyBytes>,
) -> PyResult<bool> {
    let data_slice = data.as_bytes();
    match ubah_bytes_internal(filename, offset, data_slice) {
        Ok(b) => Ok(b),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string())),
    }
}

#[pyfunction(name = "cariPattern")]
fn cari_pattern_py(_py: Python, filename: &str, pattern: &Bound<'_, PyBytes>) -> PyResult<Vec<u64>> {
    let pattern_slice = pattern.as_bytes();
    match cari_pattern_internal(filename, pattern_slice) {
        Ok(v) => Ok(v),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string())),
    }
}

#[pymodule]
fn re_tools(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_header_info_py, m)?)?;
    m.add_function(wrap_pyfunction!(ekstrak_strings_py, m)?)?;
    m.add_function(wrap_pyfunction!(hitung_entropy_py, m)?)?;
    m.add_function(wrap_pyfunction!(deteksi_pattern_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_instruksi_py, m)?)?;
    m.add("ARCH_UNKNOWN", ArsitekturDisasm::ARCH_UNKNOWN as u32)?;
    m.add("ARCH_X86_32", ArsitekturDisasm::ARCH_X86_32 as u32)?;
    m.add("ARCH_X86_64", ArsitekturDisasm::ARCH_X86_64 as u32)?;
    m.add("ARCH_ARM_32", ArsitekturDisasm::ARCH_ARM_32 as u32)?;
    m.add("ARCH_ARM_64", ArsitekturDisasm::ARCH_ARM_64 as u32)?;
    m.add_function(wrap_pyfunction!(generate_cfg_py, m)?)?;
    m.add_function(wrap_pyfunction!(diff_binary_py, m)?)?;
    m.add_function(wrap_pyfunction!(lihat_bytes_py, m)?)?;
    m.add_function(wrap_pyfunction!(ubah_bytes_py, m)?)?;
    m.add_function(wrap_pyfunction!(cari_pattern_py, m)?)?;
    Ok(())
}