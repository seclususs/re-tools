use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::ffi::CStr;

use crate::error::ReToolsError;
use crate::logic::static_analysis::analyzer::{
    deteksi_pattern_internal, ekstrak_strings_internal, hitung_entropy_internal, scan_yara_internal,
};
use crate::logic::static_analysis::binary::Binary;
use crate::logic::static_analysis::cfg::generate_cfg_internal;
use crate::logic::static_analysis::diff::diff_binary_internal;
use crate::logic::static_analysis::disasm::{logic_decode_instruksi, ArsitekturDisasm};
use crate::logic::static_analysis::hexeditor::{
    cari_pattern_internal, lihat_bytes_internal, ubah_bytes_internal,
};
use crate::logic::ir::lifter::angkat_blok_instruksi;

use log::{error, info};


fn map_err_to_py(err: ReToolsError) -> PyErr {
    error!("Error pada boundary Python API: {}", err);
    match err {
        ReToolsError::IoError(e) => PyIOError::new_err(e.to_string()),
        ReToolsError::ParseError(s) => PyValueError::new_err(s),
        ReToolsError::NulError(e) => PyValueError::new_err(e.to_string()),
        ReToolsError::Utf8Error(e) => PyValueError::new_err(e.to_string()),
        ReToolsError::RegexError(e) => PyValueError::new_err(e.to_string()),
        ReToolsError::CapstoneError(e) => PyValueError::new_err(e.to_string()),
        ReToolsError::YaraError(e) => PyValueError::new_err(e.to_string()),
        ReToolsError::Generic(s) => PyValueError::new_err(s),
    }
}

#[pyfunction(name = "parseHeaderInfo")]
fn parse_header_info_py(py: Python, file_path: &str) -> PyResult<PyObject> {
    info!("py: parseHeaderInfo dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    let header_info = &binary.header;
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

#[pyfunction(name = "ekstrakStrings")]
fn ekstrak_strings_py(py: Python, file_path: &str, min_length: usize) -> PyResult<PyObject> {
    info!("py: ekstrakStrings dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    match ekstrak_strings_internal(&binary, min_length) {
        Ok(strings_info) => {
            let py_strings: Vec<String> = strings_info.into_iter().map(|s| s.content).collect();
            Ok(py_strings.to_object(py))
        }
        Err(e) => Err(map_err_to_py(e)),
    }
}

#[pyfunction(name = "hitungEntropy")]
fn hitung_entropy_py(_py: Python, file_path: &str, block_size: usize) -> PyResult<Vec<f64>> {
    info!("py: hitungEntropy dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    match hitung_entropy_internal(&binary, block_size) {
        Ok(results) => Ok(results),
        Err(e) => Err(map_err_to_py(e)),
    }
}

#[pyfunction(name = "deteksiPattern")]
fn deteksi_pattern_py(_py: Python, file_path: &str, regex_str: &str) -> PyResult<Vec<String>> {
    info!("py: deteksiPattern dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    match deteksi_pattern_internal(&binary, regex_str) {
        Ok(matches) => Ok(matches),
        Err(e) => Err(map_err_to_py(e)),
    }
}

#[pyfunction(name = "scanYara")]
fn scan_yara_py(py: Python, file_path: &str, yara_rules: &str) -> PyResult<PyObject> {
    info!("py: scanYara dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    match scan_yara_internal(&binary, yara_rules) {
        Ok(results) => {
            let py_results = PyList::new_bound(py);
            for m in results {
                let dict = PyDict::new_bound(py);
                dict.set_item("rule_name", m.rule_name)?;
                let py_strings = PyList::new_bound(py);
                for s in m.strings {
                    let string_dict = PyDict::new_bound(py);
                    string_dict.set_item("identifier", s.identifier)?;
                    string_dict.set_item("offset", s.offset)?;
                    py_strings.append(string_dict)?;
                }
                dict.set_item("strings", py_strings)?;
                py_results.append(dict)?;
            }
            Ok(py_results.to_object(py))
        }
        Err(e) => Err(map_err_to_py(e)),
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

#[pyfunction(name = "generateCFG")]
fn generate_cfg_py(_py: Python, file_path: &str) -> PyResult<String> {
    info!("py: generateCFG dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    match generate_cfg_internal(&binary) {
        Ok(dot_str) => Ok(dot_str),
        Err(e) => Err(map_err_to_py(e)),
    }
}

#[pyfunction(name = "diffBinary")]
fn diff_binary_py(py: Python, file1: &str, file2: &str) -> PyResult<Vec<PyObject>> {
    info!("py: diffBinary dipanggil untuk: {} vs {}", file1, file2);
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
        Err(e) => Err(PyValueError::new_err(e)),
    }
}

#[pyfunction(name = "lihatBytes")]
fn lihat_bytes_py(_py: Python, filename: &str, offset: u64, length: usize) -> PyResult<String> {
    info!("py: lihatBytes dipanggil untuk: {}", filename);
    match lihat_bytes_internal(filename, offset, length) {
        Ok(s) => Ok(s),
        Err(e) => Err(map_err_to_py(e)),
    }
}

#[pyfunction(name = "ubahBytes")]
fn ubah_bytes_py(
    _py: Python,
    filename: &str,
    offset: u64,
    data: &Bound<'_, PyBytes>,
) -> PyResult<bool> {
    info!("py: ubahBytes dipanggil untuk: {}", filename);
    let data_slice = data.as_bytes();
    match ubah_bytes_internal(filename, offset, data_slice) {
        Ok(b) => Ok(b),
        Err(e) => Err(map_err_to_py(e)),
    }
}

#[pyfunction(name = "cariPattern")]
fn cari_pattern_py(_py: Python, filename: &str, pattern: &Bound<'_, PyBytes>) -> PyResult<Vec<u64>> {
    info!("py: cariPattern dipanggil untuk: {}", filename);
    let pattern_slice = pattern.as_bytes();
    match cari_pattern_internal(filename, pattern_slice) {
        Ok(v) => Ok(v),
        Err(e) => Err(map_err_to_py(e)),
    }
}

#[pyfunction(name = "parseSections")]
fn parse_sections_py(py: Python, file_path: &str) -> PyResult<PyObject> {
    info!("py: parseSections dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    let py_list = PyList::new_bound(py);
    for section in &binary.sections {
        let dict = PyDict::new_bound(py);
        dict.set_item("name", &section.name)?;
        dict.set_item("addr", section.addr)?;
        dict.set_item("size", section.size)?;
        dict.set_item("offset", section.offset)?;
        dict.set_item("tipe", section.tipe)?;
        py_list.append(dict)?;
    }
    Ok(py_list.to_object(py))
}

#[pyfunction(name = "parseSymbols")]
fn parse_symbols_py(py: Python, file_path: &str) -> PyResult<PyObject> {
    info!("py: parseSymbols dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    let py_list = PyList::new_bound(py);
    for symbol in &binary.symbols {
        let dict = PyDict::new_bound(py);
        dict.set_item("name", &symbol.name)?;
        dict.set_item("addr", symbol.addr)?;
        dict.set_item("size", symbol.size)?;
        dict.set_item("symbol_type", &symbol.symbol_type)?;
        dict.set_item("bind", &symbol.bind)?;
        py_list.append(dict)?;
    }
    Ok(py_list.to_object(py))
}

#[pyfunction(name = "parseDynamicSectionElf")]
fn parse_dynamic_section_elf_py(py: Python, file_path: &str) -> PyResult<PyObject> {
    info!("py: parseDynamicSectionElf dipanggil untuk: {}", file_path);
    let binary = Binary::load(file_path).map_err(map_err_to_py)?;
    let py_list = PyList::new_bound(py);
    for entry in &binary.elf_dynamic_info {
        let dict = PyDict::new_bound(py);
        dict.set_item("tag_name", &entry.tag_name)?;
        dict.set_item("value", entry.value)?;
        py_list.append(dict)?;
    }
    Ok(py_list.to_object(py))
}

#[pymodule]
fn re_tools(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_header_info_py, m)?)?;
    m.add_function(wrap_pyfunction!(ekstrak_strings_py, m)?)?;
    m.add_function(wrap_pyfunction!(hitung_entropy_py, m)?)?;
    m.add_function(wrap_pyfunction!(deteksi_pattern_py, m)?)?;
    m.add_function(wrap_pyfunction!(scan_yara_py, m)?)?;
    m.add_function(wrap_pyfunction!(decode_instruksi_py, m)?)?;
    m.add_function(wrap_pyfunction!(get_ir_for_instruksi_py, m)?)?;
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
    m.add_function(wrap_pyfunction!(parse_sections_py, m)?)?;
    m.add_function(wrap_pyfunction!(parse_symbols_py, m)?)?;
    m.add_function(wrap_pyfunction!(parse_dynamic_section_elf_py, m)?)?;
    Ok(())
}