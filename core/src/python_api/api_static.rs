//! Author: [Seclususs](https://github.com/seclususs)

use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::error::ReToolsError;
use crate::logic::static_analysis::analyzer::{
	detect_packer, scan_pola_regex, extract_str_raw,
	get_akses_data, get_penelepon, calc_entropi,
	identify_lib, scan_yara, scan_crypto_const,
};
use crate::logic::static_analysis::cfg::create_graf_cfg;
use crate::logic::static_analysis::decompiler::decompile_function_internal;
use crate::logic::static_analysis::diff::diff_binary_internal;
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::static_analysis::hexeditor::{
	scan_pola_bytes, view_bytes_hex, patch_bytes_raw,
};
use crate::logic::static_analysis::parser::Binary;

use log::{error, info};

pub fn convert_err_py(err: ReToolsError) -> PyErr {
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
fn wrap_parse_header(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
	info!("py: parseHeaderInfo dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	let header_info = &binary.header;
	let dict = PyDict::new(py);
	dict.set_item("valid", header_info.valid)?;
	dict.set_item("format", header_info.format)?;
	dict.set_item("arch", header_info.arch)?;
	dict.set_item("bits", header_info.bits)?;
	dict.set_item("entry_point", header_info.addr_masuk)?;
	dict.set_item("machine_id", header_info.machine_id)?;
	dict.set_item("is_lib", header_info.is_lib)?;
	dict.set_item("file_size", header_info.sz_berkas)?;
	Ok(dict.into())
}

#[pyfunction(name = "parseHeaderInfoRaw")]
fn wrap_parse_header_raw(
	py: Python,
	jalur_berkas: &str,
	id_arch: u32,
	va_basis: u64,
) -> PyResult<Py<PyAny>> {
	info!("py: parseHeaderInfoRaw dipanggil untuk: {}", jalur_berkas);
	let arch = match id_arch {
		1 => ArsitekturDisasm::ARCH_X86_32,
		2 => ArsitekturDisasm::ARCH_X86_64,
		3 => ArsitekturDisasm::ARCH_ARM_32,
		4 => ArsitekturDisasm::ARCH_ARM_64,
		_ => ArsitekturDisasm::ARCH_UNKNOWN,
	};
	let binary = Binary::load_raw(jalur_berkas, arch, va_basis).map_err(convert_err_py)?;
	let header_info = &binary.header;
	let dict = PyDict::new(py);
	dict.set_item("valid", header_info.valid)?;
	dict.set_item("format", header_info.format)?;
	dict.set_item("arch", header_info.arch)?;
	dict.set_item("bits", header_info.bits)?;
	dict.set_item("entry_point", header_info.addr_masuk)?;
	dict.set_item("machine_id", header_info.machine_id)?;
	dict.set_item("is_lib", header_info.is_lib)?;
	dict.set_item("file_size", header_info.sz_berkas)?;
	Ok(dict.into())
}

#[pyfunction(name = "ekstrakStrings")]
fn wrap_extract_str(py: Python, jalur_berkas: &str, len_min: usize) -> PyResult<Py<PyAny>> {
	info!("py: ekstrakStrings dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match extract_str_raw(&binary, len_min) {
		Ok(strings_info) => {
			let py_strings: Vec<String> = strings_info.into_iter().map(|s| s.content).collect();
			let list = PyList::new(py, py_strings)?;
			Ok(list.into())
		}
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "hitungEntropy")]
fn wrap_calc_entropi(_py: Python, jalur_berkas: &str, sz_blok: usize) -> PyResult<Vec<f64>> {
	info!("py: hitungEntropy dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match calc_entropi(&binary, sz_blok) {
		Ok(results) => Ok(results),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "deteksiPattern")]
fn wrap_scan_pola(_py: Python, jalur_berkas: &str, pola_regex: &str) -> PyResult<Vec<String>> {
	info!("py: deteksiPattern dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match scan_pola_regex(&binary, pola_regex) {
		Ok(matches) => Ok(matches),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "scanYara")]
fn wrap_scan_yara(py: Python, jalur_berkas: &str, aturan_yara: &str) -> PyResult<Py<PyAny>> {
	info!("py: scanYara dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match scan_yara(&binary, aturan_yara) {
		Ok(results) => {
			let py_results = PyList::empty(py);
			for m in results {
				let dict = PyDict::new(py);
				dict.set_item("rule_name", m.rule_name)?;
				let py_strings = PyList::empty(py);
				for s in m.strings {
					let string_dict = PyDict::new(py);
					string_dict.set_item("identifier", s.identifier)?;
					string_dict.set_item("offset", s.offset)?;
					py_strings.append(string_dict)?;
				}
				dict.set_item("strings", py_strings)?;
				py_results.append(dict)?;
			}
			Ok(py_results.into())
		}
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "scanCryptoConstants")]
fn wrap_scan_crypto(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
	info!("py: scanCryptoConstants dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match scan_crypto_const(&binary) {
		Ok(results) => {
			let json_str = serde_json::to_string(&results)
				.map_err(|e| PyValueError::new_err(e.to_string()))?;
			let json_module = PyModule::import(py, "json")?;
			let py_json = json_module.getattr("loads")?.call1((json_str,))?;
			Ok(py_json.into())
		}
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "deteksiHeuristicPacker")]
fn wrap_scan_packer(
	py: Python,
	jalur_berkas: &str,
	nilai_ambang: f64,
) -> PyResult<Py<PyAny>> {
	info!("py: deteksiHeuristicPacker dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match detect_packer(&binary, nilai_ambang) {
		Ok(results) => {
			let json_str = serde_json::to_string(&results)
				.map_err(|e| PyValueError::new_err(e.to_string()))?;
			let json_module = PyModule::import(py, "json")?;
			let py_json = json_module.getattr("loads")?.call1((json_str,))?;
			Ok(py_json.into())
		}
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "identifikasiFungsiLibrary")]
fn wrap_scan_lib(
	py: Python,
	jalur_berkas: &str,
	sig_json: &str,
) -> PyResult<Py<PyAny>> {
	info!("py: identifikasiFungsiLibrary dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match identify_lib(&binary, sig_json) {
		Ok(results) => {
			let json_str = serde_json::to_string(&results)
				.map_err(|e| PyValueError::new_err(e.to_string()))?;
			let json_module = PyModule::import(py, "json")?;
			let py_json = json_module.getattr("loads")?.call1((json_str,))?;
			Ok(py_json.into())
		}
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "buatCFG")]
fn wrap_create_cfg(_py: Python, jalur_berkas: &str) -> PyResult<String> {
	info!("py: buatCFG dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match create_graf_cfg(&binary) {
		Ok(dot_str) => Ok(dot_str),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "decompileFunction")]
fn wrap_create_decomp(
	_py: Python,
	jalur_berkas: &str,
	va_fungsi: u64,
) -> PyResult<String> {
	info!(
		"py: decompileFunction dipanggil untuk: {} @ 0x{:x}",
		jalur_berkas, va_fungsi
	);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match decompile_function_internal(&binary, va_fungsi) {
		Ok(pseudocode) => Ok(pseudocode),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "diffBinary")]
fn wrap_calc_diff(py: Python, jalur_1: &str, jalur_2: &str) -> PyResult<Vec<Py<PyAny>>> {
	info!("py: diffBinary dipanggil untuk: {} vs {}", jalur_1, jalur_2);
	match diff_binary_internal(jalur_1, jalur_2) {
		Ok(results) => {
			let mut py_results: Vec<Py<PyAny>> = Vec::new();
			for res in results {
				let dict = PyDict::new(py);
				dict.set_item("functionName", res.function_name)?;
				dict.set_item("addressFile1", format!("0x{:x}", res.address_file1))?;
				dict.set_item("addressFile2", format!("0x{:x}", res.address_file2))?;
				dict.set_item("status", res.status)?;
				py_results.push(dict.into());
			}
			Ok(py_results)
		}
		Err(e) => Err(PyValueError::new_err(e)),
	}
}

#[pyfunction(name = "lihatBytes")]
fn wrap_read_bytes(_py: Python, jalur_berkas: &str, off_set: u64, len_baca: usize) -> PyResult<String> {
	info!("py: lihatBytes dipanggil untuk: {}", jalur_berkas);
	match view_bytes_hex(jalur_berkas, off_set, len_baca) {
		Ok(s) => Ok(s),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "ubahBytes")]
fn wrap_write_bytes(
	_py: Python,
	jalur_berkas: &str,
	off_set: u64,
	data_bytes: &Bound<'_, PyBytes>,
) -> PyResult<bool> {
	info!("py: ubahBytes dipanggil untuk: {}", jalur_berkas);
	let slice_data = data_bytes.as_bytes();
	match patch_bytes_raw(jalur_berkas, off_set, slice_data) {
		Ok(b) => Ok(b),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "cariPattern")]
fn wrap_scan_bytes(_py: Python, jalur_berkas: &str, pola_bytes: &Bound<'_, PyBytes>) -> PyResult<Vec<u64>> {
	info!("py: cariPattern dipanggil untuk: {}", jalur_berkas);
	let slice_pola = pola_bytes.as_bytes();
	match scan_pola_bytes(jalur_berkas, slice_pola) {
		Ok(v) => Ok(v),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "parseSections")]
fn wrap_parse_seksi(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
	info!("py: parseSections dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	let py_list = PyList::empty(py);
	for section in &binary.sections {
		let dict = PyDict::new(py);
		dict.set_item("name", &section.name)?;
		dict.set_item("addr", section.addr)?;
		dict.set_item("size", section.size)?;
		dict.set_item("offset", section.offset)?;
		dict.set_item("flags", section.flags)?;
		py_list.append(dict)?;
	}
	Ok(py_list.into())
}

#[pyfunction(name = "parseSymbols")]
fn wrap_parse_simbol(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
	info!("py: parseSymbols dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	let py_list = PyList::empty(py);
	for symbol in &binary.symbols {
		let dict = PyDict::new(py);
		dict.set_item("name", &symbol.name)?;
		dict.set_item("addr", symbol.addr)?;
		dict.set_item("size", symbol.size)?;
		dict.set_item("symbol_type", &symbol.symbol_type)?;
		dict.set_item("bind", &symbol.bind)?;
		py_list.append(dict)?;
	}
	Ok(py_list.into())
}

#[pyfunction(name = "parseImports")]
fn wrap_parse_impor(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
	info!("py: parseImports dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	let py_list = PyList::empty(py);
	for import_info in &binary.imports {
		let dict = PyDict::new(py);
		dict.set_item("name", &import_info.name)?;
		py_list.append(dict)?;
	}
	Ok(py_list.into())
}

#[pyfunction(name = "parseExports")]
fn wrap_parse_ekspor(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
	info!("py: parseExports dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	let py_list = PyList::empty(py);
	for export_info in &binary.exports {
		let dict = PyDict::new(py);
		dict.set_item("name", &export_info.name)?;
		dict.set_item("addr", export_info.addr)?;
		py_list.append(dict)?;
	}
	Ok(py_list.into())
}

#[pyfunction(name = "parseDynamicSectionElf")]
fn wrap_parse_dyn(py: Python, jalur_berkas: &str) -> PyResult<Py<PyAny>> {
	info!("py: parseDynamicSectionElf dipanggil untuk: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	let py_list = PyList::empty(py);
	for entry in &binary.elf_dynamic_info {
		let dict = PyDict::new(py);
		dict.set_item("tag_name", &entry.tag_name)?;
		dict.set_item("value", entry.value)?;
		py_list.append(dict)?;
	}
	Ok(py_list.into())
}

#[pyfunction(name = "getKodeAksesData")]
fn wrap_scan_akses(
	_py: Python,
	jalur_berkas: &str,
	va_data: u64,
) -> PyResult<Vec<u64>> {
	info!(
		"py: getKodeAksesData dipanggil untuk: {} @ 0x{:x}",
		jalur_berkas, va_data
	);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match get_akses_data(&binary, va_data) {
		Ok(results) => Ok(results),
		Err(e) => Err(convert_err_py(e)),
	}
}

#[pyfunction(name = "getPeneleponFungsi")]
fn wrap_scan_penelepon(
	_py: Python,
	jalur_berkas: &str,
	va_fungsi: u64,
) -> PyResult<Vec<u64>> {
	info!(
		"py: getPeneleponFungsi dipanggil untuk: {} @ 0x{:x}",
		jalur_berkas, va_fungsi
	);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	match get_penelepon(&binary, va_fungsi) {
		Ok(results) => Ok(results),
		Err(e) => Err(convert_err_py(e)),
	}
}

pub fn init_modul_static(m: &Bound<'_, PyModule>) -> PyResult<()> {
	m.add_function(wrap_pyfunction!(wrap_parse_header, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_parse_header_raw, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_extract_str, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_calc_entropi, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_pola, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_yara, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_packer, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_lib, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_create_cfg, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_create_decomp, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_calc_diff, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_read_bytes, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_write_bytes, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_bytes, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_parse_seksi, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_parse_simbol, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_parse_impor, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_parse_ekspor, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_parse_dyn, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_akses, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_penelepon, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_crypto, m)?)?;
	Ok(())
}