//! Author: [Seclususs](https://github.com/seclususs)

#![allow(unsafe_op_in_unsafe_fn)]

use crate::error::{set_err_last, ReToolsError};
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
use crate::utils::copy_bytes_safe;

use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::slice;

unsafe fn c_load_binary_and_serialize<F, T>(
	ptr_jalur_raw: *const c_char,
	func_aksi: F,
) -> *mut c_char
where
	F: FnOnce(&Binary) -> Result<T, ReToolsError>,
	T: serde::Serialize,
{
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
	match func_aksi(&obj_biner) {
		Ok(obj_data) => match serde_json::to_string(&obj_data) {
			Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
			Err(e) => {
				set_err_last(ReToolsError::Generic(format!(
					"Serialisasi JSON gagal: {}",
					e
				)));
				ptr_json_error
			}
		},
		Err(e) => {
			set_err_last(e);
			ptr_json_error
		}
	}
}

unsafe fn c_load_raw_binary_and_serialize<F, T>(
	ptr_jalur_raw: *const c_char,
	val_arch_id: c_int,
	va_basis: u64,
	func_aksi: F,
) -> *mut c_char
where
	F: FnOnce(&Binary) -> Result<T, ReToolsError>,
	T: serde::Serialize,
{
	let ptr_json_error = CString::new("[]").unwrap().into_raw();
	let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_json_error;
		}
	};
	let enum_arch = match val_arch_id {
		1 => ArsitekturDisasm::ARCH_X86_32,
		2 => ArsitekturDisasm::ARCH_X86_64,
		3 => ArsitekturDisasm::ARCH_ARM_32,
		4 => ArsitekturDisasm::ARCH_ARM_64,
		_ => ArsitekturDisasm::ARCH_UNKNOWN,
	};
	let obj_biner = match Binary::load_raw(str_jalur_sumber, enum_arch, va_basis) {
		Ok(b) => b,
		Err(e) => {
			set_err_last(e);
			return ptr_json_error;
		}
	};
	match func_aksi(&obj_biner) {
		Ok(obj_data) => match serde_json::to_string(&obj_data) {
			Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
			Err(e) => {
				set_err_last(ReToolsError::Generic(format!(
					"Serialisasi JSON gagal: {}",
					e
				)));
				ptr_json_error
			}
		},
		Err(e) => {
			set_err_last(e);
			ptr_json_error
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseHeaderRaw_json(
	ptr_jalur_raw: *const c_char,
	val_arch_id: c_int,
	va_basis: u64,
) -> *mut c_char {
	c_load_raw_binary_and_serialize(ptr_jalur_raw, val_arch_id, va_basis, |obj_biner| Ok(obj_biner.header))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseHeader_json(ptr_jalur_raw: *const c_char) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| Ok(obj_biner.header))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseSeksi_json(ptr_jalur_raw: *const c_char) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| Ok(obj_biner.sections.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseSimbol_json(ptr_jalur_raw: *const c_char) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| Ok(obj_biner.symbols.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseImpor_json(ptr_jalur_raw: *const c_char) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| Ok(obj_biner.imports.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseEkspor_json(ptr_jalur_raw: *const c_char) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| Ok(obj_biner.exports.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseElfDyn_json(ptr_jalur_raw: *const c_char) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| Ok(obj_biner.elf_dynamic_info.clone()))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanString_rs(
	ptr_jalur_raw: *const c_char,
	len_min: c_int,
) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| {
		extract_str_raw(obj_biner, len_min as usize)
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_calcEntropy_json(
	ptr_jalur_raw: *const c_char,
	sz_blok: c_int,
) -> *mut c_char {
	if sz_blok <= 0 {
		set_err_last(ReToolsError::Generic("Block size harus > 0".to_string()));
		return CString::new("[]").unwrap().into_raw();
	}
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| {
		calc_entropi(obj_biner, sz_blok as usize)
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanPola_rs(
	ptr_jalur_raw: *const c_char,
	ptr_pola_regex: *const c_char,
	ptr_buf_luaran: *mut c_char,
	sz_buf_maks: c_int,
) -> c_int {
	if ptr_jalur_raw.is_null()
		|| ptr_pola_regex.is_null()
		|| ptr_buf_luaran.is_null()
		|| sz_buf_maks <= 0
	{
		set_err_last(ReToolsError::Generic(
			"Invalid arguments untuk c_deteksi_pattern_rs".to_string(),
		));
		return -1;
	}
	let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return -1;
		}
	};
	let str_regex = match CStr::from_ptr(ptr_pola_regex).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return -1;
		}
	};
	let obj_biner = match Binary::load(str_jalur_sumber) {
		Ok(b) => b,
		Err(e) => {
			set_err_last(e);
			return -1;
		}
	};
	let list_hasil = scan_pola_regex(&obj_biner, str_regex);
	let str_json_hasil = match list_hasil {
		Ok(matches) => {
			serde_json::to_string(&matches)
				.unwrap_or_else(|e| format!("[\"Error serialisasi: {}\"]", e))
		}
		Err(e) => {
			set_err_last(e);
			"[]".to_string()
		}
	};
	let bytes_json = str_json_hasil.as_bytes();
	if bytes_json.len() >= sz_buf_maks as usize {
		set_err_last(ReToolsError::Generic(
			"Ukuran buffer output JSON tidak cukup".to_string(),
		));
		return -1;
	}
	let slice_luaran = std::slice::from_raw_parts_mut(ptr_buf_luaran, sz_buf_maks as usize);
	copy_bytes_safe(bytes_json, slice_luaran);
	0
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanYara_rs(
	ptr_jalur_raw: *const c_char,
	ptr_aturan_yara: *const c_char,
) -> *mut c_char {
	let ptr_json_error = CString::new("[]").unwrap().into_raw();
	let str_aturan = match CStr::from_ptr(ptr_aturan_yara).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_json_error;
		}
	};
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| {
		scan_yara(obj_biner, str_aturan)
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanKripto_json(ptr_jalur_raw: *const c_char) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| scan_crypto_const(obj_biner))
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanPacker(
	ptr_jalur_raw: *const c_char,
	ambang_entropy: f64,
) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| {
		detect_packer(obj_biner, ambang_entropy)
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanLib(
	ptr_jalur_raw: *const c_char,
	ptr_json_sig: *const c_char,
) -> *mut c_char {
	let ptr_json_error = CString::new("[]").unwrap().into_raw();
	let str_json_sig = match CStr::from_ptr(ptr_json_sig).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_json_error;
		}
	};
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| {
		identify_lib(obj_biner, str_json_sig)
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_calcDiffBiner_json(
	ptr_path1_raw: *const c_char,
	ptr_path2_raw: *const c_char,
) -> *mut c_char {
	let ptr_json_error = CString::new("[]").unwrap().into_raw();
	let str_path1 = match CStr::from_ptr(ptr_path1_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_json_error;
		}
	};
	let str_path2 = match CStr::from_ptr(ptr_path2_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_json_error;
		}
	};
	match diff_binary_internal(str_path1, str_path2) {
		Ok(vec_hasil) => match serde_json::to_string(&vec_hasil) {
			Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
			Err(e) => {
				set_err_last(ReToolsError::Generic(format!(
					"Serialisasi JSON gagal: {}",
					e
				)));
				ptr_json_error
			}
		},
		Err(msg_error) => {
			set_err_last(ReToolsError::Generic(msg_error));
			ptr_json_error
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_createCFG(ptr_jalur_raw: *const c_char) -> *mut c_char {
	let str_error_dot = "digraph G {{ error [label=\"Koneksi error\"]; }}";
	let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return CString::new(str_error_dot.replace("Koneksi error", "Invalid Path UTF-8"))
				.unwrap()
				.into_raw();
		}
	};
	let res_biner = Binary::load(str_jalur_sumber);
	let str_hasil_dot = match res_biner {
		Ok(obj_biner) => match create_graf_cfg(&obj_biner) {
			Ok(str_dot) => str_dot,
			Err(e) => {
				let str_msg = e.to_string();
				set_err_last(e);
				format!("digraph G {{ error [label=\"{}\"]; }}", str_msg)
			}
		},
		Err(e) => {
			let str_msg = e.to_string();
			set_err_last(e);
			format!("digraph G {{ error [label=\"{}\"]; }}", str_msg)
		}
	};
	CString::new(str_hasil_dot).unwrap_or_default().into_raw()
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_createPseudocode(
	ptr_jalur_raw: *const c_char,
	va_fungsi: u64,
) -> *mut c_char {
	let ptr_error_str = CString::new("/* Decompilation Error */").unwrap().into_raw();
	let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_error_str;
		}
	};
	let obj_biner = match Binary::load(str_jalur_sumber) {
		Ok(b) => b,
		Err(e) => {
			set_err_last(e);
			return ptr_error_str;
		}
	};
	match decompile_function_internal(&obj_biner, va_fungsi) {
		Ok(str_kode_pseudo) => CString::new(str_kode_pseudo).unwrap_or_default().into_raw(),
		Err(e) => {
			set_err_last(e);
			ptr_error_str
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_readBytes_hex(
	ptr_jalur_raw: *const c_char,
	off_posisi: c_int,
	len_baca: c_int,
	ptr_buf_hex: *mut c_char,
	sz_buf_maks: c_int,
) -> c_int {
	if ptr_jalur_raw.is_null()
		|| ptr_buf_hex.is_null()
		|| sz_buf_maks <= 0
		|| off_posisi < 0
		|| len_baca < 0
	{
		set_err_last(ReToolsError::Generic(
			"Invalid arguments untuk c_lihat_bytes".to_string(),
		));
		return -1;
	}
	let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return -1;
		}
	};
	match view_bytes_hex(str_jalur_sumber, off_posisi as u64, len_baca as usize) {
		Ok(str_hex) => {
			let bytes_hex = str_hex.as_bytes();
			if bytes_hex.len() >= sz_buf_maks as usize {
				set_err_last(ReToolsError::Generic(
					"Buffer output hex tidak cukup".to_string(),
				));
				return -1;
			}
			let slice_luaran = slice::from_raw_parts_mut(ptr_buf_hex, sz_buf_maks as usize);
			copy_bytes_safe(bytes_hex, slice_luaran);
			0
		}
		Err(e) => {
			set_err_last(e);
			-1
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_writeBytes(
	ptr_jalur_raw: *const c_char,
	off_posisi: c_int,
	ptr_data_baru: *const u8,
	len_data: c_int,
) -> c_int {
	if ptr_jalur_raw.is_null() || ptr_data_baru.is_null() || off_posisi < 0 || len_data <= 0 {
		set_err_last(ReToolsError::Generic(
			"Invalid arguments untuk c_ubah_bytes".to_string(),
		));
		return -1;
	}
	let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return -1;
		}
	};
	let slice_data = slice::from_raw_parts(ptr_data_baru, len_data as usize);
	match patch_bytes_raw(str_jalur_sumber, off_posisi as u64, slice_data) {
		Ok(true) => 1,
		Ok(false) => 0,
		Err(e) => {
			set_err_last(e);
			0
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanPolaBytes_json(
	ptr_jalur_raw: *const c_char,
	ptr_pola: *const u8,
	len_pola: c_int,
) -> *mut c_char {
	let ptr_json_error = CString::new("[]").unwrap().into_raw();
	if ptr_jalur_raw.is_null() || ptr_pola.is_null() || len_pola <= 0 {
		set_err_last(ReToolsError::Generic(
			"Invalid arguments untuk c_cari_pattern_json".to_string(),
		));
		return ptr_json_error;
	}
	let str_jalur_sumber = match CStr::from_ptr(ptr_jalur_raw).to_str() {
		Ok(s) => s,
		Err(e) => {
			set_err_last(e.into());
			return ptr_json_error;
		}
	};
	let slice_pola = slice::from_raw_parts(ptr_pola, len_pola as usize);
	match scan_pola_bytes(str_jalur_sumber, slice_pola) {
		Ok(list_hasil) => match serde_json::to_string(&list_hasil) {
			Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
			Err(e) => {
				set_err_last(ReToolsError::Generic(format!(
					"Serialisasi JSON gagal: {}",
					e
				)));
				ptr_json_error
			}
		},
		Err(e) => {
			set_err_last(e);
			ptr_json_error
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanAksesData_json(
	ptr_jalur_raw: *const c_char,
	va_data: u64,
) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| {
		get_akses_data(obj_biner, va_data)
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_scanPenelepon_json(
	ptr_jalur_raw: *const c_char,
	va_fungsi: u64,
) -> *mut c_char {
	c_load_binary_and_serialize(ptr_jalur_raw, |obj_biner| {
		get_penelepon(obj_biner, va_fungsi)
	})
}