//! Author: [Seclususs](https://github.com/seclususs)

use crate::error::{set_err_last, ReToolsError};
use crate::logic::data_flow::chains::build_chain_def;
use crate::logic::data_flow::liveness::calc_live_var;
use crate::logic::data_flow::tipe::{infer_type_base, verify_bound_mem};
use crate::logic::data_flow::vsa::{analyze_set_nilai, VsaState};
use crate::logic::static_analysis::cfg::build_cfg_internal;
use crate::logic::static_analysis::parser::Binary;
use crate::logic::data_flow::ssa::construct_ssa_complete;

use libc::c_char;
use petgraph::graph::NodeIndex;
use std::ffi::{CStr, CString};
use std::collections::{HashMap, HashSet};

unsafe fn c_analyze_binary_and_serialize<F>(
	ptr_path_raw: *const c_char,
	func_aksi: F,
) -> *mut c_char
where
	F: FnOnce(
		&Binary,
		&petgraph::graph::DiGraph<
			crate::logic::static_analysis::cfg::BasicBlock,
			&'static str,
		>,
	) -> Result<String, ReToolsError> + std::panic::UnwindSafe,
{
	let ptr_json_error = CString::new("{}").unwrap().into_raw();
	if ptr_path_raw.is_null() {
		set_err_last(ReToolsError::Generic("Path pointer null".to_string()));
		return ptr_json_error;
	}
	let result = std::panic::catch_unwind(|| {
		let str_path_sumber = match unsafe { CStr::from_ptr(ptr_path_raw) }.to_str() {
			Ok(s) => s,
			Err(e) => {
				set_err_last(e.into());
				return ptr_json_error;
			}
		};
		let obj_biner = match Binary::load(str_path_sumber) {
			Ok(b) => b,
			Err(e) => {
				set_err_last(e);
				return ptr_json_error;
			}
		};
		let mut graf_cfg = match build_cfg_internal(&obj_biner, None) {
			Ok(g) => g,
			Err(e) => {
				set_err_last(e);
				return ptr_json_error;
			}
		};
		construct_ssa_complete(&mut graf_cfg);
		match func_aksi(&obj_biner, &graf_cfg) {
			Ok(str_json) => CString::new(str_json).unwrap_or_default().into_raw(),
			Err(e) => {
				set_err_last(e);
				ptr_json_error
			}
		}
	});
	match result {
		Ok(ptr) => ptr,
		Err(_) => {
			set_err_last(ReToolsError::Generic("Panic di c_analyze_binary_and_serialize".to_string()));
			ptr_json_error
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getLivenessAnalysis_json(
	ptr_path_raw: *const c_char,
) -> *mut c_char {
	unsafe {
		c_analyze_binary_and_serialize(ptr_path_raw, |_obj_biner, graf_cfg| {
			let obj_liveness = calc_live_var(graf_cfg);
			let mut peta_liveness_sederhana: std::collections::HashMap<usize, (HashSet<String>, HashSet<String>)> =
				std::collections::HashMap::new();
			for (idx_simpul, set_masuk) in obj_liveness.live_in {
				let set_keluar = obj_liveness.live_out.get(&idx_simpul).unwrap().clone();
				peta_liveness_sederhana.insert(idx_simpul.index(), (set_masuk, set_keluar));
			}
			serde_json::to_string(&peta_liveness_sederhana).map_err(|e| ReToolsError::Generic(e.to_string()))
		})
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getReachingDefs_json(
	ptr_path_raw: *const c_char,
) -> *mut c_char {
	unsafe {
		c_analyze_binary_and_serialize(ptr_path_raw, |_obj_biner, graf_cfg| {
			let (obj_info, _, _) = build_chain_def(graf_cfg);
			let mut peta_info_sederhana: std::collections::HashMap<
				usize,
				(
					std::collections::HashMap<String, HashSet<crate::logic::data_flow::chains::DefLocation>>,
					std::collections::HashMap<String, HashSet<crate::logic::data_flow::chains::DefLocation>>,
				),
			> = std::collections::HashMap::new();
			for (idx_simpul, set_masuk) in obj_info.in_sets {
				let set_keluar = obj_info.out_sets.get(&idx_simpul).unwrap().clone();
				peta_info_sederhana.insert(idx_simpul.index(), (set_masuk, set_keluar));
			}
			serde_json::to_string(&peta_info_sederhana).map_err(|e| ReToolsError::Generic(e.to_string()))
		})
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDefUseChains_json(
	ptr_path_raw: *const c_char,
) -> *mut c_char {
	unsafe {
		c_analyze_binary_and_serialize(ptr_path_raw, |_obj_biner, graf_cfg| {
			let (_, obj_def_use, _) = build_chain_def(graf_cfg);
			serde_json::to_string(&obj_def_use.chains).map_err(|e| ReToolsError::Generic(e.to_string()))
		})
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getUseDefChains_json(
	ptr_path_raw: *const c_char,
) -> *mut c_char {
	unsafe {
		c_analyze_binary_and_serialize(ptr_path_raw, |_obj_biner, graf_cfg| {
			let (_, _, obj_use_def) = build_chain_def(graf_cfg);
			serde_json::to_string(&obj_use_def.chains).map_err(|e| ReToolsError::Generic(e.to_string()))
		})
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getValueSetAnalysis_json(
	ptr_path_raw: *const c_char,
) -> *mut c_char {
	unsafe {
		c_analyze_binary_and_serialize(ptr_path_raw, |obj_biner, graf_cfg| {
			let peta_vsa = analyze_set_nilai(graf_cfg, obj_biner, None);
			let peta_vsa_sederhana: HashMap<usize, (VsaState, VsaState)> = peta_vsa
				.into_iter()
				.map(|(idx_simpul, states)| (idx_simpul.index(), states))
				.collect();
			serde_json::to_string(&peta_vsa_sederhana).map_err(|e| ReToolsError::Generic(e.to_string()))
		})
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getTipeInference_json(
	ptr_path_raw: *const c_char,
) -> *mut c_char {
	unsafe {
		c_analyze_binary_and_serialize(ptr_path_raw, |obj_biner, graf_cfg| {
			let peta_vsa = analyze_set_nilai(graf_cfg, obj_biner, None);
			let peta_vsa_keluar: HashMap<NodeIndex, VsaState> = peta_vsa
				.into_iter()
				.map(|(idx_simpul, (_, state_keluar))| (idx_simpul, state_keluar))
				.collect();
			let info_tipe = infer_type_base(&peta_vsa_keluar, graf_cfg, obj_biner);
			serde_json::to_string(&info_tipe).map_err(|e| ReToolsError::Generic(e.to_string()))
		})
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getMemoryAccessCheck_json(
	ptr_path_raw: *const c_char,
) -> *mut c_char {
	unsafe {
		c_analyze_binary_and_serialize(ptr_path_raw, |obj_biner, graf_cfg| {
			let peta_vsa = analyze_set_nilai(graf_cfg, obj_biner, None);
			let peta_vsa_keluar: HashMap<NodeIndex, VsaState> = peta_vsa
				.into_iter()
				.map(|(idx_simpul, (_, state_keluar))| (idx_simpul, state_keluar))
				.collect();
			let list_cek = verify_bound_mem(&peta_vsa_keluar, graf_cfg, obj_biner);
			serde_json::to_string(&list_cek).map_err(|e| ReToolsError::Generic(e.to_string()))
		})
	}
}