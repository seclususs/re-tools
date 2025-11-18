//! Author: [Seclususs](https://github.com/seclususs)

use crate::error::{set_last_error, ReToolsError};
use crate::logic::data_flow::chains::bangun_chains_reaching_defs;
use crate::logic::data_flow::liveness::hitung_analisis_liveness;
use crate::logic::data_flow::tipe::{analisis_tipe_dasar, verifikasi_batas_memori};
use crate::logic::data_flow::vsa::{analisis_value_set, VsaState};
use crate::logic::static_analysis::cfg::bangun_cfg_internal;
use crate::logic::static_analysis::parser::Binary;
use crate::logic::data_flow::ssa::konstruksi_ssa_lengkap;

use libc::c_char;
use petgraph::graph::NodeIndex;
use std::ffi::{CStr, CString};
use std::collections::{HashMap, HashSet};

unsafe fn c_analyze_binary_and_serialize<F>(
	file_path_c: *const c_char,
	f: F,
) -> *mut c_char
where
	F: FnOnce(
		&Binary,
		&petgraph::graph::DiGraph<
			crate::logic::static_analysis::cfg::BasicBlock,
			&'static str,
		>,
	) -> Result<String, ReToolsError>,
{
	let error_json = CString::new("{}").unwrap().into_raw();
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
    konstruksi_ssa_lengkap(&mut cfg);
	match f(&binary, &cfg) {
		Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
		Err(e) => {
			set_last_error(e);
			error_json
		}
	}
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getLivenessAnalysis_json(
	file_path_c: *const c_char,
) -> *mut c_char {
	c_analyze_binary_and_serialize(file_path_c, |_binary, cfg| {
		let liveness = hitung_analisis_liveness(cfg);
		let mut simple_liveness: std::collections::HashMap<usize, (HashSet<String>, HashSet<String>)> =
			std::collections::HashMap::new();
		for (node, in_set) in liveness.live_in {
			let out_set = liveness.live_out.get(&node).unwrap().clone();
			simple_liveness.insert(node.index(), (in_set, out_set));
		}
		serde_json::to_string(&simple_liveness).map_err(|e| ReToolsError::Generic(e.to_string()))
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getReachingDefs_json(
	file_path_c: *const c_char,
) -> *mut c_char {
	c_analyze_binary_and_serialize(file_path_c, |_binary, cfg| {
		let (info, _, _) = bangun_chains_reaching_defs(cfg);
		let mut simple_info: std::collections::HashMap<
			usize,
			(
				std::collections::HashMap<String, HashSet<crate::logic::data_flow::chains::DefLocation>>,
				std::collections::HashMap<String, HashSet<crate::logic::data_flow::chains::DefLocation>>,
			),
		> = std::collections::HashMap::new();
		for (node, in_set) in info.in_sets {
			let out_set = info.out_sets.get(&node).unwrap().clone();
			simple_info.insert(node.index(), (in_set, out_set));
		}
		serde_json::to_string(&simple_info).map_err(|e| ReToolsError::Generic(e.to_string()))
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDefUseChains_json(
	file_path_c: *const c_char,
) -> *mut c_char {
	c_analyze_binary_and_serialize(file_path_c, |_binary, cfg| {
		let (_, def_use, _) = bangun_chains_reaching_defs(cfg);
		serde_json::to_string(&def_use.chains).map_err(|e| ReToolsError::Generic(e.to_string()))
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getUseDefChains_json(
	file_path_c: *const c_char,
) -> *mut c_char {
	c_analyze_binary_and_serialize(file_path_c, |_binary, cfg| {
		let (_, _, use_def) = bangun_chains_reaching_defs(cfg);
		serde_json::to_string(&use_def.chains).map_err(|e| ReToolsError::Generic(e.to_string()))
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getValueSetAnalysis_json(
	file_path_c: *const c_char,
) -> *mut c_char {
	c_analyze_binary_and_serialize(file_path_c, |_binary, cfg| {
		let vsa = analisis_value_set(cfg);
		let simple_vsa: HashMap<usize, (VsaState, VsaState)> = vsa
			.into_iter()
			.map(|(idx, states)| (idx.index(), states))
			.collect();
		serde_json::to_string(&simple_vsa).map_err(|e| ReToolsError::Generic(e.to_string()))
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getTipeInference_json(
	file_path_c: *const c_char,
) -> *mut c_char {
	c_analyze_binary_and_serialize(file_path_c, |binary, cfg| {
		let vsa = analisis_value_set(cfg);
		let vsa_out_states: HashMap<NodeIndex, VsaState> = vsa
			.into_iter()
			.map(|(idx, (_, out_state))| (idx, out_state))
			.collect();
		let tipe_info = analisis_tipe_dasar(&vsa_out_states, cfg, binary);
		serde_json::to_string(&tipe_info).map_err(|e| ReToolsError::Generic(e.to_string()))
	})
}

#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getMemoryAccessCheck_json(
	file_path_c: *const c_char,
) -> *mut c_char {
	c_analyze_binary_and_serialize(file_path_c, |binary, cfg| {
		let vsa = analisis_value_set(cfg);
		let vsa_out_states: HashMap<NodeIndex, VsaState> = vsa
			.into_iter()
			.map(|(idx, (_, out_state))| (idx, out_state))
			.collect();
		let checks = verifikasi_batas_memori(&vsa_out_states, cfg, binary);
		serde_json::to_string(&checks).map_err(|e| ReToolsError::Generic(e.to_string()))
	})
}