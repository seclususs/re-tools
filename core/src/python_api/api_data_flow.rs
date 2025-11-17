//! Author: [Seclususs](https://github.com/seclususs)

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use super::api_static::map_err_to_py;
use crate::logic::data_flow::chains::bangun_chains_reaching_defs;
use crate::logic::data_flow::liveness::hitung_analisis_liveness;
use crate::logic::data_flow::tipe::{analisis_tipe_dasar, verifikasi_batas_memori};
use crate::logic::data_flow::vsa::{analisis_value_set, VsaState};
use crate::logic::static_analysis::cfg::bangun_cfg_internal;
use crate::logic::static_analysis::parser::Binary;

use log::info;
use petgraph::graph::NodeIndex;
use std::collections::{HashMap, HashSet};

fn analyze_binary_and_serialize_py<F>(
	py: Python,
	file_path: &str,
	f: F,
) -> PyResult<PyObject>
where
	F: FnOnce(
		&Binary,
		&petgraph::graph::DiGraph<
			crate::logic::static_analysis::cfg::BasicBlock,
			&'static str,
		>,
	) -> PyResult<String>,
{
	info!("py: Menganalisis binary: {}", file_path);
	let binary = Binary::load(file_path).map_err(map_err_to_py)?;
	let cfg = bangun_cfg_internal(&binary).map_err(map_err_to_py)?;
	let json_str = f(&binary, &cfg)?;
	let json_module = PyModule::import_bound(py, "json")?;
	let py_json = json_module.getattr("loads")?.call1((json_str,))?;
	Ok(py_json.to_object(py))
}

#[pyfunction(name = "getLivenessAnalysis")]
fn get_liveness_analysis_py(py: Python, file_path: &str) -> PyResult<PyObject> {
	analyze_binary_and_serialize_py(py, file_path, |_binary, cfg| {
		let liveness = hitung_analisis_liveness(cfg);
		let mut simple_liveness: HashMap<String, (HashSet<String>, HashSet<String>)> =
			HashMap::new();
		for (node, in_set) in liveness.live_in {
			let out_set = liveness.live_out.get(&node).unwrap().clone();
			simple_liveness.insert(format!("block_{}", node.index()), (in_set, out_set));
		}
		serde_json::to_string(&simple_liveness).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getReachingDefs")]
fn get_reaching_defs_py(py: Python, file_path: &str) -> PyResult<PyObject> {
	analyze_binary_and_serialize_py(py, file_path, |_binary, cfg| {
		let (info, _, _) = bangun_chains_reaching_defs(cfg);
		let mut simple_info: HashMap<String, (ReachingDefSet, ReachingDefSet)> = HashMap::new();
		for (node, in_set) in info.in_sets {
			let out_set = info.out_sets.get(&node).unwrap().clone();
			simple_info.insert(format!("block_{}", node.index()), (in_set, out_set));
		}
		type ReachingDefSet = HashMap<String, HashSet<crate::logic::data_flow::chains::DefLocation>>;
		serde_json::to_string(&simple_info).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getDefUseChains")]
fn get_def_use_chains_py(py: Python, file_path: &str) -> PyResult<PyObject> {
	analyze_binary_and_serialize_py(py, file_path, |_binary, cfg| {
		let (_, def_use, _) = bangun_chains_reaching_defs(cfg);
		serde_json::to_string(&def_use.chains).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getUseDefChains")]
fn get_use_def_chains_py(py: Python, file_path: &str) -> PyResult<PyObject> {
	analyze_binary_and_serialize_py(py, file_path, |_binary, cfg| {
		let (_, _, use_def) = bangun_chains_reaching_defs(cfg);
		serde_json::to_string(&use_def.chains).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getValueSetAnalysis")]
fn get_value_set_analysis_py(py: Python, file_path: &str) -> PyResult<PyObject> {
	analyze_binary_and_serialize_py(py, file_path, |_binary, cfg| {
		let vsa = analisis_value_set(cfg);
		let simple_vsa: HashMap<String, (VsaState, VsaState)> = vsa
			.into_iter()
			.map(|(idx, states)| (format!("block_{}", idx.index()), states))
			.collect();
		serde_json::to_string(&simple_vsa).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getTipeInference")]
fn get_tipe_inference_py(py: Python, file_path: &str) -> PyResult<PyObject> {
	analyze_binary_and_serialize_py(py, file_path, |binary, cfg| {
		let vsa = analisis_value_set(cfg);
		let vsa_out_states: HashMap<NodeIndex, VsaState> = vsa
			.into_iter()
			.map(|(idx, (_, out_state))| (idx, out_state))
			.collect();
		let tipe_info = analisis_tipe_dasar(&vsa_out_states, cfg, binary);
		serde_json::to_string(&tipe_info).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getMemoryAccessCheck")]
fn get_memory_access_check_py(py: Python, file_path: &str) -> PyResult<PyObject> {
	analyze_binary_and_serialize_py(py, file_path, |binary, cfg| {
		let vsa = analisis_value_set(cfg);
		let vsa_out_states: HashMap<NodeIndex, VsaState> = vsa
			.into_iter()
			.map(|(idx, (_, out_state))| (idx, out_state))
			.collect();
		let checks = verifikasi_batas_memori(&vsa_out_states, cfg, binary);
		serde_json::to_string(&checks).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

pub fn register_data_flow_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
	m.add_function(wrap_pyfunction!(get_liveness_analysis_py, m)?)?;
	m.add_function(wrap_pyfunction!(get_reaching_defs_py, m)?)?;
	m.add_function(wrap_pyfunction!(get_def_use_chains_py, m)?)?;
	m.add_function(wrap_pyfunction!(get_use_def_chains_py, m)?)?;
	m.add_function(wrap_pyfunction!(get_value_set_analysis_py, m)?)?;
	m.add_function(wrap_pyfunction!(get_tipe_inference_py, m)?)?;
	m.add_function(wrap_pyfunction!(get_memory_access_check_py, m)?)?;
	Ok(())
}