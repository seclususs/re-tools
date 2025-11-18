//! Author: [Seclususs](https://github.com/seclususs)

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use super::api_static::convert_err_py;
use crate::logic::data_flow::chains::build_chain_def;
use crate::logic::data_flow::liveness::calc_live_var;
use crate::logic::data_flow::tipe::{infer_type_base, verify_bound_mem};
use crate::logic::data_flow::vsa::{analyze_set_nilai, VsaState};
use crate::logic::static_analysis::cfg::build_cfg_internal;
use crate::logic::static_analysis::parser::Binary;
use crate::logic::data_flow::ssa::construct_ssa_complete;

use log::info;
use petgraph::graph::NodeIndex;
use std::collections::{HashMap, HashSet};

fn wrap_calc_analisis<F>(
	py: Python,
	jalur_berkas: &str,
	f: F,
) -> PyResult<PyObject>
where
	F: FnOnce(
		&Binary,
		&mut petgraph::graph::DiGraph<
			crate::logic::static_analysis::cfg::BasicBlock,
			&'static str,
		>,
	) -> PyResult<String>,
{
	info!("py: Menganalisis binary: {}", jalur_berkas);
	let binary = Binary::load(jalur_berkas).map_err(convert_err_py)?;
	let mut cfg = build_cfg_internal(&binary).map_err(convert_err_py)?;
    construct_ssa_complete(&mut cfg);
	let json_str = f(&binary, &mut cfg)?;
	let json_module = PyModule::import_bound(py, "json")?;
	let py_json = json_module.getattr("loads")?.call1((json_str,))?;
	Ok(py_json.to_object(py))
}

#[pyfunction(name = "getLivenessAnalysis")]
fn wrap_calc_liveness(py: Python, jalur_berkas: &str) -> PyResult<PyObject> {
	wrap_calc_analisis(py, jalur_berkas, |_binary, cfg| {
		let liveness = calc_live_var(cfg);
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
fn wrap_calc_reaching(py: Python, jalur_berkas: &str) -> PyResult<PyObject> {
	wrap_calc_analisis(py, jalur_berkas, |_binary, cfg| {
		let (info, _, _) = build_chain_def(cfg);
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
fn wrap_calc_def_use(py: Python, jalur_berkas: &str) -> PyResult<PyObject> {
	wrap_calc_analisis(py, jalur_berkas, |_binary, cfg| {
		let (_, def_use, _) = build_chain_def(cfg);
		serde_json::to_string(&def_use.chains).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getUseDefChains")]
fn wrap_calc_use_def(py: Python, jalur_berkas: &str) -> PyResult<PyObject> {
	wrap_calc_analisis(py, jalur_berkas, |_binary, cfg| {
		let (_, _, use_def) = build_chain_def(cfg);
		serde_json::to_string(&use_def.chains).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getValueSetAnalysis")]
fn wrap_calc_vsa(py: Python, jalur_berkas: &str) -> PyResult<PyObject> {
	wrap_calc_analisis(py, jalur_berkas, |_binary, cfg| {
		let vsa = analyze_set_nilai(cfg);
		let simple_vsa: HashMap<String, (VsaState, VsaState)> = vsa
			.into_iter()
			.map(|(idx, states)| (format!("block_{}", idx.index()), states))
			.collect();
		serde_json::to_string(&simple_vsa).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getTipeInference")]
fn wrap_calc_tipe(py: Python, jalur_berkas: &str) -> PyResult<PyObject> {
	wrap_calc_analisis(py, jalur_berkas, |binary, cfg| {
		let vsa = analyze_set_nilai(cfg);
		let vsa_out_states: HashMap<NodeIndex, VsaState> = vsa
			.into_iter()
			.map(|(idx, (_, out_state))| (idx, out_state))
			.collect();
		let tipe_info = infer_type_base(&vsa_out_states, cfg, binary);
		serde_json::to_string(&tipe_info).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

#[pyfunction(name = "getMemoryAccessCheck")]
fn wrap_scan_mem_check(py: Python, jalur_berkas: &str) -> PyResult<PyObject> {
	wrap_calc_analisis(py, jalur_berkas, |binary, cfg| {
		let vsa = analyze_set_nilai(cfg);
		let vsa_out_states: HashMap<NodeIndex, VsaState> = vsa
			.into_iter()
			.map(|(idx, (_, out_state))| (idx, out_state))
			.collect();
		let checks = verify_bound_mem(&vsa_out_states, cfg, binary);
		serde_json::to_string(&checks).map_err(|e| PyValueError::new_err(e.to_string()))
	})
}

pub fn init_modul_data_flow(m: &Bound<'_, PyModule>) -> PyResult<()> {
	m.add_function(wrap_pyfunction!(wrap_calc_liveness, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_calc_reaching, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_calc_def_use, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_calc_use_def, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_calc_vsa, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_calc_tipe, m)?)?;
	m.add_function(wrap_pyfunction!(wrap_scan_mem_check, m)?)?;
	Ok(())
}