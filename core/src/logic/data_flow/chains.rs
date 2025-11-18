//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};
use crate::logic::static_analysis::cfg::BasicBlock;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DefLocation {
	pub block_id: usize,
	pub instruction_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct UseLocation {
	pub block_id: usize,
	pub instruction_index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DefUseChains {
	pub chains: HashMap<String, HashMap<DefLocation, HashSet<UseLocation>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UseDefChains {
	pub chains: HashMap<String, HashMap<UseLocation, HashSet<DefLocation>>>,
}

type ReachingDefSet = HashMap<String, HashSet<DefLocation>>;

#[derive(Debug, Clone)]
pub struct ReachingDefsInfo {
	pub in_sets: HashMap<NodeIndex, ReachingDefSet>,
	pub out_sets: HashMap<NodeIndex, ReachingDefSet>,
}

fn scan_use_expr(ekspresi: &MicroExpr) -> HashSet<String> {
	let mut set_guna = HashSet::new();
	let mut stack = vec![ekspresi];
	while let Some(e) = stack.pop() {
		match e {
			MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg, .. })) => {
				set_guna.insert(id_reg.clone());
			}
			MicroExpr::UnaryOp(_, inner) => stack.push(inner),
			MicroExpr::BinaryOp(_, kiri, kanan)
			| MicroExpr::Compare(kiri, kanan)
			| MicroExpr::TestBit(kiri, kanan) => {
				stack.push(kiri);
				stack.push(kanan);
			}
			MicroExpr::LoadMemori(inner) => stack.push(inner),
			_ => {}
		}
	}
	set_guna
}

pub fn build_chain_def(
	graf: &DiGraph<BasicBlock, &'static str>,
) -> (ReachingDefsInfo, DefUseChains, UseDefChains) {
	let mut peta_gen: HashMap<NodeIndex, ReachingDefSet> = HashMap::new();
	let mut peta_kill: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut peta_masuk: HashMap<NodeIndex, ReachingDefSet> = HashMap::new();
	let mut peta_keluar: HashMap<NodeIndex, ReachingDefSet> = HashMap::new();
	let list_simpul: Vec<NodeIndex> = graf.node_indices().collect();
	for &idx_simpul in &list_simpul {
		let blok = graf.node_weight(idx_simpul).unwrap();
		let mut set_gen = ReachingDefSet::new();
		let mut set_kill = HashSet::new();
		let mut idx_instr = 0;
		for (_, list_instr) in &blok.instructions {
			for instr in list_instr {
				if let MicroInstruction::Assign(SsaVariabel { id_reg: nama_reg, .. }, _) = instr {
					let lokasi = DefLocation {
						block_id: idx_simpul.index(),
						instruction_index: idx_instr,
					};
					if !set_kill.contains(nama_reg) {
						set_gen.entry(nama_reg.clone()).or_default().insert(lokasi);
					}
					set_kill.insert(nama_reg.clone());
				}
				idx_instr += 1;
			}
		}
		peta_gen.insert(idx_simpul, set_gen);
		peta_kill.insert(idx_simpul, set_kill);
		peta_masuk.insert(idx_simpul, HashMap::new());
		peta_keluar.insert(idx_simpul, HashMap::new());
	}
	let mut changed = true;
	while changed {
		changed = false;
		for &idx_simpul in &list_simpul {
			let mut set_masuk_baru = ReachingDefSet::new();
			for sisi_pred in graf.edges_directed(idx_simpul, Direction::Incoming) {
				let pred = sisi_pred.source();
				if let Some(pred_out) = peta_keluar.get(&pred) {
					for (var, defs) in pred_out {
						set_masuk_baru.entry(var.clone()).or_default().extend(defs.iter().cloned());
					}
				}
			}
			let set_gen_simpul = peta_gen.get(&idx_simpul).unwrap();
			let set_kill_simpul = peta_kill.get(&idx_simpul).unwrap();
			let mut set_keluar_baru = set_masuk_baru.clone();
			for var_killed in set_kill_simpul {
				set_keluar_baru.remove(var_killed);
			}
			for (var_gen, defs_gen) in set_gen_simpul {
				set_keluar_baru.entry(var_gen.clone()).or_default().clear();
				set_keluar_baru.entry(var_gen.clone()).or_default().extend(defs_gen.iter().cloned());
			}
			let old_out = peta_keluar.get_mut(&idx_simpul).unwrap();
			if *old_out != set_keluar_baru {
				*old_out = set_keluar_baru;
				changed = true;
			}
		}
	}
	let mut def_use_chains: HashMap<String, HashMap<DefLocation, HashSet<UseLocation>>> = HashMap::new();
	let mut use_def_chains: HashMap<String, HashMap<UseLocation, HashSet<DefLocation>>> = HashMap::new();
	for &idx_simpul in &list_simpul {
		let blok = graf.node_weight(idx_simpul).unwrap();
		let mut current_defs = peta_masuk.get(&idx_simpul).unwrap().clone();
		let mut idx_instr = 0;
		for (_, list_instr) in &blok.instructions {
			for instr in list_instr {
				let mut uses = HashSet::new();
				match instr {
					MicroInstruction::Assign(_, ekspresi) => uses.extend(scan_use_expr(ekspresi)),
					MicroInstruction::StoreMemori(addr, data) => {
						uses.extend(scan_use_expr(addr));
						uses.extend(scan_use_expr(data));
					}
					MicroInstruction::Jump(ekspresi) => uses.extend(scan_use_expr(ekspresi)),
					MicroInstruction::JumpKondisi(kondisi, target) => {
						uses.extend(scan_use_expr(kondisi));
						uses.extend(scan_use_expr(target));
					}
					MicroInstruction::Call(ekspresi) => uses.extend(scan_use_expr(ekspresi)),
					_ => {}
				}
				let lokasi_guna = UseLocation { block_id: idx_simpul.index(), instruction_index: idx_instr };
				for var_used in &uses {
					if let Some(defs) = current_defs.get(var_used) {
						use_def_chains.entry(var_used.clone()).or_default().entry(lokasi_guna.clone()).or_default().extend(defs.iter().cloned());
						for def in defs {
							def_use_chains.entry(var_used.clone()).or_default().entry(def.clone()).or_default().insert(lokasi_guna.clone());
						}
					}
				}
				if let MicroInstruction::Assign(SsaVariabel { id_reg: nama_reg, .. }, _) = instr {
					let lokasi_def = DefLocation { block_id: idx_simpul.index(), instruction_index: idx_instr };
					current_defs.entry(nama_reg.clone()).or_default().clear();
					current_defs.entry(nama_reg.clone()).or_default().insert(lokasi_def);
				}
				idx_instr += 1;
			}
		}
	}
	(
		ReachingDefsInfo { in_sets: peta_masuk, out_sets: peta_keluar },
		DefUseChains { chains: def_use_chains },
		UseDefChains { chains: use_def_chains }
	)
}