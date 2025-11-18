//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};
use crate::logic::static_analysis::cfg::BasicBlock;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct LivenessInfo {
	pub live_in: HashMap<NodeIndex, HashSet<String>>,
	pub live_out: HashMap<NodeIndex, HashSet<String>>,
	pub use_set: HashMap<NodeIndex, HashSet<String>>,
	pub def_set: HashMap<NodeIndex, HashSet<String>>,
}

fn scan_use_expr(ekspresi: &MicroExpr, set_guna: &mut HashSet<String>, set_def: &HashSet<String>) {
	match ekspresi {
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg, .. })) => {
			if !set_def.contains(id_reg) {
				set_guna.insert(id_reg.clone());
			}
		}
		MicroExpr::UnaryOp(_, inner) => scan_use_expr(inner, set_guna, set_def),
		MicroExpr::BinaryOp(_, kiri, kanan)
		| MicroExpr::Compare(kiri, kanan)
		| MicroExpr::TestBit(kiri, kanan) => {
			scan_use_expr(kiri, set_guna, set_def);
			scan_use_expr(kanan, set_guna, set_def);
		}
		MicroExpr::LoadMemori(inner) => scan_use_expr(inner, set_guna, set_def),
		MicroExpr::Operand(MicroOperand::Konstanta(_)) => {}
		MicroExpr::Operand(MicroOperand::Flag(_)) => {}
	}
}

fn scan_use_def_blok(
	blok: &BasicBlock,
) -> (HashSet<String>, HashSet<String>) {
	let mut set_guna = HashSet::new();
	let mut set_def = HashSet::new();
	for (_, list_instr) in &blok.instructions {
		for instr in list_instr {
			match instr {
				MicroInstruction::Assign(SsaVariabel { id_reg, .. }, ekspresi) => {
					scan_use_expr(ekspresi, &mut set_guna, &set_def);
					set_def.insert(id_reg.clone());
				}
				MicroInstruction::StoreMemori(addr, data) => {
					scan_use_expr(addr, &mut set_guna, &set_def);
					scan_use_expr(data, &mut set_guna, &set_def);
				}
				MicroInstruction::Jump(ekspresi) => {
					scan_use_expr(ekspresi, &mut set_guna, &set_def);
				}
				MicroInstruction::JumpKondisi(kondisi, target) => {
					scan_use_expr(kondisi, &mut set_guna, &set_def);
					scan_use_expr(target, &mut set_guna, &set_def);
				}
				MicroInstruction::Call(ekspresi) => {
					scan_use_expr(ekspresi, &mut set_guna, &set_def);
				}
				MicroInstruction::AtomicRMW { op: _, addr_mem, nilai, tujuan_lama } => {
					scan_use_expr(addr_mem, &mut set_guna, &set_def);
					scan_use_expr(nilai, &mut set_guna, &set_def);
					if let Some(var_lama) = tujuan_lama {
						set_def.insert(var_lama.id_reg.clone());
					}
				}
				MicroInstruction::UpdateFlag(_flag_name, ekspresi) => {
					scan_use_expr(ekspresi, &mut set_guna, &set_def);
				}
				MicroInstruction::VectorOp { tujuan, op_1, op_2, .. } => {
					for op in op_1.iter().chain(op_2.iter()) {
						if let MicroOperand::SsaVar(v) = op {
							if !set_def.contains(&v.id_reg) {
								set_guna.insert(v.id_reg.clone());
							}
						}
					}
					set_def.insert(tujuan.id_reg.clone());
				}
				_ => {}
			}
		}
	}
	(set_guna, set_def)
}

pub fn calc_live_var(
	graf: &DiGraph<BasicBlock, &'static str>,
) -> LivenessInfo {
	let mut live_in: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut live_out: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut use_set: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut def_set: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let list_simpul: Vec<NodeIndex> = graf.node_indices().collect();
	for &idx_simpul in &list_simpul {
		let blok = graf.node_weight(idx_simpul).unwrap();
		let (set_guna, set_def) = scan_use_def_blok(blok);
		use_set.insert(idx_simpul, set_guna);
		def_set.insert(idx_simpul, set_def);
		live_in.insert(idx_simpul, HashSet::new());
		live_out.insert(idx_simpul, HashSet::new());
	}
	let mut changed = true;
	while changed {
		changed = false;
		for &idx_simpul in list_simpul.iter().rev() {
			let mut set_keluar_baru = HashSet::new();
			for sisi_suksesor in graf.edges_directed(idx_simpul, Direction::Outgoing) {
				let suksesor = sisi_suksesor.target();
				if let Some(set_masuk_suksesor) = live_in.get(&suksesor) {
					set_keluar_baru.extend(set_masuk_suksesor.iter().cloned());
				}
			}
			let set_keluar_lama = live_out.get_mut(&idx_simpul).unwrap();
			if *set_keluar_lama != set_keluar_baru {
				*set_keluar_lama = set_keluar_baru.clone();
				changed = true;
			}
			let set_guna_blok = use_set.get(&idx_simpul).unwrap();
			let set_def_blok = def_set.get(&idx_simpul).unwrap();
			let mut set_keluar_minus_def = set_keluar_baru.clone();
			for def in set_def_blok {
				set_keluar_minus_def.remove(def);
			}
			let mut set_masuk_baru = set_guna_blok.clone();
			set_masuk_baru.extend(set_keluar_minus_def.iter().cloned());
			let set_masuk_lama = live_in.get_mut(&idx_simpul).unwrap();
			if *set_masuk_lama != set_masuk_baru {
				*set_masuk_lama = set_masuk_baru;
				changed = true;
			}
		}
	}
	LivenessInfo {
		live_in,
		live_out,
		use_set,
		def_set,
	}
}