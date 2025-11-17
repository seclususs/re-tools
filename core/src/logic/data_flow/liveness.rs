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

fn get_uses_in_expr(expr: &MicroExpr, uses: &mut HashSet<String>, defs: &HashSet<String>) {
	match expr {
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar, .. })) => {
			if !defs.contains(nama_dasar) {
				uses.insert(nama_dasar.clone());
			}
		}
		MicroExpr::OperasiUnary(_, inner) => get_uses_in_expr(inner, uses, defs),
		MicroExpr::OperasiBiner(_, left, right)
		| MicroExpr::Bandingkan(left, right)
		| MicroExpr::UjiBit(left, right) => {
			get_uses_in_expr(left, uses, defs);
			get_uses_in_expr(right, uses, defs);
		}
		MicroExpr::MuatMemori(inner) => get_uses_in_expr(inner, uses, defs),
		MicroExpr::Operand(MicroOperand::Konstanta(_)) => {}
	}
}

fn get_uses_defs_block(
	block: &BasicBlock,
) -> (HashSet<String>, HashSet<String>) {
	let mut uses = HashSet::new();
	let mut defs = HashSet::new();
	for (_, instructions) in &block.instructions {
		for instruction in instructions {
			match instruction {
				MicroInstruction::Assign(SsaVariabel { nama_dasar, .. }, expr) => {
					get_uses_in_expr(expr, &mut uses, &defs);
					defs.insert(nama_dasar.clone());
				}
				MicroInstruction::SimpanMemori(addr_expr, data_expr) => {
					get_uses_in_expr(addr_expr, &mut uses, &defs);
					get_uses_in_expr(data_expr, &mut uses, &defs);
				}
				MicroInstruction::Lompat(expr) => {
					get_uses_in_expr(expr, &mut uses, &defs);
				}
				MicroInstruction::LompatKondisi(cond_expr, target_expr) => {
					get_uses_in_expr(cond_expr, &mut uses, &defs);
					get_uses_in_expr(target_expr, &mut uses, &defs);
				}
				MicroInstruction::Panggil(expr) => {
					get_uses_in_expr(expr, &mut uses, &defs);
				}
				_ => {}
			}
		}
	}
	(uses, defs)
}

pub fn hitung_analisis_liveness(
	graph: &DiGraph<BasicBlock, &'static str>,
) -> LivenessInfo {
	let mut live_in: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut live_out: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut use_set: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut def_set: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let nodes: Vec<NodeIndex> = graph.node_indices().collect();
	for &node in &nodes {
		let block = graph.node_weight(node).unwrap();
		let (uses, defs) = get_uses_defs_block(block);
		use_set.insert(node, uses);
		def_set.insert(node, defs);
		live_in.insert(node, HashSet::new());
		live_out.insert(node, HashSet::new());
	}
	let mut changed = true;
	while changed {
		changed = false;
		for &node in nodes.iter().rev() {
			let mut new_out = HashSet::new();
			for successor_edge in graph.edges_directed(node, Direction::Outgoing) {
				let successor = successor_edge.target();
				if let Some(in_set) = live_in.get(&successor) {
					new_out.extend(in_set.iter().cloned());
				}
			}
			let old_out = live_out.get_mut(&node).unwrap();
			if *old_out != new_out {
				*old_out = new_out.clone();
				changed = true;
			}
			let current_uses = use_set.get(&node).unwrap();
			let current_defs = def_set.get(&node).unwrap();
			let mut out_minus_def = new_out.clone();
			for def in current_defs {
				out_minus_def.remove(def);
			}
			let mut new_in = current_uses.clone();
			new_in.extend(out_minus_def.iter().cloned());
			let old_in = live_in.get_mut(&node).unwrap();
			if *old_in != new_in {
				*old_in = new_in;
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