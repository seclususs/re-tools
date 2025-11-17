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

fn get_uses_in_expr(expr: &MicroExpr) -> HashSet<String> {
	let mut uses = HashSet::new();
	let mut stack = vec![expr];
	while let Some(e) = stack.pop() {
		match e {
			MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar, .. })) => {
				uses.insert(nama_dasar.clone());
			}
			MicroExpr::OperasiUnary(_, inner) => stack.push(inner),
			MicroExpr::OperasiBiner(_, left, right)
			| MicroExpr::Bandingkan(left, right)
			| MicroExpr::UjiBit(left, right) => {
				stack.push(left);
				stack.push(right);
			}
			MicroExpr::MuatMemori(inner) => stack.push(inner),
			_ => {}
		}
	}
	uses
}

pub fn bangun_chains_reaching_defs(
	graph: &DiGraph<BasicBlock, &'static str>,
) -> (ReachingDefsInfo, DefUseChains, UseDefChains) {
	let mut gen_sets: HashMap<NodeIndex, ReachingDefSet> = HashMap::new();
	let mut kill_sets: HashMap<NodeIndex, HashSet<String>> = HashMap::new();
	let mut in_sets: HashMap<NodeIndex, ReachingDefSet> = HashMap::new();
	let mut out_sets: HashMap<NodeIndex, ReachingDefSet> = HashMap::new();
	let nodes: Vec<NodeIndex> = graph.node_indices().collect();
	for &node in &nodes {
		let block = graph.node_weight(node).unwrap();
		let mut r#gen = ReachingDefSet::new();
		let mut kill = HashSet::new();
		let mut instruction_index = 0;
		for (_, instructions) in &block.instructions {
			for instruction in instructions {
				if let MicroInstruction::Assign(SsaVariabel { nama_dasar, .. }, _) = instruction {
					let loc = DefLocation {
						block_id: node.index(),
						instruction_index,
					};
					if !kill.contains(nama_dasar) {
						r#gen.entry(nama_dasar.clone()).or_default().insert(loc);
					}
					kill.insert(nama_dasar.clone());
				}
				instruction_index += 1;
			}
		}
		gen_sets.insert(node, r#gen);
		kill_sets.insert(node, kill);
		in_sets.insert(node, HashMap::new());
		out_sets.insert(node, HashMap::new());
	}
	let mut changed = true;
	while changed {
		changed = false;
		for &node in &nodes {
			let mut new_in = ReachingDefSet::new();
			for pred_edge in graph.edges_directed(node, Direction::Incoming) {
				let pred = pred_edge.source();
				if let Some(pred_out) = out_sets.get(&pred) {
					for (var, defs) in pred_out {
						new_in.entry(var.clone()).or_default().extend(defs.iter().cloned());
					}
				}
			}
			let r#gen = gen_sets.get(&node).unwrap();
			let kill = kill_sets.get(&node).unwrap();
			let mut new_out = new_in.clone();
			for var_killed in kill {
				new_out.remove(var_killed);
			}
			for (var_gen, defs_gen) in r#gen {
				new_out.entry(var_gen.clone()).or_default().clear();
				new_out.entry(var_gen.clone()).or_default().extend(defs_gen.iter().cloned());
			}
			let old_out = out_sets.get_mut(&node).unwrap();
			if *old_out != new_out {
				*old_out = new_out;
				changed = true;
			}
		}
	}
	let mut def_use_chains: HashMap<String, HashMap<DefLocation, HashSet<UseLocation>>> = HashMap::new();
	let mut use_def_chains: HashMap<String, HashMap<UseLocation, HashSet<DefLocation>>> = HashMap::new();
	for &node in &nodes {
		let block = graph.node_weight(node).unwrap();
		let mut current_defs = in_sets.get(&node).unwrap().clone();
		let mut instruction_index = 0;
		for (_, instructions) in &block.instructions {
			for instruction in instructions {
				let mut uses = HashSet::new();
				match instruction {
					MicroInstruction::Assign(_, expr) => uses.extend(get_uses_in_expr(expr)),
					MicroInstruction::SimpanMemori(addr_expr, data_expr) => {
						uses.extend(get_uses_in_expr(addr_expr));
						uses.extend(get_uses_in_expr(data_expr));
					}
					MicroInstruction::Lompat(expr) => uses.extend(get_uses_in_expr(expr)),
					MicroInstruction::LompatKondisi(cond_expr, target_expr) => {
						uses.extend(get_uses_in_expr(cond_expr));
						uses.extend(get_uses_in_expr(target_expr));
					}
					MicroInstruction::Panggil(expr) => uses.extend(get_uses_in_expr(expr)),
					_ => {}
				}
				let use_loc = UseLocation { block_id: node.index(), instruction_index };
				for var_used in &uses {
					if let Some(defs) = current_defs.get(var_used) {
						use_def_chains.entry(var_used.clone()).or_default().entry(use_loc.clone()).or_default().extend(defs.iter().cloned());
						for def in defs {
							def_use_chains.entry(var_used.clone()).or_default().entry(def.clone()).or_default().insert(use_loc.clone());
						}
					}
				}
				if let MicroInstruction::Assign(SsaVariabel { nama_dasar, .. }, _) = instruction {
					let def_loc = DefLocation { block_id: node.index(), instruction_index };
					current_defs.entry(nama_dasar.clone()).or_default().clear();
					current_defs.entry(nama_dasar.clone()).or_default().insert(def_loc);
				}
				instruction_index += 1;
			}
		}
	}
	(
		ReachingDefsInfo { in_sets, out_sets },
		DefUseChains { chains: def_use_chains },
		UseDefChains { chains: use_def_chains }
	)
}