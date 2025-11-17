//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::ir::instruction::{MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};
use crate::logic::static_analysis::cfg::BasicBlock;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Hash)]
pub enum ValueDomain {
	Unknown,
	Constant(u64),
	Range(u64, u64),
}

impl ValueDomain {
	pub fn meet(&self, other: &Self) -> Self {
		match (self, other) {
			(ValueDomain::Unknown, _) | (_, ValueDomain::Unknown) => ValueDomain::Unknown,
			(ValueDomain::Constant(c1), ValueDomain::Constant(c2)) => {
				if *c1 == *c2 {
					ValueDomain::Constant(*c1)
				} else {
					ValueDomain::Range(std::cmp::min(*c1, *c2), std::cmp::max(*c1, *c2))
				}
			}
			(ValueDomain::Constant(c), ValueDomain::Range(min, max))
			| (ValueDomain::Range(min, max), ValueDomain::Constant(c)) => {
				ValueDomain::Range(std::cmp::min(*c, *min), std::cmp::max(*c, *max))
			}
			(ValueDomain::Range(min1, max1), ValueDomain::Range(min2, max2)) => {
				ValueDomain::Range(std::cmp::min(*min1, *min2), std::cmp::max(*max1, *max2))
			}
		}
	}
	pub fn add(&self, other: &Self) -> Self {
		match (self, other) {
			(ValueDomain::Constant(c1), ValueDomain::Constant(c2)) => {
				ValueDomain::Constant(c1.wrapping_add(*c2))
			}
			(ValueDomain::Constant(c), ValueDomain::Range(min, max))
			| (ValueDomain::Range(min, max), ValueDomain::Constant(c)) => {
				ValueDomain::Range(min.wrapping_add(*c), max.wrapping_add(*c))
			}
			(ValueDomain::Range(min1, max1), ValueDomain::Range(min2, max2)) => {
				ValueDomain::Range(min1.wrapping_add(*min2), max1.wrapping_add(*max2))
			}
			_ => ValueDomain::Unknown,
		}
	}
	pub fn sub(&self, other: &Self) -> Self {
		match (self, other) {
			(ValueDomain::Constant(c1), ValueDomain::Constant(c2)) => {
				ValueDomain::Constant(c1.wrapping_sub(*c2))
			}
			(ValueDomain::Range(min, max), ValueDomain::Constant(c)) => {
				ValueDomain::Range(min.wrapping_sub(*c), max.wrapping_sub(*c))
			}
			(ValueDomain::Constant(c), ValueDomain::Range(min, max)) => {
				ValueDomain::Range(c.wrapping_sub(*max), c.wrapping_sub(*min))
			}
			(ValueDomain::Range(min1, max1), ValueDomain::Range(min2, max2)) => {
				ValueDomain::Range(min1.wrapping_sub(*max2), max1.wrapping_sub(*min2))
			}
			_ => ValueDomain::Unknown,
		}
	}
}

impl Default for ValueDomain {
	fn default() -> Self {
		ValueDomain::Unknown
	}
}

pub type VsaState = HashMap<String, ValueDomain>;

fn eval_expr(expr: &MicroExpr, state: &VsaState) -> ValueDomain {
	match expr {
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar, .. })) => {
			state.get(nama_dasar).cloned().unwrap_or_default()
		}
		MicroExpr::Operand(MicroOperand::Konstanta(c)) => ValueDomain::Constant(*c),
		MicroExpr::OperasiUnary(_, inner) => eval_expr(inner, state),
		MicroExpr::OperasiBiner(op, left, right) => {
			let v1 = eval_expr(left, state);
			let v2 = eval_expr(right, state);
			match op {
				crate::logic::ir::instruction::MicroBinOp::Add => v1.add(&v2),
				crate::logic::ir::instruction::MicroBinOp::Sub => v1.sub(&v2),
				_ => ValueDomain::Unknown,
			}
		}
		MicroExpr::MuatMemori(_) => ValueDomain::Unknown,
		_ => ValueDomain::Unknown,
	}
}

fn transfer_function(block: &BasicBlock, state_in: &VsaState) -> VsaState {
	let mut state_out = state_in.clone();
	for (_, instructions) in &block.instructions {
		for instruction in instructions {
			if let MicroInstruction::Assign(SsaVariabel { nama_dasar, .. }, expr) = instruction {
				let value = eval_expr(expr, &state_out);
				state_out.insert(nama_dasar.clone(), value);
			}
		}
	}
	state_out
}

pub fn analisis_value_set(
	graph: &DiGraph<BasicBlock, &'static str>,
) -> HashMap<NodeIndex, (VsaState, VsaState)> {
	let mut in_states: HashMap<NodeIndex, VsaState> = HashMap::new();
	let mut out_states: HashMap<NodeIndex, VsaState> = HashMap::new();
	let nodes: Vec<NodeIndex> = graph.node_indices().collect();
	for &node in &nodes {
		in_states.insert(node, VsaState::new());
		out_states.insert(node, VsaState::new());
	}
	let mut changed = true;
	while changed {
		changed = false;
		for &node in &nodes {
			let mut new_in = VsaState::new();
			let mut predecessors = graph.neighbors_directed(node, Direction::Incoming);
			if let Some(pred_node) = predecessors.next() {
				new_in = out_states.get(&pred_node).unwrap().clone();
				for pred_node in predecessors {
					let pred_out = out_states.get(&pred_node).unwrap();
					for (var, domain) in pred_out {
						let current_domain = new_in.entry(var.clone()).or_default();
						*current_domain = current_domain.meet(domain);
					}
				}
			}
			if *in_states.get(&node).unwrap() != new_in {
				in_states.insert(node, new_in.clone());
				changed = true;
			}
			let new_out = transfer_function(graph.node_weight(node).unwrap(), &new_in);
			if *out_states.get(&node).unwrap() != new_out {
				out_states.insert(node, new_out);
				changed = true;
			}
		}
	}
	nodes
		.into_iter()
		.map(|node| {
			(
				node,
				(
					in_states.remove(&node).unwrap(),
					out_states.remove(&node).unwrap(),
				),
			)
		})
		.collect()
}