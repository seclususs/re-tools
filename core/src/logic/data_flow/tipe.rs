//! Author: [Seclususs](https://github.com/seclususs)

use crate::logic::data_flow::vsa::{ValueDomain, VsaState};
use crate::logic::ir::instruction::{MicroExpr, MicroInstruction, MicroOperand, SsaVariabel};
use crate::logic::static_analysis::cfg::BasicBlock;
use crate::logic::static_analysis::parser::Binary;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum InferredTipe {
	Unknown,
	Integer,
	Pointer(Box<InferredTipe>),
	Struct(HashMap<u64, InferredTipe>),
	Array {
		element_tipe: Box<InferredTipe>,
		panjang: ValueDomain,
	},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TipeAnalysisResult {
	pub var_tipe: HashMap<String, InferredTipe>,
	pub struct_reconstruction: HashMap<u64, InferredTipe>,
}

fn get_base_reg_and_offset(
	expr: &MicroExpr,
) -> (Option<String>, Option<ValueDomain>, u64) {
	match expr {
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar, .. })) => {
			(Some(nama_dasar.clone()), None, 0)
		}
		MicroExpr::OperasiBiner(
			crate::logic::ir::instruction::MicroBinOp::Add,
			left,
			right,
		) => {
			if let MicroExpr::Operand(MicroOperand::Konstanta(offset)) = **right {
				let (base, idx, _) = get_base_reg_and_offset(left);
				(base, idx, offset)
			} else if let MicroExpr::Operand(MicroOperand::Konstanta(offset)) = **left {
				let (base, idx, _) = get_base_reg_and_offset(right);
				(base, idx, offset)
			} else {
				(None, None, 0)
			}
		}
		_ => (None, None, 0),
	}
}

pub fn analisis_tipe_dasar(
	vsa_states: &HashMap<NodeIndex, VsaState>,
	cfg: &DiGraph<BasicBlock, &'static str>,
	_binary: &Binary,
) -> TipeAnalysisResult {
	let mut var_tipe = HashMap::new();
	let mut struct_reconstruction = HashMap::new();
	for (node_idx, state) in vsa_states {
		let block = cfg.node_weight(*node_idx).unwrap();
		for (_va, instructions) in &block.instructions {
			for instruction in instructions {
				let addr_expr_opt = match instruction {
					MicroInstruction::SimpanMemori(addr_expr, _) => Some(addr_expr),
					MicroInstruction::Assign(_, expr) => {
						if let MicroExpr::MuatMemori(addr_expr) = expr {
							Some(&**addr_expr)
						} else {
							None
						}
					}
					_ => None,
				};
				if let Some(addr_expr) = addr_expr_opt {
					let (base_reg, _, offset) = get_base_reg_and_offset(addr_expr);
					if let Some(reg_name) = base_reg {
						let reg_domain = state.get(&reg_name).cloned().unwrap_or_default();
						match reg_domain {
							ValueDomain::Constant(base_addr) => {
								let struct_entry = struct_reconstruction
									.entry(base_addr)
									.or_insert(InferredTipe::Struct(HashMap::new()));
								if let InferredTipe::Struct(fields) = struct_entry {
									fields
										.entry(offset)
										.or_insert(InferredTipe::Integer);
								}
								var_tipe
									.insert(reg_name, InferredTipe::Pointer(Box::new(InferredTipe::Unknown)));
							}
							ValueDomain::Range(min, max) => {
								if min > 0x10000 && max > 0x10000 {
									var_tipe.insert(
										reg_name.clone(),
										InferredTipe::Pointer(Box::new(InferredTipe::Unknown)),
									);
								} else {
									var_tipe
										.entry(reg_name.clone())
										.or_insert(InferredTipe::Integer);
								}
							}
							ValueDomain::Unknown => {
								var_tipe
									.entry(reg_name.clone())
									.or_insert(InferredTipe::Unknown);
							}
						}
					}
				}
			}
		}
	}
	TipeAnalysisResult {
		var_tipe,
		struct_reconstruction,
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryAccessCheck {
	pub va: u64,
	pub base_reg: String,
	pub index_reg: Option<String>,
	pub index_domain: ValueDomain,
	pub stride: u64,
	pub offset: u64,
	pub info: String,
}

pub fn verifikasi_batas_memori(
	vsa_states: &HashMap<NodeIndex, VsaState>,
	cfg: &DiGraph<BasicBlock, &'static str>,
	_binary: &Binary,
) -> Vec<MemoryAccessCheck> {
	let mut checks = Vec::new();
	for (node_idx, state) in vsa_states {
		let block = cfg.node_weight(*node_idx).unwrap();
		for (va, instructions) in &block.instructions {
			for instruction in instructions {
				let addr_expr_opt = match instruction {
					MicroInstruction::SimpanMemori(addr_expr, _) => Some(addr_expr),
					MicroInstruction::Assign(_, expr) => {
						if let MicroExpr::MuatMemori(addr_expr) = expr {
							Some(&**addr_expr)
						} else {
							None
						}
					}
					_ => None,
				};
				if let Some(addr_expr) = addr_expr_opt {
					if let (Some(base), Some(index_domain), stride, offset) =
						find_array_access(addr_expr, state)
					{
						let (index_reg, info) = match index_domain {
							ValueDomain::Unknown => (None, "Indeks tidak diketahui".to_string()),
							ValueDomain::Constant(c) => {
								(None, format!("Akses konstan pada indeks {}", c))
							}
							ValueDomain::Range(min, max) => (
								None,
								format!("Potensi akses array, indeks [{}, {}]", min, max),
							),
						};
						checks.push(MemoryAccessCheck {
							va: *va,
							base_reg: base,
							index_reg,
							index_domain,
							stride,
							offset,
							info,
						});
					}
				}
			}
		}
	}
	checks
}

fn find_array_access(
	expr: &MicroExpr,
	state: &VsaState,
) -> (Option<String>, Option<ValueDomain>, u64, u64) {
	if let MicroExpr::OperasiBiner(
		crate::logic::ir::instruction::MicroBinOp::Add,
		left,
		right,
	) = expr
	{
		if let (Some(base), Some(index_domain), stride, offset) =
			find_array_access_inner(&**left, &**right, state)
		{
			return (Some(base), Some(index_domain), stride, offset);
		}
		if let (Some(base), Some(index_domain), stride, offset) =
			find_array_access_inner(&**right, &**left, state)
		{
			return (Some(base), Some(index_domain), stride, offset);
		}
		if let (Some(base), Some(index_domain), stride, offset) =
			find_array_access_inner(right, left, state)
		{
			return (Some(base), Some(index_domain), stride, offset);
		}
	} else if let MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar, .. })) = expr {
		return (Some(nama_dasar.clone()), Some(ValueDomain::Constant(0)), 1, 0);
	}
	(None, None, 0, 0)
}

fn find_array_access_inner(
	base_expr: &MicroExpr,
	index_expr: &MicroExpr,
	state: &VsaState,
) -> (Option<String>, Option<ValueDomain>, u64, u64) {
	let base_reg = match base_expr {
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar, .. })) => {
			Some(nama_dasar.clone())
		}
		_ => None,
	};
	let (index_domain, stride, offset) = match index_expr {
		MicroExpr::OperasiBiner(
			crate::logic::ir::instruction::MicroBinOp::Mul,
			idx,
			stride_expr,
		) => {
			let stride_val = match **stride_expr {
				MicroExpr::Operand(MicroOperand::Konstanta(s)) => s,
				_ => 1,
			};
			let domain = match &**idx {
				MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar: nama_dasar_ref, .. })) => {
					state.get(nama_dasar_ref.as_str()).cloned().unwrap_or_default()
				}
				MicroExpr::Operand(MicroOperand::Konstanta(c)) => ValueDomain::Constant(*c),
				_ => ValueDomain::Unknown,
			};
			(Some(domain), stride_val, 0)
		}
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { nama_dasar: nama_dasar_ref, .. })) => {
			(state.get(nama_dasar_ref.as_str()).cloned(), 1, 0)
		}
		MicroExpr::Operand(MicroOperand::Konstanta(c)) => (Some(ValueDomain::Constant(*c)), 1, *c),
		_ => (None, 1, 0),
	};
	(base_reg, index_domain, stride, offset)
}