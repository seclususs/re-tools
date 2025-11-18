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

fn extract_base_offset(
	ekspresi: &MicroExpr,
) -> (Option<String>, Option<ValueDomain>, u64) {
	match ekspresi {
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg, .. })) => {
			(Some(id_reg.clone()), None, 0)
		}
		MicroExpr::BinaryOp(
			crate::logic::ir::instruction::MicroBinOp::Add,
			kiri,
			kanan,
		) => {
			if let MicroExpr::Operand(MicroOperand::Konstanta(offset)) = **kanan {
				let (base, idx, _) = extract_base_offset(kiri);
				(base, idx, offset)
			} else if let MicroExpr::Operand(MicroOperand::Konstanta(offset)) = **kiri {
				let (base, idx, _) = extract_base_offset(kanan);
				(base, idx, offset)
			} else {
				(None, None, 0)
			}
		}
		_ => (None, None, 0),
	}
}

pub fn infer_type_base(
	peta_state_vsa: &HashMap<NodeIndex, VsaState>,
	cfg: &DiGraph<BasicBlock, &'static str>,
	_binary: &Binary,
) -> TipeAnalysisResult {
	let mut tipe_var = HashMap::new();
	let mut struct_reconstruction = HashMap::new();
	for (idx_simpul, state) in peta_state_vsa {
		let blok = cfg.node_weight(*idx_simpul).unwrap();
		for (_va, list_instr) in &blok.instructions {
			for instr in list_instr {
				let addr_expr_opt = match instr {
					MicroInstruction::StoreMemori(addr, _) => Some(addr),
					MicroInstruction::Assign(_, ekspresi) => {
						if let MicroExpr::LoadMemori(addr) = ekspresi {
							Some(&**addr)
						} else {
							None
						}
					}
					_ => None,
				};
				if let Some(addr) = addr_expr_opt {
					let (base_reg, _, offset) = extract_base_offset(addr);
					if let Some(nama_reg) = base_reg {
						let domain_reg = state.variables.get(&nama_reg).cloned().unwrap_or_default();
						match domain_reg {
							ValueDomain::Constant(base_addr) => {
								let struct_entry = struct_reconstruction
									.entry(base_addr)
									.or_insert(InferredTipe::Struct(HashMap::new()));
								if let InferredTipe::Struct(fields) = struct_entry {
									fields
										.entry(offset)
										.or_insert(InferredTipe::Integer);
								}
								tipe_var
									.insert(nama_reg, InferredTipe::Pointer(Box::new(InferredTipe::Unknown)));
							}
							ValueDomain::Range(min, max) => {
								if min > 0x10000 && max > 0x10000 {
									tipe_var.insert(
										nama_reg.clone(),
										InferredTipe::Pointer(Box::new(InferredTipe::Unknown)),
									);
								} else {
									tipe_var
										.entry(nama_reg.clone())
										.or_insert(InferredTipe::Integer);
								}
							}
							ValueDomain::Unknown => {
								tipe_var
									.entry(nama_reg.clone())
									.or_insert(InferredTipe::Unknown);
							}
							ValueDomain::Pointer(_) | ValueDomain::PointerSet(_) => {
								tipe_var.insert(
									nama_reg.clone(),
									InferredTipe::Pointer(Box::new(InferredTipe::Unknown)),
								);
							}
						}
					}
				}
			}
		}
	}
	TipeAnalysisResult {
		var_tipe: tipe_var,
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

pub fn verify_bound_mem(
	peta_state_vsa: &HashMap<NodeIndex, VsaState>,
	cfg: &DiGraph<BasicBlock, &'static str>,
	_binary: &Binary,
) -> Vec<MemoryAccessCheck> {
	let mut list_cek = Vec::new();
	for (idx_simpul, state) in peta_state_vsa {
		let blok = cfg.node_weight(*idx_simpul).unwrap();
		for (va, list_instr) in &blok.instructions {
			for instr in list_instr {
				let addr_expr_opt = match instr {
					MicroInstruction::StoreMemori(addr, _) => Some(addr),
					MicroInstruction::Assign(_, ekspresi) => {
						if let MicroExpr::LoadMemori(addr) = ekspresi {
							Some(&**addr)
						} else {
							None
						}
					}
					_ => None,
				};
				if let Some(addr) = addr_expr_opt {
					if let (Some(base), Some(index_domain), stride, offset) =
						detect_access_array(addr, state)
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
							ValueDomain::Pointer(_) | ValueDomain::PointerSet(_) => {
								(None, "Akses menggunakan pointer".to_string())
							}
						};
						list_cek.push(MemoryAccessCheck {
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
	list_cek
}

fn detect_access_array(
	ekspresi: &MicroExpr,
	state: &VsaState,
) -> (Option<String>, Option<ValueDomain>, u64, u64) {
	if let MicroExpr::BinaryOp(
		crate::logic::ir::instruction::MicroBinOp::Add,
		kiri,
		kanan,
	) = ekspresi
	{
		if let (Some(base), Some(index_domain), stride, offset) =
			detect_access_array_inner(&**kiri, &**kanan, state)
		{
			return (Some(base), Some(index_domain), stride, offset);
		}
		if let (Some(base), Some(index_domain), stride, offset) =
			detect_access_array_inner(&**kanan, &**kiri, state)
		{
			return (Some(base), Some(index_domain), stride, offset);
		}
		if let (Some(base), Some(index_domain), stride, offset) =
			detect_access_array_inner(kanan, kiri, state)
		{
			return (Some(base), Some(index_domain), stride, offset);
		}
	} else if let MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg, .. })) = ekspresi {
		return (Some(id_reg.clone()), Some(ValueDomain::Constant(0)), 1, 0);
	}
	(None, None, 0, 0)
}

fn detect_access_array_inner(
	base_expr: &MicroExpr,
	index_expr: &MicroExpr,
	state: &VsaState,
) -> (Option<String>, Option<ValueDomain>, u64, u64) {
	let base_reg = match base_expr {
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg, .. })) => {
			Some(id_reg.clone())
		}
		_ => None,
	};
	let (index_domain, stride, offset) = match index_expr {
		MicroExpr::BinaryOp(
			crate::logic::ir::instruction::MicroBinOp::Mul,
			idx,
			stride_expr,
		) => {
			let stride_val = match **stride_expr {
				MicroExpr::Operand(MicroOperand::Konstanta(s)) => s,
				_ => 1,
			};
			let domain = match &**idx {
				MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg: nama_dasar_ref, .. })) => {
					state.variables.get(nama_dasar_ref.as_str()).cloned().unwrap_or_default()
				}
				MicroExpr::Operand(MicroOperand::Konstanta(c)) => ValueDomain::Constant(*c),
				_ => ValueDomain::Unknown,
			};
			(Some(domain), stride_val, 0)
		}
		MicroExpr::Operand(MicroOperand::SsaVar(SsaVariabel { id_reg: nama_dasar_ref, .. })) => {
			(state.variables.get(nama_dasar_ref.as_str()).cloned(), 1, 0)
		}
		MicroExpr::Operand(MicroOperand::Konstanta(c)) => (Some(ValueDomain::Constant(*c)), 1, *c),
		_ => (None, 1, 0),
	};
	(base_reg, index_domain, stride, offset)
}