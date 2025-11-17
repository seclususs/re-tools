//! Author: [Seclususs](https://github.com/seclususs)

#![allow(non_snake_case)]
use crate::error::ReToolsError;
use crate::logic::static_analysis::parser::{Binary, SectionInfo};
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::ir::lifter::angkat_blok_instruksi;
use crate::logic::ir::instruction::{MicroInstruction, MicroOperand, MicroExpr};

use log::{debug, info, warn};
use petgraph::dot::Dot;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::algo::dominators::{self, Dominators};
use petgraph::visit::{EdgeRef, IntoNodeIdentifiers};
use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone)]
pub struct BasicBlock {
	pub va_start: u64,
	pub va_end: u64,
	pub instructions: Vec<(u64, Vec<MicroInstruction>)>,
	pub size: u64,
}

impl fmt::Display for BasicBlock {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		if self.va_start == 0 && self.size == 0 && self.instructions.is_empty() {
			return write!(f, "TARGET_LOMPAT_DINAMIS\\n(unresolved)");
		}
		let mut label = format!("0x{:x} (size: {} bytes):\\n", self.va_start, self.size);
		for (va, irs) in &self.instructions {
			for ir in irs {
				let ir_str = format!("{:?}", ir)
					.replace('"', "\\\"")
					.replace('\n', "\\n")
					.replace('<', "\\<")
					.replace('>', "\\>");
				label.push_str(&format!("  0x{:x}: {}\\n", va, ir_str));
			}
		}
		write!(f, "{}", label)
	}
}

fn va_to_offset(va: u64, sections: &[SectionInfo]) -> Option<u64> {
	for sec in sections {
		if va >= sec.addr && va < (sec.addr + sec.size) {
			let relative_offset = va - sec.addr;
			return Some(sec.offset + relative_offset);
		}
	}
	None
}

fn baca_pointer_di_va(va: u64, binary: &Binary) -> Option<u64> {
	let offset = va_to_offset(va, &binary.sections)? as usize;
	let data = &binary.file_data;
	if binary.header.bits == 64 {
		if offset + 8 <= data.len() {
			let bytes: [u8; 8] = data[offset..offset + 8].try_into().ok()?;
			Some(u64::from_le_bytes(bytes))
		} else {
			None
		}
	} else {
		if offset + 4 <= data.len() {
			let bytes: [u8; 4] = data[offset..offset + 4].try_into().ok()?;
			Some(u32::from_le_bytes(bytes) as u64)
		} else {
			None
		}
	}
}

fn ekstrak_basis_tabel(expr: &MicroExpr) -> Option<u64> {
	match expr {
		MicroExpr::Operand(MicroOperand::Konstanta(imm)) => Some(*imm),
		MicroExpr::OperasiBiner(_, left, right) => {
			ekstrak_basis_tabel(left).or_else(|| ekstrak_basis_tabel(right))
		}
		MicroExpr::Operand(MicroOperand::SsaVar(_)) => None,
		MicroExpr::MuatMemori(inner) => ekstrak_basis_tabel(inner),
		_ => None,
	}
}

fn pindai_target_tabel(base_va: u64, binary: &Binary) -> Vec<u64> {
	let mut targets = Vec::new();
	let pointer_size = if binary.header.bits == 64 { 8 } else { 4 };
	let text_section = binary.sections.iter().find(|s| s.name.starts_with(".text"));
	let (text_start, text_end) = if let Some(sec) = text_section {
		(sec.addr, sec.addr + sec.size)
	} else {
		(0, u64::MAX)
	};
	for i in 0..256 {
		let current_va = base_va + (i * pointer_size);
		match baca_pointer_di_va(current_va, binary) {
			Some(target_va) => {
				if target_va >= text_start && target_va < text_end {
					if targets.contains(&target_va) {
						continue;
					}
					targets.push(target_va);
				} else {
					break;
				}
			}
			None => {
				break;
			}
		}
	}
	targets
}

fn tentukan_target_lompat(expr: &MicroExpr, binary: &Binary) -> Vec<u64> {
	match expr {
		MicroExpr::Operand(MicroOperand::Konstanta(imm)) => {
			vec![*imm]
		}
		MicroExpr::MuatMemori(mem_expr) => {
			match ekstrak_basis_tabel(mem_expr) {
				Some(base_va) => {
					let targets = pindai_target_tabel(base_va, binary);
					if !targets.is_empty() {
						targets
					} else {
						if let MicroExpr::Operand(MicroOperand::Konstanta(va)) = **mem_expr {
							baca_pointer_di_va(va, binary).map_or(vec![], |target| vec![target])
						} else {
							vec![]
						}
					}
				}
				None => vec![]
			}
		}
		MicroExpr::OperasiBiner(_, left, right) => {
			let mut targets = tentukan_target_lompat(left, binary);
			targets.extend(tentukan_target_lompat(right, binary));
			targets
		}
		_ => vec![],
	}
}

fn is_ir_branch(ir: &MicroInstruction) -> bool {
	matches!(ir, MicroInstruction::Lompat(_) | MicroInstruction::LompatKondisi(_, _) | MicroInstruction::Kembali | MicroInstruction::Panggil(_))
}

pub fn bangun_cfg_internal(binary: &Binary) -> Result<DiGraph<BasicBlock, &'static str>, ReToolsError> {
	info!("Mulai bangun CFG (IR-based) untuk: {}", binary.file_path);
	let text_section = binary
		.sections
		.iter()
		.find(|s| s.name.starts_with(".text") || (s.flags & 0x4) != 0 || (s.flags & 0x20000000) != 0);
	let (text_data, base_addr) = if let Some(section) = text_section {
		info!(
			"Section executable ditemukan: {} addr=0x{:x}, size=0x{:x}",
			section.name, section.addr, section.size
		);
		let text_data_offset = section.offset as usize;
		let text_data_size = section.size as usize;
		if text_data_offset
			.saturating_add(text_data_size)
			> binary.file_data.len()
		{
			return Err(ReToolsError::ParseError(
				"Section .text di luar batas file".to_string(),
			));
		}
		let data_slice = &binary.file_data[text_data_offset..(text_data_offset + text_data_size)];
		(data_slice, section.addr)
	} else {
		warn!("Section .text tidak ditemukan");
		return Err(ReToolsError::ParseError(
			"Section .text tidak ditemukan".to_string(),
		));
	};
	let arch_disasm = binary.header.get_disasm_arch();
	if arch_disasm == ArsitekturDisasm::ARCH_UNKNOWN {
		return Err(ReToolsError::ParseError(format!(
			"Arsitektur tidak didukung untuk CFG: {}/{} bits",
			binary.header.arch, binary.header.bits
		)));
	}
	let mut lifted_instructions = HashMap::new();
	let mut offset: usize = 0;
	while offset < text_data.len() {
		let va = base_addr + offset as u64;
		let (size, irs) = match angkat_blok_instruksi(&text_data[offset..], va, arch_disasm) {
			Ok((size, ir_vec)) if size > 0 => (size, ir_vec),
			_ => (1, vec![MicroInstruction::TidakTerdefinisi]),
		};
		if size == 0 { 
			warn!("Disasm size 0 pada 0x{:x}, break", va);
			break; 
		}
		lifted_instructions.insert(va, (irs, size));
		offset += size;
	}
	info!("Pass 0 (Angkat IR) selesai. {} instruksi diangkat.", lifted_instructions.len());
	let mut leaders = HashSet::new();
	let mut worklist = Vec::new();
	let entry_point = binary.header.entry_point;
	let text_end_va = base_addr + text_data.len() as u64;
	if entry_point >= base_addr && entry_point < text_end_va {
		 worklist.push(entry_point);
		 leaders.insert(entry_point);
	} else {
		warn!("Entry point 0x{:x} di luar .text section (0x{:x} - 0x{:x}). Mulai dari basis .text.", entry_point, base_addr, text_end_va);
		worklist.push(base_addr);
		leaders.insert(base_addr);
	}
	for sym in &binary.symbols {
		if sym.symbol_type == "FUNC" && sym.addr >= base_addr && sym.addr < text_end_va {
			if leaders.insert(sym.addr) {
				worklist.push(sym.addr);
			}
		}
	}
	info!("Pass 1 (Leader Discovery) mulai dengan {} entries...", worklist.len());
	while let Some(current_va) = worklist.pop() {
		let mut va = current_va;
		loop {
			let (irs, size) = match lifted_instructions.get(&va) {
				Some((irs, size)) => (irs.clone(), *size),
				None => {
					break;
				}
			};
			if size == 0 { break; }
			if let Some(last_ir) = irs.last() {
				if is_ir_branch(last_ir) {
					let fallthrough_va = va + size as u64;
					if fallthrough_va < text_end_va && leaders.insert(fallthrough_va) {
						worklist.push(fallthrough_va);
					}
					let targets = match last_ir {
						MicroInstruction::Lompat(expr) => tentukan_target_lompat(expr, binary),
						MicroInstruction::LompatKondisi(_, expr) => tentukan_target_lompat(expr, binary),
						MicroInstruction::Panggil(expr) => tentukan_target_lompat(expr, binary),
						_ => vec![]
					};
					for target_va in targets {
						if target_va >= base_addr && target_va < text_end_va && leaders.insert(target_va) {
							worklist.push(target_va);
						}
					}
					break;
				}
			}
			va += size as u64;
			if va >= text_end_va || leaders.contains(&va) {
				break;
			}
		}
	}
	info!("Pass 1 selesai. Ditemukan {} leaders", leaders.len());
	let mut graph = DiGraph::<BasicBlock, &'static str>::new();
	let mut node_map = HashMap::<u64, NodeIndex>::new();
	let dynamic_jump_node = graph.add_node(BasicBlock {
		va_start: 0,
		va_end: 0,
		instructions: Vec::new(),
		size: 0,
	});
	let mut sorted_leaders: Vec<u64> = leaders.iter().cloned().collect();
	sorted_leaders.sort();
	debug!("Pass 2: Membuat basic blocks");
	for &leader_va in &sorted_leaders {
		if node_map.contains_key(&leader_va) {
			continue;
		}
		let mut block_instrs: Vec<(u64, Vec<MicroInstruction>)> = Vec::new();
		let mut current_addr = leader_va;
		let mut block_size: u64 = 0;
		loop {
			let (irs, size) = match lifted_instructions.get(&current_addr) {
				Some((irs, size)) => (irs.clone(), *size),
				None => {
					break;
				}
			};
			if size == 0 {
				 break;
			}
			let last_ir = irs.last().cloned();
			block_instrs.push((current_addr, irs));
			block_size += size as u64;
			current_addr += size as u64;
			if let Some(ir) = last_ir {
				if is_ir_branch(&ir) {
					break;
				}
			}
			if leaders.contains(&current_addr) || current_addr >= text_end_va {
				break;
			}
		}
		let block = BasicBlock {
			va_start: leader_va,
			va_end: current_addr,
			instructions: block_instrs,
			size: block_size,
		};
		let node_idx = graph.add_node(block);
		node_map.insert(leader_va, node_idx);
	}
	info!("Pass 2 selesai. Dibuat {} nodes", graph.node_count());
	debug!("Pass 3: Menghubungkan edges");
	let mut edges_to_add = Vec::new();
	for (&_va, &node_idx) in &node_map {
		let block = match graph.node_weight(node_idx) {
			Some(b) => b,
			None => continue,
		};
		let fallthrough_va = block.va_end;
		let last_ir = block.instructions.last().and_then(|(_, irs)| irs.last());
		if last_ir.is_none() {
			if let Some(fallthrough_idx) = node_map.get(&fallthrough_va) {
				edges_to_add.push((node_idx, *fallthrough_idx, "Fallthrough"));
			}
			continue;
		}
		match last_ir.unwrap() {
			MicroInstruction::Lompat(target_expr) => {
				let targets = tentukan_target_lompat(target_expr, binary);
				if targets.is_empty() {
					edges_to_add.push((node_idx, dynamic_jump_node, "Jump (Dynamic)"));
				} else {
					for target_va in targets {
						if let Some(target_idx) = node_map.get(&target_va) {
							edges_to_add.push((node_idx, *target_idx, "Jump"));
						}
					}
				}
			}
			MicroInstruction::LompatKondisi(_, target_expr) => {
				let targets = tentukan_target_lompat(target_expr, binary);
				if targets.is_empty() {
					edges_to_add.push((node_idx, dynamic_jump_node, "Jump (True, Dynamic)"));
				} else {
					 for target_va in targets {
						if let Some(target_idx) = node_map.get(&target_va) {
							edges_to_add.push((node_idx, *target_idx, "Jump (True)"));
						}
					}
				}
				if let Some(fallthrough_idx) = node_map.get(&fallthrough_va) {
					edges_to_add.push((node_idx, *fallthrough_idx, "Fallthrough (False)"));
				}
			}
			MicroInstruction::Kembali => {
			}
			MicroInstruction::Panggil(_) => {
				 if let Some(fallthrough_idx) = node_map.get(&fallthrough_va) {
					edges_to_add.push((node_idx, *fallthrough_idx, "Fallthrough (Call)"));
				}
			}
			_ => {
				if let Some(fallthrough_idx) = node_map.get(&fallthrough_va) {
					edges_to_add.push((node_idx, *fallthrough_idx, "Fallthrough"));
				}
			}
		}
	}
	for (source, target, label) in edges_to_add {
		graph.add_edge(source, target, label);
	}
	info!("Pass 3 selesai. Dibuat {} edges", graph.edge_count());
	Ok(graph)
}

pub fn generateCfgGraph(binary: &Binary) -> Result<String, ReToolsError> {
	let graph = bangun_cfg_internal(binary)?;
	let dot_str = Dot::with_config(&graph, &[]);
	Ok(format!("{}", dot_str))
}

pub fn hitungDominators(graph: &DiGraph<BasicBlock, &'static str>, entry_node: NodeIndex) -> Dominators<NodeIndex> {
	dominators::simple_fast(graph, entry_node)
}

pub fn deteksiNaturalLoops(graph: &DiGraph<BasicBlock, &'static str>, doms: &Dominators<NodeIndex>) -> Vec<NodeIndex> {
	let mut headers = HashSet::new();
	for edge in graph.edge_references() {
		let source_node = edge.source();
		let target_node = edge.target();
		if doms.dominators(source_node).map_or(false, |mut iter| iter.any(|d| d == target_node)) {
			headers.insert(target_node);
		}
	}
	headers.into_iter().collect()
}

pub fn cariFunctionExits(graph: &DiGraph<BasicBlock, &'static str>) -> Vec<NodeIndex> {
	let mut exit_nodes = Vec::new();
	for node_idx in graph.node_identifiers() {
		if let Some(block) = graph.node_weight(node_idx) {
			if let Some((_, last_irs)) = block.instructions.last() {
				if let Some(MicroInstruction::Kembali) = last_irs.last() {
					exit_nodes.push(node_idx);
				}
			}
		}
	}
	exit_nodes
}