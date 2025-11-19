//! Author: [Seclususs](https://github.com/seclususs)

#![allow(non_snake_case)]
use crate::error::ReToolsError;
use crate::logic::static_analysis::parser::{Binary, SectionInfo};
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::ir::lifter::lift_blok_instr;
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

fn read_ptr_at_va(va: u64, binary: &Binary) -> Option<u64> {
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

fn extract_base_table(expr: &MicroExpr) -> Option<u64> {
	match expr {
		MicroExpr::Operand(MicroOperand::Konstanta(imm)) => Some(*imm),
		MicroExpr::BinaryOp(_, left, right) => {
			extract_base_table(left).or_else(|| extract_base_table(right))
		}
		MicroExpr::Operand(MicroOperand::SsaVar(_)) => None,
		MicroExpr::LoadMemori(inner) => extract_base_table(inner),
		_ => None,
	}
}

fn scan_target_table(va_basis: u64, binary: &Binary, sz_limit: usize) -> Vec<u64> {
	let mut list_target = Vec::new();
	let sz_ptr = if binary.header.bits == 64 { 8 } else { 4 };
	let seksi_teks = binary.sections.iter().find(|s| s.name.starts_with(".text"));
	let (va_mulai, va_akhir) = if let Some(sec) = seksi_teks {
		(sec.addr, sec.addr + sec.size)
	} else {
		(0, u64::MAX)
	};
	let max_entries = if sz_limit > 0 { sz_limit } else { 256 };
	for i in 0..max_entries {
		let va_kini = va_basis + (i as u64 * sz_ptr);
		match read_ptr_at_va(va_kini, binary) {
			Some(va_target) => {
				if va_target >= va_mulai && va_target < va_akhir {
					if list_target.contains(&va_target) {
						continue;
					}
					list_target.push(va_target);
				} else {
					break;
				}
			}
			None => {
				break;
			}
		}
	}
	list_target
}

fn detect_bounds_check(
	prev_instructions: &[MicroInstruction], 
	reg_index: &str
) -> Option<usize> {
	for instr in prev_instructions.iter().rev() {
		if let MicroInstruction::UpdateFlag(_, expr_flag) = instr {
			if let MicroExpr::UnaryOp(_, inner) = expr_flag {
				if let MicroExpr::Compare(left, right) = &**inner {
					match (&**left, &**right) {
						(MicroExpr::Operand(MicroOperand::SsaVar(v)), MicroExpr::Operand(MicroOperand::Konstanta(k))) 
						if v.id_reg == reg_index => return Some(*k as usize),
						(MicroExpr::Operand(MicroOperand::Konstanta(k)), MicroExpr::Operand(MicroOperand::SsaVar(v))) 
						if v.id_reg == reg_index => return Some(*k as usize),
						_ => {}
					}
				}
			}
		}
	}
	None
}

fn extract_index_reg(expr: &MicroExpr) -> Option<String> {
	match expr {
		MicroExpr::Operand(MicroOperand::SsaVar(v)) => Some(v.id_reg.clone()),
		MicroExpr::BinaryOp(_, left, right) => {
			extract_index_reg(left).or_else(|| extract_index_reg(right))
		}
		MicroExpr::LoadMemori(inner) => extract_index_reg(inner),
		_ => None,
	}
}

fn determine_target_jump(
	expr: &MicroExpr, 
	binary: &Binary,
	prev_instructions: &[MicroInstruction]
) -> Vec<u64> {
	match expr {
		MicroExpr::Operand(MicroOperand::Konstanta(imm)) => {
			vec![*imm]
		}
		MicroExpr::LoadMemori(mem_expr) => {
			match extract_base_table(mem_expr) {
				Some(va_basis) => {
					let sz_limit = if let Some(reg) = extract_index_reg(mem_expr) {
						detect_bounds_check(prev_instructions, &reg).unwrap_or(0)
					} else {
						0
					};
					let list_target = scan_target_table(va_basis, binary, sz_limit);
					if !list_target.is_empty() {
						list_target
					} else {
						if let MicroExpr::Operand(MicroOperand::Konstanta(va)) = **mem_expr {
							read_ptr_at_va(va, binary).map_or(vec![], |target| vec![target])
						} else {
							vec![]
						}
					}
				}
				None => vec![]
			}
		}
		MicroExpr::BinaryOp(_, left, right) => {
			let mut list_target = determine_target_jump(left, binary, prev_instructions);
			list_target.extend(determine_target_jump(right, binary, prev_instructions));
			list_target
		}
		_ => vec![],
	}
}

fn is_ir_branch(ir: &MicroInstruction) -> bool {
	matches!(ir, MicroInstruction::Jump(_) | MicroInstruction::JumpKondisi(_, _) | MicroInstruction::Return | MicroInstruction::Call(_))
}

pub fn build_cfg_internal(
    biner: &Binary,
    peta_target_dinamis: Option<&HashMap<u64, u64>>
) -> Result<DiGraph<BasicBlock, &'static str>, ReToolsError> {
	info!("Mulai bangun CFG (IR-based) untuk: {}", biner.path_berkas);
	let seksi_teks = biner
		.sections
		.iter()
		.find(|s| s.name.starts_with(".text") || (s.flags & 0x4) != 0 || (s.flags & 0x20000000) != 0);
	let (data_teks, va_basis) = if let Some(section) = seksi_teks {
		info!(
			"Section executable ditemukan: {} addr=0x{:x}, size=0x{:x}",
			section.name, section.addr, section.size
		);
		let off_data = section.offset as usize;
		let sz_data = section.size as usize;
		if off_data
			.saturating_add(sz_data)
			> biner.file_data.len()
		{
			return Err(ReToolsError::ParseError(
				"Section .text di luar batas file".to_string(),
			));
		}
		let slice_data = &biner.file_data[off_data..(off_data + sz_data)];
		(slice_data, section.addr)
	} else {
		warn!("Section .text tidak ditemukan");
		return Err(ReToolsError::ParseError(
			"Section .text tidak ditemukan".to_string(),
		));
	};
	let arch_disasm = biner.header.get_disasm_arch();
	if arch_disasm == ArsitekturDisasm::ARCH_UNKNOWN {
		return Err(ReToolsError::ParseError(format!(
			"Arsitektur tidak didukung untuk CFG: {}/{} bits",
			biner.header.arch, biner.header.bits
		)));
	}
	let mut map_instr_lifted: HashMap<u64, (Vec<MicroInstruction>, usize)> = HashMap::new();
	let mut off_set: usize = 0;
	while off_set < data_teks.len() {
		let va_kini = va_basis + off_set as u64;
		let (sz_instr, vec_ir) = match lift_blok_instr(&data_teks[off_set..], va_kini, arch_disasm) {
			Ok((size, ir_vec)) if size > 0 => (size, ir_vec),
			_ => (1, vec![MicroInstruction::Undefined]),
		};
		if sz_instr == 0 { 
			warn!("Disasm size 0 pada 0x{:x}, break", va_kini);
			break; 
		}
		map_instr_lifted.insert(va_kini, (vec_ir, sz_instr));
		off_set += sz_instr;
	}
	info!("Pass 0 (Angkat IR) selesai. {} instruksi diangkat.", map_instr_lifted.len());
	let mut set_leader = HashSet::new();
	let mut list_kerja = Vec::new();
	let entry_point = biner.header.addr_masuk;
	let va_akhir_teks = va_basis + data_teks.len() as u64;
	if entry_point >= va_basis && entry_point < va_akhir_teks {
		 list_kerja.push(entry_point);
		 set_leader.insert(entry_point);
	} else {
		warn!("Entry point 0x{:x} di luar .text section (0x{:x} - 0x{:x}). Mulai dari basis .text.", entry_point, va_basis, va_akhir_teks);
		list_kerja.push(va_basis);
		set_leader.insert(va_basis);
	}
	for sym in &biner.symbols {
		if sym.symbol_type == "FUNC" && sym.addr >= va_basis && sym.addr < va_akhir_teks {
			if set_leader.insert(sym.addr) {
				list_kerja.push(sym.addr);
			}
		}
	}
    if let Some(peta_dinamis) = peta_target_dinamis {
        for (_, va_target) in peta_dinamis {
             if *va_target >= va_basis && *va_target < va_akhir_teks {
                if set_leader.insert(*va_target) {
                    list_kerja.push(*va_target);
                    info!("Menambahkan leader dari trace dinamis: 0x{:x}", va_target);
                }
            }
        }
    }
	info!("Pass 1 (Leader Discovery) mulai dengan {} entries...", list_kerja.len());
	while let Some(va_saat_ini) = list_kerja.pop() {
		let mut va_kini = va_saat_ini;
		loop {
			let (vec_ir, sz_instr) = match map_instr_lifted.get(&va_kini) {
				Some((irs, size)) => (irs.clone(), *size),
				None => {
					break;
				}
			};
			if sz_instr == 0 { break; }
			if let Some(ir_akhir) = vec_ir.last() {
				if is_ir_branch(ir_akhir) {
					let va_lanjut = va_kini + sz_instr as u64;
					if va_lanjut < va_akhir_teks && set_leader.insert(va_lanjut) {
						list_kerja.push(va_lanjut);
					}
                    let mut list_target = Vec::new();
                    if let Some(peta_dinamis) = peta_target_dinamis {
                        if let Some(target_dinamis) = peta_dinamis.get(&va_kini) {
                             list_target.push(*target_dinamis);
                        }
                    }
                    if list_target.is_empty() {
                        list_target = match ir_akhir {
                            MicroInstruction::Jump(expr) => determine_target_jump(expr, biner, &vec_ir),
                            MicroInstruction::JumpKondisi(_, expr) => determine_target_jump(expr, biner, &vec_ir),
                            MicroInstruction::Call(expr) => determine_target_jump(expr, biner, &vec_ir),
                            _ => vec![]
                        };
                    }
					for va_target in list_target {
						if va_target >= va_basis && va_target < va_akhir_teks && set_leader.insert(va_target) {
							list_kerja.push(va_target);
						}
					}
					break;
				}
			}
			va_kini += sz_instr as u64;
			if va_kini >= va_akhir_teks || set_leader.contains(&va_kini) {
				break;
			}
		}
	}
	info!("Pass 1 selesai. Ditemukan {} leaders", set_leader.len());
	let mut graf = DiGraph::<BasicBlock, &'static str>::new();
	let mut peta_simpul = HashMap::<u64, NodeIndex>::new();
	let simpul_lompat_dinamis = graf.add_node(BasicBlock {
		va_start: 0,
		va_end: 0,
		instructions: Vec::new(),
		size: 0,
	});
	let mut list_leader_urut: Vec<u64> = set_leader.iter().cloned().collect();
	list_leader_urut.sort();
	debug!("Pass 2: Membuat basic blocks");
	for &va_leader in &list_leader_urut {
		if peta_simpul.contains_key(&va_leader) {
			continue;
		}
		let mut vec_instr_blok: Vec<(u64, Vec<MicroInstruction>)> = Vec::new();
		let mut va_kini = va_leader;
		let mut sz_blok: u64 = 0;
		loop {
			let (vec_ir, sz_instr) = match map_instr_lifted.get(&va_kini) {
				Some((irs, size)) => (irs.clone(), *size),
				None => {
					break;
				}
			};
			if sz_instr == 0 {
				 break;
			}
			let ir_akhir = vec_ir.last().cloned();
			vec_instr_blok.push((va_kini, vec_ir));
			sz_blok += sz_instr as u64;
			va_kini += sz_instr as u64;
			if let Some(ir) = ir_akhir {
				if is_ir_branch(&ir) {
					break;
				}
			}
			if set_leader.contains(&va_kini) || va_kini >= va_akhir_teks {
				break;
			}
		}
		let blok = BasicBlock {
			va_start: va_leader,
			va_end: va_kini,
			instructions: vec_instr_blok,
			size: sz_blok,
		};
		let idx_simpul = graf.add_node(blok);
		peta_simpul.insert(va_leader, idx_simpul);
	}
	info!("Pass 2 selesai. Dibuat {} nodes", graf.node_count());
	debug!("Pass 3: Menghubungkan edges");
	let mut list_sisi = Vec::new();
	for (&_va, &idx_simpul) in &peta_simpul {
		let blok = match graf.node_weight(idx_simpul) {
			Some(b) => b,
			None => continue,
		};
		let va_lanjut = blok.va_end;
		let ir_akhir = blok.instructions.last().and_then(|(_, irs)| irs.last());
        let va_ir_akhir = blok.instructions.last().map(|(v, _)| *v).unwrap_or(0);
		let irs_semua: Vec<MicroInstruction> = blok.instructions.iter().flat_map(|(_, irs)| irs.clone()).collect();
		if ir_akhir.is_none() {
			if let Some(idx_lanjut) = peta_simpul.get(&va_lanjut) {
				list_sisi.push((idx_simpul, *idx_lanjut, "Fallthrough"));
			}
			continue;
		}
        let resolve_targets = |expr: &MicroExpr, va_sumber: u64| -> Vec<u64> {
            if let Some(peta_dinamis) = peta_target_dinamis {
                if let Some(target) = peta_dinamis.get(&va_sumber) {
                    return vec![*target];
                }
            }
            determine_target_jump(expr, biner, &irs_semua)
        };
		match ir_akhir.unwrap() {
			MicroInstruction::Jump(expr_target) => {
				let list_target = resolve_targets(expr_target, va_ir_akhir);
				if list_target.is_empty() {
					list_sisi.push((idx_simpul, simpul_lompat_dinamis, "Jump (Dynamic)"));
				} else {
					for va_target in list_target {
						if let Some(idx_target) = peta_simpul.get(&va_target) {
							list_sisi.push((idx_simpul, *idx_target, "Jump"));
						}
					}
				}
			}
			MicroInstruction::JumpKondisi(_, expr_target) => {
				let list_target = resolve_targets(expr_target, va_ir_akhir);
				if list_target.is_empty() {
					list_sisi.push((idx_simpul, simpul_lompat_dinamis, "Jump (True, Dynamic)"));
				} else {
					 for va_target in list_target {
						if let Some(idx_target) = peta_simpul.get(&va_target) {
							list_sisi.push((idx_simpul, *idx_target, "Jump (True)"));
						}
					}
				}
				if let Some(idx_lanjut) = peta_simpul.get(&va_lanjut) {
					list_sisi.push((idx_simpul, *idx_lanjut, "Fallthrough (False)"));
				}
			}
			MicroInstruction::Return => {
			}
			MicroInstruction::Call(expr_target) => {
                let list_target = resolve_targets(expr_target, va_ir_akhir);
                 for va_target in list_target {
                    if let Some(idx_target) = peta_simpul.get(&va_target) {
                        list_sisi.push((idx_simpul, *idx_target, "Call"));
                    }
                 }

				 if let Some(idx_lanjut) = peta_simpul.get(&va_lanjut) {
					list_sisi.push((idx_simpul, *idx_lanjut, "Fallthrough (Call)"));
				}
			}
			_ => {
				if let Some(idx_lanjut) = peta_simpul.get(&va_lanjut) {
					list_sisi.push((idx_simpul, *idx_lanjut, "Fallthrough"));
				}
			}
		}
	}
	for (sumber, target, label) in list_sisi {
		graf.add_edge(sumber, target, label);
	}
	info!("Pass 3 selesai. Dibuat {} edges", graf.edge_count());
	Ok(graf)
}

pub fn create_graf_cfg(biner: &Binary) -> Result<String, ReToolsError> {
	let graf = build_cfg_internal(biner, None)?;
	let dot_str = Dot::with_config(&graf, &[]);
	Ok(format!("{}", dot_str))
}

pub fn calc_dominators(graf: &DiGraph<BasicBlock, &'static str>, idx_simpul_entry: NodeIndex) -> Dominators<NodeIndex> {
	dominators::simple_fast(graf, idx_simpul_entry)
}

pub fn detect_loop_natural(graf: &DiGraph<BasicBlock, &'static str>, doms: &Dominators<NodeIndex>) -> Vec<NodeIndex> {
	let mut set_header = HashSet::new();
	for sisi in graf.edge_references() {
		let simpul_sumber = sisi.source();
		let simpul_target = sisi.target();
		if doms.dominators(simpul_sumber).map_or(false, |mut iter| iter.any(|d| d == simpul_target)) {
			set_header.insert(simpul_target);
		}
	}
	set_header.into_iter().collect()
}

pub fn find_exit_func(graf: &DiGraph<BasicBlock, &'static str>) -> Vec<NodeIndex> {
	let mut list_simpul_exit = Vec::new();
	for idx_simpul in graf.node_identifiers() {
		if let Some(blok) = graf.node_weight(idx_simpul) {
			if let Some((_, irs_akhir)) = blok.instructions.last() {
				if let Some(MicroInstruction::Return) = irs_akhir.last() {
					list_simpul_exit.push(idx_simpul);
				}
			}
		}
	}
	list_simpul_exit
}