use crate::error::ReToolsError;
use crate::logic::static_analysis::binary::Binary;
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::ir::lifter::angkat_blok_instruksi;
use crate::logic::ir::instruction::{IrInstruction, IrOperand, IrExpression};

use libc::c_char;
use log::{debug, error, info, warn};
use petgraph::dot::Dot;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fmt;


#[derive(Debug, Clone)]
struct BasicBlock {
    va_start: u64,
    va_end: u64,
    instructions: Vec<(u64, Vec<IrInstruction>)>,
    size: u64,
}

impl fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut label = format!("0x{:x} (size: {} bytes):\\n", self.va_start, self.size);
        for (va, irs) in &self.instructions {
            for ir in irs {
                let ir_str = format!("{:?}", ir)
                    .replace('"', "\\\"")
                    .replace('\n', "\\n");
                label.push_str(&format!("  0x{:x}: {}\\n", va, ir_str));
            }
        }
        write!(f, "{}", label)
    }
}

fn get_target_va_from_expr(expr: &IrExpression) -> Option<u64> {
    if let IrExpression::Operand(IrOperand::Immediate(imm)) = expr {
        Some(*imm)
    } else {
        None
    }
}

fn is_ir_branch(ir: &IrInstruction) -> bool {
    matches!(ir, IrInstruction::Jmp(_) | IrInstruction::JmpCond(_, _) | IrInstruction::Ret)
}

pub fn generate_cfg_internal(binary: &Binary) -> Result<String, ReToolsError> {
    info!("Mulai generate CFG (IR-based) untuk: {}", binary.file_path);
    let text_section = binary.sections.iter().find(|s| s.name == ".text");
    let (text_data, base_addr) = if let Some(section) = text_section {
        info!(
            "Section .text ditemukan: addr=0x{:x}, size=0x{:x}",
            section.addr, section.size
        );
        let text_data_offset = section.offset as usize;
        let text_data_size = section.size as usize;
        if text_data_offset
            .saturating_add(text_data_size)
            > binary.file_bytes.len()
        {
            return Err(ReToolsError::ParseError(
                "Section .text di luar batas file".to_string(),
            ));
        }
        let data_slice = &binary.file_bytes[text_data_offset..(text_data_offset + text_data_size)];
        (data_slice, section.addr)
    } else {
        warn!("Section .text tidak ditemukan");
        return Err(ReToolsError::ParseError(
            "Section .text tidak ditemukan".to_string(),
        ));
    };
    let arch_disasm = match (binary.header.arch, binary.header.bits) {
        ("x86-64", 64) => ArsitekturDisasm::ARCH_X86_64,
        ("x86", 32) => ArsitekturDisasm::ARCH_X86_32,
        ("AArch64", 64) => ArsitekturDisasm::ARCH_ARM_64,
        ("ARM", 32) => ArsitekturDisasm::ARCH_ARM_32,
        _ => ArsitekturDisasm::ARCH_X86_64,
    };
    let mut leaders = HashSet::new();
    let mut lifted_instructions = HashMap::new();
    leaders.insert(base_addr);
    debug!("Pass 1: Identifikasi leaders dan angkat IR");
    let mut offset: usize = 0;
    while offset < text_data.len() {
        let va = base_addr + offset as u64;
        let (size, irs) = match angkat_blok_instruksi(&text_data[offset..], va, arch_disasm) {
            Ok((size, ir_vec)) if size > 0 => (size, ir_vec),
            _ => (1, vec![IrInstruction::Undefined]),
        };
        lifted_instructions.insert(va, (irs.clone(), size));
        if let Some(last_ir) = irs.last() {
            if is_ir_branch(last_ir) {
                let fallthrough_addr = va + size as u64;
                if fallthrough_addr <= base_addr + text_data.len() as u64 {
                    leaders.insert(fallthrough_addr);
                }
                let target_addr_opt = match last_ir {
                    IrInstruction::Jmp(expr) | IrInstruction::JmpCond(_, expr) | IrInstruction::Call(expr) => {
                        get_target_va_from_expr(expr)
                    }
                    _ => None
                };
                if let Some(target_addr) = target_addr_opt {
                    if target_addr != 0 {
                       leaders.insert(target_addr);
                    }
                }
            }
        }
        offset += size;
    }
    info!("Pass 1 selesai. Ditemukan {} leaders", leaders.len());
    let mut graph = DiGraph::<BasicBlock, &'static str>::new();
    let mut node_map = HashMap::<u64, NodeIndex>::new();
    let mut sorted_leaders: Vec<u64> = leaders.iter().cloned().collect();
    sorted_leaders.sort();
    debug!("Pass 2: Membuat basic blocks");
    for &leader_va in &sorted_leaders {
        if node_map.contains_key(&leader_va) {
            continue;
        }
        let mut block_instrs: Vec<(u64, Vec<IrInstruction>)> = Vec::new();
        let mut current_addr = leader_va;
        let mut block_size: u64 = 0;
        loop {
            let (irs, size) = match lifted_instructions.get(&current_addr) {
                Some((irs, size)) => (irs.clone(), *size),
                None => (vec![IrInstruction::Undefined], 1),
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
            if leaders.contains(&current_addr) || current_addr >= (base_addr + text_data.len() as u64) {
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
            IrInstruction::Jmp(target_expr) => {
                if let Some(target_va) = get_target_va_from_expr(target_expr) {
                    if let Some(target_idx) = node_map.get(&target_va) {
                        edges_to_add.push((node_idx, *target_idx, "Jump"));
                    }
                }
            }
            IrInstruction::JmpCond(_, target_expr) => {
                if let Some(target_va) = get_target_va_from_expr(target_expr) {
                    if let Some(target_idx) = node_map.get(&target_va) {
                        edges_to_add.push((node_idx, *target_idx, "Jump (True)"));
                    }
                }
                if let Some(fallthrough_idx) = node_map.get(&fallthrough_va) {
                    edges_to_add.push((node_idx, *fallthrough_idx, "Fallthrough (False)"));
                }
            }
            IrInstruction::Ret => {
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
    let dot_str = Dot::with_config(&graph, &[]);
    Ok(format!("{}", dot_str))
}

pub unsafe fn c_generate_cfg_rs(filename_c: *const c_char) -> *mut c_char {
    let path_str = match CStr::from_ptr(filename_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Path tidak valid UTF-8: {}", e);
            return CString::new("digraph G {{ error [label=\"Invalid Path\"]; }}")
                .unwrap()
                .into_raw();
        }
    };
    let binary_result = Binary::load(path_str);
    let dot_result = match binary_result {
        Ok(binary) => match generate_cfg_internal(&binary) {
            Ok(dot) => dot,
            Err(e) => {
                error!("generate_cfg_internal gagal: {}", e);
                format!("digraph G {{ error [label=\"{}\"]; }}", e)
            }
        },
        Err(e) => {
            error!("Binary::load gagal: {}", e);
            format!("digraph G {{ error [label=\"{}\"]; }}", e)
        }
    };
    CString::new(dot_result).unwrap_or_default().into_raw()
}