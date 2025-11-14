use crate::error::ReToolsError;
use crate::logic::static_analysis::disasm::{logic_decode_instruksi, ArsitekturDisasm};
use crate::logic::static_analysis::parser::C_SectionInfo;
use libc::{c_char, c_int};
use log::{debug, error, info, warn};
use petgraph::dot::{Config, Dot};
use petgraph::graph::DiGraph;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs;
use std::path::Path;

use crate::c_api::c_getDaftarSections;


fn get_text_section_internal(
    filename: &str,
) -> Result<(Vec<u8>, u64, u64), ReToolsError> {
    info!("Mencari section .text di {}", filename);
    let filename_c = CString::new(filename)?;
    let mut buffer: Vec<C_SectionInfo> = vec![
        C_SectionInfo {
            name: [0; 128],
            addr: 0,
            size: 0,
            offset: 0,
            tipe: 0,
        };
        256
    ];
    let count = unsafe {
        c_getDaftarSections(
            filename_c.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as c_int,
        )
    };
    if count < 0 {
        warn!("c_getDaftarSections gagal (count: {})", count);
        return Err(ReToolsError::ParseError(
            "Gagal mendapatkan daftar sections".to_string(),
        ));
    }
    let text_section = buffer[..count as usize].iter().find(|s| {
        let name = unsafe { CStr::from_ptr(s.name.as_ptr()).to_str().unwrap_or("") };
        name == ".text"
    });
    if let Some(section) = text_section {
        info!(
            "Section .text ditemukan: addr=0x{:x}, size=0x{:x}",
            section.addr, section.size
        );
        let mut file = fs::File::open(Path::new(filename))?;
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(section.offset))?;
        let mut data = vec![0; section.size as usize];
        file.read_exact(&mut data)?;
        Ok((data, section.addr, section.offset))
    } else {
        warn!("Section .text tidak ditemukan");
        Err(ReToolsError::ParseError(
            "Section .text tidak ditemukan".to_string(),
        ))
    }
}

pub fn generate_cfg_internal(filename: &str) -> Result<String, ReToolsError> {
    info!("Mulai generate CFG untuk: {}", filename);
    let (text_data, base_addr, _) = get_text_section_internal(filename)?;
    let mut leaders = HashSet::new();
    let mut jump_targets = HashMap::new();
    let mut instructions = HashMap::new();
    leaders.insert(base_addr);
    let mut offset: usize = 0;
    debug!("Pass 1: Identifikasi leaders dan instruksi");
    while offset < text_data.len() {
        let va = base_addr + offset as u64;
        let instr = logic_decode_instruksi(
            text_data.as_ptr(),
            text_data.len(),
            offset,
            va,
            ArsitekturDisasm::ARCH_X86_64,
        );
        if instr.valid == 0 {
            offset += 1;
            continue;
        }
        let mnemonic =
            unsafe { CStr::from_ptr(instr.mnemonic_instruksi.as_ptr()).to_str().unwrap() };
        let op_str = unsafe { CStr::from_ptr(instr.str_operand.as_ptr()).to_str().unwrap() };
        let instr_str_full = format!("{} {}", mnemonic, op_str);
        let instr_str_upper = instr_str_full.to_uppercase().trim_end().to_string();
        instructions.insert(va, (instr_str_upper, instr.ukuran as usize));
        let is_branch = mnemonic.starts_with('j') || mnemonic == "call" || mnemonic == "ret";
        if is_branch {
            let fallthrough_addr = va + instr.ukuran as u64;
            if fallthrough_addr <= base_addr + text_data.len() as u64 {
                leaders.insert(fallthrough_addr);
            }
            if mnemonic != "ret" {
                if let Ok(target_addr) = u64::from_str_radix(op_str.trim_start_matches("0x"), 16) {
                    leaders.insert(target_addr);
                    jump_targets.insert(va, (target_addr, mnemonic.starts_with('j')));
                }
            }
        }
        offset += instr.ukuran as usize;
    }
    info!("Pass 1 selesai. Ditemukan {} leaders", leaders.len());
    let mut graph = DiGraph::<String, &'static str>::new();
    let mut node_map = HashMap::new();
    let mut sorted_leaders: Vec<u64> = leaders.into_iter().collect();
    sorted_leaders.sort();
    debug!("Pass 2: Membuat basic blocks");
    for &leader_addr in &sorted_leaders {
        let mut block_content = String::new();
        let mut current_addr = leader_addr;
        while current_addr < base_addr + text_data.len() as u64 {
            if let Some((instr_str, size)) = instructions.get(&current_addr) {
                block_content.push_str(&format!("{:#x}: {}\n", current_addr, instr_str));
                current_addr += *size as u64;

                if jump_targets.contains_key(&(current_addr - *size as u64))
                    || sorted_leaders.binary_search(&current_addr).is_ok()
                {
                    break;
                }
            } else {
                break;
            }
        }
        if !block_content.is_empty() {
            let node_idx = graph.add_node(block_content);
            node_map.insert(leader_addr, node_idx);
        }
    }
    info!("Pass 2 selesai. Dibuat {} nodes", graph.node_count());
    debug!("Pass 3: Menghubungkan edges");
    for &leader_addr in &sorted_leaders {
        let Some(&node_idx) = node_map.get(&leader_addr) else {
            continue;
        };
        let mut current_addr = leader_addr;
        let mut last_instr_addr = leader_addr;
        while current_addr < base_addr + text_data.len() as u64 {
            if let Some((_, size)) = instructions.get(&current_addr) {
                last_instr_addr = current_addr;
                current_addr += *size as u64;
                if sorted_leaders.binary_search(&current_addr).is_ok()
                    || jump_targets.contains_key(&last_instr_addr)
                {
                    break;
                }
            } else {
                break;
            }
        }
        if let Some((target_addr, is_conditional)) = jump_targets.get(&last_instr_addr) {
            if let Some(target_node_idx) = node_map.get(target_addr) {
                graph.add_edge(node_idx, *target_node_idx, "Jump");
            }
            if *is_conditional {
                if let Some(fallthrough_node_idx) = node_map.get(&current_addr) {
                    graph.add_edge(node_idx, *fallthrough_node_idx, "Fallthrough");
                }
            }
        } else if !instructions
            .get(&last_instr_addr)
            .map_or(false, |(s, _)| s.contains("RET"))
        {
            if let Some(fallthrough_node_idx) = node_map.get(&current_addr) {
                graph.add_edge(node_idx, *fallthrough_node_idx, "Fallthrough");
            }
        }
    }
    info!(
        "Pass 3 selesai. Dibuat {} edges",
        graph.edge_count()
    );
    let dot_str = Dot::with_config(&graph, &[Config::EdgeNoLabel]);
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
    let dot_result = match generate_cfg_internal(path_str) {
        Ok(dot) => dot,
        Err(e) => {
            error!("generate_cfg_internal gagal: {}", e);
            format!("digraph G {{ error [label=\"{}\"]; }}", e)
        }
    };
    CString::new(dot_result).unwrap_or_default().into_raw()
}