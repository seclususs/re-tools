use libc::c_int;
use log::{debug, info};
use std::collections::HashMap;

use crate::error::ReToolsError;
use crate::logic::static_analysis::parser::{Binary, SectionInfo, SymbolInfo};
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::ir::lifter::angkat_blok_instruksi;
use crate::logic::ir::instruction::IrInstruction;


#[derive(Debug, serde::Serialize)]
pub struct DiffResultInternal {
    pub function_name: String,
    pub address_file1: u64,
    pub address_file2: u64,
    pub status: String,
}

const STATUS_MATCHED: c_int = 0;
const STATUS_MODIFIED: c_int = 1;
const STATUS_REMOVED: c_int = 2;
const STATUS_ADDED: c_int = 3;

fn va_to_offset(va: u64, sections: &[SectionInfo]) -> Option<u64> {
    for sec in sections {
        if va >= sec.addr && va < (sec.addr + sec.size) {
            let relative_offset = va - sec.addr;
            return Some(sec.offset + relative_offset);
        }
    }
    None
}

fn get_arch_from_binary(binary: &Binary) -> ArsitekturDisasm {
    match (binary.header.arch, binary.header.bits) {
        ("x86-64", 64) => ArsitekturDisasm::ARCH_X86_64,
        ("x86", 32) => ArsitekturDisasm::ARCH_X86_32,
        ("AArch64", 64) => ArsitekturDisasm::ARCH_ARM_64,
        ("ARM", 32) => ArsitekturDisasm::ARCH_ARM_32,
        _ => ArsitekturDisasm::ARCH_X86_64,
    }
}

fn lift_function_to_ir(
    binary: &Binary,
    sym: &SymbolInfo,
    arch: ArsitekturDisasm,
) -> Result<Vec<IrInstruction>, ReToolsError> {
    let func_va = sym.addr;
    let func_size = sym.size;
    if func_size == 0 {
        return Ok(Vec::new());
    }
    let func_offset = va_to_offset(func_va, &binary.sections)
        .ok_or_else(|| ReToolsError::Generic(format!("VA 0x{:x} tidak ditemukan di sections", func_va)))?;
    let start = func_offset as usize;
    let end = start.saturating_add(func_size as usize);
    if start > binary.file_data.len() || end > binary.file_data.len() {
        return Err(ReToolsError::Generic(format!("Simbol 0x{:x} di luar batas file", func_va)));
    }
    let func_bytes = &binary.file_data[start..end];
    let mut all_irs = Vec::new();
    let mut current_offset = 0;
    while current_offset < func_bytes.len() {
        let current_va = func_va + current_offset as u64;
        let (size, irs) = match angkat_blok_instruksi(&func_bytes[current_offset..], current_va, arch) {
            Ok((size, ir_vec)) if size > 0 => (size, ir_vec),
            _ => (1, vec![IrInstruction::Undefined]),
        };
        all_irs.extend(irs);
        current_offset += size;
        if size == 0 {
            break;
        }
    }
    Ok(all_irs)
}

fn is_ir_branch(ir: &IrInstruction) -> bool {
    matches!(ir, IrInstruction::Jmp(_) | IrInstruction::JmpCond(_, _) | IrInstruction::Ret | IrInstruction::Call(_))
}

fn get_ir_signature(ir: &IrInstruction) -> &'static str {
    match ir {
        IrInstruction::Set(_, _) => "Set",
        IrInstruction::Push(_) => "Push",
        IrInstruction::Pop(_) => "Pop",
        IrInstruction::Jmp(_) => "Jmp",
        IrInstruction::JmpCond(_, _) => "JmpCond",
        IrInstruction::Call(_) => "Call",
        IrInstruction::Ret => "Ret",
        IrInstruction::Nop => "Nop",
        IrInstruction::Syscall => "Syscall",
        IrInstruction::Undefined => "Undefined",
        IrInstruction::AturBendera(_, _) => "AturBendera",
        IrInstruction::InstruksiVektor(_, _) => "InstruksiVektor",
    }
}

fn generate_function_signature(irs: Vec<IrInstruction>) -> Vec<String> {
    let mut all_block_sigs = Vec::new();
    let mut current_block_sig = String::new();
    for ir in irs {
        current_block_sig.push_str(get_ir_signature(&ir));
        current_block_sig.push(';');
        if is_ir_branch(&ir) {
            all_block_sigs.push(current_block_sig);
            current_block_sig = String::new();
        }
    }
    if !current_block_sig.is_empty() {
        all_block_sigs.push(current_block_sig);
    }
    all_block_sigs
}

fn compare_function_signatures(
    sig1_res: Result<Vec<String>, ReToolsError>,
    sig2_res: Result<Vec<String>, ReToolsError>,
) -> c_int {
    match (sig1_res, sig2_res) {
        (Ok(sig1), Ok(sig2)) => {
            if sig1 == sig2 {
                STATUS_MATCHED
            } else {
                STATUS_MODIFIED
            }
        }
        _ => STATUS_MODIFIED,
    }
}

fn perform_diff_logic(
    binary1: &Binary,
    binary2: &Binary,
) -> Result<Vec<DiffResultInternal>, ReToolsError> {
    let arch1 = get_arch_from_binary(binary1);
    let arch2 = get_arch_from_binary(binary2);
    let symbols1_map: HashMap<String, &SymbolInfo> = binary1
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "FUNC" && s.size > 0)
        .map(|s| (s.name.clone(), s))
        .collect();
    let symbols2_map: HashMap<String, &SymbolInfo> = binary2
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "FUNC" && s.size > 0)
        .map(|s| (s.name.clone(), s))
        .collect();
    info!(
        "Membandingkan (IR-based) {} simbol FUNC dari file 1 vs {} simbol FUNC dari file 2",
        symbols1_map.len(),
        symbols2_map.len()
    );
    let mut results: Vec<DiffResultInternal> = Vec::new();
    let mut processed_names: HashMap<String, bool> = HashMap::new();
    let status_map = ["Matched", "Modified", "Removed", "Added", "Unknown"];
    debug!("Membandingkan simbol dari file 1...");
    for (name, sym1) in &symbols1_map {
        processed_names.insert(name.clone(), true);
        let mut status_code = STATUS_REMOVED;
        let mut addr2 = 0;
        let sig1 = lift_function_to_ir(binary1, sym1, arch1).map(generate_function_signature);
        if let Some(sym2) = symbols2_map.get(name) {
            addr2 = sym2.addr;
            let sig2 = lift_function_to_ir(binary2, sym2, arch2).map(generate_function_signature);
            status_code = compare_function_signatures(sig1, sig2);
        }
        results.push(DiffResultInternal {
            function_name: name.clone(),
            address_file1: sym1.addr,
            address_file2: addr2,
            status: status_map[status_code as usize].to_string(),
        });
    }
    debug!("Mencari simbol yang ditambah di file 2...");
    for (name, sym2) in &symbols2_map {
        if !processed_names.contains_key(name) {
            results.push(DiffResultInternal {
                function_name: name.clone(),
                address_file1: 0,
                address_file2: sym2.addr,
                status: status_map[STATUS_ADDED as usize].to_string(),
            });
        }
    }
    Ok(results)
}

pub fn diff_binary_internal(
    file1_path: &str,
    file2_path: &str,
) -> Result<Vec<DiffResultInternal>, String> {
    info!("Mulai diff binary: {} vs {}", file1_path, file2_path);
    let binary1 = Binary::load(file1_path).map_err(|e| e.to_string())?;
    let binary2 = Binary::load(file2_path).map_err(|e| e.to_string())?;
    let results = perform_diff_logic(&binary1, &binary2).map_err(|e| e.to_string())?;
    info!("Diff selesai, {} hasil ditemukan", results.len());
    Ok(results)
}