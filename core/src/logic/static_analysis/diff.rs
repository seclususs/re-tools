//! Author: [Seclususs](https://github.com/seclususs)

use libc::c_int;
use log::{debug, info};
use std::collections::HashMap;

use crate::error::ReToolsError;
use crate::logic::static_analysis::parser::{Binary, SectionInfo, SymbolInfo};
use crate::logic::static_analysis::disasm::ArsitekturDisasm;
use crate::logic::ir::lifter::lift_blok_instr;
use crate::logic::ir::instruction::MicroInstruction;

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
        ("x86-66", 64) => ArsitekturDisasm::ARCH_X86_64,
        ("x86", 32) => ArsitekturDisasm::ARCH_X86_32,
        ("AArch64", 64) => ArsitekturDisasm::ARCH_ARM_64,
        ("ARM", 32) => ArsitekturDisasm::ARCH_ARM_32,
        _ => ArsitekturDisasm::ARCH_X86_64,
    }
}

fn lift_fungsi_ke_ir(
    biner: &Binary,
    simbol: &SymbolInfo,
    arch: ArsitekturDisasm,
) -> Result<Vec<MicroInstruction>, ReToolsError> {
    let va_fungsi = simbol.addr;
    let sz_fungsi = simbol.size;
    if sz_fungsi == 0 {
        return Ok(Vec::new());
    }
    let off_fungsi = va_to_offset(va_fungsi, &biner.sections)
        .ok_or_else(|| ReToolsError::Generic(format!("VA 0x{:x} tidak ditemukan di sections", va_fungsi)))?;
    let idx_mulai = off_fungsi as usize;
    let idx_akhir = idx_mulai.saturating_add(sz_fungsi as usize);
    if idx_mulai > biner.file_data.len() || idx_akhir > biner.file_data.len() {
        return Err(ReToolsError::Generic(format!("Simbol 0x{:x} di luar batas file", va_fungsi)));
    }
    let bytes_fungsi = &biner.file_data[idx_mulai..idx_akhir];
    let mut list_ir = Vec::new();
    let mut off_kini = 0;
    while off_kini < bytes_fungsi.len() {
        let va_kini = va_fungsi + off_kini as u64;
        let (sz, vec_ir) = match lift_blok_instr(&bytes_fungsi[off_kini..], va_kini, arch) {
            Ok((size, ir_vec)) if size > 0 => (size, ir_vec),
            _ => (1, vec![MicroInstruction::Undefined]),
        };
        list_ir.extend(vec_ir);
        off_kini += sz;
        if sz == 0 {
            break;
        }
    }
    Ok(list_ir)
}

fn check_ir_cabang(ir: &MicroInstruction) -> bool {
    matches!(ir, MicroInstruction::Jump(_) | MicroInstruction::JumpKondisi(_, _) | MicroInstruction::Return | MicroInstruction::Call(_))
}

fn get_tanda_ir(ir: &MicroInstruction) -> &'static str {
    match ir {
        MicroInstruction::Assign(_, _) => "Assign",
        MicroInstruction::StoreMemori(_, _) => "StoreMemori",
        MicroInstruction::Jump(_) => "Jump",
        MicroInstruction::JumpKondisi(_, _) => "JumpKondisi",
        MicroInstruction::Call(_) => "Call",
        MicroInstruction::Return => "Return",
        MicroInstruction::Nop => "Nop",
        MicroInstruction::Syscall => "Syscall",
        MicroInstruction::Undefined => "Undefined",
        MicroInstruction::VectorOp { .. } => "VectorOp",
        MicroInstruction::AtomicRMW { .. } => "Atomic",
        MicroInstruction::MemoryFence => "Fence",
        MicroInstruction::UpdateFlag(_, _) => "UpdateFlag",
        MicroInstruction::Phi { .. } => "Phi",
    }
}

fn create_tanda_fungsi(list_ir: Vec<MicroInstruction>) -> Vec<String> {
    let mut list_tanda_blok = Vec::new();
    let mut tanda_blok_kini = String::new();
    for ir in list_ir {
        tanda_blok_kini.push_str(get_tanda_ir(&ir));
        tanda_blok_kini.push(';');
        if check_ir_cabang(&ir) {
            list_tanda_blok.push(tanda_blok_kini);
            tanda_blok_kini = String::new();
        }
    }
    if !tanda_blok_kini.is_empty() {
        list_tanda_blok.push(tanda_blok_kini);
    }
    list_tanda_blok
}

fn cmp_tanda_fungsi(
    res_tanda_1: Result<Vec<String>, ReToolsError>,
    res_tanda_2: Result<Vec<String>, ReToolsError>,
) -> c_int {
    match (res_tanda_1, res_tanda_2) {
        (Ok(t1), Ok(t2)) => {
            if t1 == t2 {
                STATUS_MATCHED
            } else {
                STATUS_MODIFIED
            }
        }
        _ => STATUS_MODIFIED,
    }
}

fn calc_diff_biner(
    biner_1: &Binary,
    biner_2: &Binary,
) -> Result<Vec<DiffResultInternal>, ReToolsError> {
    let arch_1 = get_arch_from_binary(biner_1);
    let arch_2 = get_arch_from_binary(biner_2);
    let peta_simbol_1: HashMap<String, &SymbolInfo> = biner_1
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "FUNC" && s.size > 0)
        .map(|s| (s.name.clone(), s))
        .collect();
    let peta_simbol_2: HashMap<String, &SymbolInfo> = biner_2
        .symbols
        .iter()
        .filter(|s| s.symbol_type == "FUNC" && s.size > 0)
        .map(|s| (s.name.clone(), s))
        .collect();
    info!(
        "Membandingkan (IR-based) {} simbol FUNC dari file 1 vs {} simbol FUNC dari file 2",
        peta_simbol_1.len(),
        peta_simbol_2.len()
    );
    let mut list_hasil: Vec<DiffResultInternal> = Vec::new();
    let mut peta_nama_diproses: HashMap<String, bool> = HashMap::new();
    let map_status = ["Matched", "Modified", "Removed", "Added", "Unknown"];
    debug!("Membandingkan simbol dari file 1...");
    for (nama, sym1) in &peta_simbol_1 {
        peta_nama_diproses.insert(nama.clone(), true);
        let mut kode_status = STATUS_REMOVED;
        let mut addr_2 = 0;
        let tanda_1 = lift_fungsi_ke_ir(biner_1, sym1, arch_1).map(create_tanda_fungsi);
        if let Some(sym2) = peta_simbol_2.get(nama) {
            addr_2 = sym2.addr;
            let tanda_2 = lift_fungsi_ke_ir(biner_2, sym2, arch_2).map(create_tanda_fungsi);
            kode_status = cmp_tanda_fungsi(tanda_1, tanda_2);
        }
        list_hasil.push(DiffResultInternal {
            function_name: nama.clone(),
            address_file1: sym1.addr,
            address_file2: addr_2,
            status: map_status[kode_status as usize].to_string(),
        });
    }
    debug!("Mencari simbol yang ditambah di file 2...");
    for (nama, sym2) in &peta_simbol_2 {
        if !peta_nama_diproses.contains_key(nama) {
            list_hasil.push(DiffResultInternal {
                function_name: nama.clone(),
                address_file1: 0,
                address_file2: sym2.addr,
                status: map_status[STATUS_ADDED as usize].to_string(),
            });
        }
    }
    Ok(list_hasil)
}

pub fn diff_binary_internal(
    path_berkas_1: &str,
    path_berkas_2: &str,
) -> Result<Vec<DiffResultInternal>, String> {
    info!("Mulai diff binary: {} vs {}", path_berkas_1, path_berkas_2);
    let biner_1 = Binary::load(path_berkas_1).map_err(|e| e.to_string())?;
    let biner_2 = Binary::load(path_berkas_2).map_err(|e| e.to_string())?;
    let hasil = calc_diff_biner(&biner_1, &biner_2).map_err(|e| e.to_string())?;
    info!("Diff selesai, {} hasil ditemukan", hasil.len());
    Ok(hasil)
}