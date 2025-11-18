//! Author: [Seclususs](https://github.com/seclususs)

use capstone::prelude::*;
use libc::{c_char, c_int};
use std::slice;

use crate::error::ReToolsError;
use crate::utils::copy_str_safe;
use log::{debug, error};


#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArsitekturDisasm {
    ARCH_UNKNOWN = 0,
    ARCH_X86_32 = 1,
    ARCH_X86_64 = 2,
    ARCH_ARM_32 = 3,
    ARCH_ARM_64 = 4,
    ARCH_RISCV_32 = 5,
    ARCH_RISCV_64 = 6,
    ARCH_MIPS_32 = 7,
    ARCH_MIPS_64 = 8,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct C_Instruksi {
    pub mnemonic_instruksi: [c_char; 32],
    pub str_operand: [c_char; 64],
    pub ukuran: c_int,
    pub valid: c_int,
}

pub fn create_instr_invalid(sz: c_int) -> C_Instruksi {
    let mut instr = C_Instruksi {
        mnemonic_instruksi: [0; 32],
        str_operand: [0; 64],
        ukuran: sz,
        valid: 0,
    };
    copy_str_safe("(invalid)", &mut instr.mnemonic_instruksi);
    instr
}

pub fn create_instance_capstone_by_arch(
    arch: ArsitekturDisasm,
) -> Result<Capstone, ReToolsError> {
    debug!("Membuat instance Capstone untuk arsitektur: {:?}", arch);
    let cs_builder_result = match arch {
        ArsitekturDisasm::ARCH_X86_32 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_ARM_32 => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_ARM_64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_RISCV_32 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_RISCV_64 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_MIPS_32 => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_MIPS_64 => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .detail(true)
            .build(),
        ArsitekturDisasm::ARCH_UNKNOWN => {
            debug!("Arsitektur tidak diketahui, menggunakan default x86-64");
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build()
        }
    };
    cs_builder_result.map_err(ReToolsError::from)
}

pub fn decode_instr_single(
    ptr_data: *const u8,
    len_data: usize,
    off_set: usize,
    va_basis: u64,
    arch: ArsitekturDisasm,
) -> C_Instruksi {
    if off_set >= len_data {
        debug!("Offset di luar batas: {} >= {}", off_set, len_data);
        return create_instr_invalid(0);
    }
    let slice_data = unsafe { slice::from_raw_parts(ptr_data, len_data) };
    let slice_kode = &slice_data[off_set..];
    if slice_kode.is_empty() {
        debug!("Code slice kosong pada offset: {}", off_set);
        return create_instr_invalid(0);
    }
    let obj_capstone = match create_instance_capstone_by_arch(arch) {
        Ok(cs) => cs,
        Err(e) => {
            error!("Gagal membuat instance Capstone: {}", e);
            return create_instr_invalid(1);
        }
    };
    let res_insns = obj_capstone.disasm_count(slice_kode, va_basis, 1);
    match res_insns {
        Ok(insns) => {
            if let Some(insn) = insns.first() {
                let mut c_instr = C_Instruksi {
                    mnemonic_instruksi: [0; 32],
                    str_operand: [0; 64],
                    ukuran: insn.bytes().len() as c_int,
                    valid: 1,
                };
                copy_str_safe(insn.mnemonic().unwrap_or(""), &mut c_instr.mnemonic_instruksi);
                copy_str_safe(insn.op_str().unwrap_or(""), &mut c_instr.str_operand);
                debug!(
                    "Disasm sukses: VA=0x{:x}, Mnem={}, Ops={}",
                    va_basis,
                    insn.mnemonic().unwrap_or(""),
                    insn.op_str().unwrap_or("")
                );
                c_instr
            } else {
                debug!(
                    "Capstone tidak mengembalikan instruksi pada VA=0x{:x}",
                    va_basis
                );
                create_instr_invalid(1)
            }
        }
        Err(e) => {
            error!(
                "Capstone disasm error pada VA=0x{:x}: {}",
                va_basis, e
            );
            create_instr_invalid(1)
        }
    }
}