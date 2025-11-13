use capstone::prelude::*;
use libc::{c_char, c_int};
use std::slice;

use crate::utils::strncpy_rs;


#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArsitekturDisasm {
    ARCH_UNKNOWN = 0,
    ARCH_X86_32 = 1,
    ARCH_X86_64 = 2,
    ARCH_ARM_32 = 3,
    ARCH_ARM_64 = 4,
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

fn invalid_instruction(size: c_int) -> C_Instruksi {
    let mut instr = C_Instruksi {
        mnemonic_instruksi: [0; 32],
        str_operand: [0; 64],
        ukuran: size,
        valid: 0,
    };
    strncpy_rs("(invalid)", &mut instr.mnemonic_instruksi);
    instr
}

fn create_capstone_instance_by_arch(
    arch: ArsitekturDisasm,
) -> Result<Capstone, capstone::Error> {
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
        ArsitekturDisasm::ARCH_UNKNOWN => {
            Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build()
        }
    };
    cs_builder_result
}

pub fn logic_decode_instruksi(
    ptr_data: *const u8,
    len_data: usize,
    offset: usize,
    instruction_base_va: u64,
    arch: ArsitekturDisasm,
) -> C_Instruksi {
    if offset >= len_data {
        return invalid_instruction(0);
    }
    let data_slice = unsafe { slice::from_raw_parts(ptr_data, len_data) };
    let code_slice = &data_slice[offset..];
    if code_slice.is_empty() {
        return invalid_instruction(0);
    }
    let cs_instance_result = create_capstone_instance_by_arch(arch);
    let cs_instance = match cs_instance_result {
        Ok(cs) => cs,
        Err(_) => return invalid_instruction(1),
    };
    let insns_result = cs_instance.disasm_count(code_slice, instruction_base_va, 1);
    match insns_result {
        Ok(insns) => {
            if let Some(insn) = insns.first() {
                let mut c_instr = C_Instruksi {
                    mnemonic_instruksi: [0; 32],
                    str_operand: [0; 64],
                    ukuran: insn.bytes().len() as c_int,
                    valid: 1,
                };
                strncpy_rs(insn.mnemonic().unwrap_or(""), &mut c_instr.mnemonic_instruksi);
                strncpy_rs(insn.op_str().unwrap_or(""), &mut c_instr.str_operand);
                c_instr
            } else {
                invalid_instruction(1)
            }
        }
        Err(_) => {
            invalid_instruction(1)
        }
    }
}