use capstone::prelude::*;
use libc::{c_char, c_int};
use std::slice;

use super::utils::strncpy_rs;

/// Struct C-ABI yang akan di return ke C++
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct C_Instruksi {
    // Nama mnemonic instruksinya
    pub mnemonic_instruksi: [c_char; 32],
    // String operand, misal "rax, rbx"
    pub str_operand: [c_char; 64],
    // Ukuran instruksi (dalam bytes)
    pub ukuran: c_int,
    // Flag: 1 kalo valid, 0 kalo gagal decode
    pub valid: c_int,
}

/// C_Instruksi default yang invalid
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

/// Logika internal untuk disassembly
pub fn logic_decode_instruksi(
    ptr_data: *const u8, // Pointer mentah ke data bytes
    len_data: usize, // Panjang total data
    offset: usize, // Offset saat ini
) -> C_Instruksi {
    // Bounds check dulu
    if offset >= len_data {
        return invalid_instruction(0);
    }

    // Bikin slice yang aman dari raw pointer-nya
    let data_slice = unsafe { slice::from_raw_parts(ptr_data, len_data) };

    // Slice datanya dari offset
    let code_slice = &data_slice[offset..];
    if code_slice.is_empty() {
        return invalid_instruction(0);
    }

    // Inisialisasi Capstone
    // TODO: Idealnya, instance Capstone ini di-cache, jangan dibuat di tiap call
    let cs_result = Capstone::new()
        .x86() // Set arsitektur ke x86
        .mode(arch::x86::ArchMode::Mode64) // Mode 64-bit
        .detail(true) // Kita butuh detail
        .build();

    let cs = match cs_result {
        Ok(cs) => cs,
        Err(_) => return invalid_instruction(1), // Gagal init Capstone
    };

    // Disassemble SATU instruksi
    let insns_result = cs.disasm_count(code_slice, 0x0, 1); // 0x0 itu virtual address, bisa apa aja

    match insns_result {
        Ok(insns) => {
            if let Some(insn) = insns.first() {
                // Sukses decode, isi struct C_Instruksi
                let mut c_instr = C_Instruksi {
                    mnemonic_instruksi: [0; 32],
                    str_operand: [0; 64],
                    ukuran: insn.bytes().len() as c_int,
                    valid: 1,
                };

                // Salin mnemonic dan operand
                strncpy_rs(insn.mnemonic().unwrap_or(""), &mut c_instr.mnemonic_instruksi);
                strncpy_rs(insn.op_str().unwrap_or(""), &mut c_instr.str_operand);

                c_instr
            } else {
                // Capstone gak nemu instruksi
                invalid_instruction(1)
            }
        }
        Err(_) => {
            // Error pas disassembly
            invalid_instruction(1)
        }
    }
}