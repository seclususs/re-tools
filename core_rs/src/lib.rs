// Impor crate eksternal
extern crate capstone;
extern crate libc;

// Impor Crate
use capstone::prelude::*;
use libc::{c_char, c_int};
use std::ptr;
use std::slice;

// Struct C-ABI yang akan di return ke C++
#[allow(non_camel_case_types)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct C_Instruksi {
    // char mnemonic[32];
    // Nama mnemonic instruksinya
    pub mnemonic_instruksi: [c_char; 32],
    
    // char op_str[64];
    // String operand, misal "rax, rbx"
    pub str_operand: [c_char; 64],
    
    // int size;
    // Ukuran instruksi (dalam bytes)
    pub ukuran: c_int,
    
    // int valid;
    // Flag: 1 kalo valid, 0 kalo gagal decode
    pub valid: c_int,
}

/// Helper strncpy Rust ke fixed-size C buffer
fn strncpy_rs(src: &str, dest: &mut [c_char]) {
    let src_bytes = src.as_bytes();
    let len = std::cmp::min(src_bytes.len(), dest.len() - 1);

    // Salin datanya
    unsafe {
        ptr::copy_nonoverlapping(src_bytes.as_ptr() as *const c_char, dest.as_mut_ptr(), len);
    }
    // null-terminator
    dest[len] = 0;
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

/// Fungsi C-ABI buat disassembly pake Capstone
#[unsafe(no_mangle)]
pub extern "C" fn c_decodeInstruksi(
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

    // Disassemble SATU instruksi aja
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
                // Capstone nggak nemu instruksi
                invalid_instruction(1)
            }
        }
        Err(_) => {
            // Error pas disassembly
            invalid_instruction(1)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_disasm_rust_side() {
        // Test: PUSH RBP; MOV RBP, RSP; NOP; RET
        let code: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        let ptr = code.as_ptr();
        let len = code.len();

        // PUSH RBP (0x55)
        let insn1 = c_decodeInstruksi(ptr, len, 0);
        assert_eq!(insn1.valid, 1);
        assert_eq!(insn1.ukuran, 1);
        assert_eq!(unsafe { CStr::from_ptr(insn1.mnemonic_instruksi.as_ptr()).to_str().unwrap() }, "push");
        assert_eq!(unsafe { CStr::from_ptr(insn1.str_operand.as_ptr()).to_str().unwrap() }, "rbp");

        // MOV RBP, RSP (0x48 0x89 0xE5)
        let insn2 = c_decodeInstruksi(ptr, len, 1); // Offset 1
        assert_eq!(insn2.valid, 1);
        assert_eq!(insn2.ukuran, 3);
        assert_eq!(unsafe { CStr::from_ptr(insn2.mnemonic_instruksi.as_ptr()).to_str().unwrap() }, "mov");
        assert_eq!(unsafe { CStr::from_ptr(insn2.str_operand.as_ptr()).to_str().unwrap() }, "rbp, rsp");

        // NOP (0x90)
        let insn3 = c_decodeInstruksi(ptr, len, 4); // Offset 1 + 3
        assert_eq!(insn3.valid, 1);
        assert_eq!(insn3.ukuran, 1);
        assert_eq!(unsafe { CStr::from_ptr(insn3.mnemonic_instruksi.as_ptr()).to_str().unwrap() }, "nop");
        assert_eq!(unsafe { CStr::from_ptr(insn3.str_operand.as_ptr()).to_str().unwrap() }, "");

        // RET (0xC3)
        let insn4 = c_decodeInstruksi(ptr, len, 5); // Offset 1 + 3 + 1
        assert_eq!(insn4.valid, 1);
        assert_eq!(insn4.ukuran, 1);
        assert_eq!(unsafe { CStr::from_ptr(insn4.mnemonic_instruksi.as_ptr()).to_str().unwrap() }, "ret");
    }
}