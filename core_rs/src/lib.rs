mod disasm;
mod parser;
mod utils;

extern crate capstone;
extern crate goblin;
extern crate libc;

use disasm::{logic_decode_instruksi, C_Instruksi};
use libc::c_char;
use parser::{logic_parse_header_elf, C_ElfHeader};

/// Fungsi C-ABI buat disassembly
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_decodeInstruksi(
    ptr_data: *const u8, // Pointer mentah ke data bytes
    len_data: usize, // Panjang total data
    offset: usize, // Offset saat ini
) -> C_Instruksi {
    // Panggil logika dari modul disasm
    logic_decode_instruksi(ptr_data, len_data, offset)
}

/// Fungsi C-ABI untuk parsing ELF Header
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseHeaderElf(file_path_c: *const c_char) -> C_ElfHeader {
    // Panggil logika dari modul parser
    logic_parse_header_elf(file_path_c)
}

// TESTS)
#[cfg(test)]
mod tests {
    use super::*; // Impor c_... functions
    use std::ffi::CStr;

    #[test]
    fn test_disasm_rust_side() {
        // Test: PUSH RBP; MOV RBP, RSP; NOP; RET
        let code: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        let ptr = code.as_ptr();
        let len = code.len();

        // PUSH RBP (0x55)
        let insn1 = unsafe { c_decodeInstruksi(ptr, len, 0) };
        assert_eq!(insn1.valid, 1);
        assert_eq!(insn1.ukuran, 1);
        assert_eq!(
            unsafe { CStr::from_ptr(insn1.mnemonic_instruksi.as_ptr()).to_str().unwrap() },
            "push"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(insn1.str_operand.as_ptr()).to_str().unwrap() },
            "rbp"
        );

        // MOV RBP, RSP (0x48 0x89 0xE5)
        let insn2 = unsafe { c_decodeInstruksi(ptr, len, 1) }; // Offset 1
        assert_eq!(insn2.valid, 1);
        assert_eq!(insn2.ukuran, 3);
        assert_eq!(
            unsafe { CStr::from_ptr(insn2.mnemonic_instruksi.as_ptr()).to_str().unwrap() },
            "mov"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(insn2.str_operand.as_ptr()).to_str().unwrap() },
            "rbp, rsp"
        );

        // NOP (0x90)
        let insn3 = unsafe { c_decodeInstruksi(ptr, len, 4) }; // Offset 1 + 3
        assert_eq!(insn3.valid, 1);
        assert_eq!(insn3.ukuran, 1);
        assert_eq!(
            unsafe { CStr::from_ptr(insn3.mnemonic_instruksi.as_ptr()).to_str().unwrap() },
            "nop"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(insn3.str_operand.as_ptr()).to_str().unwrap() },
            ""
        );

        // RET (0xC3)
        let insn4 = unsafe { c_decodeInstruksi(ptr, len, 5) }; // Offset 1 + 3 + 1
        assert_eq!(insn4.valid, 1);
        assert_eq!(insn4.ukuran, 1);
        assert_eq!(
            unsafe { CStr::from_ptr(insn4.mnemonic_instruksi.as_ptr()).to_str().unwrap() },
            "ret"
        );
    }
}