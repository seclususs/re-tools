mod disasm;
mod parser;
mod tracer;
mod utils;

extern crate capstone;
extern crate goblin;
extern crate libc;
extern crate serde;
extern crate serde_json;

use disasm::{logic_decode_instruksi, ArsitekturDisasm, C_Instruksi};
use libc::c_char;
use parser::{
    logic_parse_binary_header, logic_parse_sections_elf, logic_parse_symbols_elf,
};
use std::ffi::CString;
pub use tracer::*;

/// Fungsi C-ABI buat disassembly
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_decodeInstruksi(
    ptr_data: *const u8, // Pointer mentah ke data bytes
    len_data: usize, // Panjang total data
    offset: usize, // Offset saat ini
    arch: ArsitekturDisasm, // Parameter arsitektur baru
) -> C_Instruksi {
    logic_decode_instruksi(ptr_data, len_data, offset, arch)
}

/// Fungsi C-ABI untuk parse header generik (ELF, PE, Mach-O)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseBinaryHeader(file_path_c: *const c_char) -> *mut c_char {
    logic_parse_binary_header(file_path_c)
}

/// Fungsi C-ABI untuk parse ELF Sections
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseSectionsElf(file_path_c: *const c_char) -> *mut c_char {
    logic_parse_sections_elf(file_path_c)
}

/// Fungsi C-ABI untuk parse ELF Symbols
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_parseSymbolsElf(file_path_c: *const c_char) -> *mut c_char {
    logic_parse_symbols_elf(file_path_c)
}

/// Fungsi C-ABI untuk membebaskan string JSON
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_freeJsonString(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}

/// TEST
#[cfg(test)]
mod tests {
    use super::*; // Impor c_... functions
    use std::ffi::CStr;

    #[test]
    fn test_disasm_rust_side_x86_64() {
        // Test: PUSH RBP; MOV RBP, RSP; NOP; RET
        let code: Vec<u8> = vec![0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        let ptr = code.as_ptr();
        let len = code.len();
        let arch = ArsitekturDisasm::ARCH_X86_64;

        // PUSH RBP (0x55)
        let insn1 = unsafe { c_decodeInstruksi(ptr, len, 0, arch) };
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
        let insn2 = unsafe { c_decodeInstruksi(ptr, len, 1, arch) }; // Offset 1
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
    }

    #[test]
    fn test_disasm_rust_side_aarch64() {
        // Test: MOV X0, #0 (0xD2800000 di-reverse jadi 00 00 80 D2)
        let code: Vec<u8> = vec![0x00, 0x00, 0x80, 0xD2];
        let ptr = code.as_ptr();
        let len = code.len();
        let arch = ArsitekturDisasm::ARCH_ARM_64;

        let insn1 = unsafe { c_decodeInstruksi(ptr, len, 0, arch) };
        assert_eq!(insn1.valid, 1);
        assert_eq!(insn1.ukuran, 4);
        assert_eq!(
            unsafe { CStr::from_ptr(insn1.mnemonic_instruksi.as_ptr()).to_str().unwrap() },
            "mov"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(insn1.str_operand.as_ptr()).to_str().unwrap() },
            "x0, #0"
        );
    }
}