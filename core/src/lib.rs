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
use libc::{c_char, c_int};
use parser::{C_HeaderInfo, C_SectionInfo, C_SymbolInfo};
pub use tracer::{
    rt_attachProses, rt_bacaMemory, rt_continueProses, rt_detachProses, rt_getRegisters,
    rt_setBreakpoint, rt_setRegisters, rt_singleStep, rt_tulisMemory, rt_tungguEvent,
};

/// Fungsi C-ABI buat disassembly
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_decodeInstruksi(
    ptr_data: *const u8, // Pointer mentah ke data bytes
    len_data: usize, // Panjang total data
    offset: usize, // Offset saat ini
    instruction_base_va: u64, // VA dari instruksi
    arch: ArsitekturDisasm, // Parameter arsitektur baru
) -> C_Instruksi {
    logic_decode_instruksi(ptr_data, len_data, offset, instruction_base_va, arch)
}

/// Fungsi C-ABI untuk parse header generik (ELF, PE, Mach-O)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getBinaryHeader(
    file_path_c: *const c_char,
    out_header: *mut C_HeaderInfo,
) -> c_int {
    unsafe { parser::c_getBinaryHeader(file_path_c, out_header) }
}

/// Fungsi C-ABI untuk parse ELF Sections
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSections(
    file_path_c: *const c_char,
    out_buffer: *mut C_SectionInfo,
    max_count: c_int,
) -> c_int {
    unsafe { parser::c_getDaftarSections(file_path_c, out_buffer, max_count) }
}

/// Fungsi C-ABI untuk parse ELF Symbols
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSimbol(
    file_path_c: *const c_char,
    out_buffer: *mut C_SymbolInfo,
    max_count: c_int,
) -> c_int {
    unsafe { parser::c_getDaftarSimbol(file_path_c, out_buffer, max_count) }
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
        let base_va: u64 = 0x1000; // Asumsi base VA

        // PUSH RBP (0x55) di 0x1000
        let insn1 = unsafe { c_decodeInstruksi(ptr, len, 0, base_va, arch) };
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

        // MOV RBP, RSP (0x48 0x89 0xE5) di 0x1001
        let insn2 = unsafe { c_decodeInstruksi(ptr, len, 1, base_va + 1, arch) }; // Offset 1
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
}