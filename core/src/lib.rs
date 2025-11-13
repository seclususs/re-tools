mod disasm;
mod parser;
mod tracer;
mod utils;
mod analyzer;
mod cfg;
mod diff;

extern crate capstone;
extern crate goblin;
extern crate libc;
extern crate serde;
extern crate serde_json;
extern crate petgraph;
extern crate encoding_rs;

use disasm::{logic_decode_instruksi, ArsitekturDisasm, C_Instruksi};
use libc::{c_char, c_int};
use parser::{C_HeaderInfo, C_SectionInfo, C_SymbolInfo};
use diff::C_DiffResult;
pub use tracer::{
    rt_attachProses, rt_bacaMemory, rt_continueProses, rt_detachProses, rt_getRegisters,
    rt_setBreakpoint, rt_setRegisters, rt_singleStep, rt_tulisMemory, rt_tungguEvent,
};

// KUMPULAN SEMUA C-ABI WRAPPER 

/// Fungsi C-ABI buat disassembly
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_decodeInstruksi(
    ptr_data: *const u8, 
    len_data: usize, 
    offset: usize, 
    instruction_base_va: u64,
    arch: ArsitekturDisasm,
) -> C_Instruksi {
    logic_decode_instruksi(ptr_data, len_data, offset, instruction_base_va, arch)
}

/// Fungsi C-ABI untuk parse header generik (ELF, PE, Mach-O)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getBinaryHeader(
    file_path_c: *const c_char,
    out_header: *mut C_HeaderInfo,
) -> c_int {
    unsafe { parser::c_get_binary_header(file_path_c, out_header) }
}

/// Fungsi C-ABI untuk parse ELF Sections
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSections(
    file_path_c: *const c_char,
    out_buffer: *mut C_SectionInfo,
    max_count: c_int,
) -> c_int {
    unsafe { parser::c_get_daftar_sections(file_path_c, out_buffer, max_count) }
}

/// Fungsi C-ABI untuk parse ELF Symbols
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getDaftarSimbol(
    file_path_c: *const c_char,
    out_buffer: *mut C_SymbolInfo,
    max_count: c_int,
) -> c_int {
    unsafe { parser::c_get_daftar_simbol(file_path_c, out_buffer, max_count) }
}

/// Fungsi C-ABI untuk Analyzer (Strings)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_getStringsList_rs(
    file_path_c: *const c_char,
    min_length: c_int,
) -> *mut c_char {
    unsafe { analyzer::c_get_strings_list(file_path_c, min_length) }
}

/// Wrapper untuk c_diffBinary_rs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_diffBinary_rs(
    file1_c: *const c_char,
    file2_c: *const c_char,
    out_results: *mut C_DiffResult,
    max_results: c_int,
) -> c_int {
    unsafe { diff::c_diff_binary_rs(file1_c, file2_c, out_results, max_results) }
}

/// Wrapper untuk c_generateCFG_rs
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_generateCFG_rs(filename_c: *const c_char) -> *mut c_char {
    unsafe { cfg::c_generate_cfg_rs(filename_c) }
}

/// Wrapper untuk c_freeString
#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_freeString(ptr: *mut c_char) {
    unsafe {
        utils::c_free_string(ptr);
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