use goblin::elf::Elf;
use libc::{c_char, c_int};
use std::ffi::CStr;
use std::fs;
use std::mem::MaybeUninit;
use std::path::Path;

use super::utils::strncpy_rs;

/// Struct C-ABI untuk ElfHeader
#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct C_ElfHeader {
    // char magic[5];
    pub magic: [c_char; 5],
    // uint64_t entry_point;
    pub entry_point: u64,
    // uint16_t machine;
    pub machine: u16,
    // uint16_t section_count;
    pub section_count: u16,
    // int valid;
    pub valid: c_int,
    // uint64_t ukuran_file_size;
    pub ukuran_file_size: u64,
    // uint64_t padding
    pub padding: u64,
}

/// C_ElfHeader yang invalid (gagal parse)
fn invalid_elf_header() -> C_ElfHeader {
    let mut header: C_ElfHeader = unsafe { MaybeUninit::zeroed().assume_init() };
    strncpy_rs("ERR", &mut header.magic);
    header.valid = 0;
    header
}

/// Logika internal untuk parsing ELF
pub fn logic_parse_header_elf(file_path_c: *const c_char) -> C_ElfHeader {
    // Konversi *const c_char ke &str yang aman
    let path_cstr = unsafe {
        if file_path_c.is_null() {
            return invalid_elf_header();
        }
        CStr::from_ptr(file_path_c)
    };

    let path_str = match path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return invalid_elf_header(), // Error jika path bukan UTF-8 valid
    };
    let path = Path::new(path_str);

    // Baca file ke buffer
    let buffer_bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return invalid_elf_header(), // Gagal baca file
    };

    // Simpan ukuran file
    let ukuran_file_actual = buffer_bytes.len() as u64;

    // Parse menggunakan Goblin
    match Elf::parse(&buffer_bytes) {
        Ok(elf) => {
            // Sukses parse, isi struct C_ElfHeader
            let elf_header = elf.header;
            let mut c_header: C_ElfHeader = unsafe { MaybeUninit::zeroed().assume_init() };

            strncpy_rs("ELF", &mut c_header.magic); // Tanda sukses
            c_header.valid = 1;
            c_header.entry_point = elf_header.e_entry;
            c_header.machine = elf_header.e_machine;
            c_header.section_count = elf_header.e_shnum;
            c_header.ukuran_file_size = ukuran_file_actual; // Isi ukuran file
            c_header
        }
        Err(_) => {
            // Gagal parse (bukan ELF valid)
            invalid_elf_header()
        }
    }
}