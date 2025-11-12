use goblin::elf::Elf;
use libc::{c_char, c_int};
use serde::Serialize;
use serde_json;
use std::ffi::{CStr, CString};
use std::fs;
use std::mem::MaybeUninit;
use std::path::Path;
use std::ptr;

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

#[derive(Serialize)]
struct InfoSection<'a> {
    name: &'a str,
    addr: u64,
    size: u64,
    offset: u64,
    tipe: u32,
}

#[derive(Serialize)]
struct InfoSimbol<'a> {
    name: &'a str,
    addr: u64,
    size: u64,
    symbol_type: &'a str,
    bind: &'a str,
}

/// Logika internal untuk parse sections
pub fn logic_parse_sections_elf(file_path_c: *const c_char) -> *mut c_char {
    let path_cstr = unsafe {
        if file_path_c.is_null() {
            return ptr::null_mut();
        }
        CStr::from_ptr(file_path_c)
    };
    let path_str = match path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let buffer_bytes = match fs::read(Path::new(path_str)) {
        Ok(bytes) => bytes,
        Err(_) => return ptr::null_mut(),
    };
    
    match Elf::parse(&buffer_bytes) {
        Ok(elf) => {
            let mut sections_vec = Vec::new();
            for section in &elf.section_headers {
                let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("(unknown)");
                sections_vec.push(InfoSection {
                    name: section_name,
                    addr: section.sh_addr,
                    size: section.sh_size,
                    offset: section.sh_offset,
                    tipe: section.sh_type,
                });
            }
            let json_string = serde_json::to_string(&sections_vec).unwrap_or_else(|_| "[]".to_string());
            match CString::new(json_string) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Logika internal untuk parse symbols
pub fn logic_parse_symbols_elf(file_path_c: *const c_char) -> *mut c_char {
    let path_cstr = unsafe {
        if file_path_c.is_null() {
            return ptr::null_mut();
        }
        CStr::from_ptr(file_path_c)
    };
    let path_str = match path_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let buffer_bytes = match fs::read(Path::new(path_str)) {
        Ok(bytes) => bytes,
        Err(_) => return ptr::null_mut(),
    };
    
    match Elf::parse(&buffer_bytes) {
        Ok(elf) => {
            let mut symbols_vec = Vec::new();
            
            // Simbol statis
            for sym in &elf.syms {
                let symbol_name = elf.strtab.get_at(sym.st_name).unwrap_or("(unknown_static)");
                if symbol_name.is_empty() { continue; } // Skip empty names
                
                symbols_vec.push(InfoSimbol {
                    name: symbol_name,
                    addr: sym.st_value,
                    size: sym.st_size,
                    symbol_type: st_type_to_str(sym.st_type()),
                    bind: st_bind_to_str(sym.st_bind()),
                });
            }
            
            // Simbol dinamis
            for sym in &elf.dynsyms {
                 let symbol_name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("(unknown_dynamic)");
                 if symbol_name.is_empty() { continue; } // Skip empty names
                 
                 symbols_vec.push(InfoSimbol {
                    name: symbol_name,
                    addr: sym.st_value,
                    size: sym.st_size,
                    symbol_type: st_type_to_str(sym.st_type()),
                    bind: st_bind_to_str(sym.st_bind()),
                });
            }

            let json_string = serde_json::to_string(&symbols_vec).unwrap_or_else(|_| "[]".to_string());
             match CString::new(json_string) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

// Helper untuk konversi Tipe Simbol Goblin ke string
fn st_type_to_str(st_type: u8) -> &'static str {
    match st_type {
        goblin::elf::sym::STT_NOTYPE => "NOTYPE",
        goblin::elf::sym::STT_OBJECT => "OBJECT",
        goblin::elf::sym::STT_FUNC => "FUNC",
        goblin::elf::sym::STT_SECTION => "SECTION",
        goblin::elf::sym::STT_FILE => "FILE",
        goblin::elf::sym::STT_COMMON => "COMMON",
        goblin::elf::sym::STT_TLS => "TLS",
        _ => "OTHER",
    }
}

// Helper untuk konversi Binding Simbol Goblin ke string
fn st_bind_to_str(st_bind: u8) -> &'static str {
    match st_bind {
        goblin::elf::sym::STB_LOCAL => "LOCAL",
        goblin::elf::sym::STB_GLOBAL => "GLOBAL",
        goblin::elf::sym::STB_WEAK => "WEAK",
        _ => "OTHER_BIND",
    }
}