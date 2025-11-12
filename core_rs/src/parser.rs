use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::Object;
use libc::c_char;
use serde::Serialize;
use serde_json;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::Path;
use std::ptr;

// Struct Generik
#[derive(Serialize)]
struct GenericHeaderInfo {
    valid: bool,
    format: &'static str,
    arch: &'static str,
    bits: u16,
    entry_point: u64,
    machine_id: u64,
    is_lib: bool,
    file_size: u64,
}

impl GenericHeaderInfo {
    /// Header yang invalid
    fn invalid() -> Self {
        GenericHeaderInfo {
            valid: false,
            format: "Unknown",
            arch: "Unknown",
            bits: 0,
            entry_point: 0,
            machine_id: 0,
            is_lib: false,
            file_size: 0,
        }
    }

    /// Helper untuk map ELF machine ID ke string
    fn arch_from_elf_machine(machine: u16) -> &'static str {
        match machine {
            goblin::elf::header::EM_X86_64 => "x86-64",
            goblin::elf::header::EM_386 => "x86",
            goblin::elf::header::EM_AARCH64 => "AArch64",
            goblin::elf::header::EM_ARM => "ARM",
            _ => "Unknown",
        }
    }

    /// Helper untuk map PE machine ID ke string
    fn arch_from_pe_machine(machine: u16) -> &'static str {
        match machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => "x86-64",
            goblin::pe::header::COFF_MACHINE_X86 => "x86",
            goblin::pe::header::COFF_MACHINE_ARM64 => "AArch64",
            goblin::pe::header::COFF_MACHINE_ARMNT => "ARM",
            _ => "Unknown",
        }
    }

    /// Helper untuk map Mach-O cputype ke string
    fn arch_from_macho_cputype(cputype: u32) -> &'static str {
        match cputype {
            c if c == goblin::mach::cputype::CPU_TYPE_X86_64
                || c == goblin::mach::cputype::CPU_TYPE_X86 =>
            {
                "x86"
            }
            c if c == goblin::mach::cputype::CPU_TYPE_ARM64
                || c == goblin::mach::cputype::CPU_TYPE_ARM =>
            {
                "ARM"
            }
            _ => "Unknown",
        }
    }
}

/// Logika internal untuk parse header (ELF, PE, Mach-O)
pub fn logic_parse_binary_header(file_path_c: *const c_char) -> *mut c_char {
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
    let file_size_actual = buffer_bytes.len() as u64;

    // Goblin auto-deteksi format
    let header_info = match Object::parse(&buffer_bytes) {
        Ok(Object::Elf(elf)) => {
            let machine_id = elf.header.e_machine;
            GenericHeaderInfo {
                valid: true,
                format: "ELF",
                arch: GenericHeaderInfo::arch_from_elf_machine(machine_id),
                bits: if elf.is_64 { 64 } else { 32 },
                entry_point: elf.entry,
                machine_id: machine_id as u64,
                is_lib: elf.header.e_type == goblin::elf::header::ET_DYN,
                file_size: file_size_actual,
            }
        }
        Ok(Object::PE(pe)) => {
            let machine_id = pe.header.coff_header.machine;
            GenericHeaderInfo {
                valid: true,
                format: "PE",
                arch: GenericHeaderInfo::arch_from_pe_machine(machine_id),
                bits: if pe.is_64 { 64 } else { 32 },
                entry_point: pe.entry as u64,
                machine_id: machine_id as u64,
                is_lib: pe.is_lib,
                file_size: file_size_actual,
            }
        }
        Ok(Object::Mach(mach)) => {
            // Mach bisa multi-arsitektur (Fat binary)
            let (format_str, bits, machine_id, entry, is_lib) = match mach {
                Mach::Binary(macho) => (
                    "Mach-O",
                    if macho.is_64 { 64 } else { 32 },
                    macho.header.cputype() as u64,
                    macho.entry,
                    macho.header.filetype == goblin::mach::header::MH_DYLIB,
                ),
                Mach::Fat(multiarch) => {
                    if let Ok(goblin::mach::SingleArch::MachO(macho)) = multiarch.get(0) {
                        (
                            "Mach-O (Fat)",
                            if macho.is_64 { 64 } else { 32 },
                            macho.header.cputype() as u64,
                            macho.entry,
                            macho.header.filetype == goblin::mach::header::MH_DYLIB,
                        )
                    } else {
                        ("Mach-O (Fat-Empty/Archive)", 0, 0, 0, false)
                    }
                }
            };
            GenericHeaderInfo {
                valid: true,
                format: format_str,
                arch: GenericHeaderInfo::arch_from_macho_cputype(machine_id as u32),
                bits,
                entry_point: entry,
                machine_id,
                is_lib,
                file_size: file_size_actual,
            }
        }
        Ok(Object::Archive(_)) => GenericHeaderInfo {
            valid: true,
            format: "Archive (.a/.lib)",
            ..GenericHeaderInfo::invalid()
        },
        _ => GenericHeaderInfo {
            file_size: file_size_actual,
            ..GenericHeaderInfo::invalid()
        },
    };

    // Serialize ke JSON
    let json_string = serde_json::to_string(&header_info).unwrap_or_else(|_| "{}".to_string());
    match CString::new(json_string) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

// Fungsi Parser Section & Simbol
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
            let json_string =
                serde_json::to_string(&sections_vec).unwrap_or_else(|_| "[]".to_string());
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
                if symbol_name.is_empty() {
                    continue;
                } // Skip empty names

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
                let symbol_name = elf
                    .dynstrtab
                    .get_at(sym.st_name)
                    .unwrap_or("(unknown_dynamic)");
                if symbol_name.is_empty() {
                    continue;
                } // Skip empty names

                symbols_vec.push(InfoSimbol {
                    name: symbol_name,
                    addr: sym.st_value,
                    size: sym.st_size,
                    symbol_type: st_type_to_str(sym.st_type()),
                    bind: st_bind_to_str(sym.st_bind()),
                });
            }
            
            let json_string =
                serde_json::to_string(&symbols_vec).unwrap_or_else(|_| "[]".to_string());
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