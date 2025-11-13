use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::Object;
use libc::{c_char, c_int};
use std::ffi::CStr;
use std::fs;
use std::path::Path;
use std::slice;

use super::utils::strncpy_rs;

// Struct Generik internal
struct InternalHeaderInfo {
    valid: bool,
    format: &'static str,
    arch: &'static str,
    bits: u16,
    entry_point: u64,
    machine_id: u64,
    is_lib: bool,
    file_size: u64,
}

impl InternalHeaderInfo {
    fn invalid() -> Self {
        InternalHeaderInfo {
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
    fn arch_from_elf_machine(machine: u16) -> &'static str {
        match machine {
            goblin::elf::header::EM_X86_64 => "x86-64",
            goblin::elf::header::EM_386 => "x86",
            goblin::elf::header::EM_AARCH64 => "AArch64",
            goblin::elf::header::EM_ARM => "ARM",
            _ => "Unknown",
        }
    }
    fn arch_from_pe_machine(machine: u16) -> &'static str {
        match machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => "x86-64",
            goblin::pe::header::COFF_MACHINE_X86 => "x86",
            goblin::pe::header::COFF_MACHINE_ARM64 => "AArch64",
            goblin::pe::header::COFF_MACHINE_ARMNT => "ARM",
            _ => "Unknown",
        }
    }
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

// Definisi Struct C-ABI
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct C_HeaderInfo {
    pub valid: i32,
    pub format: [c_char; 64],
    pub arch: [c_char; 64],
    pub bits: u16,
    pub entry_point: u64,
    pub machine_id: u64,
    pub is_lib: i32,
    pub file_size: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct C_SectionInfo {
    pub name: [c_char; 128],
    pub addr: u64,
    pub size: u64,
    pub offset: u64,
    pub tipe: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct C_SymbolInfo {
    pub name: [c_char; 128],
    pub addr: u64,
    pub size: u64,
    pub symbol_type: [c_char; 64],
    pub bind: [c_char; 64],
}

/// Helper untuk baca file
fn read_file_bytes(file_path_c: *const c_char) -> Option<Vec<u8>> {
    // Operasi FFI (deref pointer)
    unsafe {
        let path_cstr = {
            if file_path_c.is_null() {
                return None;
            }
            CStr::from_ptr(file_path_c)
        };
        let path_str = path_cstr.to_str().ok()?;
        fs::read(Path::new(path_str)).ok()
    }
}

/// Helper untuk konversi Tipe Simbol Goblin ke string
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

/// Helper untuk konversi Binding Simbol Goblin ke string
fn st_bind_to_str(st_bind: u8) -> &'static str {
    match st_bind {
        goblin::elf::sym::STB_LOCAL => "LOCAL",
        goblin::elf::sym::STB_GLOBAL => "GLOBAL",
        goblin::elf::sym::STB_WEAK => "WEAK",
        _ => "OTHER_BIND",
    }
}

/// Implementasi c_getBinaryHeader
#[allow(non_snake_case)]
pub unsafe fn c_get_binary_header(
    file_path_c: *const c_char,
    out_header: *mut C_HeaderInfo,
) -> c_int {
    unsafe {
        if out_header.is_null() {
            return -1;
        }

        let Some(buffer_bytes) = read_file_bytes(file_path_c) else {
            return -1;
        };
        let file_size_actual = buffer_bytes.len() as u64;

        let header_info = match Object::parse(&buffer_bytes) {
            Ok(Object::Elf(elf)) => {
                let machine_id = elf.header.e_machine;
                InternalHeaderInfo {
                    valid: true,
                    format: "ELF",
                    arch: InternalHeaderInfo::arch_from_elf_machine(machine_id),
                    bits: if elf.is_64 { 64 } else { 32 },
                    entry_point: elf.entry,
                    machine_id: machine_id as u64,
                    is_lib: elf.header.e_type == goblin::elf::header::ET_DYN,
                    file_size: file_size_actual,
                }
            }
            Ok(Object::PE(pe)) => {
                let machine_id = pe.header.coff_header.machine;
                InternalHeaderInfo {
                    valid: true,
                    format: "PE",
                    arch: InternalHeaderInfo::arch_from_pe_machine(machine_id),
                    bits: if pe.is_64 { 64 } else { 32 },
                    entry_point: pe.entry as u64,
                    machine_id: machine_id as u64,
                    is_lib: pe.is_lib,
                    file_size: file_size_actual,
                }
            }
            Ok(Object::Mach(mach)) => {
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
                InternalHeaderInfo {
                    valid: true,
                    format: format_str,
                    arch: InternalHeaderInfo::arch_from_macho_cputype(machine_id as u32),
                    bits,
                    entry_point: entry,
                    machine_id,
                    is_lib,
                    file_size: file_size_actual,
                }
            }
            Ok(Object::Archive(_)) => InternalHeaderInfo {
                valid: true,
                format: "Archive (.a/.lib)",
                ..InternalHeaderInfo::invalid()
            },
            _ => InternalHeaderInfo {
                file_size: file_size_actual,
                ..InternalHeaderInfo::invalid()
            },
        };

        // Isi struct C_HeaderInfo
        let out = &mut *out_header;
        out.valid = if header_info.valid { 1 } else { 0 };
        strncpy_rs(header_info.format, &mut out.format);
        strncpy_rs(header_info.arch, &mut out.arch);
        out.bits = header_info.bits;
        out.entry_point = header_info.entry_point;
        out.machine_id = header_info.machine_id;
        out.is_lib = if header_info.is_lib { 1 } else { 0 };
        out.file_size = header_info.file_size;

        0 // Sukses
    }
}

/// Implementasi c_getDaftarSections
#[allow(non_snake_case)]
pub unsafe fn c_get_daftar_sections(
    file_path_c: *const c_char,
    out_buffer: *mut C_SectionInfo,
    max_count: c_int,
) -> c_int {
    unsafe {
        if out_buffer.is_null() || max_count <= 0 {
            return -1;
        }

        let Some(buffer_bytes) = read_file_bytes(file_path_c) else {
            return -1;
        };

        match Elf::parse(&buffer_bytes) {
            Ok(elf) => {
                let sections = &elf.section_headers;
                if sections.len() > max_count as usize {
                    return -1; // Buffer tidak cukup
                }

                // Buat slice C dari buffer C++
                let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);

                for (i, section) in sections.iter().enumerate() {
                    let section_name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("(unknown)");
                    let out_item = &mut out_slice[i];

                    strncpy_rs(section_name, &mut out_item.name);
                    out_item.addr = section.sh_addr;
                    out_item.size = section.sh_size;
                    out_item.offset = section.sh_offset;
                    out_item.tipe = section.sh_type;
                }
                sections.len() as c_int // Kembalikan jumlah section yang diisi
            }
            Err(_) => -1, // Gagal parse ELF
        }
    }
}

/// Implementasi c_getDaftarSimbol
#[allow(non_snake_case)]
pub unsafe fn c_get_daftar_simbol(
    file_path_c: *const c_char,
    out_buffer: *mut C_SymbolInfo,
    max_count: c_int,
) -> c_int {
    // Tambahkan blok unsafe
    unsafe {
        if out_buffer.is_null() || max_count <= 0 {
            return -1;
        }

        let Some(buffer_bytes) = read_file_bytes(file_path_c) else {
            return -1;
        };

        match Elf::parse(&buffer_bytes) {
            Ok(elf) => {
                // Gabungkan simbol statis dan dinamis
                let mut all_symbols = Vec::new();
                for sym in &elf.syms {
                    let symbol_name = elf.strtab.get_at(sym.st_name).unwrap_or("(unknown_static)");
                    if !symbol_name.is_empty() {
                        all_symbols.push((symbol_name, sym));
                    }
                }
                for sym in &elf.dynsyms {
                    let symbol_name = elf
                        .dynstrtab
                        .get_at(sym.st_name)
                        .unwrap_or("(unknown_dynamic)");
                    if !symbol_name.is_empty() {
                        all_symbols.push((symbol_name, sym));
                    }
                }

                if all_symbols.len() > max_count as usize {
                    return -1; // Buffer tidak cukup
                }

                // Buat slice C dari buffer C++ (Operasi unsafe)
                let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);

                for (i, (symbol_name, sym)) in all_symbols.iter().enumerate() {
                    let out_item = &mut out_slice[i];
                    strncpy_rs(symbol_name, &mut out_item.name);
                    out_item.addr = sym.st_value;
                    out_item.size = sym.st_size;
                    strncpy_rs(st_type_to_str(sym.st_type()), &mut out_item.symbol_type);
                    strncpy_rs(st_bind_to_str(sym.st_bind()), &mut out_item.bind);
                }
                all_symbols.len() as c_int // Kembalikan jumlah simbol
            }
            Err(_) => -1, // Gagal parse ELF
        }
    }
}