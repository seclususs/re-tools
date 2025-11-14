use goblin::elf::Elf;
use goblin::mach::Mach;
use goblin::Object;
use libc::{c_char, c_int};
use std::ffi::CStr;
use std::fs;
use std::path::Path;
use std::slice;

use crate::error::ReToolsError;
use crate::utils::strncpy_rs;
use log::{debug, error, info, warn};


#[derive(Debug, Clone, Copy)]
pub struct InternalHeaderInfo {
    pub valid: bool,
    pub format: &'static str,
    pub arch: &'static str,
    pub bits: u16,
    pub entry_point: u64,
    pub machine_id: u64,
    pub is_lib: bool,
    pub file_size: u64,
}

impl InternalHeaderInfo {
    pub fn invalid() -> Self {
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
    pub fn arch_from_elf_machine(machine: u16) -> &'static str {
        match machine {
            goblin::elf::header::EM_X86_64 => "x86-64",
            goblin::elf::header::EM_386 => "x86",
            goblin::elf::header::EM_AARCH64 => "AArch64",
            goblin::elf::header::EM_ARM => "ARM",
            _ => "Unknown",
        }
    }
    pub fn arch_from_pe_machine(machine: u16) -> &'static str {
        match machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => "x86-64",
            goblin::pe::header::COFF_MACHINE_X86 => "x86",
            goblin::pe::header::COFF_MACHINE_ARM64 => "AArch64",
            goblin::pe::header::COFF_MACHINE_ARMNT => "ARM",
            _ => "Unknown",
        }
    }
    pub fn arch_from_macho_cputype(cputype: u32) -> &'static str {
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

pub fn parse_header_info_internal(file_path: &str) -> Result<InternalHeaderInfo, ReToolsError> {
    info!("Mulai parse header untuk: {}", file_path);
    let buffer_bytes = fs::read(file_path)?;
    let file_size_actual = buffer_bytes.len() as u64;
    debug!("Ukuran file dibaca: {} bytes", file_size_actual);
    let header_info = match Object::parse(&buffer_bytes) {
        Ok(Object::Elf(elf)) => {
            let machine_id = elf.header.e_machine;
            info!("Format file terdeteksi: ELF");
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
            info!("Format file terdeteksi: PE");
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
            info!("Format file terdeteksi: Mach-O");
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
                        warn!("Mach-O (Fat) tidak berisi-arsitektur MachO yang valid");
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
        Ok(Object::Archive(_)) => {
            info!("Format file terdeteksi: Archive");
            InternalHeaderInfo {
                valid: true,
                format: "Archive (.a/.lib)",
                ..InternalHeaderInfo::invalid()
            }
        }
        Err(e) => {
            warn!("Goblin parse gagal: {}", e);
            Err(ReToolsError::ParseError(e.to_string()))?
        }
        _ => {
            warn!("Format file tidak diketahui atau tidak didukung");
            InternalHeaderInfo {
                file_size: file_size_actual,
                ..InternalHeaderInfo::invalid()
            }
        }
    };
    Ok(header_info)
}

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

pub fn read_file_bytes(file_path_c: *const c_char) -> Result<Vec<u8>, ReToolsError> {
    unsafe {
        let path_cstr = {
            if file_path_c.is_null() {
                error!("file_path_c adalah null");
                return Err(ReToolsError::Generic("Path is null".to_string()));
            }
            CStr::from_ptr(file_path_c)
        };
        let path_str = path_cstr.to_str()?;
        debug!("Membaca file bytes dari: {}", path_str);
        Ok(fs::read(Path::new(path_str))?)
    }
}

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

fn st_bind_to_str(st_bind: u8) -> &'static str {
    match st_bind {
        goblin::elf::sym::STB_LOCAL => "LOCAL",
        goblin::elf::sym::STB_GLOBAL => "GLOBAL",
        goblin::elf::sym::STB_WEAK => "WEAK",
        _ => "OTHER_BIND",
    }
}

#[allow(non_snake_case)]
pub unsafe fn c_get_binary_header(
    file_path_c: *const c_char,
    out_header: *mut C_HeaderInfo,
) -> c_int {
    let path_str_result = CStr::from_ptr(file_path_c).to_str();
    let internal_result = match path_str_result {
        Ok(path_str) => parse_header_info_internal(path_str),
        Err(e) => Err(ReToolsError::from(e)),
    };
    match internal_result {
        Ok(header_info) => {
            let out = &mut *out_header;
            out.valid = if header_info.valid { 1 } else { 0 };
            strncpy_rs(header_info.format, &mut out.format);
            strncpy_rs(header_info.arch, &mut out.arch);
            out.bits = header_info.bits;
            out.entry_point = header_info.entry_point;
            out.machine_id = header_info.machine_id;
            out.is_lib = if header_info.is_lib { 1 } else { 0 };
            out.file_size = header_info.file_size;
            0
        }
        Err(e) => {
            error!("c_get_binary_header gagal: {}", e);
            -1
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn c_get_daftar_sections(
    file_path_c: *const c_char,
    out_buffer: *mut C_SectionInfo,
    max_count: c_int,
) -> c_int {
    unsafe {
        if out_buffer.is_null() || max_count <= 0 {
            error!("Buffer output invalid atau max_count <= 0");
            return -1;
        }
        let buffer_bytes = match read_file_bytes(file_path_c) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Gagal membaca file bytes: {}", e);
                return -1;
            }
        };
        match Elf::parse(&buffer_bytes) {
            Ok(elf) => {
                let sections = &elf.section_headers;
                if sections.len() > max_count as usize {
                    warn!(
                        "Jumlah sections ({}) melebihi max_count ({})",
                        sections.len(),
                        max_count
                    );
                    return -1;
                }
                info!("Ditemukan {} sections", sections.len());
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
                sections.len() as c_int
            }
            Err(e) => {
                error!("Gagal parse ELF: {}", e);
                -1
            }
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn c_get_daftar_simbol(
    file_path_c: *const c_char,
    out_buffer: *mut C_SymbolInfo,
    max_count: c_int,
) -> c_int {
    unsafe {
        if out_buffer.is_null() || max_count <= 0 {
            error!("Buffer output invalid atau max_count <= 0");
            return -1;
        }
        let buffer_bytes = match read_file_bytes(file_path_c) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Gagal membaca file bytes: {}", e);
                return -1;
            }
        };
        match Elf::parse(&buffer_bytes) {
            Ok(elf) => {
                let mut all_symbols = Vec::new();
                for sym in &elf.syms {
                    let symbol_name = elf.strtab.get_at(sym.st_name).unwrap_or("(unknown_static)");
                    if !symbol_name.is_empty() {
                        all_symbols.push((symbol_name, sym));
                    }
                }
                debug!("Ditemukan {} static symbols", elf.syms.len());
                for sym in &elf.dynsyms {
                    let symbol_name = elf
                        .dynstrtab
                        .get_at(sym.st_name)
                        .unwrap_or("(unknown_dynamic)");
                    if !symbol_name.is_empty() {
                        all_symbols.push((symbol_name, sym));
                    }
                }
                debug!("Ditemukan {} dynamic symbols", elf.dynsyms.len());
                if all_symbols.len() > max_count as usize {
                    warn!(
                        "Jumlah total simbol ({}) melebihi max_count ({})",
                        all_symbols.len(),
                        max_count
                    );
                    return -1;
                }
                info!("Total simbol yang diproses: {}", all_symbols.len());
                let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);
                for (i, (symbol_name, sym)) in all_symbols.iter().enumerate() {
                    let out_item = &mut out_slice[i];
                    strncpy_rs(symbol_name, &mut out_item.name);
                    out_item.addr = sym.st_value;
                    out_item.size = sym.st_size;
                    strncpy_rs(st_type_to_str(sym.st_type()), &mut out_item.symbol_type);
                    strncpy_rs(st_bind_to_str(sym.st_bind()), &mut out_item.bind);
                }
                all_symbols.len() as c_int
            }
            Err(e) => {
                error!("Gagal parse ELF: {}", e);
                -1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    fn create_dummy_elf(path: &str) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        let elf_header: [u8; 64] = [
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        file.write_all(&elf_header)?;
        Ok(())
    }

    #[test]
    fn test_parse_header_info_internal_success() {
        let test_file = "test_elf_parser.bin";
        create_dummy_elf(test_file).unwrap();
        let result = parse_header_info_internal(test_file);
        assert!(result.is_ok());
        let header = result.unwrap();
        assert!(header.valid);
        assert_eq!(header.format, "ELF");
        assert_eq!(header.arch, "x86-64");
        assert_eq!(header.bits, 64);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_parse_header_info_internal_not_found() {
        let result = parse_header_info_internal("file_tidak_ada.bin");
        assert!(result.is_err());
        match result.err().unwrap() {
            ReToolsError::IoError(_) => (),
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_read_file_bytes_c_invalid_path() {
        let s = std::ffi::CString::new("file_tidak_ada.bin").unwrap();
        let result = read_file_bytes(s.as_ptr());
        assert!(result.is_err());
        match result.err().unwrap() {
            ReToolsError::IoError(_) => (),
            _ => panic!("Expected IoError"),
        }
    }
}