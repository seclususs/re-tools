use libc::{c_char, c_int};
use std::ffi::CStr;
use std::slice;

use crate::error::{set_last_error, ReToolsError};
use crate::logic::static_analysis::binary::{Binary, InternalHeaderInfo};
use crate::utils::strncpy_rs;
use log::info;

#[allow(non_snake_case)]
#[deprecated(
    note = "Gunakan Binary::load() secara internal. Fungsi ini dipertahankan hanya untuk C-API."
)]
pub fn parse_header_info_internal(
    file_path: &str,
) -> Result<InternalHeaderInfo, ReToolsError> {
    Binary::load(file_path).map(|b| b.header)
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
    pub flags: u64,
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

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct C_ImportInfo {
    pub name: [c_char; 128],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct C_ExportInfo {
    pub name: [c_char; 128],
    pub addr: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct C_ElfDynamicInfo {
    pub tag_name: [c_char; 64],
    pub value: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct C_DiffResult {
    pub function_name: [c_char; 128],
    pub address_file1: u64,
    pub address_file2: u64,
    pub status: c_int,
}

#[allow(non_snake_case)]
pub unsafe fn c_get_binary_header(
    file_path_c: *const c_char,
    out_header: *mut C_HeaderInfo,
) -> c_int {
    let path_str_result = CStr::from_ptr(file_path_c).to_str();
    let binary_result = match path_str_result {
        Ok(path_str) => Binary::load(path_str),
        Err(e) => Err(ReToolsError::from(e)),
    };
    match binary_result {
        Ok(binary) => {
            let header_info = &binary.header;
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
            set_last_error(e);
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
            set_last_error(ReToolsError::Generic("Buffer output invalid atau max_count <= 0".to_string()));
            return -1;
        }
        let path_str_result = CStr::from_ptr(file_path_c).to_str();
        let binary_result = match path_str_result {
            Ok(path_str) => Binary::load(path_str),
            Err(e) => Err(ReToolsError::from(e)),
        };
        match binary_result {
            Ok(binary) => {
                let sections = &binary.sections;
                if sections.len() > max_count as usize {
                    set_last_error(ReToolsError::Generic(format!(
                        "Jumlah sections ({}) melebihi max_count ({})",
                        sections.len(),
                        max_count
                    )));
                    return -1;
                }
                info!("Ditemukan {} sections", sections.len());
                let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);
                for (i, section) in sections.iter().enumerate() {
                    let out_item = &mut out_slice[i];
                    strncpy_rs(&section.name, &mut out_item.name);
                    out_item.addr = section.addr;
                    out_item.size = section.size;
                    out_item.offset = section.offset;
                    out_item.flags = section.flags;
                }
                sections.len() as c_int
            }
            Err(e) => {
                set_last_error(e);
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
            set_last_error(ReToolsError::Generic("Buffer output invalid atau max_count <= 0".to_string()));
            return -1;
        }
        let path_str_result = CStr::from_ptr(file_path_c).to_str();
        let binary_result = match path_str_result {
            Ok(path_str) => Binary::load(path_str),
            Err(e) => Err(ReToolsError::from(e)),
        };
        match binary_result {
            Ok(binary) => {
                let all_symbols = &binary.symbols;
                if all_symbols.len() > max_count as usize {
                    set_last_error(ReToolsError::Generic(format!(
                        "Jumlah total simbol ({}) melebihi max_count ({})",
                        all_symbols.len(),
                        max_count
                    )));
                    return -1;
                }
                info!("Total simbol yang diproses: {}", all_symbols.len());
                let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);
                for (i, sym) in all_symbols.iter().enumerate() {
                    let out_item = &mut out_slice[i];
                    strncpy_rs(&sym.name, &mut out_item.name);
                    out_item.addr = sym.addr;
                    out_item.size = sym.size;
                    strncpy_rs(&sym.symbol_type, &mut out_item.symbol_type);
                    strncpy_rs(&sym.bind, &mut out_item.bind);
                }
                all_symbols.len() as c_int
            }
            Err(e) => {
                set_last_error(e);
                -1
            }
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn c_get_daftar_imports(
    file_path_c: *const c_char,
    out_buffer: *mut C_ImportInfo,
    max_count: c_int,
) -> c_int {
    if out_buffer.is_null() || max_count <= 0 {
        set_last_error(ReToolsError::Generic("Buffer output invalid atau max_count <= 0".to_string()));
        return -1;
    }
    let path_str_result = CStr::from_ptr(file_path_c).to_str();
    let binary_result = match path_str_result {
        Ok(path_str) => Binary::load(path_str),
        Err(e) => Err(ReToolsError::from(e)),
    };
    match binary_result {
        Ok(binary) => {
            let imports = &binary.imports;
            if imports.len() > max_count as usize {
                set_last_error(ReToolsError::Generic(format!(
                    "Jumlah imports ({}) melebihi max_count ({})",
                    imports.len(),
                    max_count
                )));
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);
            for (i, import_info) in imports.iter().enumerate() {
                let out_item = &mut out_slice[i];
                strncpy_rs(&import_info.name, &mut out_item.name);
            }
            imports.len() as c_int
        }
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn c_get_daftar_exports(
    file_path_c: *const c_char,
    out_buffer: *mut C_ExportInfo,
    max_count: c_int,
) -> c_int {
    if out_buffer.is_null() || max_count <= 0 {
        set_last_error(ReToolsError::Generic("Buffer output invalid atau max_count <= 0".to_string()));
        return -1;
    }
    let path_str_result = CStr::from_ptr(file_path_c).to_str();
    let binary_result = match path_str_result {
        Ok(path_str) => Binary::load(path_str),
        Err(e) => Err(ReToolsError::from(e)),
    };
    match binary_result {
        Ok(binary) => {
            let exports = &binary.exports;
            if exports.len() > max_count as usize {
                set_last_error(ReToolsError::Generic(format!(
                    "Jumlah exports ({}) melebihi max_count ({})",
                    exports.len(),
                    max_count
                )));
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_buffer, max_count as usize);
            for (i, export_info) in exports.iter().enumerate() {
                let out_item = &mut out_slice[i];
                strncpy_rs(&export_info.name, &mut out_item.name);
                out_item.addr = export_info.addr;
            }
            exports.len() as c_int
        }
        Err(e) => {
            set_last_error(e);
            -1
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
        let result = Binary::load(test_file).map(|b| b.header);
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
        let result = Binary::load("file_tidak_ada.bin").map(|b| b.header);
        assert!(result.is_err());
        match result.err().unwrap() {
            ReToolsError::IoError(_) => (),
            _ => panic!("Expected IoError"),
        }
    }
}