use crate::error::ReToolsError;
use goblin::elf::dynamic;
use goblin::elf::sym;
use goblin::Object;
use std::fs;


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

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u64,
    pub tipe: u32,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub symbol_type: String,
    pub bind: String,
}

#[derive(Debug, Clone)]
pub struct ImportInfo {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ExportInfo {
    pub name: String,
    pub addr: u64,
}

#[derive(Debug, Clone)]
pub struct ElfDynamicInfo {
    pub tag_name: String,
    pub value: u64,
}

#[derive(Debug)]
pub struct Binary {
    pub file_path: String,
    pub file_bytes: Vec<u8>,
    pub header: InternalHeaderInfo,
    pub sections: Vec<SectionInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub elf_dynamic_info: Vec<ElfDynamicInfo>,
}

impl Binary {
    pub fn load(file_path: &str) -> Result<Self, ReToolsError> {
        let file_bytes = fs::read(file_path)?;
        let file_path_string = file_path.to_string();
        let obj = Object::parse(&file_bytes)
            .map_err(|e| ReToolsError::ParseError(e.to_string()))?;
        let header = Self::parse_header_internal(&obj, file_bytes.len() as u64)?;
        let sections = Self::parse_sections_internal(&obj)?;
        let symbols = Self::parse_symbols_internal(&obj)?;
        let imports = Self::parse_imports_internal(&obj)?;
        let exports = Self::parse_exports_internal(&obj)?;
        let elf_dynamic_info = Self::parse_elf_dynamic_info_internal(&obj)?;
        Ok(Binary {
            file_path: file_path_string,
            file_bytes,
            header,
            sections,
            symbols,
            imports,
            exports,
            elf_dynamic_info,
        })
    }

    fn parse_header_internal(
        obj: &Object,
        file_size: u64,
    ) -> Result<InternalHeaderInfo, ReToolsError> {
        match obj {
            Object::Elf(elf) => {
                let machine_id = elf.header.e_machine;
                Ok(InternalHeaderInfo {
                    valid: true,
                    format: "ELF",
                    arch: InternalHeaderInfo::arch_from_elf_machine(machine_id),
                    bits: if elf.is_64 { 64 } else { 32 },
                    entry_point: elf.entry,
                    machine_id: machine_id as u64,
                    is_lib: elf.header.e_type == goblin::elf::header::ET_DYN,
                    file_size,
                })
            }
            Object::PE(pe) => {
                let machine_id = pe.header.coff_header.machine;
                Ok(InternalHeaderInfo {
                    valid: true,
                    format: "PE",
                    arch: InternalHeaderInfo::arch_from_pe_machine(machine_id),
                    bits: if pe.is_64 { 64 } else { 32 },
                    entry_point: pe.entry as u64,
                    machine_id: machine_id as u64,
                    is_lib: pe.is_lib,
                    file_size,
                })
            }
            Object::Mach(mach) => {
                let (format_str, bits, machine_id, entry, is_lib) = match mach {
                    goblin::mach::Mach::Binary(macho) => (
                        "Mach-O",
                        if macho.is_64 { 64 } else { 32 },
                        macho.header.cputype() as u64,
                        macho.entry,
                        macho.header.filetype == goblin::mach::header::MH_DYLIB,
                    ),
                    goblin::mach::Mach::Fat(multiarch) => {
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
                Ok(InternalHeaderInfo {
                    valid: true,
                    format: format_str,
                    arch: InternalHeaderInfo::arch_from_macho_cputype(machine_id as u32),
                    bits,
                    entry_point: entry,
                    machine_id,
                    is_lib,
                    file_size,
                })
            }
            Object::Archive(_) => Ok(InternalHeaderInfo {
                valid: true,
                format: "Archive (.a/.lib)",
                file_size,
                ..InternalHeaderInfo::invalid()
            }),
            _ => Ok(InternalHeaderInfo {
                file_size,
                ..InternalHeaderInfo::invalid()
            }),
        }
    }

    fn parse_sections_internal(obj: &Object) -> Result<Vec<SectionInfo>, ReToolsError> {
        match obj {
            Object::Elf(elf) => {
                let mut sections_vec = Vec::new();
                for section in &elf.section_headers {
                    let section_name =
                        elf.shdr_strtab.get_at(section.sh_name).unwrap_or("(unknown)");
                    sections_vec.push(SectionInfo {
                        name: section_name.to_string(),
                        addr: section.sh_addr,
                        size: section.sh_size,
                        offset: section.sh_offset,
                        tipe: section.sh_type,
                    });
                }
                Ok(sections_vec)
            }
            Object::PE(pe) => {
                let mut sections_vec = Vec::new();
                for section in &pe.sections {
                    let section_name = section.name().unwrap_or("(unknown)");
                    sections_vec.push(SectionInfo {
                        name: section_name.to_string(),
                        addr: section.virtual_address as u64,
                        size: section.virtual_size as u64,
                        offset: section.pointer_to_raw_data as u64,
                        tipe: section.characteristics,
                    });
                }
                Ok(sections_vec)
            }
            Object::Mach(mach) => {
                let mut sections_vec = Vec::new();
                match mach {
                    goblin::mach::Mach::Binary(m) => {
                        let segments_iter = m.segments.iter();
                        for segment in segments_iter {
                            for section_result in segment {
                                if let Ok((section, _data)) = section_result {
                                    sections_vec.push(SectionInfo {
                                        name: section.name().unwrap_or("?").to_string(),
                                        addr: section.addr,
                                        size: section.size,
                                        offset: section.offset as u64,
                                        tipe: section.flags,
                                    });
                                }
                            }
                        }
                    }
                    goblin::mach::Mach::Fat(m) => {
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = m.get(0) {
                            let segments_iter = macho.segments.iter();
                            for segment in segments_iter {
                                for section_result in segment {
                                    if let Ok((section, _data)) = section_result {
                                        sections_vec.push(SectionInfo {
                                            name: section.name().unwrap_or("?").to_string(),
                                            addr: section.addr,
                                            size: section.size,
                                            offset: section.offset as u64,
                                            tipe: section.flags,
                                        });
                                    }
                                }
                            }
                        } else {
                            return Ok(Vec::new());
                        }
                    }
                };
                Ok(sections_vec)
            }
            _ => Ok(Vec::new()),
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

    fn parse_symbols_internal(obj: &Object) -> Result<Vec<SymbolInfo>, ReToolsError> {
        match obj {
            Object::Elf(elf) => {
                let mut all_symbols = Vec::new();
                for sym in &elf.syms {
                    let symbol_name = elf.strtab.get_at(sym.st_name).unwrap_or("(unknown_static)");
                    if !symbol_name.is_empty() {
                        all_symbols.push(SymbolInfo {
                            name: symbol_name.to_string(),
                            addr: sym.st_value,
                            size: sym.st_size,
                            symbol_type: Self::st_type_to_str(sym.st_type()).to_string(),
                            bind: Self::st_bind_to_str(sym.st_bind()).to_string(),
                        });
                    }
                }
                for sym in &elf.dynsyms {
                    let symbol_name = elf
                        .dynstrtab
                        .get_at(sym.st_name)
                        .unwrap_or("(unknown_dynamic)");
                    if !symbol_name.is_empty() {
                        all_symbols.push(SymbolInfo {
                            name: symbol_name.to_string(),
                            addr: sym.st_value,
                            size: sym.st_size,
                            symbol_type: Self::st_type_to_str(sym.st_type()).to_string(),
                            bind: Self::st_bind_to_str(sym.st_bind()).to_string(),
                        });
                    }
                }
                Ok(all_symbols)
            }
            Object::PE(_pe) => {
                Ok(Vec::new())
            }
            Object::Mach(mach) => {
                let mut all_symbols = Vec::new();
                fn process_symbols<'a>(
                    symbols: goblin::mach::symbols::SymbolIterator<'a>,
                    all_symbols: &mut Vec<SymbolInfo>,
                ) {
                    for symbol_result in symbols {
                        if let Ok(symbol) = symbol_result {
                            let name = symbol.0;
                            let nlist = symbol.1;
                            all_symbols.push(SymbolInfo {
                                name: name.to_string(),
                                addr: nlist.n_value,
                                size: 0,
                                symbol_type: "".to_string(),
                                bind: "".to_string(),
                            });
                        }
                    }
                }
                match mach {
                    goblin::mach::Mach::Binary(m) => {
                        process_symbols(m.symbols(), &mut all_symbols);
                    }
                    goblin::mach::Mach::Fat(m) => {
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = m.get(0) {
                            process_symbols(macho.symbols(), &mut all_symbols);
                        }
                    }
                };
                Ok(all_symbols)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn parse_imports_internal(obj: &Object) -> Result<Vec<ImportInfo>, ReToolsError> {
        let mut imports_vec = Vec::new();
        match obj {
            Object::Elf(elf) => {
                imports_vec = elf
                    .dynsyms
                    .iter()
                    .filter(|sym| sym.is_import())
                    .filter_map(|sym| elf.dynstrtab.get_at(sym.st_name))
                    .filter(|name| !name.is_empty())
                    .map(|name| ImportInfo {
                        name: name.to_string(),
                    })
                    .collect();
            }
            Object::PE(pe) => {
                for import in &pe.imports {
                    imports_vec.push(ImportInfo {
                        name: import.name.to_string(),
                    });
                }
            }
            Object::Mach(mach) => {
                match mach {
                    goblin::mach::Mach::Binary(m) => {
                        if let Ok(imports) = m.imports() {
                            for import in imports {
                                imports_vec.push(ImportInfo {
                                    name: import.name.to_string(),
                                });
                            }
                        }
                    }
                    goblin::mach::Mach::Fat(m) => {
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = m.get(0) {
                            if let Ok(imports) = macho.imports() {
                                for import in imports {
                                    imports_vec.push(ImportInfo {
                                        name: import.name.to_string(),
                                    });
                                }
                            }
                        }
                    }
                };
            }
            _ => {}
        }
        Ok(imports_vec)
    }

    fn parse_exports_internal(obj: &Object) -> Result<Vec<ExportInfo>, ReToolsError> {
        let mut exports_vec = Vec::new();
        match obj {
            Object::Elf(elf) => {
                exports_vec = elf
                    .dynsyms
                    .iter()
                    .filter_map(|sym| {
                        let bind = sym::st_bind(sym.st_info);
                        let type_ = sym::st_type(sym.st_info);
                        let vis = sym::st_visibility(sym.st_other);

                        if !sym.is_import()
                            && (bind == sym::STB_GLOBAL || bind == sym::STB_WEAK)
                            && type_ == sym::STT_FUNC
                            && vis != sym::STV_HIDDEN
                        {
                            elf.dynstrtab
                                .get_at(sym.st_name)
                                .map(|name| (name, sym.st_value))
                        } else {
                            None
                        }
                    })
                    .filter(|(name, _addr)| !name.is_empty())
                    .map(|(name, addr)| ExportInfo {
                        name: name.to_string(),
                        addr,
                    })
                    .collect();
            }
            Object::PE(pe) => {
                for export in &pe.exports {
                    if let Some(name) = export.name {
                        exports_vec.push(ExportInfo {
                            name: name.to_string(),
                            addr: export.rva as u64,
                        });
                    }
                }
            }
            Object::Mach(mach) => {
                match mach {
                    goblin::mach::Mach::Binary(m) => {
                        if let Ok(exports) = m.exports() {
                            for export in exports {
                                exports_vec.push(ExportInfo {
                                    name: export.name.to_string(),
                                    addr: export.offset,
                                });
                            }
                        }
                    }
                    goblin::mach::Mach::Fat(m) => {
                        if let Ok(goblin::mach::SingleArch::MachO(macho)) = m.get(0) {
                            if let Ok(exports) = macho.exports() {
                                for export in exports {
                                    exports_vec.push(ExportInfo {
                                        name: export.name.to_string(),
                                        addr: export.offset,
                                    });
                                }
                            }
                        }
                    }
                };
            }
            _ => {}
        }
        Ok(exports_vec)
    }

    fn elf_tag_to_str(tag: u64) -> &'static str {
        match tag {
            dynamic::DT_NULL => "DT_NULL",
            dynamic::DT_NEEDED => "DT_NEEDED",
            dynamic::DT_PLTRELSZ => "DT_PLTRELSZ",
            dynamic::DT_PLTGOT => "DT_PLTGOT",
            dynamic::DT_HASH => "DT_HASH",
            dynamic::DT_STRTAB => "DT_STRTAB",
            dynamic::DT_SYMTAB => "DT_SYMTAB",
            dynamic::DT_RELA => "DT_RELA",
            dynamic::DT_RELASZ => "DT_RELASZ",
            dynamic::DT_RELAENT => "DT_RELAENT",
            dynamic::DT_STRSZ => "DT_STRSZ",
            dynamic::DT_SYMENT => "DT_SYMENT",
            dynamic::DT_INIT => "DT_INIT",
            dynamic::DT_FINI => "DT_FINI",
            dynamic::DT_SONAME => "DT_SONAME",
            dynamic::DT_RPATH => "DT_RPATH",
            dynamic::DT_SYMBOLIC => "DT_SYMBOLIC",
            dynamic::DT_REL => "DT_REL",
            dynamic::DT_RELSZ => "DT_RELSZ",
            dynamic::DT_RELENT => "DT_RELENT",
            dynamic::DT_PLTREL => "DT_PLTREL",
            dynamic::DT_DEBUG => "DT_DEBUG",
            dynamic::DT_TEXTREL => "DT_TEXTREL",
            dynamic::DT_JMPREL => "DT_JMPREL",
            dynamic::DT_BIND_NOW => "DT_BIND_NOW",
            dynamic::DT_INIT_ARRAY => "DT_INIT_ARRAY",
            dynamic::DT_FINI_ARRAY => "DT_FINI_ARRAY",
            dynamic::DT_INIT_ARRAYSZ => "DT_INIT_ARRAYSZ",
            dynamic::DT_FINI_ARRAYSZ => "DT_FINI_ARRAYSZ",
            dynamic::DT_RUNPATH => "DT_RUNPATH",
            dynamic::DT_FLAGS => "DT_FLAGS",
            dynamic::DT_PREINIT_ARRAY => "DT_PREINIT_ARRAY",
            dynamic::DT_PREINIT_ARRAYSZ => "DT_PREINIT_ARRAYSZ",
            dynamic::DT_VERSYM => "DT_VERSYM",
            dynamic::DT_VERDEF => "DT_VERDEF",
            dynamic::DT_VERDEFNUM => "DT_VERDEFNUM",
            dynamic::DT_VERNEED => "DT_VERNEED",
            dynamic::DT_VERNEEDNUM => "DT_VERNEEDNUM",
            dynamic::DT_GNU_HASH => "DT_GNU_HASH",
            _ => "DT_UNKNOWN",
        }
    }

    fn parse_elf_dynamic_info_internal(obj: &Object) -> Result<Vec<ElfDynamicInfo>, ReToolsError> {
        if let Object::Elf(elf) = obj {
            if let Some(dynamic) = &elf.dynamic {
                let mut entries = Vec::new();
                for entry in &dynamic.dyns {
                    entries.push(ElfDynamicInfo {
                        tag_name: Self::elf_tag_to_str(entry.d_tag).to_string(),
                        value: entry.d_val,
                    });
                }
                return Ok(entries);
            }
        }
        Ok(Vec::new())
    }
}