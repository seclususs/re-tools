//! Author: [Seclususs](https://github.com/seclususs)

use encoding_rs::{UTF_16BE, UTF_16LE};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Cursor, Read};

use crate::error::ReToolsError;
use crate::logic::static_analysis::parser::Binary;
use crate::logic::static_analysis::disasm::{
    create_instance_capstone_by_arch, ArsitekturDisasm,
};
use log::{debug, info, warn};
use regex::bytes::Regex;
use memchr::memmem::Finder;

#[derive(Serialize)]
pub struct StringInfo {
    pub offset: u64,
    pub content: String,
    pub encoding: &'static str,
}

#[derive(Serialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
}

#[derive(Serialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub strings: Vec<YaraStringMatch>,
}

#[derive(Serialize)]
pub struct PackerHeuristicInfo {
    pub section_name: String,
    pub section_offset: u64,
    pub section_size: u64,
    pub entropy: f64,
    pub is_writable: bool,
    pub is_executable: bool,
}

#[derive(Serialize)]
pub struct LibraryMatch {
    pub signature_name: String,
    pub offset: u64,
    pub matched_bytes_hex: String,
}

#[derive(Serialize)]
pub struct CryptoMatch {
    pub algorithm: String,
    pub constant_name: String,
    pub offset: u64,
}

#[derive(Deserialize)]
struct FlirtSignatureInput {
    pub name: String,
    pub sig_hash: String, 
    #[allow(dead_code)]
    pub size_bound: u64,
}

struct Fnv1aHasher {
    state: u64,
}

impl Fnv1aHasher {
    fn new() -> Self {
        Fnv1aHasher {
            state: 0xcbf29ce484222325,
        }
    }
    fn update(&mut self, byte: u8) {
        self.state ^= byte as u64;
        self.state = self.state.wrapping_mul(0x100000001b3);
    }
    fn finish(&self) -> u64 {
        self.state
    }
}

pub fn extract_str_raw(
    biner: &Binary,
    len_min: usize,
) -> Result<Vec<StringInfo>, ReToolsError> {
    info!(
        "Mulai ekstrak strings dari: {} (min_length: {})",
        biner.path_berkas, len_min
    );
    let buf_data = &biner.file_data;
    debug!("Ukuran file dibaca: {} bytes", buf_data.len());
    let strings_info = extract_str_all(buf_data, len_min);
    info!("Selesai ekstrak strings, ditemukan: {}", strings_info.len());
    Ok(strings_info)
}

pub fn extract_str_all(buf_data: &[u8], len_min: usize) -> Vec<StringInfo> {
    let mut strings_found = Vec::new();
    let mut current_ascii = Vec::new();
    let mut current_ascii_offset = 0;
    debug!("Mencari strings ASCII...");
    for (i, &byte) in buf_data.iter().enumerate() {
        if (32..=126).contains(&byte) {
            if current_ascii.is_empty() {
                current_ascii_offset = i as u64;
            }
            current_ascii.push(byte);
        } else if !current_ascii.is_empty() {
            if current_ascii.len() >= len_min {
                if let Ok(s) = String::from_utf8(current_ascii.clone()) {
                    strings_found.push(StringInfo {
                        offset: current_ascii_offset,
                        content: s,
                        encoding: "ASCII",
                    });
                }
            }
            current_ascii.clear();
        }
    }
    if current_ascii.len() >= len_min {
        if let Ok(s) = String::from_utf8(current_ascii) {
            strings_found.push(StringInfo {
                offset: current_ascii_offset,
                content: s,
                encoding: "ASCII",
            });
        }
    }
    debug!("Ditemukan {} strings ASCII", strings_found.len());
    for encoding in [UTF_16LE, UTF_16BE] {
        let enc_name = if encoding == UTF_16LE {
            "UTF-16LE"
        } else {
            "UTF-16BE"
        };
        debug!("Mencari strings {}...", enc_name);
        let (cow, _had_errors) = encoding.decode_without_bom_handling(buf_data);
        let decoded_str = cow.as_ref();
        let mut current_utf16_offset = 0;
        let mut current_utf16_str = String::new();
        let mut count_enc = 0;
        for (i, c) in decoded_str.char_indices() {
            if c.is_ascii_graphic()
                || c.is_alphanumeric()
                || c.is_whitespace()
                || c.is_ascii_punctuation()
            {
                if current_utf16_str.is_empty() {
                    current_utf16_offset = i as u64;
                }
                current_utf16_str.push(c);
            } else if !current_utf16_str.is_empty() {
                if current_utf16_str.len() >= len_min {
                    strings_found.push(StringInfo {
                        offset: current_utf16_offset,
                        content: current_utf16_str.clone(),
                        encoding: enc_name,
                    });
                    count_enc += 1;
                }
                current_utf16_str.clear();
            }
        }
        if current_utf16_str.len() >= len_min {
            strings_found.push(StringInfo {
                offset: current_utf16_offset,
                content: current_utf16_str,
                encoding: enc_name,
            });
            count_enc += 1;
        }
        debug!("Ditemukan {} strings {}", count_enc, enc_name);
    }
    strings_found
}

fn calc_entropi_blok(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    for &b in data {
        *counts.entry(b).or_insert(0) += 1;
    }
    let mut entropy = 0.0;
    let sz_data = data.len() as f64;
    for (_key, val) in counts {
        let p_x = (val as f64) / sz_data;
        if p_x > 0.0 {
            entropy -= p_x * p_x.log2();
        }
    }
    entropy
}

pub fn calc_entropi(
    biner: &Binary,
    sz_blok: usize,
) -> Result<Vec<f64>, ReToolsError> {
    info!(
        "Mulai hitung entropy untuk: {} (block_size: {})",
        biner.path_berkas, sz_blok
    );
    let mut entropies = Vec::new();
    if sz_blok == 0 {
        warn!("Block size adalah 0, mengembalikan vector kosong");
        return Ok(entropies);
    }
    let mut cursor = Cursor::new(&biner.file_data);
    let mut buf_data = vec![0; sz_blok];
    loop {
        match cursor.read(&mut buf_data) {
            Ok(0) => break,
            Ok(sz_read) => {
                let blok_data = &buf_data[..sz_read];
                entropies.push(calc_entropi_blok(blok_data));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    info!(
        "Selesai hitung entropy, {} blocks diproses",
        entropies.len()
    );
    Ok(entropies)
}

pub fn scan_pola_regex(
    biner: &Binary,
    str_regex: &str,
) -> Result<Vec<String>, ReToolsError> {
    info!(
        "Mulai deteksi pattern regex: '{}' di file: {}",
        str_regex, biner.path_berkas
    );
    let data_berkas = &biner.file_data;
    debug!("Ukuran file dibaca: {} bytes", data_berkas.len());
    let re = Regex::new(str_regex)?;
    let matches: Vec<String> = re
        .find_iter(data_berkas)
        .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string())
        .collect();
    info!("Ditemukan {} matches", matches.len());
    Ok(matches)
}

pub fn scan_yara(
    biner: &Binary,
    rule_yara: &str,
) -> Result<Vec<YaraMatch>, ReToolsError> {
    info!("Mulai scan YARA di file: {}", biner.path_berkas);
    let rules = yara::Compiler::new()?
        .add_rules_str(rule_yara)?
        .compile_rules()?;
    let matches = rules.scan_mem(&biner.file_data, 10)?;
    let results: Vec<YaraMatch> = matches.iter().map(|m| {
        YaraMatch {
            rule_name: m.identifier.to_string(),
            strings: m.strings.iter().map(|s| {
                YaraStringMatch {
                    identifier: s.identifier.to_string(),
                    offset: s.matches.first().map_or(0, |m| m.offset) as u64,
                }
            }).collect(),
        }
    }).collect();
    info!("Scan YARA selesai, {} rules matched", results.len());
    Ok(results)
}

#[allow(non_snake_case)]
pub fn detect_packer(
    biner: &Binary,
    ambang_entropy: f64,
) -> Result<Vec<PackerHeuristicInfo>, ReToolsError> {
    info!(
        "Mulai deteksi heuristic packer untuk: {} (entropy > {})",
        biner.path_berkas, ambang_entropy
    );
    let mut results = Vec::new();
    let len_berkas = biner.file_data.len();
    const SHF_WRITE: u64 = 0x1;
    const SHF_EXECINSTR: u64 = 0x4;
    const IMAGE_SCN_MEM_WRITE: u64 = 0x80000000;
    const IMAGE_SCN_MEM_EXECUTE: u64 = 0x20000000;
    for section in &biner.sections {
        let (is_writable, is_executable) = match biner.header.format {
            "ELF" => (
                (section.flags & SHF_WRITE) != 0,
                (section.flags & SHF_EXECINSTR) != 0,
            ),
            "PE" => (
                (section.flags & IMAGE_SCN_MEM_WRITE) != 0,
                (section.flags & IMAGE_SCN_MEM_EXECUTE) != 0,
            ),
            _ => (false, false),
        };
        if is_writable && is_executable {
            let start = std::cmp::min(len_berkas, section.offset as usize);
            let end = std::cmp::min(len_berkas, (section.offset + section.size) as usize);
            if start >= end {
                continue;
            }
            let bytes_section = &biner.file_data[start..end];
            let entropy = calc_entropi_blok(bytes_section);
            if entropy > ambang_entropy {
                results.push(PackerHeuristicInfo {
                    section_name: section.name.clone(),
                    section_offset: section.offset,
                    section_size: section.size,
                    entropy,
                    is_writable,
                    is_executable,
                });
            }
        }
    }
    info!(
        "Deteksi heuristic packer selesai, {} section mencurigakan",
        results.len()
    );
    Ok(results)
}

fn calc_fuzzy_sig(
    kode_bytes: &[u8],
    addr: u64,
    arch: ArsitekturDisasm,
) -> Option<String> {
    let cs = match create_instance_capstone_by_arch(arch) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let insns = match cs.disasm_count(kode_bytes, addr, 0) {
        Ok(i) => i,
        Err(_) => return None,
    };
    if insns.len() < 3 {
        return None;
    }
    let mut hasher = Fnv1aHasher::new();
    for insn in insns.iter() {
        let bytes = insn.bytes();
        let mnemonic = insn.mnemonic().unwrap_or("").as_bytes();
        if bytes.len() > 4 || mnemonic.starts_with(b"j") || mnemonic.starts_with(b"call") {
            for &b in mnemonic {
                hasher.update(b);
            }
            hasher.update(0xFF); 
        } else {
            for &b in bytes {
                hasher.update(b);
            }
        }
    }
    let val_hash = hasher.finish();
    Some(format!("{:016x}", val_hash))
}

#[allow(non_snake_case)]
pub fn identify_lib(
    biner: &Binary,
    json_sig: &str,
) -> Result<Vec<LibraryMatch>, ReToolsError> {
    info!(
        "Mulai FLIRT-like identification untuk: {}",
        biner.path_berkas
    );
    let signatures: HashMap<String, String> = match serde_json::from_str(json_sig) {
        Ok(s) => s,
        Err(_) => {
            let list: Vec<FlirtSignatureInput> = serde_json::from_str(json_sig)
                .map_err(|e| ReToolsError::Generic(format!("JSON format error: {}", e)))?;
            list.into_iter().map(|item| (item.sig_hash, item.name)).collect()
        }
    };
    let arch = biner.header.get_disasm_arch();
    if arch == ArsitekturDisasm::ARCH_UNKNOWN {
        return Err(ReToolsError::Generic("Arsitektur tidak didukung untuk analisis FLIRT".to_string()));
    }
    let mut results = Vec::new();
    for symbol in &biner.symbols {
        if symbol.symbol_type == "FUNC" && symbol.size > 0 {
            let off_mulai = symbol.addr; 
            let mut off_berkas = 0;
            let mut found = false;
            for section in &biner.sections {
                if off_mulai >= section.addr && off_mulai < (section.addr + section.size) {
                    off_berkas = section.offset + (off_mulai - section.addr);
                    found = true;
                    break;
                }
            }
            if !found || off_berkas as usize >= biner.file_data.len() {
                continue;
            }
            let sz = std::cmp::min(symbol.size as usize, 256); 
            let end = std::cmp::min(biner.file_data.len(), off_berkas as usize + sz);
            let slice_kode = &biner.file_data[off_berkas as usize..end];
            if let Some(hash_gen) = calc_fuzzy_sig(slice_kode, off_mulai, arch) {
                if let Some(func_name) = signatures.get(&hash_gen) {
                    debug!("Match FLIRT: {} di 0x{:x}", func_name, off_mulai);
                    results.push(LibraryMatch {
                        signature_name: func_name.clone(),
                        offset: off_mulai,
                        matched_bytes_hex: hash_gen,
                    });
                }
            }
        }
    }
    if results.is_empty() {
        let simple_sigs: HashMap<String, String> = serde_json::from_str(json_sig).unwrap_or_default();
        for (name, pattern) in simple_sigs {
            if let Ok(re) = Regex::new(&pattern) {
                 for m in re.find_iter(&biner.file_data) {
                    let hex_match = m.as_bytes().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                    results.push(LibraryMatch {
                        signature_name: name.clone(),
                        offset: m.start() as u64,
                        matched_bytes_hex: hex_match,
                    });
                }
            }
        }
    }
    info!(
        "Identifikasi fungsi library selesai, {} match ditemukan",
        results.len()
    );
    Ok(results)
}

pub fn scan_crypto_const(
    biner: &Binary,
) -> Result<Vec<CryptoMatch>, ReToolsError> {
    info!("Mulai scan konstanta kriptografi: {}", biner.path_berkas);
    let mut results = Vec::new();
    let data = &biner.file_data;
    let constants_db = [
        ("AES", "S-Box (Forward)", &b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76"[..]),
        ("AES", "S-Box (Inverse)", &b"\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb"[..]),
        ("SHA-256", "H[0]-H[3]", &b"\x6a\x09\xe6\x67\xbb\x67\xae\x85\x3c\x6e\xf3\x72\xa5\x4f\xf5\x3a"[..]),
        ("SHA-256", "H[4]-H[7]", &b"\x51\x0e\x27\xbc\x9b\x05\x68\x8c\x1f\x83\xd9\xab\x5b\xe0\xcd\x19"[..]),
        ("SHA-256", "K[0]-K[3]", &b"\x42\x8a\x2f\x98\x71\x37\x44\x91\xb5\xc0\xfb\xcf\xe9\xb5\xdc\x8a"[..]),
        ("SHA-1", "H[0]-H[4]", &b"\x67\x45\x23\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x10\x32\x54\x76\xc3\xd2\xe1\xf0"[..]),
        ("MD5", "A,B,C,D", &b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"[..]),
        ("SHA-512", "H[0]-H[3]", &b"\x6a\x09\xe6\x67\xf3\xbc\xc9\x08\xbb\x67\xae\x85\x84\xca\xa7\x3b\x3c\x6e\xf3\x72\xfe\x94\xf8\x2b\xa5\x4f\xf5\x3a\x5f\x1d\x36\xf1"[..]),
    ];
    for (algo, name, pattern) in constants_db.iter() {
        let finder = Finder::new(pattern);
        for offset in finder.find_iter(data) {
            results.push(CryptoMatch {
                algorithm: algo.to_string(),
                constant_name: name.to_string(),
                offset: offset as u64,
            });
        }
    }
    info!("Scan konstanta kripto selesai, {} match ditemukan", results.len());
    Ok(results)
}

#[allow(non_snake_case)]
pub fn get_akses_data(
    biner: &Binary,
    addr_data: u64,
) -> Result<Vec<u64>, ReToolsError> {
    match biner.data_access_graph.get(&addr_data) {
        Some(accessors) => Ok(accessors.clone()),
        None => Ok(Vec::new()),
    }
}

#[allow(non_snake_case)]
pub fn get_penelepon(
    biner: &Binary,
    addr_fungsi: u64,
) -> Result<Vec<u64>, ReToolsError> {
    let mut callers = Vec::new();
    for (va_caller, vas_callee) in &biner.call_graph {
        if vas_callee.contains(&addr_fungsi) {
            callers.push(*va_caller);
        }
    }
    Ok(callers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    fn create_test_file(path: &str, content: &[u8]) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(content)?;
        Ok(())
    }

    #[test]
    fn test_extract_str_raw_mixed() {
        let test_file = "test_strings.bin";
        let content = b"This is ASCII\x00\x01\x02\x57\x00\x4F\x00\x52\x00\x44\x00\x00\x00Another ASCII";
        create_test_file(test_file, content).unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = extract_str_raw(&binary, 4);
        assert!(result.is_ok());
        let strings = result.unwrap();
        let contents: Vec<String> = strings.iter().map(|s| s.content.clone()).collect();
        assert!(contents.contains(&"This is ASCII".to_string()));
        assert!(contents.contains(&"WORD".to_string()));
        assert!(contents.contains(&"Another ASCII".to_string()));
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_calc_entropi_success() {
        let test_file = "test_entropy.bin";
        let content = vec![0x00; 1024];
        create_test_file(test_file, &content).unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = calc_entropi(&binary, 512);
        assert!(result.is_ok());
        let entropies = result.unwrap();
        assert_eq!(entropies.len(), 2);
        assert!((entropies[0] - 0.0).abs() < f64::EPSILON);
        assert!((entropies[1] - 0.0).abs() < f64::EPSILON);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_scan_pola_regex_success() {
        let test_file = "test_pattern.bin";
        let content = b"Some data here 12345 and more data 67890.";
        create_test_file(test_file, content).unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = scan_pola_regex(&binary, r"\d{5}");
        assert!(result.is_ok());
        let matches = result.unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], "12345");
        assert_eq!(matches[1], "67890");
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_scan_pola_regex_invalid_regex() {
        let test_file = "test_pattern_invalid.bin";
        create_test_file(test_file, b"data").unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = scan_pola_regex(&binary, r"[");
        assert!(result.is_err());
        match result.err().unwrap() {
            ReToolsError::RegexError(_) => (),
            _ => panic!("Expected RegexError"),
        }
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_scan_yara_success() {
        let test_file = "test_yara.bin";
        let content = b"This file contains a test string HELLO_YARA.";
        create_test_file(test_file, content).unwrap();
        let binary = Binary::load(test_file).unwrap();
        let test_rule = r#"
        rule HelloWorld {
            strings:
                $a = "HELLO_YARA"
            condition:
                $a
        }
        "#;
        let result = scan_yara(&binary, test_rule);
        assert!(result.is_ok());
        let matches = result.unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "HelloWorld");
        assert_eq!(matches[0].strings.len(), 1);
        assert_eq!(matches[0].strings[0].identifier, "$a");
        assert_eq!(matches[0].strings[0].offset, 28);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_scan_yara_invalid_rule() {
        let test_file = "test_yara_invalid_rule.bin";
        create_test_file(test_file, b"data").unwrap();
        let binary = Binary::load(test_file).unwrap();
        let invalid_rule = "rule Invalid { condition: false }";
        let result = scan_yara(&binary, invalid_rule);
        assert!(result.is_err());
        match result.err().unwrap() {
            ReToolsError::YaraError(_) => (),
            _ => panic!("Expected YaraError"),
        }
        std::fs::remove_file(test_file).unwrap();
    }
}