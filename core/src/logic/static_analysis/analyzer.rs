use encoding_rs::{UTF_16BE, UTF_16LE};
use libc::{c_char, c_int};
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Cursor, Read};

use crate::error::ReToolsError;
use crate::logic::static_analysis::binary::Binary;
use crate::utils::strncpy_rs_from_bytes;
use log::{debug, error, info, warn};
use regex::bytes::Regex;


#[derive(Serialize)]
pub struct StringInfo {
    pub offset: u64,
    pub content: String,
    pub encoding: &'static str,
}

pub fn ekstrak_strings_internal(
    binary: &Binary,
    min_length: usize,
) -> Result<Vec<StringInfo>, ReToolsError> {
    info!(
        "Mulai ekstrak strings dari: {} (min_length: {})",
        binary.file_path, min_length
    );
    let buffer_bytes = &binary.file_bytes;
    debug!("Ukuran file dibaca: {} bytes", buffer_bytes.len());
    let strings_info = extract_all_strings(buffer_bytes, min_length);
    info!("Selesai ekstrak strings, ditemukan: {}", strings_info.len());
    Ok(strings_info)
}

pub fn extract_all_strings(buffer: &[u8], min_length: usize) -> Vec<StringInfo> {
    let mut strings_found = Vec::new();
    let mut current_ascii = Vec::new();
    let mut current_ascii_offset = 0;
    debug!("Mencari strings ASCII...");
    for (i, &byte) in buffer.iter().enumerate() {
        if (32..=126).contains(&byte) {
            if current_ascii.is_empty() {
                current_ascii_offset = i as u64;
            }
            current_ascii.push(byte);
        } else if !current_ascii.is_empty() {
            if current_ascii.len() >= min_length {
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
    if current_ascii.len() >= min_length {
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
        let (cow, _had_errors) = encoding.decode_without_bom_handling(buffer);
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
                if current_utf16_str.len() >= min_length {
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
        if current_utf16_str.len() >= min_length {
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

pub unsafe fn c_get_strings_list(
    file_path_c: *const c_char,
    min_length: c_int,
) -> *mut c_char {
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Path tidak valid UTF-8: {}", e);
            return CString::new("[]").unwrap().into_raw();
        }
    };
    let binary = match Binary::load(path_str) {
        Ok(b) => b,
        Err(e) => {
            error!("Binary::load gagal: {}", e);
            return CString::new("[]").unwrap().into_raw();
        }
    };
    let strings = match ekstrak_strings_internal(&binary, min_length as usize) {
        Ok(s) => s,
        Err(e) => {
            error!("ekstrak_strings_internal gagal: {}", e);
            return CString::new("[]").unwrap().into_raw();
        }
    };
    let json_result = match serde_json::to_string(&strings) {
        Ok(json) => json,
        Err(e) => {
            error!("Serialisasi JSON gagal: {}", e);
            "[]".to_string()
        }
    };
    CString::new(json_result).unwrap_or_default().into_raw()
}

fn calculate_entropy_for_block(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = HashMap::new();
    for &b in data {
        *counts.entry(b).or_insert(0) += 1;
    }
    let mut entropy = 0.0;
    let data_size = data.len() as f64;
    for (_key, val) in counts {
        let p_x = (val as f64) / data_size;
        if p_x > 0.0 {
            entropy -= p_x * p_x.log2();
        }
    }
    entropy
}

pub fn hitung_entropy_internal(
    binary: &Binary,
    block_size: usize,
) -> Result<Vec<f64>, ReToolsError> {
    info!(
        "Mulai hitung entropy untuk: {} (block_size: {})",
        binary.file_path, block_size
    );
    let mut entropies = Vec::new();
    if block_size == 0 {
        warn!("Block size adalah 0, mengembalikan vector kosong");
        return Ok(entropies);
    }
    let mut cursor = Cursor::new(&binary.file_bytes);
    let mut buffer = vec![0; block_size];
    loop {
        match cursor.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                let block_data = &buffer[..bytes_read];
                entropies.push(calculate_entropy_for_block(block_data));
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

pub unsafe fn c_hitung_entropy_rs(
    file_path_c: *const c_char,
    block_size: c_int,
    out_entropies: *mut f64,
    max_entropies: c_int,
) -> c_int {
    if file_path_c.is_null()
        || out_entropies.is_null()
        || max_entropies <= 0
        || block_size <= 0
    {
        error!("Invalid arguments untuk c_hitung_entropy_rs");
        return -1;
    }
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Path tidak valid UTF-8: {}", e);
            return -1;
        }
    };
    let binary = match Binary::load(path_str) {
        Ok(b) => b,
        Err(e) => {
            error!("Binary::load gagal: {}", e);
            return -1;
        }
    };
    let results = match hitung_entropy_internal(&binary, block_size as usize) {
        Ok(res) => res,
        Err(e) => {
            error!("hitung_entropy_internal gagal: {}", e);
            return -1;
        }
    };
    if results.len() > max_entropies as usize {
        warn!(
            "Jumlah hasil entropy ({}) melebihi max_entropies ({})",
            results.len(),
            max_entropies
        );
        return -1;
    }
    let out_slice = std::slice::from_raw_parts_mut(out_entropies, max_entropies as usize);
    for (i, &res) in results.iter().enumerate() {
        out_slice[i] = res;
    }
    results.len() as c_int
}

pub fn deteksi_pattern_internal(
    binary: &Binary,
    regex_str: &str,
) -> Result<Vec<String>, ReToolsError> {
    info!(
        "Mulai deteksi pattern regex: '{}' di file: {}",
        regex_str, binary.file_path
    );
    let file_bytes = &binary.file_bytes;
    debug!("Ukuran file dibaca: {} bytes", file_bytes.len());
    let re = Regex::new(regex_str)?;
    let matches: Vec<String> = re
        .find_iter(file_bytes)
        .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string())
        .collect();
    info!("Ditemukan {} matches", matches.len());
    Ok(matches)
}

pub unsafe fn c_deteksi_pattern_rs(
    file_path_c: *const c_char,
    regex_str_c: *const c_char,
    out_buffer: *mut c_char,
    out_buffer_size: c_int,
) -> c_int {
    if file_path_c.is_null()
        || regex_str_c.is_null()
        || out_buffer.is_null()
        || out_buffer_size <= 0
    {
        error!("Invalid arguments untuk c_deteksi_pattern_rs");
        return -1;
    }
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Path tidak valid UTF-8: {}", e);
            return -1;
        }
    };
    let regex_str = match CStr::from_ptr(regex_str_c).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Regex tidak valid UTF-8: {}", e);
            return -1;
        }
    };
    let binary = match Binary::load(path_str) {
        Ok(b) => b,
        Err(e) => {
            error!("Binary::load gagal: {}", e);
            return -1;
        }
    };
    let results = deteksi_pattern_internal(&binary, regex_str);
    let json_result_string = match results {
        Ok(matches) => {
            serde_json::to_string(&matches).unwrap_or_else(|e| format!("[\"Error serialisasi: {}\"]", e))
        }
        Err(e) => format!("[\"Error: {}\"]", e),
    };
    let json_bytes = json_result_string.as_bytes();
    if json_bytes.len() >= out_buffer_size as usize {
        warn!("Ukuran buffer output JSON tidak cukup");
        return -1;
    }
    let out_slice = std::slice::from_raw_parts_mut(out_buffer, out_buffer_size as usize);
    strncpy_rs_from_bytes(json_bytes, out_slice);
    0
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
    fn test_ekstrak_strings_internal_mixed() {
        let test_file = "test_strings.bin";
        let content = b"This is ASCII\x00\x01\x02\x57\x00\x4F\x00\x52\x00\x44\x00\x00\x00Another ASCII";
        create_test_file(test_file, content).unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = ekstrak_strings_internal(&binary, 4);
        assert!(result.is_ok());
        let strings = result.unwrap();
        let contents: Vec<String> = strings.iter().map(|s| s.content.clone()).collect();
        assert!(contents.contains(&"This is ASCII".to_string()));
        assert!(contents.contains(&"WORD".to_string()));
        assert!(contents.contains(&"Another ASCII".to_string()));
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_hitung_entropy_internal_success() {
        let test_file = "test_entropy.bin";
        let content = vec![0x00; 1024];
        create_test_file(test_file, &content).unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = hitung_entropy_internal(&binary, 512);
        assert!(result.is_ok());
        let entropies = result.unwrap();
        assert_eq!(entropies.len(), 2);
        assert!((entropies[0] - 0.0).abs() < f64::EPSILON);
        assert!((entropies[1] - 0.0).abs() < f64::EPSILON);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_deteksi_pattern_internal_success() {
        let test_file = "test_pattern.bin";
        let content = b"Some data here 12345 and more data 67890.";
        create_test_file(test_file, content).unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = deteksi_pattern_internal(&binary, r"\d{5}");
        assert!(result.is_ok());
        let matches = result.unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0], "12345");
        assert_eq!(matches[1], "67890");
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_deteksi_pattern_internal_invalid_regex() {
        let test_file = "test_pattern_invalid.bin";
        create_test_file(test_file, b"data").unwrap();
        let binary = Binary::load(test_file).unwrap();
        let result = deteksi_pattern_internal(&binary, r"[");
        assert!(result.is_err());
        match result.err().unwrap() {
            ReToolsError::RegexError(_) => (),
            _ => panic!("Expected RegexError"),
        }
        std::fs::remove_file(test_file).unwrap();
    }
}