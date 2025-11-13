use encoding_rs::{UTF_16BE, UTF_16LE};
use libc::{c_char, c_int};
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use std::io::Read;

use crate::utils::strncpy_rs_from_bytes;
use regex::bytes::Regex;


#[derive(Serialize)]
pub struct StringInfo {
    pub offset: u64,
    pub content: String,
    pub encoding: &'static str,
}

pub fn ekstrak_strings_internal(file_path: &str, min_length: usize) -> Result<Vec<StringInfo>, std::io::Error> {
    let buffer_bytes = fs::read(file_path)?;
    let strings_info = extract_all_strings(&buffer_bytes, min_length);
    Ok(strings_info)
}

pub fn read_file_bytes_internal(file_path_c: *const c_char) -> Option<Vec<u8>> {
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

pub fn extract_all_strings(buffer: &[u8], min_length: usize) -> Vec<StringInfo> {
    let mut strings_found = Vec::new();
    let mut current_ascii = Vec::new();
    let mut current_ascii_offset = 0;
    for (i, &byte) in buffer.iter().enumerate() {
        if byte >= 32 && byte <= 126 {
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
    for encoding in [UTF_16LE, UTF_16BE] {
        let (cow, _had_errors) = encoding.decode_without_bom_handling(buffer);
        let decoded_str = cow.as_ref();
        let mut current_utf16_offset = 0;
        let mut current_utf16_str = String::new();
        for (i, c) in decoded_str.char_indices() {
            if c.is_ascii_graphic() || c.is_alphanumeric() || c.is_whitespace() || c.is_ascii_punctuation() {
                 if current_utf16_str.is_empty() {
                    current_utf16_offset = i as u64; 
                 }
                 current_utf16_str.push(c);
            } else if !current_utf16_str.is_empty() {
                 if current_utf16_str.len() >= min_length {
                     strings_found.push(StringInfo {
                         offset: current_utf16_offset,
                         content: current_utf16_str.clone(),
                         encoding: if encoding == UTF_16LE { "UTF-16LE" } else { "UTF-16BE" },
                     });
                 }
                 current_utf16_str.clear();
            }
        }
         if current_utf16_str.len() >= min_length {
             strings_found.push(StringInfo {
                 offset: current_utf16_offset,
                 content: current_utf16_str,
                 encoding: if encoding == UTF_16LE { "UTF-16LE" } else { "UTF-16BE" },
             });
         }
    }
    strings_found
}

pub unsafe fn c_get_strings_list(
    file_path_c: *const c_char,
    min_length: c_int,
) -> *mut c_char {
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(_) => return CString::new("[]").unwrap().into_raw(),
    };
    let strings = match ekstrak_strings_internal(path_str, min_length as usize) {
        Ok(s) => s,
        Err(_) => return CString::new("[]").unwrap().into_raw(),
    };
    let json_result = match serde_json::to_string(&strings) {
        Ok(json) => json,
        Err(_) => "[]".to_string(),
    };
    CString::new(json_result).unwrap_or_default().into_raw()
}

fn calculate_entropy_for_block(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
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

pub fn hitung_entropy_internal(file_path: &str, block_size: usize) -> Result<Vec<f64>, std::io::Error> {
    let mut entropies = Vec::new();
    if block_size == 0 { return Ok(entropies); }
    let path = Path::new(file_path);
    let mut file = fs::File::open(path)?;
    let mut buffer = vec![0; block_size];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                let block_data = &buffer[..bytes_read];
                entropies.push(calculate_entropy_for_block(block_data));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(entropies)
}

pub unsafe fn c_hitung_entropy_rs(
    file_path_c: *const c_char,
    block_size: c_int,
    out_entropies: *mut f64,
    max_entropies: c_int,
) -> c_int {
    if file_path_c.is_null() || out_entropies.is_null() || max_entropies <= 0 || block_size <= 0 {
        return -1;
    }
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let results = match hitung_entropy_internal(path_str, block_size as usize) {
        Ok(res) => res,
        Err(_) => return -1,
    };
    if results.len() > max_entropies as usize {
        return -1;
    }
    let out_slice = std::slice::from_raw_parts_mut(out_entropies, max_entropies as usize);
    for (i, &res) in results.iter().enumerate() {
        out_slice[i] = res;
    }
    results.len() as c_int
}

pub fn deteksi_pattern_internal(file_path: &str, regex_str: &str) -> Result<Vec<String>, String> {
    let file_bytes = match fs::read(file_path) {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("Gagal baca file: {}", e)),
    };
    let re = match Regex::new(regex_str) {
        Ok(re) => re,
        Err(e) => return Err(format!("Regex tidak valid: {}", e)),
    };
    let matches: Vec<String> = re.find_iter(&file_bytes)
        .map(|m| String::from_utf8_lossy(m.as_bytes()).to_string())
        .collect();
    Ok(matches)
}

pub unsafe fn c_deteksi_pattern_rs(
    file_path_c: *const c_char,
    regex_str_c: *const c_char,
    out_buffer: *mut c_char,
    out_buffer_size: c_int,
) -> c_int {
    if file_path_c.is_null() || regex_str_c.is_null() || out_buffer.is_null() || out_buffer_size <= 0 {
        return -1;
    }
    let path_str = match CStr::from_ptr(file_path_c).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let regex_str = match CStr::from_ptr(regex_str_c).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let results = deteksi_pattern_internal(path_str, regex_str);
    let json_result_string = match results {
        Ok(matches) => serde_json::to_string(&matches).unwrap_or_else(|e| format!("[\"Error serialisasi: {}\"]", e)),
        Err(e) => format!("[\"Error: {}\"]", e),
    };
    let json_bytes = json_result_string.as_bytes();
    if json_bytes.len() >= out_buffer_size as usize {
        return -1;
    }
    let out_slice = std::slice::from_raw_parts_mut(out_buffer, out_buffer_size as usize);
    strncpy_rs_from_bytes(json_bytes, out_slice);
    0
}