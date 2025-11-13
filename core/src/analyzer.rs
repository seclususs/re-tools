use encoding_rs::{UTF_16BE, UTF_16LE};
use libc::{c_char, c_int};
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::fs;
use std::path::Path;

/// Struct internal untuk menyimpan string yang ditemukan beserta offsetnya
#[derive(Serialize)]
struct StringInfo {
    offset: u64,
    content: String,
    encoding: &'static str,
}

/// Helper untuk membaca file
fn read_file_bytes_internal(file_path_c: *const c_char) -> Option<Vec<u8>> {
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

/// Logika internal untuk mengekstrak semua string (ASCII & UTF-16)
fn extract_all_strings(buffer: &[u8], min_length: usize) -> Vec<StringInfo> {
    let mut strings_found = Vec::new();

    // Ekstraksi ASCII
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

    // Ekstraksi UTF-16 LE
    // (Pencarian sederhana, bukan yang paling efisien)
    for encoding in [UTF_16LE, UTF_16BE] {
        let (cow, _had_errors) = encoding.decode_without_bom_handling(buffer);
        let decoded_str = cow.as_ref();
        
        let mut current_utf16_offset = 0;
        let mut current_utf16_str = String::new();

        for (i, c) in decoded_str.char_indices() {
            if c.is_ascii_graphic() || c.is_alphanumeric() || c.is_whitespace() || c.is_ascii_punctuation() {
                 if current_utf16_str.is_empty() {
                    // Offset byte, bukan char index
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

/// C-ABI: c_getStringsList
/// Mengembalikan daftar string (ASCII & UTF-16) sebagai JSON string.
/// Format JSON: [ { "offset": 0, "content": "string1", "encoding": "ASCII" }, ... ]
/// @param file_path_c Path ke file.
/// @param min_length Panjang minimum string.
/// @return Pointer ke string JSON (harus dibebaskan dengan c_freeString).
pub unsafe fn c_get_strings_list(
    file_path_c: *const c_char,
    min_length: c_int,
) -> *mut c_char {
    let Some(buffer) = read_file_bytes_internal(file_path_c) else {
        return CString::new("[]").unwrap().into_raw();
    };

    let strings = extract_all_strings(&buffer, min_length as usize);
    let json_result = match serde_json::to_string(&strings) {
        Ok(json) => json,
        Err(_) => "[]".to_string(),
    };

    CString::new(json_result).unwrap_or_default().into_raw()
}