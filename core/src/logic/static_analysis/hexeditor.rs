use crate::utils::strncpy_rs_from_bytes;
use libc::{c_char, c_int};
use memchr::memmem::Finder;
use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::slice;

pub fn lihat_bytes_internal(
    filename: &str,
    offset: u64,
    length: usize,
) -> Result<String, std::io::Error> {
    let path = Path::new(filename);
    let mut file = File::open(path)?;

    file.seek(SeekFrom::Start(offset))?;

    let mut buffer = vec![0; length];
    let bytes_read = file.read(&mut buffer)?;
    buffer.truncate(bytes_read);
    let hex_strings: Vec<String> = buffer.iter().map(|b| format!("{:02X}", b)).collect();
    Ok(hex_strings.join(" "))
}

pub fn ubah_bytes_internal(
    filename: &str,
    offset: u64,
    data: &[u8],
) -> Result<bool, std::io::Error> {
    let path = Path::new(filename);
    let mut file = OpenOptions::new().write(true).open(path)?;

    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;
    Ok(true)
}

pub fn cari_pattern_internal(
    filename: &str,
    pattern: &[u8],
) -> Result<Vec<u64>, std::io::Error> {
    if pattern.is_empty() {
        return Ok(Vec::new());
    }
    let file_data = std::fs::read(filename)?;
    
    let finder = Finder::new(pattern);
    let offsets: Vec<u64> = finder
        .find_iter(&file_data)
        .map(|i| i as u64) 
        .collect();
        
    Ok(offsets)
}

pub unsafe fn c_lihat_bytes(
    filename: *const c_char,
    offset: c_int,
    length: c_int,
    out_buffer: *mut c_char,
    out_buffer_size: c_int,
) -> c_int {
    if filename.is_null() || out_buffer.is_null() || out_buffer_size <= 0 || offset < 0 || length < 0 {
        return -1;
    }

    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    match lihat_bytes_internal(path_str, offset as u64, length as usize) {
        Ok(hex_str) => {
            let hex_bytes = hex_str.as_bytes();
            if hex_bytes.len() >= out_buffer_size as usize {
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_buffer, out_buffer_size as usize);
            strncpy_rs_from_bytes(hex_bytes, out_slice);
            0 
        }
        Err(_) => -1,
    }
}

pub unsafe fn c_ubah_bytes(
    filename: *const c_char,
    offset: c_int,
    data: *const u8,
    data_len: c_int,
) -> c_int {
    if filename.is_null() || data.is_null() || offset < 0 || data_len <= 0 {
        return -1;
    }
    
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let data_slice = slice::from_raw_parts(data, data_len as usize);

    match ubah_bytes_internal(path_str, offset as u64, data_slice) {
        Ok(true) => 1,
        _ => 0,
    }
}

pub unsafe fn c_cari_pattern(
    filename: *const c_char,
    pattern: *const u8,
    pattern_len: c_int,
    out_offsets: *mut c_int,
    max_offsets: c_int,
) -> c_int {
    if filename.is_null() || pattern.is_null() || out_offsets.is_null() || pattern_len <= 0 || max_offsets <= 0 {
        return -1;
    }

    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let pattern_slice = slice::from_raw_parts(pattern, pattern_len as usize);
    
    match cari_pattern_internal(path_str, pattern_slice) {
        Ok(results) => {
            if results.len() > max_offsets as usize {
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_offsets, max_offsets as usize);
            for (i, &res) in results.iter().enumerate() {
                out_slice[i] = res as c_int;
            }
            results.len() as c_int
        }
        Err(_) => -1,
    }
}