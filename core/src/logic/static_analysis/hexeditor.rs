use crate::error::{set_last_error, ReToolsError};
use crate::utils::strncpy_rs_from_bytes;
use libc::{c_char, c_int};
use log::{debug, info, warn};
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
) -> Result<String, ReToolsError> {
    info!(
        "Mulai lihat_bytes: {} offset: {} length: {}",
        filename, offset, length
    );
    let path = Path::new(filename);
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0; length];
    let bytes_read = file.read(&mut buffer)?;
    buffer.truncate(bytes_read);
    debug!("Bytes dibaca: {}", bytes_read);
    let hex_strings: Vec<String> = buffer.iter().map(|b| format!("{:02X}", b)).collect();
    Ok(hex_strings.join(" "))
}

pub fn ubah_bytes_internal(
    filename: &str,
    offset: u64,
    data: &[u8],
) -> Result<bool, ReToolsError> {
    info!(
        "Mulai ubah_bytes: {} offset: {} length: {}",
        filename,
        offset,
        data.len()
    );
    let path = Path::new(filename);
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;
    info!("Ubah bytes berhasil");
    Ok(true)
}

pub fn cari_pattern_internal(
    filename: &str,
    pattern: &[u8],
) -> Result<Vec<u64>, ReToolsError> {
    info!(
        "Mulai cari_pattern: {} length: {}",
        filename,
        pattern.len()
    );
    if pattern.is_empty() {
        warn!("Pattern pencarian kosong");
        return Ok(Vec::new());
    }
    let file_data = std::fs::read(filename)?;
    debug!("Ukuran file dibaca: {}", file_data.len());
    let finder = Finder::new(pattern);
    let offsets: Vec<u64> = finder
        .find_iter(&file_data)
        .map(|i| i as u64)
        .collect();

    info!("Ditemukan {} cocok", offsets.len());
    Ok(offsets)
}

pub unsafe fn c_lihat_bytes(
    filename: *const c_char,
    offset: c_int,
    length: c_int,
    out_buffer: *mut c_char,
    out_buffer_size: c_int,
) -> c_int {
    if filename.is_null()
        || out_buffer.is_null()
        || out_buffer_size <= 0
        || offset < 0
        || length < 0
    {
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_lihat_bytes".to_string()));
        return -1;
    }
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    match lihat_bytes_internal(path_str, offset as u64, length as usize) {
        Ok(hex_str) => {
            let hex_bytes = hex_str.as_bytes();
            if hex_bytes.len() >= out_buffer_size as usize {
                set_last_error(ReToolsError::Generic("Buffer output hex tidak cukup".to_string()));
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_buffer, out_buffer_size as usize);
            strncpy_rs_from_bytes(hex_bytes, out_slice);
            0
        }
        Err(e) => {
            set_last_error(e);
            -1
        }
    }
}

pub unsafe fn c_ubah_bytes(
    filename: *const c_char,
    offset: c_int,
    data: *const u8,
    data_len: c_int,
) -> c_int {
    if filename.is_null() || data.is_null() || offset < 0 || data_len <= 0 {
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_ubah_bytes".to_string()));
        return -1;
    }
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    let data_slice = slice::from_raw_parts(data, data_len as usize);
    match ubah_bytes_internal(path_str, offset as u64, data_slice) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(e) => {
            set_last_error(e);
            0
        }
    }
}

pub unsafe fn c_cari_pattern(
    filename: *const c_char,
    pattern: *const u8,
    pattern_len: c_int,
    out_offsets: *mut c_int,
    max_offsets: c_int,
) -> c_int {
    if filename.is_null()
        || pattern.is_null()
        || out_offsets.is_null()
        || pattern_len <= 0
        || max_offsets <= 0
    {
        set_last_error(ReToolsError::Generic("Invalid arguments untuk c_cari_pattern".to_string()));
        return -1;
    }
    let path_str = match CStr::from_ptr(filename).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(e.into());
            return -1;
        }
    };
    let pattern_slice = slice::from_raw_parts(pattern, pattern_len as usize);
    match cari_pattern_internal(path_str, pattern_slice) {
        Ok(results) => {
            if results.len() > max_offsets as usize {
                set_last_error(ReToolsError::Generic(format!(
                    "Jumlah hasil ({}) melebihi max_offsets ({})",
                    results.len(),
                    max_offsets
                )));
                return -1;
            }
            let out_slice = slice::from_raw_parts_mut(out_offsets, max_offsets as usize);
            for (i, &res) in results.iter().enumerate() {
                out_slice[i] = res as c_int;
            }
            results.len() as c_int
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
    fn create_test_file(path: &str, content: &[u8]) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(content)?;
        Ok(())
    }

    #[test]
    fn test_hex_editor_cycle() {
        let test_file = "test_hex_cycle.bin";
        let initial_content = b"\xDE\xAD\xBE\xEF\x00\x00";
        create_test_file(test_file, initial_content).unwrap();
        let hex_str = lihat_bytes_internal(test_file, 0, 4).unwrap();
        assert_eq!(hex_str, "DE AD BE EF");
        let offsets = cari_pattern_internal(test_file, b"\xAD\xBE").unwrap();
        assert_eq!(offsets, vec![1u64]);
        let new_data = b"\xCA\xFE";
        let success = ubah_bytes_internal(test_file, 2, new_data).unwrap();
        assert!(success);
        let final_hex_str = lihat_bytes_internal(test_file, 0, 6).unwrap();
        assert_eq!(final_hex_str, "DE AD CA FE 00 00");
        let final_offsets = cari_pattern_internal(test_file, b"\xAD\xBE").unwrap();
        assert_eq!(final_offsets, vec![] as Vec<u64>);
        let new_offsets = cari_pattern_internal(test_file, b"\xAD\xCA\xFE").unwrap();
        assert_eq!(new_offsets, vec![1u64]);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_cari_pattern_internal_empty() {
        let test_file = "test_hex_empty_pattern.bin";
        create_test_file(test_file, b"data").unwrap();
        let offsets = cari_pattern_internal(test_file, b"").unwrap();
        assert_eq!(offsets, vec![] as Vec<u64>);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_lihat_bytes_internal_out_of_bounds() {
        let test_file = "test_hex_oob.bin";
        create_test_file(test_file, b"hello").unwrap();
        let hex_str = lihat_bytes_internal(test_file, 10, 5).unwrap();
        assert_eq!(hex_str, "");
        std::fs::remove_file(test_file).unwrap();
    }
}