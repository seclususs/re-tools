use crate::error::ReToolsError;
use log::{debug, info, warn};
use memchr::memmem::Finder;
use memmap2::Mmap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;


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
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let file_len = mmap.len();
    let start = std::cmp::min(offset as usize, file_len);
    let end = std::cmp::min(file_len, (offset + length as u64) as usize);
    let buffer = &mmap[start..end];
    debug!("Bytes dibaca: {}", buffer.len());
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
    let file = File::open(filename)?;
    let file_data = unsafe { Mmap::map(&file)? };
    debug!("Ukuran file dibaca: {}", file_data.len());
    let finder = Finder::new(pattern);
    let offsets: Vec<u64> = finder
        .find_iter(&file_data)
        .map(|i| i as u64)
        .collect();
    info!("Ditemukan {} cocok", offsets.len());
    Ok(offsets)
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