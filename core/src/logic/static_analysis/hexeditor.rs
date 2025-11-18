//! Author: [Seclususs](https://github.com/seclususs)

use crate::error::ReToolsError;
use log::{debug, info, warn};
use memchr::memmem::Finder;
use memmap2::Mmap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub fn view_bytes_hex(
    path_berkas: &str,
    off_set: u64,
    len_baca: usize,
) -> Result<String, ReToolsError> {
    info!(
        "Mulai lihat_bytes: {} offset: {} length: {}",
        path_berkas, off_set, len_baca
    );
    let jalur = Path::new(path_berkas);
    let berkas = File::open(jalur)?;
    let map_mem = unsafe { Mmap::map(&berkas)? };
    let sz_berkas = map_mem.len();
    let idx_mulai = std::cmp::min(off_set as usize, sz_berkas);
    let idx_akhir = std::cmp::min(sz_berkas, (off_set + len_baca as u64) as usize);
    let slice_buf = &map_mem[idx_mulai..idx_akhir];
    debug!("Bytes dibaca: {}", slice_buf.len());
    let list_hex: Vec<String> = slice_buf.iter().map(|b| format!("{:02X}", b)).collect();
    Ok(list_hex.join(" "))
}

pub fn patch_bytes_raw(
    path_berkas: &str,
    off_set: u64,
    slice_data: &[u8],
) -> Result<bool, ReToolsError> {
    info!(
        "Mulai ubah_bytes: {} offset: {} length: {}",
        path_berkas,
        off_set,
        slice_data.len()
    );
    let jalur = Path::new(path_berkas);
    let mut berkas = OpenOptions::new().write(true).open(jalur)?;
    berkas.seek(SeekFrom::Start(off_set))?;
    berkas.write_all(slice_data)?;
    info!("Ubah bytes berhasil");
    Ok(true)
}

pub fn scan_pola_bytes(
    path_berkas: &str,
    pola_bytes: &[u8],
) -> Result<Vec<u64>, ReToolsError> {
    info!(
        "Mulai cari_pattern: {} length: {}",
        path_berkas,
        pola_bytes.len()
    );
    if pola_bytes.is_empty() {
        warn!("Pattern pencarian kosong");
        return Ok(Vec::new());
    }
    let berkas = File::open(path_berkas)?;
    let data_berkas = unsafe { Mmap::map(&berkas)? };
    debug!("Ukuran file dibaca: {}", data_berkas.len());
    let finder = Finder::new(pola_bytes);
    let list_offset: Vec<u64> = finder
        .find_iter(&data_berkas)
        .map(|i| i as u64)
        .collect();
    info!("Ditemukan {} cocok", list_offset.len());
    Ok(list_offset)
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
        let hex_str = view_bytes_hex(test_file, 0, 4).unwrap();
        assert_eq!(hex_str, "DE AD BE EF");
        let offsets = scan_pola_bytes(test_file, b"\xAD\xBE").unwrap();
        assert_eq!(offsets, vec![1u64]);
        let new_data = b"\xCA\xFE";
        let success = patch_bytes_raw(test_file, 2, new_data).unwrap();
        assert!(success);
        let final_hex_str = view_bytes_hex(test_file, 0, 6).unwrap();
        assert_eq!(final_hex_str, "DE AD CA FE 00 00");
        let final_offsets = scan_pola_bytes(test_file, b"\xAD\xBE").unwrap();
        assert_eq!(final_offsets, vec![] as Vec<u64>);
        let new_offsets = scan_pola_bytes(test_file, b"\xAD\xCA\xFE").unwrap();
        assert_eq!(new_offsets, vec![1u64]);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_cari_pattern_internal_empty() {
        let test_file = "test_hex_empty_pattern.bin";
        create_test_file(test_file, b"data").unwrap();
        let offsets = scan_pola_bytes(test_file, b"").unwrap();
        assert_eq!(offsets, vec![] as Vec<u64>);
        std::fs::remove_file(test_file).unwrap();
    }

    #[test]
    fn test_lihat_bytes_internal_out_of_bounds() {
        let test_file = "test_hex_oob.bin";
        create_test_file(test_file, b"hello").unwrap();
        let hex_str = view_bytes_hex(test_file, 10, 5).unwrap();
        assert_eq!(hex_str, "");
        std::fs::remove_file(test_file).unwrap();
    }
}