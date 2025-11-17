//! Author: [Seclususs](https://github.com/seclususs)

use libc::c_char;
use log::{debug, warn};
use std::ffi::CString;
use std::ptr;

pub fn strncpy_rs(src: &str, dest: &mut [c_char]) {
    let src_bytes = src.as_bytes();
    strncpy_rs_from_bytes(src_bytes, dest);
}

pub fn strncpy_rs_from_bytes(src_bytes: &[u8], dest: &mut [c_char]) {
    let len = std::cmp::min(src_bytes.len(), dest.len() - 1);
    if src_bytes.len() > len {
        warn!(
            "String dipotong saat strncpy: asli {} bytes, buffer {} bytes",
            src_bytes.len(),
            dest.len()
        );
    }
    unsafe {
        ptr::copy_nonoverlapping(src_bytes.as_ptr() as *const c_char, dest.as_mut_ptr(), len);
    }
    dest[len] = 0;
}

pub unsafe fn c_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        debug!("c_free_string dipanggil pada null pointer, tidak melakukan apa-apa");
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}