//! Author: [Seclususs](https://github.com/seclususs)

use libc::c_char;
use log::{debug, warn};
use std::ffi::CString;
use std::ptr;

pub fn copy_str_safe(src: &str, dest: &mut [c_char]) {
    let src_bytes = src.as_bytes();
    copy_bytes_safe(src_bytes, dest);
}

pub fn copy_bytes_safe(src_bytes: &[u8], dest: &mut [c_char]) {
    let len = std::cmp::min(src_bytes.len(), dest.len() - 1);
    if src_bytes.len() > len {
        warn!(
            "String dipotong saat copy_safe: asli {} bytes, buffer {} bytes",
            src_bytes.len(),
            dest.len()
        );
    }
    unsafe {
        ptr::copy_nonoverlapping(src_bytes.as_ptr() as *const c_char, dest.as_mut_ptr(), len);
    }
    dest[len] = 0;
}

pub unsafe fn free_str_ptr(ptr: *mut c_char) {
    if ptr.is_null() {
        debug!("free_str_ptr dipanggil pada null pointer, tidak melakukan apa-apa");
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}