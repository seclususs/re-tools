use libc::c_char;
use std::ffi::CString;
use std::ptr;

/// Helper strncpy Rust ke fixed-size C buffer
pub fn strncpy_rs(src: &str, dest: &mut [c_char]) {
    let src_bytes = src.as_bytes();
    // Kurangi 1 untuk null terminator
    let len = std::cmp::min(src_bytes.len(), dest.len() - 1);

    // Salin datanya
    unsafe {
        ptr::copy_nonoverlapping(src_bytes.as_ptr() as *const c_char, dest.as_mut_ptr(), len);
    }
    // null-terminator
    dest[len] = 0;
}

/// Membebaskan string yang dialokasi (CString::into_raw)
pub unsafe fn c_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}