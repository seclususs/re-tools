#![allow(unsafe_op_in_unsafe_fn)]

pub mod api_dynamic;
pub mod api_ir;
pub mod api_static;

use crate::error::get_last_error_message;
use crate::utils::c_free_string;
use libc::c_char;


#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_freeString(ptr: *mut c_char) {
    unsafe {
        c_free_string(ptr);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_get_last_error_message() -> *mut c_char {
    get_last_error_message()
}