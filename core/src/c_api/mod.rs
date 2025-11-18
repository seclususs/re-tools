#![allow(unsafe_op_in_unsafe_fn)]

pub mod api_dynamic;
pub mod api_ir;
pub mod api_static;
pub mod api_data_flow;

use crate::error::fetch_err_msg;
use crate::utils::free_str_ptr;
use libc::c_char;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn c_freeString(ptr_target: *mut c_char) {
	unsafe {
		free_str_ptr(ptr_target);
	}
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rt_get_last_error_message() -> *mut c_char {
	fetch_err_msg()
}