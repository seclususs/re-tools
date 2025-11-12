use libc::{c_int, c_void};

fn print_unsupported() {
    eprintln!("PERINGATAN (Rust): Fungsi tracer tidak didukung di OS ini.");
}

pub unsafe fn impl_platform_attach(_state_data: *mut c_void) -> bool {
    print_unsupported();
    false
}
pub unsafe fn impl_platform_detach(_state_data: *mut c_void) {
    print_unsupported();
}
pub unsafe fn impl_platform_baca_memory() -> c_int {
    print_unsupported();
    -1
}
pub unsafe fn impl_platform_tulis_memory() -> c_int {
    print_unsupported();
    -1
}
pub unsafe fn impl_platform_single_step() -> c_int {
    print_unsupported();
    -1
}
pub unsafe fn impl_platform_get_registers() -> c_int {
    print_unsupported();
    -1
}
pub unsafe fn impl_platform_set_registers() -> c_int {
    print_unsupported();
    -1
}
pub unsafe fn impl_platform_continue_proses() -> c_int {
    print_unsupported();
    -1
}
pub unsafe fn impl_platform_tunggu_event() -> c_int {
    print_unsupported();
    -1
}