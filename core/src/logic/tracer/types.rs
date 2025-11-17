use libc::{c_char, c_int, c_ulonglong, c_uchar};
use serde::{Serialize, Serializer};


#[allow(non_camel_case_types)]
pub type u64 = c_ulonglong;
#[allow(non_camel_case_types)]
pub type u8 = c_uchar;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct C_Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u64,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugEventTipe {
    EVENT_UNKNOWN = 0,
    EVENT_BREAKPOINT = 1,
    EVENT_SINGLE_STEP = 2,
    EVENT_PROSES_EXIT = 3,
    EVENT_THREAD_BARU = 4,
    EVENT_THREAD_EXIT = 5,
    EVENT_SYSCALL_ENTRY = 6,
    EVENT_SYSCALL_EXIT = 7,
    EVENT_MODUL_LOAD = 8,
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct C_DebugEvent {
    pub tipe: DebugEventTipe,
    pub pid_thread: c_int,
    pub info_alamat: u64,
}

fn serialize_c_char_array_as_string<S>(
    array: &[c_char; 260],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let c_str = unsafe { std::ffi::CStr::from_ptr(array.as_ptr()) };
    let str_slice = c_str.to_string_lossy();
    serializer.serialize_str(&str_slice)
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Serialize)]
pub struct C_MemoryRegionInfo {
    pub alamat_basis: u64,
    pub ukuran: u64,
    pub proteksi: u32,
    #[serde(serialize_with = "serialize_c_char_array_as_string")]
    pub path_modul: [c_char; 260],
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize)]
pub struct C_SyscallInfo {
    pub nomor_syscall: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub arg6: u64,
    pub nilai_balik: u64,
    pub adalah_entry: bool,
}