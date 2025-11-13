use libc::{c_int, c_ulonglong, c_uchar};


#[allow(non_camel_case_types)]
pub type u64 = c_ulonglong;
#[allow(non_camel_case_types)]
pub type u8 = c_uchar;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct C_Registers {
    // General Purpose
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
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct C_DebugEvent {
    pub tipe: DebugEventTipe,
    pub pid_thread: c_int,
    pub info_alamat: u64,
}