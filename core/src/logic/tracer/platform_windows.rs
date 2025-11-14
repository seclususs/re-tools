use super::state::StateDebuggerInternal;
use super::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use libc::{c_int, c_void};
use log::{debug, error, info, warn};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, LUID};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, GetThreadContext,
    ReadProcessMemory, SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT,
    DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
};
use windows_sys::Win32::Foundation::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP,
};

#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_CONTROL_AMD64 as CONTEXT_CONTROL, CONTEXT_FULL_AMD64 as CONTEXT_FULL,
};
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_CONTROL_X86 as CONTEXT_CONTROL, CONTEXT_FULL_X86 as CONTEXT_FULL,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, PROCESS_ALL_ACCESS,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};


#[allow(non_snake_case)]
unsafe fn impl_EnableDebugPrivilege_windows() -> bool {
    unsafe {
        let mut handle_token: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut handle_token,
        ) == 0
        {
            warn!(
                "WinAPI: OpenProcessToken gagal: {}",
                std::io::Error::last_os_error()
            );
            return false;
        }
        let mut luid_debug: LUID = std::mem::zeroed();
        let debug_name = b"SeDebugPrivilege\0";
        if LookupPrivilegeValueA(null(), debug_name.as_ptr(), &mut luid_debug) == 0 {
            warn!(
                "WinAPI: LookupPrivilegeValueA gagal: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(handle_token);
            return false;
        }
        let mut token_privs: TOKEN_PRIVILEGES = std::mem::zeroed();
        token_privs.PrivilegeCount = 1;
        token_privs.Privileges[0].Luid = luid_debug;
        token_privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        let b_ok = AdjustTokenPrivileges(
            handle_token,
            FALSE,
            &token_privs,
            0,
            null_mut(),
            null_mut(),
        );
        CloseHandle(handle_token);
        if b_ok == 0 {
            warn!(
                "WinAPI: AdjustTokenPrivileges gagal: {}",
                std::io::Error::last_os_error()
            );
            return false;
        }
        info!("WinAPI: SeDebugPrivilege diaktifkan");
        true
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_attach(state_data: &mut StateDebuggerInternal) -> bool {
    unsafe {
        impl_EnableDebugPrivilege_windows();
        let handle_proses = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            state_data.pid_target as u32,
        );
        if handle_proses == 0 {
            error!(
                "WinAPI: OpenProcess gagal, error: {}",
                std::io::Error::last_os_error()
            );
            return false;
        }
        state_data.handle_proses = handle_proses;
        if DebugActiveProcess(state_data.pid_target as u32) == 0 {
            error!(
                "WinAPI: DebugActiveProcess gagal, error: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(handle_proses);
            return false;
        }
        let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
        if WaitForDebugEvent(&mut debug_event, 5000) == 0 {
            error!(
                "WinAPI: Timeout menunggu event attach awal, error: {}",
                std::io::Error::last_os_error()
            );
            DebugActiveProcessStop(state_data.pid_target as u32);
            CloseHandle(handle_proses);
            return false;
        }
        info!(
            "WinAPI: Attach berhasil, event awal diterima dari thread {}",
            debug_event.dwThreadId
        );
        state_data.last_event_thread_id = debug_event.dwThreadId;
        ContinueDebugEvent(
            debug_event.dwProcessId,
            debug_event.dwThreadId,
            DBG_CONTINUE,
        );
        true
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_detach(state_data: &mut StateDebuggerInternal) {
    unsafe {
        if state_data.handle_proses != 0 {
            if DebugActiveProcessStop(state_data.pid_target as u32) == 0 {
                error!(
                    "WinAPI: DebugActiveProcessStop gagal, error: {}",
                    std::io::Error::last_os_error()
                );
            } else {
                info!(
                    "WinAPI: DebugActiveProcessStop berhasil untuk PID {}",
                    state_data.pid_target
                );
            }
            CloseHandle(state_data.handle_proses);
            state_data.handle_proses = 0;
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_bacaMemory(
    state_data: &StateDebuggerInternal,
    addr: u64,
    out_buffer: *mut u8,
    size: c_int,
) -> c_int {
    unsafe {
        let mut bytes_dibaca: usize = 0;
        if ReadProcessMemory(
            state_data.handle_proses,
            addr as *const c_void,
            out_buffer as *mut c_void,
            size as usize,
            &mut bytes_dibaca,
        ) != 0
        {
            bytes_dibaca as c_int
        } else {
            warn!(
                "WinAPI: ReadProcessMemory gagal pada 0x{:x}, error: {}",
                addr,
                std::io::Error::last_os_error()
            );
            -1
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_tulisMemory(
    state_data: &StateDebuggerInternal,
    addr: u64,
    data: *const u8,
    size: c_int,
) -> c_int {
    unsafe {
        let mut bytes_ditulis: usize = 0;
        if WriteProcessMemory(
            state_data.handle_proses,
            addr as *mut c_void,
            data as *const c_void,
            size as usize,
            &mut bytes_ditulis,
        ) != 0
        {
            bytes_ditulis as c_int
        } else {
            warn!(
                "WinAPI: WriteProcessMemory gagal pada 0x{:x}, error: {}",
                addr,
                std::io::Error::last_os_error()
            );
            -1
        }
    }
}

#[allow(non_snake_case)]
unsafe fn set_single_step_flag(thread_id: u32, enable: bool) -> bool {
    unsafe {
        let h_thread = OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE,
            thread_id,
        );
        if h_thread == 0 {
            warn!(
                "WinAPI: OpenThread gagal untuk set_single_step: {}",
                std::io::Error::last_os_error()
            );
            return false;
        }
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;
        if GetThreadContext(h_thread, &mut context) == 0 {
            warn!(
                "WinAPI: GetThreadContext gagal untuk set_single_step: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_thread);
            return false;
        }
        if enable {
            context.EFlags |= 0x100;
        } else {
            context.EFlags &= !0x100;
        }
        let success = SetThreadContext(h_thread, &context);
        if success == 0 {
            warn!(
                "WinAPI: SetThreadContext gagal untuk set_single_step: {}",
                std::io::Error::last_os_error()
            );
        }
        CloseHandle(h_thread);
        success != 0
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_singleStep(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        if state_data.last_event_thread_id == 0 {
            error!("WinAPI: singleStep gagal, last_event_thread_id adalah 0");
            return -1;
        }
        if !set_single_step_flag(state_data.last_event_thread_id, true) {
            error!("WinAPI: singleStep gagal, set_single_step_flag gagal");
            return -1;
        }
        if impl_platform_continueProses(state_data) != 0 {
            error!("WinAPI: singleStep gagal, continueProses gagal");
            return -1;
        }
        let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
        loop {
            if WaitForDebugEvent(&mut debug_event, u32::MAX) == 0 {
                error!(
                    "WinAPI: WaitForDebugEvent gagal saat single step: {}",
                    std::io::Error::last_os_error()
                );
                return -1;
            }
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
                && debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP
            {
                debug!("WinAPI: EXCEPTION_SINGLE_STEP diterima");
                ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    DBG_CONTINUE,
                );
                return 0;
            }
            debug!(
                "WinAPI: Menerima event lain saat single step: {}, melanjutkan...",
                debug_event.dwDebugEventCode
            );
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                DBG_CONTINUE,
            );
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_getRegisters(
    state_data: &mut StateDebuggerInternal,
    out_registers: *mut C_Registers,
) -> c_int {
    unsafe {
        if state_data.last_event_thread_id == 0 {
            error!("WinAPI: getRegisters gagal, last_event_thread_id adalah 0");
            return -1;
        }
        let h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, state_data.last_event_thread_id);
        if h_thread == 0 {
            error!(
                "WinAPI: OpenThread (get) gagal: {}",
                std::io::Error::last_os_error()
            );
            return -1;
        }
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;
        if GetThreadContext(h_thread, &mut context) == 0 {
            error!(
                "WinAPI: GetThreadContext gagal: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_thread);
            return -1;
        }
        CloseHandle(h_thread);
        #[cfg(target_arch = "x86_64")]
        {
            *out_registers = C_Registers {
                rax: context.Rax,
                rbx: context.Rbx,
                rcx: context.Rcx,
                rdx: context.Rdx,
                rsi: context.Rsi,
                rdi: context.Rdi,
                rbp: context.Rbp,
                rsp: context.Rsp,
                r8: context.R8,
                r9: context.R9,
                r10: context.R10,
                r11: context.R11,
                r12: context.R12,
                r13: context.R13,
                r14: context.R14,
                r15: context.R15,
                rip: context.Rip,
                eflags: context.EFlags as u64,
            };
        }
        0
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_setRegisters(
    state_data: &StateDebuggerInternal,
    registers: *const C_Registers,
) -> c_int {
    unsafe {
        if state_data.last_event_thread_id == 0 {
            error!("WinAPI: setRegisters gagal, last_event_thread_id adalah 0");
            return -1;
        }
        let h_thread = OpenThread(THREAD_SET_CONTEXT, FALSE, state_data.last_event_thread_id);
        if h_thread == 0 {
            error!(
                "WinAPI: OpenThread (set) gagal: {}",
                std::io::Error::last_os_error()
            );
            return -1;
        }
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;
        let c_regs = &*registers;
        #[cfg(target_arch = "x86_64")]
        {
            context.Rax = c_regs.rax;
            context.Rbx = c_regs.rbx;
            context.Rcx = c_regs.rcx;
            context.Rdx = c_regs.rdx;
            context.Rsi = c_regs.rsi;
            context.Rdi = c_regs.rdi;
            context.Rbp = c_regs.rbp;
            context.Rsp = c_regs.rsp;
            context.R8 = c_regs.r8;
            context.R9 = c_regs.r9;
            context.R10 = c_regs.r10;
            context.R11 = c_regs.r11;
            context.R12 = c_regs.r12;
            context.R13 = c_regs.r13;
            context.R14 = c_regs.r14;
            context.R15 = c_regs.r15;
            context.Rip = c_regs.rip;
            context.EFlags = c_regs.eflags as u32;
        }
        if SetThreadContext(h_thread, &context) == 0 {
            error!(
                "WinAPI: SetThreadContext gagal: {}",
                std::io::Error::last_os_error()
            );
            CloseHandle(h_thread);
            return -1;
        }
        CloseHandle(h_thread);
        0
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_continueProses(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        if state_data.last_event_thread_id == 0 {
            error!("WinAPI: continueProses gagal, last_event_thread_id adalah 0");
            return -1;
        }
        if ContinueDebugEvent(
            state_data.pid_target as u32,
            state_data.last_event_thread_id,
            DBG_CONTINUE,
        ) != 0
        {
            0
        } else {
            error!(
                "WinAPI: ContinueDebugEvent gagal: {}",
                std::io::Error::last_os_error()
            );
            -1
        }
    }
}

#[allow(non_snake_case)]
unsafe fn internal_handle_breakpoint_pre_step(
    state_data: &mut StateDebuggerInternal,
    debug_event: &DEBUG_EVENT,
    alamat_bp: u64,
) -> bool {
    unsafe {
        let Some(&byte_asli) = state_data.breakpoints_map.get(&alamat_bp) else {
            warn!("WinAPI: Breakpoint 0x{:x} tidak ada di map", alamat_bp);
            return false;
        };
        if impl_platform_tulisMemory(state_data, alamat_bp, &byte_asli, 1) != 1 {
            error!("WinAPI: Gagal restore byte asli pada 0x{:x}", alamat_bp);
            return false;
        }
        let thread_id = debug_event.dwThreadId;
        let h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id);
        if h_thread == 0 {
            error!("WinAPI: Gagal OpenThread (pre-step)");
            return false;
        }
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_CONTROL;
        if GetThreadContext(h_thread, &mut context) == 0 {
            error!("WinAPI: Gagal GetThreadContext (control)");
            CloseHandle(h_thread);
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        {
            context.Rip = alamat_bp;
        }
        #[cfg(target_arch = "x86")]
        {
            context.Eip = alamat_bp as u32;
        }
        if SetThreadContext(h_thread, &context) == 0 {
            error!("WinAPI: Gagal SetThreadContext (control)");
            CloseHandle(h_thread);
            return false;
        }
        context.ContextFlags = CONTEXT_FULL;
        if GetThreadContext(h_thread, &mut context) == 0 {
            error!("WinAPI: Gagal GetThreadContext (full)");
            CloseHandle(h_thread);
            return false;
        }
        context.EFlags |= 0x100;
        if SetThreadContext(h_thread, &context) == 0 {
            error!("WinAPI: Gagal SetThreadContext (TF bit)");
            CloseHandle(h_thread);
            return false;
        }
        CloseHandle(h_thread);
        state_data.handling_breakpoint_alamat = Some(alamat_bp);
        true
    }
}

#[allow(non_snake_case)]
unsafe fn internal_handle_breakpoint_post_step(
    state_data: &mut StateDebuggerInternal,
    alamat_bp: u64,
) -> bool {
    unsafe {
        let int3_byte: u8 = 0xCC;
        if impl_platform_tulisMemory(state_data, alamat_bp, &int3_byte, 1) != 1 {
            error!("WinAPI: Gagal re-set breakpoint pada 0x{:x}", alamat_bp);
            return false;
        }
        state_data.handling_breakpoint_alamat = None;
        true
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_tungguEvent(
    state_data: &mut StateDebuggerInternal,
    event_out: *mut C_DebugEvent,
) -> c_int {
    unsafe {
        let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
        loop {
            if WaitForDebugEvent(&mut debug_event, u32::MAX) == 0 {
                error!(
                    "WinAPI: WaitForDebugEvent gagal, error: {}",
                    std::io::Error::last_os_error()
                );
                return -1;
            }
            state_data.last_event_thread_id = debug_event.dwThreadId;
            let mut continue_status = DBG_CONTINUE;
            match debug_event.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    let exception_record = &debug_event.u.Exception.ExceptionRecord;
                    let alamat_exception = exception_record.ExceptionAddress as u64;
                    debug!(
                        "WinAPI: EXCEPTION_DEBUG_EVENT diterima: 0x{:x} pada 0x{:x}",
                        exception_record.ExceptionCode, alamat_exception
                    );
                    if exception_record.ExceptionCode == EXCEPTION_BREAKPOINT {
                        if state_data.breakpoints_map.contains_key(&alamat_exception) {
                            debug!("WinAPI: Menangani breakpoint internal pada 0x{:x}", alamat_exception);
                            if internal_handle_breakpoint_pre_step(
                                state_data,
                                &debug_event,
                                alamat_exception,
                            ) {
                                ContinueDebugEvent(
                                    debug_event.dwProcessId,
                                    debug_event.dwThreadId,
                                    DBG_CONTINUE,
                                );
                                continue;
                            } else {
                                error!("Gagal menangani pre-step breakpoint, tidak melanjutkan");
                                continue_status = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        } else {
                            debug!("WinAPI: Breakpoint eksternal, tidak ditangani");
                            continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    } else if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP {
                        if let Some(alamat_bp_ditangani) = state_data.handling_breakpoint_alamat {
                            debug!("WinAPI: Menangani post-step breakpoint pada 0x{:x}", alamat_bp_ditangani);
                            internal_handle_breakpoint_post_step(state_data, alamat_bp_ditangani);
                            (*event_out).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                            (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                            (*event_out).info_alamat = alamat_bp_ditangani;
                            return 0;
                        } else {
                            debug!("WinAPI: Single step eksternal");
                            (*event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                            (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                            (*event_out).info_alamat = alamat_exception;
                            return 0;
                        }
                    } else {
                        debug!("WinAPI: Eksepsi lain, tidak ditangani");
                        (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                        (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                        (*event_out).info_alamat = alamat_exception;
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    info!(
                        "WinAPI: EXIT_PROCESS_DEBUG_EVENT, status: {}",
                        debug_event.u.ExitProcess.dwExitCode
                    );
                    (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                    (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                    (*event_out).info_alamat = debug_event.u.ExitProcess.dwExitCode as u64;
                    state_data.attached_status = false;
                    return 0;
                }
                _ => {
                    debug!(
                        "WinAPI: Menerima event debug: {}",
                        debug_event.dwDebugEventCode
                    );
                }
            }
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status,
            );
        }
    }
}