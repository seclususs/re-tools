use super::platform::PlatformTracer;
use super::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use crate::error::{ReToolsError, set_last_error};
use libc::{c_int, c_void};
use std::collections::HashMap;
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
    CONTEXT_FULL_AMD64 as CONTEXT_FULL,
    CONTEXT_DEBUG_REGISTERS_AMD64 as CONTEXT_DEBUG_REGISTERS
};
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_CONTROL_X86 as CONTEXT_CONTROL, CONTEXT_FULL_X86 as CONTEXT_FULL,
    CONTEXT_DEBUG_REGISTERS_X86 as CONTEXT_DEBUG_REGISTERS
};

use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, PROCESS_ALL_ACCESS,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};


pub struct WindowsTracer {
    pid_target: u32,
    handle_proses: HANDLE,
    breakpoints_map: HashMap<u64, u8>,
    last_event_thread_id: u32,
    handling_breakpoint_alamat: Option<u64>,
}

impl WindowsTracer {
    pub fn new(pid: c_int) -> Result<Self, ReToolsError> {
        Ok(WindowsTracer {
            pid_target: pid as u32,
            handle_proses: 0,
            breakpoints_map: HashMap::new(),
            last_event_thread_id: 0,
            handling_breakpoint_alamat: None,
        })
    }
    unsafe fn enable_debug_privilege() -> bool {
        let mut handle_token: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut handle_token,
        ) == 0
        {
            return false;
        }
        let mut luid_debug: LUID = std::mem::zeroed();
        let debug_name = b"SeDebugPrivilege\0";
        if LookupPrivilegeValueA(null(), debug_name.as_ptr(), &mut luid_debug) == 0 {
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
        b_ok != 0
    }
    unsafe fn get_thread_handle(&self, thread_id: u32, access: u32) -> Result<HANDLE, ReToolsError> {
        let h_thread = OpenThread(access, FALSE, thread_id);
        if h_thread == 0 {
            Err(ReToolsError::IoError(std::io::Error::last_os_error()))
        } else {
            Ok(h_thread)
        }
    }
    unsafe fn get_thread_context(&self, thread_id: u32, flags: u32) -> Result<CONTEXT, ReToolsError> {
        let h_thread = self.get_thread_handle(thread_id, THREAD_GET_CONTEXT)?;
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = flags;
        let result = GetThreadContext(h_thread, &mut context);
        CloseHandle(h_thread);
        if result == 0 {
            Err(ReToolsError::IoError(std::io::Error::last_os_error()))
        } else {
            Ok(context)
        }
    }
    unsafe fn set_thread_context(&self, thread_id: u32, context: &CONTEXT) -> Result<(), ReToolsError> {
        let h_thread = self.get_thread_handle(thread_id, THREAD_SET_CONTEXT)?;
        let result = SetThreadContext(h_thread, context);
        CloseHandle(h_thread);
        if result == 0 {
            Err(ReToolsError::IoError(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
    unsafe fn internal_handle_breakpoint_pre_step(
        &mut self,
        debug_event: &DEBUG_EVENT,
        alamat_bp: u64,
    ) -> bool {
        let Some(&byte_asli) = self.breakpoints_map.get(&alamat_bp) else {
            return false;
        };
        if self.tulis_memory(alamat_bp, &[byte_asli]).is_err() {
            return false;
        }
        let thread_id = debug_event.dwThreadId;
        let mut context = match self.get_thread_context(thread_id, CONTEXT_FULL) {
            Ok(ctx) => ctx,
            Err(_) => return false,
        };
        #[cfg(target_arch = "x86_64")]
        {
            context.Rip = alamat_bp;
        }
        #[cfg(target_arch = "x86")]
        {
            context.Eip = alamat_bp as u32;
        }
        context.EFlags |= 0x100;
        if self.set_thread_context(thread_id, &context).is_err() {
            return false;
        }
        self.handling_breakpoint_alamat = Some(alamat_bp);
        true
    }
    unsafe fn internal_handle_breakpoint_post_step(
        &mut self,
        alamat_bp: u64,
    ) -> bool {
        if self.tulis_memory(alamat_bp, &[0xCC]).is_err() {
            return false;
        }
        self.handling_breakpoint_alamat = None;
        true
    }
    unsafe fn set_hw_bp(&self, addr: u64, index: usize) -> Result<(), ReToolsError> {
        if index > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut context = self.get_thread_context(self.last_event_thread_id, CONTEXT_DEBUG_REGISTERS)?;
        match index {
            0 => context.Dr0 = addr,
            1 => context.Dr1 = addr,
            2 => context.Dr2 = addr,
            3 => context.Dr3 = addr,
            _ => unreachable!(),
        }
        let enable_mask = 1 << (index * 2);
        let condition_mask = 0b00 << (16 + index * 4);
        let len_mask = 0b00 << (18 + index * 4);
        context.Dr7 |= enable_mask | condition_mask | len_mask;
        self.set_thread_context(self.last_event_thread_id, &context)?;
        Ok(())
    }
    unsafe fn remove_hw_bp(&self, index: usize) -> Result<(), ReToolsError> {
         if index > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut context = self.get_thread_context(self.last_event_thread_id, CONTEXT_DEBUG_REGISTERS)?;
        match index {
            0 => context.Dr0 = 0,
            1 => context.Dr1 = 0,
            2 => context.Dr2 = 0,
            3 => context.Dr3 = 0,
            _ => unreachable!(),
        }
        let disable_mask = !(1 << (index * 2));
        context.Dr7 &= disable_mask;
        self.set_thread_context(self.last_event_thread_id, &context)?;
        Ok(())
    }
}

impl PlatformTracer for WindowsTracer {
    fn attach(&mut self) -> Result<(), ReToolsError> {
        unsafe {
            WindowsTracer::enable_debug_privilege();
            let handle_proses = OpenProcess(PROCESS_ALL_ACCESS, FALSE, self.pid_target);
            if handle_proses == 0 {
                return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
            }
            self.handle_proses = handle_proses;
            if DebugActiveProcess(self.pid_target) == 0 {
                CloseHandle(handle_proses);
                return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
            }
            let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
            if WaitForDebugEvent(&mut debug_event, 5000) == 0 {
                DebugActiveProcessStop(self.pid_target);
                CloseHandle(handle_proses);
                return Err(ReToolsError::Generic("Timeout menunggu event attach".to_string()));
            }
            self.last_event_thread_id = debug_event.dwThreadId;
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                DBG_CONTINUE,
            );
            Ok(())
        }
    }
    fn detach(&mut self) -> Result<(), ReToolsError> {
        unsafe {
            for (addr, orig_byte) in &self.breakpoints_map {
                self.tulis_memory(*addr, &[*orig_byte]).ok();
            }
            self.breakpoints_map.clear();
            if self.handle_proses != 0 {
                if DebugActiveProcessStop(self.pid_target) == 0 {
                   return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
                }
                CloseHandle(self.handle_proses);
                self.handle_proses = 0;
            }
            Ok(())
        }
    }
    fn baca_memory(&self, addr: u64, size: c_int) -> Result<Vec<u8>, ReToolsError> {
        let mut buffer = vec![0u8; size as usize];
        let mut bytes_dibaca: usize = 0;
        unsafe {
            if ReadProcessMemory(
                self.handle_proses,
                addr as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                size as usize,
                &mut bytes_dibaca,
            ) != 0
            {
                buffer.truncate(bytes_dibaca);
                Ok(buffer)
            } else {
                Err(ReToolsError::IoError(std::io::Error::last_os_error()))
            }
        }
    }
    fn tulis_memory(&self, addr: u64, data: &[u8]) -> Result<usize, ReToolsError> {
        let mut bytes_ditulis: usize = 0;
        unsafe {
             if WriteProcessMemory(
                self.handle_proses,
                addr as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                &mut bytes_ditulis,
            ) != 0
            {
                Ok(bytes_ditulis)
            } else {
                Err(ReToolsError::IoError(std::io::Error::last_os_error()))
            }
        }
    }
    fn get_registers(&self) -> Result<C_Registers, ReToolsError> {
        unsafe {
            if self.last_event_thread_id == 0 {
                return Err(ReToolsError::Generic("last_event_thread_id adalah 0".to_string()));
            }
            let context = self.get_thread_context(self.last_event_thread_id, CONTEXT_FULL)?;
             #[cfg(target_arch = "x86_64")]
            {
                Ok(C_Registers {
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
                })
            }
            #[cfg(target_arch = "x86")]
            {
                Ok(C_Registers {
                    rax: context.Eax as u64,
                    rbx: context.Ebx as u64,
                    rcx: context.Ecx as u64,
                    rdx: context.Edx as u64,
                    rsi: context.Esi as u64,
                    rdi: context.Edi as u64,
                    rbp: context.Ebp as u64,
                    rsp: context.Esp as u64,
                    r8: 0, r9: 0, r10: 0, r11: 0, r12: 0, r13: 0, r14: 0, r15: 0,
                    rip: context.Eip as u64,
                    eflags: context.EFlags as u64,
                })
            }
        }
    }
    fn set_registers(&self, c_regs: &C_Registers) -> Result<(), ReToolsError> {
        unsafe {
            if self.last_event_thread_id == 0 {
                return Err(ReToolsError::Generic("last_event_thread_id adalah 0".to_string()));
            }
            let mut context = self.get_thread_context(self.last_event_thread_id, CONTEXT_FULL)?;
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
            #[cfg(target_arch = "x86")]
            {
                context.Eax = c_regs.rax as u32;
                context.Ebx = c_regs.rbx as u32;
                context.Ecx = c_regs.rcx as u32;
                context.Edx = c_regs.rdx as u32;
                context.Esi = c_regs.rsi as u32;
                context.Edi = c_regs.rdi as u32;
                context.Ebp = c_regs.rbp as u32;
                context.Esp = c_regs.rsp as u32;
                context.Eip = c_regs.rip as u32;
                context.EFlags = c_regs.eflags as u32;
            }
            self.set_thread_context(self.last_event_thread_id, &context)
        }
    }
    fn continue_proses(&self) -> Result<(), ReToolsError> {
        unsafe {
             if self.last_event_thread_id == 0 {
                return Err(ReToolsError::Generic("last_event_thread_id adalah 0".to_string()));
            }
            if ContinueDebugEvent(
                self.pid_target,
                self.last_event_thread_id,
                DBG_CONTINUE,
            ) == 0
            {
                Err(ReToolsError::IoError(std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }
    fn single_step(&mut self) -> Result<(), ReToolsError> {
        unsafe {
            if self.last_event_thread_id == 0 {
                return Err(ReToolsError::Generic("last_event_thread_id adalah 0".to_string()));
            }
            let mut context = self.get_thread_context(self.last_event_thread_id, CONTEXT_FULL)?;
            context.EFlags |= 0x100;
            self.set_thread_context(self.last_event_thread_id, &context)?;
            self.continue_proses()
        }
    }
    fn tunggu_event(&mut self, event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError> {
        unsafe {
            let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
            loop {
                if WaitForDebugEvent(&mut debug_event, u32::MAX) == 0 {
                    return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
                }
                self.last_event_thread_id = debug_event.dwThreadId;
                let mut continue_status = DBG_CONTINUE;
                match debug_event.dwDebugEventCode {
                    EXCEPTION_DEBUG_EVENT => {
                        let exception_record = &debug_event.u.Exception.ExceptionRecord;
                        let alamat_exception = exception_record.ExceptionAddress as u64;
                        if exception_record.ExceptionCode == EXCEPTION_BREAKPOINT {
                            if self.breakpoints_map.contains_key(&alamat_exception) {
                                if self.internal_handle_breakpoint_pre_step(
                                    &debug_event,
                                    alamat_exception,
                                ) {
                                    continue_status = DBG_CONTINUE;
                                } else {
                                    set_last_error(ReToolsError::Generic("Gagal pre-step breakpoint".to_string()));
                                    continue_status = DBG_EXCEPTION_NOT_HANDLED;
                                }
                            } else {
                                continue_status = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        } else if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP {
                            if let Some(alamat_bp_ditangani) = self.handling_breakpoint_alamat {
                                self.internal_handle_breakpoint_post_step(alamat_bp_ditangani);
                                (*event_out).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                                (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                                (*event_out).info_alamat = alamat_bp_ditangani;
                                return Ok(0);
                            } else {
                                (*event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                                (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                                (*event_out).info_alamat = alamat_exception;
                                return Ok(0);
                            }
                        } else {
                            (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                            (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                            (*event_out).info_alamat = alamat_exception;
                            continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    }
                    EXIT_PROCESS_DEBUG_EVENT => {
                        (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                        (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                        (*event_out).info_alamat = debug_event.u.ExitProcess.dwExitCode as u64;
                        self.handle_proses = 0;
                        return Ok(0);
                    }
                    _ => {}
                }
                ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    continue_status,
                );
            }
        }
    }
     fn set_software_breakpoint(&mut self, addr: u64) -> Result<(), ReToolsError> {
        if self.breakpoints_map.contains_key(&addr) {
            return Ok(());
        }
        let orig_bytes = self.baca_memory(addr, 1)?;
        if orig_bytes.is_empty() {
            return Err(ReToolsError::Generic(format!(
                "Gagal membaca byte asli di 0x{:x}",
                addr
            )));
        }
        let orig_byte = orig_bytes[0];
        self.tulis_memory(addr, &[0xCC])?;
        self.breakpoints_map.insert(addr, orig_byte);
        Ok(())
    }
    fn remove_software_breakpoint(&mut self, addr: u64) -> Result<(), ReToolsError> {
        if let Some(orig_byte) = self.breakpoints_map.remove(&addr) {
            self.tulis_memory(addr, &[orig_byte])?;
        }
        Ok(())
    }
    fn set_hardware_breakpoint(&mut self, addr: u64, index: usize) -> Result<(), ReToolsError> {
        unsafe { self.set_hw_bp(addr, index) }
    }
    fn remove_hardware_breakpoint(&mut self, index: usize) -> Result<(), ReToolsError> {
        unsafe { self.remove_hw_bp(index) }
    }
}

impl Drop for WindowsTracer {
    fn drop(&mut self) {
        if self.handle_proses != 0 {
            self.detach().ok();
        }
    }
}