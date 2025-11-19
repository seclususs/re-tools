//! Author: [Seclususs](https://github.com/seclususs)

#![allow(non_snake_case)]

use super::platform::PlatformTracer;
use super::types::{
    u64, u8, C_DebugEvent, C_MemoryRegionInfo, C_Registers, C_SyscallInfo, DebugEventTipe,
};
use crate::error::{set_err_last, ReToolsError};
use libc::{c_char, c_int, c_void};
use std::collections::HashMap;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, LUID};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, GetThreadContext,
    ReadProcessMemory, SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT,
    CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::Foundation::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows_sys::Win32::System::ProcessStatus::GetModuleFileNameExA;


#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_DEBUG_REGISTERS_AMD64 as CONTEXT_DEBUG_REGISTERS, CONTEXT_FULL_AMD64 as CONTEXT_FULL,
};
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_CONTROL_X86 as CONTEXT_CONTROL,
    CONTEXT_DEBUG_REGISTERS_X86 as CONTEXT_DEBUG_REGISTERS, CONTEXT_FULL_X86 as CONTEXT_FULL,
};

use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueA, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, PROCESS_ALL_ACCESS,
    THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
};

pub struct WindowsTracer {
    pid_sasaran: u32,
    ptr_handle_proses: HANDLE,
    map_titik_henti: HashMap<u64, u8>,
    id_thread_terakhir: u32,
    va_bp_sedang_ditangani: Option<u64>,
    mode_senyap: bool,
}

impl WindowsTracer {
    pub fn new(pid: c_int) -> Result<Self, ReToolsError> {
        Ok(WindowsTracer {
            pid_sasaran: pid as u32,
            ptr_handle_proses: 0,
            map_titik_henti: HashMap::new(),
            id_thread_terakhir: 0,
            va_bp_sedang_ditangani: None,
            mode_senyap: false,
        })
    }
    unsafe fn enable_debug_privilege() -> bool {
        let mut ptr_handle_token: HANDLE = 0;
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut ptr_handle_token,
        ) == 0
        {
            return false;
        }
        let mut luid_debug: LUID = std::mem::zeroed();
        let nama_debug = b"SeDebugPrivilege\0";
        if LookupPrivilegeValueA(null(), nama_debug.as_ptr(), &mut luid_debug) == 0 {
            CloseHandle(ptr_handle_token);
            return false;
        }
        let mut priv_token: TOKEN_PRIVILEGES = std::mem::zeroed();
        priv_token.PrivilegeCount = 1;
        priv_token.Privileges[0].Luid = luid_debug;
        priv_token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        let b_ok = AdjustTokenPrivileges(
            ptr_handle_token,
            FALSE,
            &priv_token,
            0,
            null_mut(),
            null_mut(),
        );
        CloseHandle(ptr_handle_token);
        b_ok != 0
    }
    unsafe fn check_memory_permission(&self, addr: u64, _len: usize, is_write: bool) -> Result<(), ReToolsError> {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        if VirtualQueryEx(
            self.ptr_handle_proses,
            addr as *const c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0 {
            return Err(ReToolsError::Generic("VirtualQueryEx failed - invalid address".to_string()));
        }
        if mbi.State != windows_sys::Win32::System::Memory::MEM_COMMIT {
            return Err(ReToolsError::Generic("Memory not committed".to_string()));
        }
        if mbi.Protect & windows_sys::Win32::System::Memory::PAGE_NOACCESS != 0 {
             return Err(ReToolsError::Generic("Access violation: PAGE_NOACCESS".to_string()));
        }
        if is_write {
            let writable_flags = windows_sys::Win32::System::Memory::PAGE_READWRITE |
                windows_sys::Win32::System::Memory::PAGE_WRITECOPY |
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE |
                windows_sys::Win32::System::Memory::PAGE_EXECUTE_WRITECOPY;
             if (mbi.Protect & writable_flags) == 0 {
                 return Err(ReToolsError::Generic("Access violation: Write protected".to_string()));
             }
        }
        Ok(())
    }
    unsafe fn get_handle_thread(
        &self,
        id_thread: u32,
        akses: u32,
    ) -> Result<HANDLE, ReToolsError> {
        let ptr_h_thread = OpenThread(akses, FALSE, id_thread);
        if ptr_h_thread == 0 {
            Err(ReToolsError::IoError(std::io::Error::last_os_error()))
        } else {
            Ok(ptr_h_thread)
        }
    }
    unsafe fn get_konteks_thread(
        &self,
        id_thread: u32,
        flags: u32,
    ) -> Result<CONTEXT, ReToolsError> {
        let ptr_h_thread = self.get_handle_thread(id_thread, THREAD_GET_CONTEXT)?;
        let mut konteks: CONTEXT = std::mem::zeroed();
        konteks.ContextFlags = flags;
        let hasil = GetThreadContext(ptr_h_thread, &mut konteks);
        CloseHandle(ptr_h_thread);
        if hasil == 0 {
            Err(ReToolsError::IoError(std::io::Error::last_os_error()))
        } else {
            Ok(konteks)
        }
    }
    unsafe fn set_konteks_thread(
        &self,
        id_thread: u32,
        konteks: &CONTEXT,
    ) -> Result<(), ReToolsError> {
        let ptr_h_thread = self.get_handle_thread(id_thread, THREAD_SET_CONTEXT)?;
        let hasil = SetThreadContext(ptr_h_thread, konteks);
        CloseHandle(ptr_h_thread);
        if hasil == 0 {
            Err(ReToolsError::IoError(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }
    unsafe fn handle_bp_pre_step_internal(
        &mut self,
        event_debug: &DEBUG_EVENT,
        va_bp: u64,
    ) -> bool {
        let Some(&byte_asli) = self.map_titik_henti.get(&va_bp) else {
            return false;
        };
        if self.write_memori(va_bp, &[byte_asli]).is_err() {
            return false;
        }
        let id_thread = event_debug.dwThreadId;
        let mut konteks = match self.get_konteks_thread(id_thread, CONTEXT_FULL) {
            Ok(ctx) => ctx,
            Err(_) => return false,
        };
        #[cfg(target_arch = "x86_64")]
        {
            konteks.Rip = va_bp;
        }
        #[cfg(target_arch = "x86")]
        {
            konteks.Eip = va_bp as u32;
        }
        konteks.EFlags |= 0x100;
        if self.set_konteks_thread(id_thread, &konteks).is_err() {
            return false;
        }
        self.va_bp_sedang_ditangani = Some(va_bp);
        true
    }
    unsafe fn handle_bp_post_step_internal(&mut self, va_bp: u64) -> bool {
        if self.write_memori(va_bp, &[0xCC]).is_err() {
            return false;
        }
        self.va_bp_sedang_ditangani = None;
        true
    }
    unsafe fn set_bp_hw_internal(&self, va_target: u64, idx_slot: usize) -> Result<(), ReToolsError> {
        if idx_slot > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut konteks =
            self.get_konteks_thread(self.id_thread_terakhir, CONTEXT_DEBUG_REGISTERS)?;
        match idx_slot {
            0 => konteks.Dr0 = va_target,
            1 => konteks.Dr1 = va_target,
            2 => konteks.Dr2 = va_target,
            3 => konteks.Dr3 = va_target,
            _ => unreachable!(),
        }
        let mask_enable = 1 << (idx_slot * 2);
        let mask_kondisi = 0b00 << (16 + idx_slot * 4);
        let mask_len = 0b00 << (18 + idx_slot * 4);
        konteks.Dr7 |= mask_enable | mask_kondisi | mask_len;
        self.set_konteks_thread(self.id_thread_terakhir, &konteks)?;
        Ok(())
    }
    unsafe fn remove_bp_hw_internal(&self, idx_slot: usize) -> Result<(), ReToolsError> {
        if idx_slot > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut konteks =
            self.get_konteks_thread(self.id_thread_terakhir, CONTEXT_DEBUG_REGISTERS)?;
        match idx_slot {
            0 => konteks.Dr0 = 0,
            1 => konteks.Dr1 = 0,
            2 => konteks.Dr2 = 0,
            3 => konteks.Dr3 = 0,
            _ => unreachable!(),
        }
        let mask_disable = !(1 << (idx_slot * 2));
        konteks.Dr7 &= mask_disable;
        self.set_konteks_thread(self.id_thread_terakhir, &konteks)?;
        Ok(())
    }
    fn proses_event_debug(&mut self, event_debug: DEBUG_EVENT, ptr_event_out: *mut C_DebugEvent) -> Result<bool, ReToolsError> {
        unsafe {
            self.id_thread_terakhir = event_debug.dwThreadId;
            let mut status_lanjut = DBG_CONTINUE;
            match event_debug.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    let rekaman_eksepsi = &event_debug.u.Exception.ExceptionRecord;
                    let va_eksepsi = rekaman_eksepsi.ExceptionAddress as u64;
                    if rekaman_eksepsi.ExceptionCode == EXCEPTION_BREAKPOINT {
                        if self.map_titik_henti.contains_key(&va_eksepsi) {
                            if self.handle_bp_pre_step_internal(
                                &event_debug,
                                va_eksepsi,
                            ) {
                                status_lanjut = DBG_CONTINUE;
                            } else {
                                set_err_last(ReToolsError::Generic(
                                    "Gagal pre-step breakpoint".to_string(),
                                ));
                                status_lanjut = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        } else {
                            status_lanjut = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    } else if rekaman_eksepsi.ExceptionCode == EXCEPTION_SINGLE_STEP {
                        if let Some(va_bp_ditangani) = self.va_bp_sedang_ditangani {
                            self.handle_bp_post_step_internal(va_bp_ditangani);
                            (*ptr_event_out).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                            (*ptr_event_out).pid_thread = event_debug.dwThreadId as c_int;
                            (*ptr_event_out).info_alamat = va_bp_ditangani;
                            return Ok(true);
                        } else {
                            (*ptr_event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                            (*ptr_event_out).pid_thread = event_debug.dwThreadId as c_int;
                            (*ptr_event_out).info_alamat = va_eksepsi;
                            return Ok(true);
                        }
                    } else {
                        (*ptr_event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                        (*ptr_event_out).pid_thread = event_debug.dwThreadId as c_int;
                        (*ptr_event_out).info_alamat = va_eksepsi;
                        status_lanjut = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    (*ptr_event_out).tipe = DebugEventTipe::EVENT_THREAD_BARU;
                    (*ptr_event_out).pid_thread = event_debug.dwThreadId as c_int;
                    (*ptr_event_out).info_alamat = event_debug
                        .u
                        .CreateThread
                        .lpStartAddress
                        .map_or(0, |ptr| ptr as usize)
                        as u64;
                    return Ok(true);
                }
                EXIT_THREAD_DEBUG_EVENT => {
                    (*ptr_event_out).tipe = DebugEventTipe::EVENT_THREAD_EXIT;
                    (*ptr_event_out).pid_thread = event_debug.dwThreadId as c_int;
                    (*ptr_event_out).info_alamat = event_debug.u.ExitThread.dwExitCode as u64;
                    return Ok(true);
                }
                LOAD_DLL_DEBUG_EVENT => {
                    (*ptr_event_out).tipe = DebugEventTipe::EVENT_MODUL_LOAD;
                    (*ptr_event_out).pid_thread = event_debug.dwThreadId as c_int;
                    (*ptr_event_out).info_alamat = event_debug.u.LoadDll.lpBaseOfDll as u64;
                    return Ok(true);
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    (*ptr_event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                    (*ptr_event_out).pid_thread = event_debug.dwThreadId as c_int;
                    (*ptr_event_out).info_alamat = event_debug.u.ExitProcess.dwExitCode as u64;
                    self.ptr_handle_proses = 0;
                    return Ok(true);
                }
                _ => {}
            }
            if ContinueDebugEvent(
                event_debug.dwProcessId,
                event_debug.dwThreadId,
                status_lanjut,
            ) == 0 {
                return Err(ReToolsError::Generic("Failed to continue debug event (Process dead?)".to_string()));
            }
            Ok(false)
        }
    }
}

impl PlatformTracer for WindowsTracer {
    fn attach_sasaran(&mut self) -> Result<(), ReToolsError> {
        unsafe {
            WindowsTracer::enable_debug_privilege();
            let ptr_h_proses = OpenProcess(PROCESS_ALL_ACCESS, FALSE, self.pid_sasaran);
            if ptr_h_proses == 0 {
                return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
            }
            self.ptr_handle_proses = ptr_h_proses;
            if DebugActiveProcess(self.pid_sasaran) == 0 {
                CloseHandle(ptr_h_proses);
                return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
            }
            let mut event_debug: DEBUG_EVENT = std::mem::zeroed();
            if WaitForDebugEvent(&mut event_debug, 5000) == 0 {
                DebugActiveProcessStop(self.pid_sasaran);
                CloseHandle(ptr_h_proses);
                return Err(ReToolsError::Generic(
                    "Timeout menunggu event attach".to_string(),
                ));
            }
            self.id_thread_terakhir = event_debug.dwThreadId;
            ContinueDebugEvent(
                event_debug.dwProcessId,
                event_debug.dwThreadId,
                DBG_CONTINUE,
            );
            Ok(())
        }
    }
    fn detach_sasaran(&mut self) -> Result<(), ReToolsError> {
        unsafe {
            for (va, byte_asli) in &self.map_titik_henti {
                self.write_memori(*va, &[*byte_asli]).ok();
            }
            self.map_titik_henti.clear();
            if self.ptr_handle_proses != 0 {
                if DebugActiveProcessStop(self.pid_sasaran) == 0 {
                    let err = std::io::Error::last_os_error();
                     if err.raw_os_error() != Some(87) { 
                         return Err(ReToolsError::IoError(err));
                     }
                }
                CloseHandle(self.ptr_handle_proses);
                self.ptr_handle_proses = 0;
            }
            Ok(())
        }
    }
    fn read_memori(&self, va_alamat: u64, sz_ukuran: c_int) -> Result<Vec<u8>, ReToolsError> {
        unsafe {
            if let Err(e) = self.check_memory_permission(va_alamat, sz_ukuran as usize, false) {
                return Err(e);
            }
        }
        let mut vec_buffer = vec![0u8; sz_ukuran as usize];
        let mut sz_terbaca: usize = 0;
        unsafe {
            if ReadProcessMemory(
                self.ptr_handle_proses,
                va_alamat as *const c_void,
                vec_buffer.as_mut_ptr() as *mut c_void,
                sz_ukuran as usize,
                &mut sz_terbaca,
            ) != 0
            {
                vec_buffer.truncate(sz_terbaca);
                Ok(vec_buffer)
            } else {
                Err(ReToolsError::IoError(std::io::Error::last_os_error()))
            }
        }
    }
    fn write_memori(&self, va_alamat: u64, buf_data: &[u8]) -> Result<usize, ReToolsError> {
        unsafe {
            if let Err(e) = self.check_memory_permission(va_alamat, buf_data.len(), true) {
                return Err(e);
            }
        }
        let mut sz_tertulis: usize = 0;
        unsafe {
            if WriteProcessMemory(
                self.ptr_handle_proses,
                va_alamat as *mut c_void,
                buf_data.as_ptr() as *const c_void,
                buf_data.len(),
                &mut sz_tertulis,
            ) != 0
            {
                Ok(sz_tertulis)
            } else {
                Err(ReToolsError::IoError(std::io::Error::last_os_error()))
            }
        }
    }
    fn get_register(&self) -> Result<C_Registers, ReToolsError> {
        unsafe {
            if self.id_thread_terakhir == 0 {
                return Err(ReToolsError::Generic(
                    "id_thread_terakhir adalah 0".to_string(),
                ));
            }
            let konteks = self.get_konteks_thread(self.id_thread_terakhir, CONTEXT_FULL)?;
            #[cfg(target_arch = "x86_64")]
            {
                Ok(C_Registers {
                    rax: konteks.Rax,
                    rbx: konteks.Rbx,
                    rcx: konteks.Rcx,
                    rdx: konteks.Rdx,
                    rsi: konteks.Rsi,
                    rdi: konteks.Rdi,
                    rbp: konteks.Rbp,
                    rsp: konteks.Rsp,
                    r8: konteks.R8,
                    r9: konteks.R9,
                    r10: konteks.R10,
                    r11: konteks.R11,
                    r12: konteks.R12,
                    r13: konteks.R13,
                    r14: konteks.R14,
                    r15: konteks.R15,
                    rip: konteks.Rip,
                    eflags: konteks.EFlags as u64,
                })
            }
            #[cfg(target_arch = "x86")]
            {
                Ok(C_Registers {
                    rax: konteks.Eax as u64,
                    rbx: konteks.Ebx as u64,
                    rcx: konteks.Ecx as u64,
                    rdx: konteks.Edx as u64,
                    rsi: konteks.Esi as u64,
                    rdi: konteks.Edi as u64,
                    rbp: konteks.Ebp as u64,
                    rsp: konteks.Esp as u64,
                    r8: 0,
                    r9: 0,
                    r10: 0,
                    r11: 0,
                    r12: 0,
                    r13: 0,
                    r14: 0,
                    r15: 0,
                    rip: konteks.Eip as u64,
                    eflags: konteks.EFlags as u64,
                })
            }
        }
    }
    fn set_register(&self, reg_nilai: &C_Registers) -> Result<(), ReToolsError> {
        unsafe {
            if self.id_thread_terakhir == 0 {
                return Err(ReToolsError::Generic(
                    "id_thread_terakhir adalah 0".to_string(),
                ));
            }
            let mut konteks = self.get_konteks_thread(self.id_thread_terakhir, CONTEXT_FULL)?;
            #[cfg(target_arch = "x86_64")]
            {
                konteks.Rax = reg_nilai.rax;
                konteks.Rbx = reg_nilai.rbx;
                konteks.Rcx = reg_nilai.rcx;
                konteks.Rdx = reg_nilai.rdx;
                konteks.Rsi = reg_nilai.rsi;
                konteks.Rdi = reg_nilai.rdi;
                konteks.Rbp = reg_nilai.rbp;
                konteks.Rsp = reg_nilai.rsp;
                konteks.R8 = reg_nilai.r8;
                konteks.R9 = reg_nilai.r9;
                konteks.R10 = reg_nilai.r10;
                konteks.R11 = reg_nilai.r11;
                konteks.R12 = reg_nilai.r12;
                konteks.R13 = reg_nilai.r13;
                konteks.R14 = reg_nilai.r14;
                konteks.R15 = reg_nilai.r15;
                konteks.Rip = reg_nilai.rip;
                konteks.EFlags = reg_nilai.eflags as u32;
            }
            #[cfg(target_arch = "x86")]
            {
                konteks.Eax = reg_nilai.rax as u32;
                konteks.Ebx = reg_nilai.rbx as u32;
                konteks.Ecx = reg_nilai.rcx as u32;
                konteks.Edx = reg_nilai.rdx as u32;
                konteks.Esi = reg_nilai.rsi as u32;
                konteks.Edi = reg_nilai.rdi as u32;
                konteks.Ebp = reg_nilai.rbp as u32;
                konteks.Esp = reg_nilai.rsp as u32;
                konteks.Eip = reg_nilai.rip as u32;
                konteks.EFlags = reg_nilai.eflags as u32;
            }
            self.set_konteks_thread(self.id_thread_terakhir, &konteks)
        }
    }
    fn continue_proses(&self) -> Result<(), ReToolsError> {
        unsafe {
            if self.id_thread_terakhir == 0 {
                return Err(ReToolsError::Generic(
                    "id_thread_terakhir adalah 0".to_string(),
                ));
            }
            if ContinueDebugEvent(
                self.pid_sasaran,
                self.id_thread_terakhir,
                DBG_CONTINUE,
            ) == 0
            {
                Err(ReToolsError::IoError(std::io::Error::last_os_error()))
            } else {
                Ok(())
            }
        }
    }
    fn step_instruksi(&mut self) -> Result<(), ReToolsError> {
        unsafe {
            if self.id_thread_terakhir == 0 {
                return Err(ReToolsError::Generic(
                    "id_thread_terakhir adalah 0".to_string(),
                ));
            }
            let mut konteks = self.get_konteks_thread(self.id_thread_terakhir, CONTEXT_FULL)?;
            konteks.EFlags |= 0x100;
            self.set_konteks_thread(self.id_thread_terakhir, &konteks)?;
            self.continue_proses()
        }
    }
    fn wait_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError> {
        unsafe {
            let mut event_debug: DEBUG_EVENT = std::mem::zeroed();
            loop {
                if WaitForDebugEvent(&mut event_debug, u32::MAX) == 0 {
                    return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
                }
                if self.proses_event_debug(event_debug, ptr_event_out)? {
                    return Ok(0);
                }
            }
        }
    }
    fn poll_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<bool, ReToolsError> {
        unsafe {
            let mut event_debug: DEBUG_EVENT = std::mem::zeroed();
            if WaitForDebugEvent(&mut event_debug, 0) == 0 {
                 return Ok(false);
            }
            self.proses_event_debug(event_debug, ptr_event_out)
        }
    }
    fn set_titik_henti_sw(&mut self, va_alamat: u64) -> Result<(), ReToolsError> {
        if self.map_titik_henti.contains_key(&va_alamat) {
            return Ok(());
        }
        let vec_byte_asli = self.read_memori(va_alamat, 1)?;
        if vec_byte_asli.is_empty() {
            return Err(ReToolsError::Generic(format!(
                "Gagal membaca byte asli di 0x{:x}",
                va_alamat
            )));
        }
        let byte_asli = vec_byte_asli[0];
        self.write_memori(va_alamat, &[0xCC])?;
        self.map_titik_henti.insert(va_alamat, byte_asli);
        Ok(())
    }
    fn remove_titik_henti_sw(&mut self, va_alamat: u64) -> Result<(), ReToolsError> {
        if let Some(byte_asli) = self.map_titik_henti.remove(&va_alamat) {
            self.write_memori(va_alamat, &[byte_asli])?;
        }
        Ok(())
    }
    fn set_titik_henti_hw(&mut self, va_alamat: u64, idx_slot: usize) -> Result<(), ReToolsError> {
        unsafe { self.set_bp_hw_internal(va_alamat, idx_slot) }
    }
    fn remove_titik_henti_hw(&mut self, idx_slot: usize) -> Result<(), ReToolsError> {
        unsafe { self.remove_bp_hw_internal(idx_slot) }
    }
    fn list_thread(&self) -> Result<Vec<c_int>, ReToolsError> {
        let mut vec_thread = Vec::new();
        unsafe {
            let ptr_h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if ptr_h_snapshot == 0 {
                return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
            }
            let mut te32: THREADENTRY32 = std::mem::zeroed();
            te32.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if Thread32First(ptr_h_snapshot, &mut te32) == 0 {
                CloseHandle(ptr_h_snapshot);
                return Err(ReToolsError::IoError(std::io::Error::last_os_error()));
            }
            loop {
                if te32.th32OwnerProcessID == self.pid_sasaran {
                    vec_thread.push(te32.th32ThreadID as c_int);
                }
                if Thread32Next(ptr_h_snapshot, &mut te32) == 0 {
                    break;
                }
            }
            CloseHandle(ptr_h_snapshot);
        }
        Ok(vec_thread)
    }
    fn get_region_memori(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError> {
        let mut vec_region = Vec::new();
        let mut ptr_va_saat_ini: usize = 0;
        unsafe {
            loop {
                let mut info_mem: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                let sz_hasil = VirtualQueryEx(
                    self.ptr_handle_proses,
                    ptr_va_saat_ini as *const c_void,
                    &mut info_mem,
                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                );
                if sz_hasil == 0 {
                    break;
                }
                let mut flag_proteksi = 0;
                if (info_mem.Protect & 0x02) != 0 {
                    flag_proteksi |= 1;
                } 
                if (info_mem.Protect & 0x04) != 0 {
                    flag_proteksi |= 3;
                } 
                if (info_mem.Protect & 0x08) != 0 {
                    flag_proteksi |= 3;
                } 
                if (info_mem.Protect & 0x10) != 0 {
                    flag_proteksi |= 5;
                } 
                if (info_mem.Protect & 0x20) != 0 {
                    flag_proteksi |= 5;
                } 
                if (info_mem.Protect & 0x40) != 0 {
                    flag_proteksi |= 7;
                } 
                if (info_mem.Protect & 0x80) != 0 {
                    flag_proteksi |= 7;
                } 
                let mut arr_path = [0 as c_char; 260];
                let mut buf_path: [u8; 260] = [0; 260];
                if GetModuleFileNameExA(
                    self.ptr_handle_proses,
                    info_mem.AllocationBase as _,
                    buf_path.as_mut_ptr(),
                    260,
                ) > 0
                {
                    let len_str = buf_path.iter().position(|&r| r == 0).unwrap_or(259);
                    for i in 0..len_str {
                        arr_path[i] = buf_path[i] as c_char;
                    }
                }
                vec_region.push(C_MemoryRegionInfo {
                    alamat_basis: info_mem.BaseAddress as u64,
                    ukuran: info_mem.RegionSize as u64,
                    proteksi: flag_proteksi,
                    path_modul: arr_path,
                });
                ptr_va_saat_ini = (info_mem.BaseAddress as usize) + info_mem.RegionSize;
            }
        }
        Ok(vec_region)
    }
    fn set_trace_syscall(&mut self, _status_aktif: bool) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic(
            "set_trace_syscall tidak didukung di Windows".to_string(),
        ))
    }
    fn get_info_syscall(&self, _id_thread: c_int) -> Result<C_SyscallInfo, ReToolsError> {
        Err(ReToolsError::Generic(
            "get_info_syscall tidak didukung di Windows".to_string(),
        ))
    }
    fn set_opsi_multithread(&mut self) -> Result<(), ReToolsError> {
        Ok(())
    }
    fn hook_api_memori(
        &mut self,
        _nama_api: &str,
        _va_entry: u64,
        _va_exit: u64,
    ) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic("Fungsi tidak diimplementasi".to_string()))
    }
    fn remove_hook_api_memori(&mut self, _nama_api: &str) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic("Fungsi tidak diimplementasi".to_string()))
    }
    fn dump_region_memori(&self, _va_alamat: u64, _sz_ukuran: usize, _jalur_berkas: &str) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic("Fungsi tidak diimplementasi".to_string()))
    }
    fn hide_status_debugger(&mut self) -> Result<(), ReToolsError> {
        self.mode_senyap = true;
        Ok(())
    }
}

impl Drop for WindowsTracer {
    fn drop(&mut self) {
        if self.ptr_handle_proses != 0 {
            self.detach_sasaran().ok();
        }
    }
}