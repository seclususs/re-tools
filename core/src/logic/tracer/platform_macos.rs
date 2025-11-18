//! Author: [Seclususs](https://github.com/seclususs)

use super::platform::PlatformTracer;
use super::types::{u64, u8, C_DebugEvent, C_MemoryRegionInfo, C_Registers, C_SyscallInfo, DebugEventTipe};
use crate::error::{set_err_last, ReToolsError};
use libc::c_int;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::unistd::Pid;
use std::collections::HashMap;

pub struct MacosTracer {
    pid_sasaran: Pid,
    map_titik_henti: HashMap<u64, u8>,
}

impl MacosTracer {
    pub fn new(pid: c_int) -> Result<Self, ReToolsError> {
        Ok(MacosTracer {
            pid_sasaran: Pid::from_raw(pid),
            map_titik_henti: HashMap::new(),
        })
    }
    unsafe fn handle_logika_bp(&mut self, pid: Pid, va_bp: u64) -> bool {
        let Some(&byte_asli) = self.map_titik_henti.get(&va_bp) else {
            return false;
        };
        if self.write_memori(va_bp, &[byte_asli]).is_err() {
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        match ptrace::getregs(pid) {
            Ok(mut reg_any) => {
                if let Some(reg) = reg_any.as_x86_64_mut() {
                    reg.rip = va_bp;
                    if ptrace::setregs(pid, reg_any).is_err() {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            Err(_) => {
                return false;
            }
        };
        if self.step_instruksi().is_err() {
            self.write_memori(va_bp, &[0xCC]).ok();
            return false;
        }
        if self.write_memori(va_bp, &[0xCC]).is_err() {
            return false;
        }
        true
    }
    #[cfg(target_arch = "x86_64")]
    fn set_bp_hw_internal(&self, va_target: u64, idx_slot: usize) -> Result<(), ReToolsError> {
        if idx_slot > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut state_debug: ptrace::DebugState = std::mem::zeroed();
        ptrace::getdbregs(self.pid_sasaran, &mut state_debug)?;
        state_debug.db_dr[idx_slot] = va_target;
        let mask_enable = 1 << (idx_slot * 2);
        let mask_kondisi = 0b00 << (16 + idx_slot * 4);
        let mask_len = 0b00 << (18 + idx_slot * 4);
        state_debug.db_dr[7] |= (mask_enable | mask_kondisi | mask_len) as u64;
        ptrace::setdbregs(self.pid_sasaran, &state_debug)?;
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    fn remove_bp_hw_internal(&self, idx_slot: usize) -> Result<(), ReToolsError> {
        if idx_slot > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut state_debug: ptrace::DebugState = std::mem::zeroed();
        ptrace::getdbregs(self.pid_sasaran, &mut state_debug)?;
        state_debug.db_dr[idx_slot] = 0;
        let mask_disable = !(1 << (idx_slot * 2));
        state_debug.db_dr[7] &= mask_disable as u64;
        ptrace::setdbregs(self.pid_sasaran, &state_debug)?;
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn set_bp_hw_internal(&self, _va: u64, _idx: usize) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic(
            "Hardware breakpoints tidak didukung di arsitektur ini".to_string(),
        ))
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn remove_bp_hw_internal(&self, _idx: usize) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic(
            "Hardware breakpoints tidak didukung di arsitektur ini".to_string(),
        ))
    }
    fn process_status_wait(&mut self, status: WaitStatus, ptr_event: *mut C_DebugEvent) -> Result<bool, ReToolsError> {
        unsafe {
            match status {
                WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                    let mut rip: u64 = 0;
                    #[cfg(target_arch = "x86_64")]
                    {
                        let reg = match ptrace::getregs(pid) {
                            Ok(reg_any) => match reg_any.as_x86_64() {
                                Some(r) => r.clone(),
                                None => return Ok(false),
                            },
                            Err(_) => return Ok(false),
                        };
                        rip = reg.rip;
                    }
                    let va_bp_potensial = rip.saturating_sub(1);
                    if self.map_titik_henti.contains_key(&va_bp_potensial) {
                        if self.handle_logika_bp(pid, va_bp_potensial) {
                            (*ptr_event).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                            (*ptr_event).pid_thread = pid.as_raw();
                            (*ptr_event).info_alamat = va_bp_potensial;
                            return Ok(true);
                        } else {
                            set_err_last(ReToolsError::Generic(format!(
                                "Gagal menangani breakpoint logic pada 0x{:x}",
                                va_bp_potensial
                            )));
                            (*ptr_event).tipe = DebugEventTipe::EVENT_UNKNOWN;
                            (*ptr_event).info_alamat = va_bp_potensial;
                            return Ok(false);
                        }
                    } else {
                        (*ptr_event).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                        (*ptr_event).pid_thread = pid.as_raw();
                        (*ptr_event).info_alamat = rip;
                        return Ok(true);
                    }
                }
                WaitStatus::Stopped(pid, sig) => {
                    ptrace::cont(pid, None).ok();
                    return Ok(false);
                }
                WaitStatus::Exited(pid, kode_status) => {
                    (*ptr_event).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                    (*ptr_event).pid_thread = pid.as_raw();
                    (*ptr_event).info_alamat = kode_status as u64;
                    return Ok(true);
                }
                WaitStatus::Signaled(pid, sinyal, _) => {
                    (*ptr_event).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                    (*ptr_event).pid_thread = pid.as_raw();
                    (*ptr_event).info_alamat = sinyal as u64;
                    return Ok(true);
                }
                _ => {
                    return Ok(false);
                }
            }
        }
    }
}

impl PlatformTracer for MacosTracer {
    fn attach_sasaran(&mut self) -> Result<(), ReToolsError> {
        ptrace::attach(self.pid_sasaran)?;
        match waitpid(self.pid_sasaran, None) {
            Ok(WaitStatus::Stopped(_, _)) => Ok(()),
            Ok(status) => Err(ReToolsError::Generic(format!(
                "Status waitpid tidak terduga setelah attach: {:?}",
                status
            ))),
            Err(e) => Err(e.into()),
        }
    }
    fn detach_sasaran(&mut self) -> Result<(), ReToolsError> {
        for (va, byte_asli) in &self.map_titik_henti {
            self.write_memori(*va, &[*byte_asli]).ok();
        }
        self.map_titik_henti.clear();
        ptrace::detach(self.pid_sasaran, None)?;
        Ok(())
    }
    fn read_memori(&self, va_alamat: u64, sz_ukuran: c_int) -> Result<Vec<u8>, ReToolsError> {
        let mut vec_buffer = Vec::with_capacity(sz_ukuran as usize);
        for i in 0..(sz_ukuran as usize) {
            let read_addr = (va_alamat + i as u64) as ptrace::AddressType;
            match ptrace::read(self.pid_sasaran, read_addr) {
                Ok(word) => {
                    vec_buffer.push((word & 0xFF) as u8);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(vec_buffer)
    }
    fn write_memori(&self, va_alamat: u64, buf_data: &[u8]) -> Result<usize, ReToolsError> {
        for (i, &byte) in buf_data.iter().enumerate() {
            let write_addr = (va_alamat + i as u64) as ptrace::AddressType;
            let data_word = byte as ptrace::WordType;
            ptrace::write(self.pid_sasaran, write_addr, data_word)?;
        }
        Ok(buf_data.len())
    }
    fn get_register(&self) -> Result<C_Registers, ReToolsError> {
        let reg_any = ptrace::getregs(self.pid_sasaran)?;
        #[cfg(target_arch = "x86_64")]
        if let Some(reg) = reg_any.as_x86_64() {
            return Ok(C_Registers {
                rax: reg.rax,
                rbx: reg.rbx,
                rcx: reg.rcx,
                rdx: reg.rdx,
                rsi: reg.rsi,
                rdi: reg.rdi,
                rbp: reg.rbp,
                rsp: reg.rsp,
                r8: reg.r8,
                r9: reg.r9,
                r10: reg.r10,
                r11: reg.r11,
                r12: reg.r12,
                r13: reg.r13,
                r14: reg.r14,
                r15: reg.r15,
                rip: reg.rip,
                eflags: reg.rflags,
            });
        }
        Err(ReToolsError::Generic(
            "Gagal konversi register ke x86_64".to_string(),
        ))
    }
    fn set_register(&self, reg_nilai: &C_Registers) -> Result<(), ReToolsError> {
        let mut reg_any = ptrace::getregs(self.pid_sasaran)?;
        #[cfg(target_arch = "x86_64")]
        if let Some(reg) = reg_any.as_x86_64_mut() {
            reg.rax = reg_nilai.rax;
            reg.rbx = reg_nilai.rbx;
            reg.rcx = reg_nilai.rcx;
            reg.rdx = reg_nilai.rdx;
            reg.rsi = reg_nilai.rsi;
            reg.rdi = reg_nilai.rdi;
            reg.rbp = reg_nilai.rbp;
            reg.rsp = reg_nilai.rsp;
            reg.r8 = reg_nilai.r8;
            reg.r9 = reg_nilai.r9;
            reg.r10 = reg_nilai.r10;
            reg.r11 = reg_nilai.r11;
            reg.r12 = reg_nilai.r12;
            reg.r13 = reg_nilai.r13;
            reg.r14 = reg_nilai.r14;
            reg.r15 = reg_nilai.r15;
            reg.rip = reg_nilai.rip;
            reg.rflags = reg_nilai.eflags;
            ptrace::setregs(self.pid_sasaran, reg_any)?;
            return Ok(());
        }
        Err(ReToolsError::Generic(
            "Gagal konversi register (mut) ke x86_64".to_string(),
        ))
    }
    fn continue_proses(&self) -> Result<(), ReToolsError> {
        ptrace::cont(self.pid_sasaran, None)?;
        Ok(())
    }
    fn step_instruksi(&mut self) -> Result<(), ReToolsError> {
        ptrace::step(self.pid_sasaran, None)?;
        match waitpid(self.pid_sasaran, None) {
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => Ok(()),
            Ok(status) => Err(ReToolsError::Generic(format!(
                "Status waitpid tidak terduga setelah step: {:?}",
                status
            ))),
            Err(e) => Err(e.into()),
        }
    }
    fn wait_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError> {
        loop {
            let status = match waitpid(self.pid_sasaran, None) {
                Ok(s) => s,
                Err(e) => return Err(e.into()),
            };
            if self.process_status_wait(status, ptr_event_out)? {
                return Ok(0);
            }
        }
    }
    fn poll_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<bool, ReToolsError> {
        match waitpid(self.pid_sasaran, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => Ok(false),
            Ok(status) => self.process_status_wait(status, ptr_event_out),
            Err(nix::errno::Errno::ECHILD) => Ok(false),
            Err(e) => Err(e.into()),
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
        self.set_bp_hw_internal(va_alamat, idx_slot)
    }
    fn remove_titik_henti_hw(&mut self, idx_slot: usize) -> Result<(), ReToolsError> {
        self.remove_bp_hw_internal(idx_slot)
    }
    fn list_thread(&self) -> Result<Vec<c_int>, ReToolsError> {
        Err(ReToolsError::Generic("list_thread belum diimplementasikan di macOS".to_string()))
    }
    fn get_region_memori(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError> {
        Err(ReToolsError::Generic("get_region_memori belum diimplementasikan di macOS".to_string()))
    }
    fn set_trace_syscall(&mut self, _status_aktif: bool) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic("set_trace_syscall belum diimplementasikan di macOS".to_string()))
    }
    fn get_info_syscall(&self, _id_thread: c_int) -> Result<C_SyscallInfo, ReToolsError> {
        Err(ReToolsError::Generic("get_info_syscall belum diimplementasikan di macOS".to_string()))
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
        Err(ReToolsError::Generic("Fitur anti-anti-debug belum diimplementasikan di macOS".to_string()))
    }
}

impl From<nix::Error> for ReToolsError {
    fn from(err: nix::Error) -> ReToolsError {
        ReToolsError::Generic(format!("Nix error: {}", err))
    }
}