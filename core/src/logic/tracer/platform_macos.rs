use super::platform::PlatformTracer;
use super::types::{u64, u8, C_DebugEvent, C_MemoryRegionInfo, C_Registers, C_SyscallInfo, DebugEventTipe};
use crate::error::{set_last_error, ReToolsError};
use libc::c_int;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;


pub struct MacosTracer {
    pid_target: Pid,
    breakpoints_map: HashMap<u64, u8>,
}

impl MacosTracer {
    pub fn new(pid: c_int) -> Result<Self, ReToolsError> {
        Ok(MacosTracer {
            pid_target: Pid::from_raw(pid),
            breakpoints_map: HashMap::new(),
        })
    }
    unsafe fn handle_breakpoint_logic(&mut self, pid: Pid, alamat_bp: u64) -> bool {
        let Some(&byte_asli) = self.breakpoints_map.get(&alamat_bp) else {
            return false;
        };
        if self.tulis_memory(alamat_bp, &[byte_asli]).is_err() {
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        match ptrace::getregs(pid) {
            Ok(mut regs_any) => {
                if let Some(regs) = regs_any.as_x86_64_mut() {
                    regs.rip = alamat_bp;
                    if ptrace::setregs(pid, regs_any).is_err() {
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
        if self.single_step().is_err() {
            self.tulis_memory(alamat_bp, &[0xCC]).ok();
            return false;
        }
        if self.tulis_memory(alamat_bp, &[0xCC]).is_err() {
            return false;
        }
        true
    }
    #[cfg(target_arch = "x86_64")]
    fn set_hw_bp(&self, addr: u64, index: usize) -> Result<(), ReToolsError> {
        if index > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut debug_state: ptrace::DebugState = std::mem::zeroed();
        ptrace::getdbregs(self.pid_target, &mut debug_state)?;
        debug_state.db_dr[index] = addr;
        let enable_mask = 1 << (index * 2);
        let condition_mask = 0b00 << (16 + index * 4);
        let len_mask = 0b00 << (18 + index * 4);
        debug_state.db_dr[7] |= (enable_mask | condition_mask | len_mask) as u64;
        ptrace::setdbregs(self.pid_target, &debug_state)?;
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    fn remove_hw_bp(&self, index: usize) -> Result<(), ReToolsError> {
        if index > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut debug_state: ptrace::DebugState = std::mem::zeroed();
        ptrace::getdbregs(self.pid_target, &mut debug_state)?;
        debug_state.db_dr[index] = 0;
        let disable_mask = !(1 << (index * 2));
        debug_state.db_dr[7] &= disable_mask as u64;
        ptrace::setdbregs(self.pid_target, &debug_state)?;
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn set_hw_bp(&self, _addr: u64, _index: usize) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic(
            "Hardware breakpoints tidak didukung di arsitektur ini".to_string(),
        ))
    }
    #[cfg(not(target_arch = "x86_64"))]
    fn remove_hw_bp(&self, _index: usize) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic(
            "Hardware breakpoints tidak didukung di arsitektur ini".to_string(),
        ))
    }
}

impl PlatformTracer for MacosTracer {
    fn attach(&mut self) -> Result<(), ReToolsError> {
        ptrace::attach(self.pid_target)?;
        match waitpid(self.pid_target, None) {
            Ok(WaitStatus::Stopped(_, _)) => Ok(()),
            Ok(status) => Err(ReToolsError::Generic(format!(
                "Status waitpid tidak terduga setelah attach: {:?}",
                status
            ))),
            Err(e) => Err(e.into()),
        }
    }
    fn detach(&mut self) -> Result<(), ReToolsError> {
        for (addr, orig_byte) in &self.breakpoints_map {
            self.tulis_memory(*addr, &[*orig_byte]).ok();
        }
        self.breakpoints_map.clear();
        ptrace::detach(self.pid_target, None)?;
        Ok(())
    }
    fn baca_memory(&self, addr: u64, size: c_int) -> Result<Vec<u8>, ReToolsError> {
        let mut buffer = Vec::with_capacity(size as usize);
        for i in 0..(size as usize) {
            let read_addr = (addr + i as u64) as ptrace::AddressType;
            match ptrace::read(self.pid_target, read_addr) {
                Ok(word) => {
                    buffer.push((word & 0xFF) as u8);
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(buffer)
    }
    fn tulis_memory(&self, addr: u64, data: &[u8]) -> Result<usize, ReToolsError> {
        for (i, &byte) in data.iter().enumerate() {
            let write_addr = (addr + i as u64) as ptrace::AddressType;
            let data_word = byte as ptrace::WordType;
            ptrace::write(self.pid_target, write_addr, data_word)?;
        }
        Ok(data.len())
    }
    fn get_registers(&self) -> Result<C_Registers, ReToolsError> {
        let regs_any = ptrace::getregs(self.pid_target)?;
        #[cfg(target_arch = "x86_64")]
        if let Some(regs) = regs_any.as_x86_64() {
            return Ok(C_Registers {
                rax: regs.rax,
                rbx: regs.rbx,
                rcx: regs.rcx,
                rdx: regs.rdx,
                rsi: regs.rsi,
                rdi: regs.rdi,
                rbp: regs.rbp,
                rsp: regs.rsp,
                r8: regs.r8,
                r9: regs.r9,
                r10: regs.r10,
                r11: regs.r11,
                r12: regs.r12,
                r13: regs.r13,
                r14: regs.r14,
                r15: regs.r15,
                rip: regs.rip,
                eflags: regs.rflags,
            });
        }
        Err(ReToolsError::Generic(
            "Gagal konversi register ke x86_64".to_string(),
        ))
    }
    fn set_registers(&self, c_regs: &C_Registers) -> Result<(), ReToolsError> {
        let mut regs_any = ptrace::getregs(self.pid_target)?;
        #[cfg(target_arch = "x86_64")]
        if let Some(regs) = regs_any.as_x86_64_mut() {
            regs.rax = c_regs.rax;
            regs.rbx = c_regs.rbx;
            regs.rcx = c_regs.rcx;
            regs.rdx = c_regs.rdx;
            regs.rsi = c_regs.rsi;
            regs.rdi = c_regs.rdi;
            regs.rbp = c_regs.rbp;
            regs.rsp = c_regs.rsp;
            regs.r8 = c_regs.r8;
            regs.r9 = c_regs.r9;
            regs.r10 = c_regs.r10;
            regs.r11 = c_regs.r11;
            regs.r12 = c_regs.r12;
            regs.r13 = c_regs.r13;
            regs.r14 = c_regs.r14;
            regs.r15 = c_regs.r15;
            regs.rip = c_regs.rip;
            regs.rflags = c_regs.eflags;
            ptrace::setregs(self.pid_target, regs_any)?;
            return Ok(());
        }
        Err(ReToolsError::Generic(
            "Gagal konversi register (mut) ke x86_64".to_string(),
        ))
    }
    fn continue_proses(&self) -> Result<(), ReToolsError> {
        ptrace::cont(self.pid_target, None)?;
        Ok(())
    }
    fn single_step(&mut self) -> Result<(), ReToolsError> {
        ptrace::step(self.pid_target, None)?;
        match waitpid(self.pid_target, None) {
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => Ok(()),
            Ok(status) => Err(ReToolsError::Generic(format!(
                "Status waitpid tidak terduga setelah step: {:?}",
                status
            ))),
            Err(e) => Err(e.into()),
        }
    }
    fn tunggu_event(&mut self, event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError> {
        unsafe {
            loop {
                match waitpid(self.pid_target, None) {
                    Ok(status) => {
                        match status {
                            WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                                let mut rip: u64 = 0;
                                #[cfg(target_arch = "x86_64")]
                                {
                                    let regs = match ptrace::getregs(pid) {
                                        Ok(regs_any) => match regs_any.as_x86_64() {
                                            Some(r) => r.clone(),
                                            None => continue,
                                        },
                                        Err(_) => continue,
                                    };
                                    rip = regs.rip;
                                }
                                let alamat_breakpoint_potensial = rip.saturating_sub(1);
                                if self
                                    .breakpoints_map
                                    .contains_key(&alamat_breakpoint_potensial)
                                {
                                    if self.handle_breakpoint_logic(
                                        pid,
                                        alamat_breakpoint_potensial,
                                    ) {
                                        (*event_out).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                                        (*event_out).pid_thread = pid.as_raw();
                                        (*event_out).info_alamat = alamat_breakpoint_potensial;
                                        return Ok(0);
                                    } else {
                                        set_last_error(ReToolsError::Generic(format!(
                                            "Gagal menangani breakpoint logic pada 0x{:x}",
                                            alamat_breakpoint_potensial
                                        )));
                                        (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                                        (*event_out).info_alamat = alamat_breakpoint_potensial;
                                        return Ok(-1);
                                    }
                                } else {
                                    (*event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                                    (*event_out).pid_thread = pid.as_raw();
                                    (*event_out).info_alamat = rip;
                                    return Ok(0);
                                }
                            }
                            WaitStatus::Stopped(pid, sig) => {
                                ptrace::cont(pid, None).ok();
                                continue;
                            }
                            WaitStatus::Exited(pid, status_code) => {
                                (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                                (*event_out).pid_thread = pid.as_raw();
                                (*event_out).info_alamat = status_code as u64;
                                return Ok(0);
                            }
                            WaitStatus::Signaled(pid, signal, _) => {
                                (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                                (*event_out).pid_thread = pid.as_raw();
                                (*event_out).info_alamat = signal as u64;
                                return Ok(0);
                            }
                            _ => {
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
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
        self.set_hw_bp(addr, index)
    }
    fn remove_hardware_breakpoint(&mut self, index: usize) -> Result<(), ReToolsError> {
        self.remove_hw_bp(index)
    }
    fn list_semua_threads(&self) -> Result<Vec<c_int>, ReToolsError> {
        Err(ReToolsError::Generic("list_semua_threads belum diimplementasikan di macOS".to_string()))
    }
    fn get_memory_regions(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError> {
        Err(ReToolsError::Generic("get_memory_regions belum diimplementasikan di macOS".to_string()))
    }
    fn set_pelacakan_syscall(&mut self, _enable: bool) -> Result<(), ReToolsError> {
        Err(ReToolsError::Generic("set_pelacakan_syscall belum diimplementasikan di macOS".to_string()))
    }
    fn get_info_syscall(&self, _pid_thread: c_int) -> Result<C_SyscallInfo, ReToolsError> {
        Err(ReToolsError::Generic("get_info_syscall belum diimplementasikan di macOS".to_string()))
    }
    fn set_options_multithread(&mut self) -> Result<(), ReToolsError> {
        Ok(())
    }
}

impl From<nix::Error> for ReToolsError {
    fn from(err: nix::Error) -> ReToolsError {
        ReToolsError::Generic(format!("Nix error: {}", err))
    }
}