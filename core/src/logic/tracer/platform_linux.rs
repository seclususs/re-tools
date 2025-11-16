use super::platform::PlatformTracer;
use super::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use crate::error::{ReToolsError, set_last_error};
use libc::c_int;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_readv, process_vm_writev, IoVec, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::IoSliceMut;


pub struct LinuxTracer {
    pid_target: Pid,
    breakpoints_map: HashMap<u64, u8>,
}

impl LinuxTracer {
    pub fn new(pid: c_int) -> Result<Self, ReToolsError> {
        Ok(LinuxTracer {
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
        let mut regs = match ptrace::getregs(pid) {
            Ok(r) => r,
            Err(_) => return false,
        };
        regs.rip = alamat_bp;
        if ptrace::setregs(pid, regs).is_err() {
            return false;
        }
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
        let mut regs = ptrace::getregs(self.pid_target)?;
        let dr7_val = regs.dr7;
        let local_enable_mask = 1 << (index * 2);
        let condition_mask = 0b00 << (16 + index * 4);
        let len_mask = 0b00 << (18 + index * 4);
        let new_dr7 = (dr7_val | local_enable_mask | condition_mask | len_mask) & !0x200;
        match index {
            0 => regs.dr0 = addr,
            1 => regs.dr1 = addr,
            2 => regs.dr2 = addr,
            3 => regs.dr3 = addr,
            _ => unreachable!(),
        }
        regs.dr7 = new_dr7;
        ptrace::setregs(self.pid_target, regs)?;
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    fn remove_hw_bp(&self, index: usize) -> Result<(), ReToolsError> {
        if index > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut regs = ptrace::getregs(self.pid_target)?;
        let local_disable_mask = !(1 << (index * 2));
        regs.dr7 &= local_disable_mask;
        match index {
            0 => regs.dr0 = 0,
            1 => regs.dr1 = 0,
            2 => regs.dr2 = 0,
            3 => regs.dr3 = 0,
            _ => unreachable!(),
        }
        ptrace::setregs(self.pid_target, regs)?;
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

impl PlatformTracer for LinuxTracer {
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
        let mut buffer = vec![0u8; size as usize];
        let mut local_iov = [IoSliceMut::new(&mut buffer)];
        let remote_iov = [RemoteIoVec {
            base: addr as usize,
            len: size as usize,
        }];
        let bytes_read = process_vm_readv(self.pid_target, &mut local_iov, &remote_iov)?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }
    fn tulis_memory(&self, addr: u64, data: &[u8]) -> Result<usize, ReToolsError> {
        let local_iov = [std::io::IoSlice::new(data)];
        let remote_iov = [RemoteIoVec {
            base: addr as usize,
            len: data.len(),
        }];
        let bytes_written = process_vm_writev(self.pid_target, &local_iov, &remote_iov)?;
        Ok(bytes_written)
    }
    fn get_registers(&self) -> Result<C_Registers, ReToolsError> {
        let regs = ptrace::getregs(self.pid_target)?;
        Ok(C_Registers {
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
            eflags: regs.eflags,
        })
    }
    fn set_registers(&self, c_regs: &C_Registers) -> Result<(), ReToolsError> {
        let mut regs = ptrace::getregs(self.pid_target)?;
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
        regs.eflags = c_regs.eflags;
        ptrace::setregs(self.pid_target, regs)?;
        Ok(())
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
                                let regs = ptrace::getregs(pid)?;
                                let alamat_breakpoint_potensial = regs.rip.saturating_sub(1);
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
                                        set_last_error(ReToolsError::Generic(format!("Gagal menangani breakpoint logic pada 0x{:x}", alamat_breakpoint_potensial)));
                                        (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                                        (*event_out).info_alamat = alamat_breakpoint_potensial;
                                        return Ok(-1);
                                    }
                                } else {
                                    (*event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                                    (*event_out).pid_thread = pid.as_raw();
                                    (*event_out).info_alamat = regs.rip;
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
}

impl From<nix::Error> for ReToolsError {
    fn from(err: nix::Error) -> ReToolsError {
        ReToolsError::Generic(format!("Nix error: {}", err))
    }
}