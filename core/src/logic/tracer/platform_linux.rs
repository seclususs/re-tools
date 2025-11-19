//! Author: [Seclususs](https://github.com/seclususs)

use super::platform::PlatformTracer;
use super::types::{u64, u8, C_DebugEvent, C_MemoryRegionInfo, C_Registers, C_SyscallInfo, DebugEventTipe};
use crate::error::{set_err_last, ReToolsError};
use libc::{c_char, c_int};
use nix::sys::ptrace;
use nix::sys::ptrace::Options;
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_readv, process_vm_writev, IoVec, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::IoSliceMut;

pub struct LinuxTracer {
    pid_sasaran: Pid,
    map_titik_henti: HashMap<u64, u8>,
    trace_syscall_aktif: bool,
    mode_senyap: bool,
}

impl LinuxTracer {
    pub fn new(pid: c_int) -> Result<Self, ReToolsError> {
        Ok(LinuxTracer {
            pid_sasaran: Pid::from_raw(pid),
            map_titik_henti: HashMap::new(),
            trace_syscall_aktif: false,
            mode_senyap: false,
        })
    }
    fn validate_mem_access(&self, addr: u64, len: usize, check_write: bool) -> Result<(), ReToolsError> {
        let maps_path = format!("/proc/{}/maps", self.pid_sasaran.as_raw());
        let content = match std::fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => return Err(ReToolsError::Generic("Target process not found or inaccessible".to_string())),
        };
        let end_addr = addr.saturating_add(len as u64);
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 { continue; }
            let range: Vec<&str> = parts[0].split('-').collect();
            if range.len() != 2 { continue; }
            let r_start = u64::from_str_radix(range[0], 16).unwrap_or(u64::MAX);
            let r_end = u64::from_str_radix(range[1], 16).unwrap_or(0);
            if addr >= r_start && end_addr <= r_end {
                let perms = parts[1];
                if check_write {
                    if perms.contains('w') { return Ok(()); }
                } else {
                    if perms.contains('r') { return Ok(()); }
                }
                return Err(ReToolsError::Generic(format!("Page permission denied for range 0x{:x}-0x{:x}", addr, end_addr)));
            }
        }
        Err(ReToolsError::Generic(format!("Memory address 0x{:x} not found in process maps", addr)))
    }
    unsafe fn handle_logika_bp(&mut self, pid: Pid, va_bp: u64) -> bool {
        let Some(&byte_asli) = self.map_titik_henti.get(&va_bp) else {
            return false;
        };
        if self.write_memori(va_bp, &[byte_asli]).is_err() {
            return false;
        }
        let mut reg_konteks = match ptrace::getregs(pid) {
            Ok(r) => r,
            Err(_) => return false,
        };
        reg_konteks.rip = va_bp;
        if ptrace::setregs(pid, reg_konteks).is_err() {
            return false;
        }
        if self.step_internal(pid).is_err() {
            self.write_memori(va_bp, &[0xCC]).ok();
            return false;
        }
        if self.write_memori(va_bp, &[0xCC]).is_err() {
            return false;
        }
        true
    }
    fn step_internal(&mut self, pid: Pid) -> Result<(), ReToolsError> {
         match ptrace::step(pid, None) {
             Ok(_) => {},
             Err(nix::Error::ESRCH) => return Err(ReToolsError::Generic("Process died during step".to_string())),
             Err(e) => return Err(e.into()),
         }
        match waitpid(pid, None) {
            Ok(WaitStatus::Stopped(_, Signal::SIGTRAP)) => Ok(()),
            Ok(status) => Err(ReToolsError::Generic(format!(
                "Status waitpid tidak terduga setelah step: {:?}",
                status
            ))),
            Err(nix::Error::ECHILD) | Err(nix::Error::ESRCH) => Err(ReToolsError::Generic("Target lost during wait".to_string())),
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(target_arch = "x86_64")]
    fn set_bp_hw_internal(&self, va_target: u64, idx_slot: usize) -> Result<(), ReToolsError> {
        if idx_slot > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut reg_konteks = ptrace::getregs(self.pid_sasaran).map_err(|_| ReToolsError::Generic("Failed to get regs (process dead?)".to_string()))?;
        let val_dr7 = reg_konteks.dr7;
        let mask_lokal = 1 << (idx_slot * 2);
        let mask_global = 1 << (idx_slot * 2 + 1);
        let mask_kondisi = 0b00 << (16 + idx_slot * 4);
        let mask_len = 0b00 << (18 + idx_slot * 4);
        let val_dr7_baru = (val_dr7 | mask_lokal | mask_global | mask_kondisi | mask_len) & !0x200;
        match idx_slot {
            0 => reg_konteks.dr0 = va_target,
            1 => reg_konteks.dr1 = va_target,
            2 => reg_konteks.dr2 = va_target,
            3 => reg_konteks.dr3 = va_target,
            _ => unreachable!(),
        }
        reg_konteks.dr7 = val_dr7_baru;
        ptrace::setregs(self.pid_sasaran, reg_konteks).map_err(|_| ReToolsError::Generic("Failed to set regs (process dead?)".to_string()))?;
        Ok(())
    }
    #[cfg(target_arch = "x86_64")]
    fn remove_bp_hw_internal(&self, idx_slot: usize) -> Result<(), ReToolsError> {
        if idx_slot > 3 {
            return Err(ReToolsError::Generic(
                "Indeks hardware breakpoint harus 0-3".to_string(),
            ));
        }
        let mut reg_konteks = ptrace::getregs(self.pid_sasaran).map_err(|_| ReToolsError::Generic("Failed to get regs (process dead?)".to_string()))?;
        let mask_disable_lokal = !(1 << (idx_slot * 2));
        let mask_disable_global = !(1 << (idx_slot * 2 + 1));
        reg_konteks.dr7 &= mask_disable_lokal & mask_disable_global;
        match idx_slot {
            0 => reg_konteks.dr0 = 0,
            1 => reg_konteks.dr1 = 0,
            2 => reg_konteks.dr2 = 0,
            3 => reg_konteks.dr3 = 0,
            _ => unreachable!(),
        }
        ptrace::setregs(self.pid_sasaran, reg_konteks).map_err(|_| ReToolsError::Generic("Failed to set regs (process dead?)".to_string()))?;
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
                    let reg_konteks = match ptrace::getregs(pid) {
                        Ok(r) => r,
                        Err(_) => {
                             (*ptr_event).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                             return Ok(true);
                        }
                    };
                    let va_potensial = reg_konteks.rip.saturating_sub(1);
                    if self.map_titik_henti.contains_key(&va_potensial) {
                        if self.handle_logika_bp(pid, va_potensial) {
                            (*ptr_event).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                            (*ptr_event).pid_thread = pid.as_raw();
                            (*ptr_event).info_alamat = va_potensial;
                            return Ok(true);
                        } else {
                            set_err_last(ReToolsError::Generic(format!(
                                "Gagal menangani breakpoint logic pada 0x{:x}",
                                va_potensial
                            )));
                            (*ptr_event).tipe = DebugEventTipe::EVENT_UNKNOWN;
                            (*ptr_event).info_alamat = va_potensial;
                            return Ok(false);
                        }
                    } else {
                        (*ptr_event).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                        (*ptr_event).pid_thread = pid.as_raw();
                        (*ptr_event).info_alamat = reg_konteks.rip;
                        return Ok(true);
                    }
                }
                WaitStatus::Stopped(pid, sig) if sig as c_int == (Signal::SIGTRAP as c_int | 0x80) => {
                    if !self.trace_syscall_aktif {
                         ptrace::cont(pid, None).ok();
                         return Ok(false);
                    }
                    let reg_konteks = match ptrace::getregs(pid) {
                        Ok(r) => r,
                        Err(_) => {
                            (*ptr_event).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                            return Ok(true);
                        }
                    };
                    if reg_konteks.orig_rax != u64::MAX {
                        (*ptr_event).tipe = DebugEventTipe::EVENT_SYSCALL_ENTRY;
                    } else {
                        (*ptr_event).tipe = DebugEventTipe::EVENT_SYSCALL_EXIT;
                    }
                    (*ptr_event).pid_thread = pid.as_raw();
                    (*ptr_event).info_alamat = reg_konteks.orig_rax;
                    return Ok(true);
                }
                WaitStatus::PtraceEvent(pid, _signal, event) => {
                     let tipe_event = match event {
                        libc::PTRACE_EVENT_CLONE => {
                            let raw_pid_baru = ptrace::getevent(pid).unwrap_or(0) as c_int;
                            (*ptr_event).info_alamat = raw_pid_baru as u64;
                            Some(DebugEventTipe::EVENT_THREAD_BARU)
                        },
                        libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK => {
                            let raw_pid_baru = ptrace::getevent(pid).unwrap_or(0) as c_int;
                            (*ptr_event).info_alamat = raw_pid_baru as u64;
                            Some(DebugEventTipe::EVENT_THREAD_BARU)
                        }
                        libc::PTRACE_EVENT_EXIT => {
                            (*ptr_event).info_alamat = 0;
                            Some(DebugEventTipe::EVENT_THREAD_EXIT)
                        }
                        _ => None
                    };
                    if let Some(tipe) = tipe_event {
                        (*ptr_event).tipe = tipe;
                        (*ptr_event).pid_thread = pid.as_raw();
                        ptrace::cont(pid, None).ok();
                        return Ok(true);
                    } else {
                        ptrace::cont(pid, None).ok();
                        return Ok(false);
                    }
                }
                WaitStatus::Stopped(pid, sig) => {
                    ptrace::cont(pid, Some(sig)).ok();
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

impl PlatformTracer for LinuxTracer {
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
        match ptrace::detach(self.pid_sasaran, None) {
            Ok(_) => Ok(()),
            Err(nix::Error::ESRCH) => Ok(()), 
            Err(e) => Err(e.into()),
        }
    }
    fn read_memori(&self, va_alamat: u64, sz_ukuran: c_int) -> Result<Vec<u8>, ReToolsError> {
        if let Err(e) = self.validate_mem_access(va_alamat, sz_ukuran as usize, false) {
            return Err(e);
        }
        let mut vec_buffer = vec![0u8; sz_ukuran as usize];
        let mut arr_iov_lokal = [IoSliceMut::new(&mut vec_buffer)];
        let arr_iov_remote = [RemoteIoVec {
            base: va_alamat as usize,
            len: sz_ukuran as usize,
        }];
        match process_vm_readv(self.pid_sasaran, &mut arr_iov_lokal, &arr_iov_remote) {
            Ok(sz_terbaca) => {
                vec_buffer.truncate(sz_terbaca);
                Ok(vec_buffer)
            },
            Err(nix::Error::ESRCH) => Err(ReToolsError::Generic("Process died".to_string())),
            Err(e) => Err(e.into())
        }
    }
    fn write_memori(&self, va_alamat: u64, buf_data: &[u8]) -> Result<usize, ReToolsError> {
        if let Err(e) = self.validate_mem_access(va_alamat, buf_data.len(), true) {
            return Err(e);
        }
        let arr_iov_lokal = [std::io::IoSlice::new(buf_data)];
        let arr_iov_remote = [RemoteIoVec {
            base: va_alamat as usize,
            len: buf_data.len(),
        }];
        match process_vm_writev(self.pid_sasaran, &arr_iov_lokal, &arr_iov_remote) {
             Ok(sz) => Ok(sz),
             Err(nix::Error::ESRCH) => Err(ReToolsError::Generic("Process died".to_string())),
             Err(e) => Err(e.into())
        }
    }
    fn get_register(&self) -> Result<C_Registers, ReToolsError> {
        let reg_konteks = ptrace::getregs(self.pid_sasaran).map_err(|_| ReToolsError::Generic("Failed to read registers".to_string()))?;
        Ok(C_Registers {
            rax: reg_konteks.rax,
            rbx: reg_konteks.rbx,
            rcx: reg_konteks.rcx,
            rdx: reg_konteks.rdx,
            rsi: reg_konteks.rsi,
            rdi: reg_konteks.rdi,
            rbp: reg_konteks.rbp,
            rsp: reg_konteks.rsp,
            r8: reg_konteks.r8,
            r9: reg_konteks.r9,
            r10: reg_konteks.r10,
            r11: reg_konteks.r11,
            r12: reg_konteks.r12,
            r13: reg_konteks.r13,
            r14: reg_konteks.r14,
            r15: reg_konteks.r15,
            rip: reg_konteks.rip,
            eflags: reg_konteks.eflags,
        })
    }
    fn set_register(&self, reg_nilai: &C_Registers) -> Result<(), ReToolsError> {
        let mut reg_konteks = ptrace::getregs(self.pid_sasaran).map_err(|_| ReToolsError::Generic("Failed to read registers for set".to_string()))?;
        reg_konteks.rax = reg_nilai.rax;
        reg_konteks.rbx = reg_nilai.rbx;
        reg_konteks.rcx = reg_nilai.rcx;
        reg_konteks.rdx = reg_nilai.rdx;
        reg_konteks.rsi = reg_nilai.rsi;
        reg_konteks.rdi = reg_nilai.rdi;
        reg_konteks.rbp = reg_nilai.rbp;
        reg_konteks.rsp = reg_nilai.rsp;
        reg_konteks.r8 = reg_nilai.r8;
        reg_konteks.r9 = reg_nilai.r9;
        reg_konteks.r10 = reg_nilai.r10;
        reg_konteks.r11 = reg_nilai.r11;
        reg_konteks.r12 = reg_nilai.r12;
        reg_konteks.r13 = reg_nilai.r13;
        reg_konteks.r14 = reg_nilai.r14;
        reg_konteks.r15 = reg_nilai.r15;
        reg_konteks.rip = reg_nilai.rip;
        reg_konteks.eflags = reg_nilai.eflags;
        ptrace::setregs(self.pid_sasaran, reg_konteks)?;
        Ok(())
    }
    fn continue_proses(&self) -> Result<(), ReToolsError> {
        let res = if self.trace_syscall_aktif {
            ptrace::syscall(self.pid_sasaran, None)
        } else {
            ptrace::cont(self.pid_sasaran, None)
        };
        match res {
             Ok(_) => Ok(()),
             Err(nix::Error::ESRCH) => Err(ReToolsError::Generic("Process died".to_string())),
             Err(e) => Err(e.into())
        }
    }
    fn step_instruksi(&mut self) -> Result<(), ReToolsError> {
        self.step_internal(self.pid_sasaran)
    }
    fn wait_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError> {
        loop {
            let status = match waitpid(Pid::from_raw(-1), None) {
                Ok(s) => s,
                Err(nix::Error::ECHILD) => return Ok(0),
                Err(e) => return Err(e.into()),
            };
            if self.process_status_wait(status, ptr_event_out)? {
                return Ok(0);
            }
        }
    }
    fn poll_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<bool, ReToolsError> {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
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
         let jalur_task = format!("/proc/{}/task", self.pid_sasaran.as_raw());
        let mut vec_thread = Vec::new();
        match std::fs::read_dir(jalur_task) {
            Ok(entries) => {
                for entri in entries {
                    let entri = entri?;
                    let str_tid = entri.file_name().into_string().unwrap_or_default();
                    if let Ok(tid) = str_tid.parse::<c_int>() {
                        vec_thread.push(tid);
                    }
                }
                Ok(vec_thread)
            },
            Err(_) => Ok(Vec::new()) 
        }
    }
    fn get_region_memori(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError> {
        let berkas_maps = format!("/proc/{}/maps", self.pid_sasaran.as_raw());
        let konten = match std::fs::read_to_string(berkas_maps) {
            Ok(k) => k,
            Err(_) => return Ok(Vec::new()),
        };
        let mut vec_region = Vec::new();
        for baris in konten.lines() {
            let vec_bagian: Vec<&str> = baris.split_whitespace().collect();
            if vec_bagian.len() < 6 {
                continue;
            }
            let rentang_addr: Vec<&str> = vec_bagian[0].split('-').collect();
            let (start, end) = (
                u64::from_str_radix(rentang_addr[0], 16).unwrap_or(0),
                u64::from_str_radix(rentang_addr[1], 16).unwrap_or(0),
            );
            let str_izin = vec_bagian[1];
            let mut flag_proteksi = 0;
            if str_izin.contains('r') { flag_proteksi |= 1; }
            if str_izin.contains('w') { flag_proteksi |= 2; }
            if str_izin.contains('x') { flag_proteksi |= 4; }
            let jalur_modul = vec_bagian[5..].join(" ");
            let mut arr_path = [0 as c_char; 260];
            let bytes_path = jalur_modul.as_bytes();
            let len_salin = std::cmp::min(bytes_path.len(), arr_path.len() - 1);
            arr_path[..len_salin].copy_from_slice(
                &bytes_path[..len_salin].iter().map(|&b| b as c_char).collect::<Vec<c_char>>()
            );
            vec_region.push(C_MemoryRegionInfo {
                alamat_basis: start,
                ukuran: end - start,
                proteksi: flag_proteksi,
                path_modul: arr_path,
            });
        }
        Ok(vec_region)
    }
    fn set_trace_syscall(&mut self, status_aktif: bool) -> Result<(), ReToolsError> {
        self.trace_syscall_aktif = status_aktif;
        self.set_opsi_multithread()
    }
    fn get_info_syscall(&self, id_thread: c_int) -> Result<C_SyscallInfo, ReToolsError> {
        let reg_konteks = ptrace::getregs(Pid::from_raw(id_thread))?;
        Ok(C_SyscallInfo {
            nomor_syscall: reg_konteks.orig_rax,
            arg1: reg_konteks.rdi,
            arg2: reg_konteks.rsi,
            arg3: reg_konteks.rdx,
            arg4: reg_konteks.r10,
            arg5: reg_konteks.r8,
            arg6: reg_konteks.r9,
            nilai_balik: reg_konteks.rax,
            adalah_entry: reg_konteks.orig_rax != u64::MAX,
        })
    }
    fn set_opsi_multithread(&mut self) -> Result<(), ReToolsError> {
        let mut opsi = Options::PTRACE_O_TRACECLONE | 
                          Options::PTRACE_O_TRACEFORK | 
                          Options::PTRACE_O_TRACEVFORK |
                          Options::PTRACE_O_TRACEEXIT;
        if self.trace_syscall_aktif {
            opsi |= Options::PTRACE_O_TRACESYSGOOD;
        }
        ptrace::setoptions(self.pid_sasaran, opsi)?;
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

impl From<nix::Error> for ReToolsError {
    fn from(err: nix::Error) -> ReToolsError {
        ReToolsError::Generic(format!("Nix error: {}", err))
    }
}