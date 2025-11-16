use super::state::StateDebuggerInternal;
use super::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use libc::{c_int, c_void};
use log::{debug, error, info, warn};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::ptr::null_mut;

pub unsafe fn impl_platform_attach(state_data: &mut StateDebuggerInternal) -> bool {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::attach(pid_target) {
            error!("macOS: PT_ATTACH gagal: {}", e);
            return false;
        }
        match waitpid(pid_target, None) {
            Ok(status) => match status {
                WaitStatus::Stopped(_, sig) => {
                    info!(
                        "macOS: Attach sukses, proses dihentikan dgn sinyal {:?}",
                        sig
                    );
                    true
                }
                _ => {
                    warn!(
                        "macOS: Status waitpid tidak terduga setelah attach: {:?}",
                        status
                    );
                    false
                }
            },
            Err(e) => {
                error!("macOS: waitpid gagal setelah attach: {}", e);
                false
            }
        }
    }
}

pub unsafe fn impl_platform_detach(state_data: &mut StateDebuggerInternal) {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::detach(pid_target, None) {
            error!("macOS: PT_DETACH gagal: {}", e);
        } else {
            info!("macOS: PT_DETACH berhasil untuk PID {}", pid_target);
        }
    }
}

pub unsafe fn impl_platform_baca_memory(
    state_data: &StateDebuggerInternal,
    addr: u64,
    out_buffer: *mut u8,
    size: c_int,
) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        let local_slice = std::slice::from_raw_parts_mut(out_buffer, size as usize);
        let mut bytes_dibaca = 0;
        for (i, byte) in local_slice.iter_mut().enumerate() {
            let read_addr = (addr + i as u64) as ptrace::AddressType;
            match ptrace::read(pid_target, read_addr) {
                Ok(word) => {
                    *byte = (word & 0xFF) as u8;
                    bytes_dibaca += 1;
                }
                Err(e) => {
                    warn!("macOS: ptrace::read gagal pada 0x{:x}: {}", read_addr, e);
                    return if bytes_dibaca > 0 { bytes_dibaca } else { -1 };
                }
            }
        }
        bytes_dibaca
    }
}

pub unsafe fn impl_platform_tulis_memory(
    state_data: &StateDebuggerInternal,
    addr: u64,
    data: *const u8,
    size: c_int,
) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        let data_slice = std::slice::from_raw_parts(data, size as usize);
        let mut bytes_ditulis = 0;
        for (i, &byte) in data_slice.iter().enumerate() {
            let write_addr = (addr + i as u64) as ptrace::AddressType;
            let data_word = byte as ptrace::WordType;
            match ptrace::write(pid_target, write_addr, data_word) {
                Ok(_) => {
                    bytes_ditulis += 1;
                }
                Err(e) => {
                    warn!("macOS: ptrace::write gagal pada 0x{:x}: {}", write_addr, e);
                    return if bytes_ditulis > 0 { bytes_ditulis } else { -1 };
                }
            }
        }
        bytes_ditulis
    }
}

pub unsafe fn impl_platform_single_step(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::step(pid_target, None) {
            error!("macOS: PT_STEP gagal: {}", e);
            return -1;
        }
        match waitpid(pid_target, None) {
            Ok(status) => {
                if matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)) {
                    0
                } else {
                    warn!(
                        "macOS: Status waitpid tidak terduga setelah step: {:?}",
                        status
                    );
                    -1
                }
            }
            Err(e) => {
                error!("macOS: waitpid gagal setelah step: {}", e);
                -1
            }
        }
    }
}

pub unsafe fn impl_platform_get_registers(
    state_data: &StateDebuggerInternal,
    out_registers: *mut C_Registers,
) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        match ptrace::getregs(pid_target) {
            Ok(regs_any) => {
                #[cfg(target_arch = "x86_64")]
                if let Some(regs) = regs_any.as_x86_64() {
                    *out_registers = C_Registers {
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
                    };
                    return 0;
                }
                error!("macOS: Gagal konversi register ke x86_64");
                -1
            }
            Err(e) => {
                error!("macOS: PT_GETREGS gagal: {}", e);
                -1
            }
        }
    }
}

pub unsafe fn impl_platform_set_registers(
    state_data: &StateDebuggerInternal,
    registers: *const C_Registers,
) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        match ptrace::getregs(pid_target) {
            Ok(mut regs_any) => {
                #[cfg(target_arch = "x86_64")]
                if let Some(regs) = regs_any.as_x86_64_mut() {
                    let c_regs = *registers;
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
                    if let Err(e) = ptrace::setregs(pid_target, regs_any) {
                        error!("macOS: PT_SETREGS gagal: {}", e);
                        -1
                    } else {
                        0
                    }
                } else {
                    error!("macOS: Gagal konversi register (mut) ke x86_64");
                    -1
                }
                
            }
            Err(e) => {
                error!("macOS: PT_GETREGS (sebelum set) gagal: {}", e);
                -1
            }
        }
    }
}

pub unsafe fn impl_platform_continue_proses(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        match ptrace::cont(pid_target, None) {
            Ok(_) => 0,
            Err(e) => {
                error!("macOS: PT_CONTINUE gagal: {}", e);
                -1
            }
        }
    }
}

unsafe fn handle_breakpoint_logic_macos(
    state_data: &mut StateDebuggerInternal,
    pid: Pid,
    alamat_bp: u64,
) -> bool {
    unsafe {
        let Some(&byte_asli) = state_data.breakpoints_map.get(&alamat_bp) else {
            warn!(
                "SIGTRAP pada 0x{:x} tapi tidak ada di map breakpoint",
                alamat_bp
            );
            return false;
        };
        if impl_platform_tulis_memory(state_data, alamat_bp, &byte_asli as *const u8, 1) != 1 {
            error!("Gagal restore byte asli pada 0x{:x}", alamat_bp);
            return false;
        }
        #[cfg(target_arch = "x86_64")]
        match ptrace::getregs(pid) {
            Ok(mut regs_any) => {
                if let Some(regs) = regs_any.as_x86_64_mut() {
                     regs.rip = alamat_bp;
                    if ptrace::setregs(pid, regs_any).is_err() {
                        error!("Gagal setregs untuk restore RIP: {}", alamat_bp);
                        return false;
                    }
                } else {
                     error!("Gagal konversi register (mut) ke x86_64 untuk restore RIP");
                     return false;
                }
            }
            Err(e) => {
                error!("Gagal getregs untuk restore RIP: {}", e);
                return false;
            }
        };
        if impl_platform_single_step(state_data) != 0 {
            let int3_byte: u8 = 0xCC;
            impl_platform_tulis_memory(state_data, alamat_bp, &int3_byte, 1);
            error!("Gagal single step setelah restore breakpoint");
            return false;
        }
        let int3_byte: u8 = 0xCC;
        if impl_platform_tulis_memory(state_data, alamat_bp, &int3_byte, 1) != 1 {
            error!("Gagal re-set breakpoint pada 0x{:x}", alamat_bp);
            return false;
        }
        true
    }
}

pub unsafe fn impl_platform_tunggu_event(
    state_data: &mut StateDebuggerInternal,
    event_out: *mut C_DebugEvent,
) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        loop {
            match waitpid(pid_target, None) {
                Ok(status) => {
                    debug!("macOS: waitpid menerima status: {:?}", status);
                    match status {
                        WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                            
                            #[cfg(target_arch = "x86_64")]
                            let regs = match ptrace::getregs(pid) {
                                Ok(regs_any) => match regs_any.as_x86_64() {
                                    Some(r) => r.clone(),
                                    None => {
                                        error!("Gagal konversi regs x86_64 pada SIGTRAP");
                                        continue;
                                    }
                                },
                                Err(e) => {
                                    error!("Gagal getregs pada SIGTRAP: {}", e);
                                    continue;
                                }
                            };

                            #[cfg(target_arch = "x86_64")]
                            let rip = regs.rip;
                            #[cfg(not(target_arch = "x86_64"))]
                            let rip: u64 = 0;

                            let alamat_breakpoint_potensial = rip.saturating_sub(1);
                            if state_data
                                .breakpoints_map
                                .contains_key(&alamat_breakpoint_potensial)
                            {
                                if handle_breakpoint_logic_macos(
                                    state_data,
                                    pid,
                                    alamat_breakpoint_potensial,
                                ) {
                                    (*event_out).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                                    (*event_out).pid_thread = pid.as_raw();
                                    (*event_out).info_alamat = alamat_breakpoint_potensial;
                                    return 0;
                                } else {
                                    error!("Gagal menangani breakpoint logic pada 0x{:x}", alamat_breakpoint_potensial);
                                    (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                                    (*event_out).info_alamat = alamat_breakpoint_potensial;
                                    return -1;
                                }
                            } else {
                                (*event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                                (*event_out).pid_thread = pid.as_raw();
                                (*event_out).info_alamat = rip;
                                return 0;
                            }
                        }
                        WaitStatus::Stopped(pid, sig) => {
                            debug!(
                                "Proses dihentikan oleh sinyal {:?}, melanjutkan...",
                                sig
                            );
                            ptrace::cont(pid, None).ok();
                            continue;
                        }
                        WaitStatus::Exited(pid, status_code) => {
                            info!("Proses PID {} exit dengan status {}", pid, status_code);
                            (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                            (*event_out).pid_thread = pid.as_raw();
                            (*event_out).info_alamat = status_code as u64;
                            return 0;
                        }
                        WaitStatus::Signaled(pid, signal, _) => {
                            info!("Proses PID {} dihentikan oleh sinyal {:?}", pid, signal);
                            (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                            (*event_out).pid_thread = pid.as_raw();
                            (*event_out).info_alamat = signal as u64;
                            return 0;
                        }
                        _ => {
                            continue;
                        }
                    }
                }
                Err(e) => {
                    error!("macOS: waitpid gagal: {}", e);
                    return -1;
                }
            }
        }
    }
}