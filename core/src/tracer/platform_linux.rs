use super::state::StateDebuggerInternal;
use super::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use libc::c_int;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::{process_vm_readv, process_vm_writev, IoVec, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;
use std::io::IoSliceMut;

pub unsafe fn impl_platform_attach(state_data: &mut StateDebuggerInternal) -> bool {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::attach(pid_target) {
            eprintln!("Linux: PTRACE_ATTACH gagal: {}", e);
            return false;
        }
        match waitpid(pid_target, None) {
            Ok(status) => match status {
                WaitStatus::Stopped(_, sig) => {
                    // Sukses attach, proses dihentikan
                    println!("Linux: Attach sukses, proses dihentikan dgn sinyal {:?}", sig);
                    true
                }
                _ => {
                    eprintln!("Linux: Status waitpid tidak terduga setelah attach: {:?}", status);
                    false
                }
            },
            Err(e) => {
                eprintln!("Linux: waitpid gagal setelah attach: {}", e);
                false
            }
        }
    }
}

pub unsafe fn impl_platform_detach(state_data: &mut StateDebuggerInternal) {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::detach(pid_target, None) {
            eprintln!("Linux: PTRACE_DETACH gagal: {}", e);
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
        let mut local_iov = [IoSliceMut::new(local_slice)];
        let remote_iov = [RemoteIoVec {
            base: addr as usize,
            len: size as usize,
        }];

        match process_vm_readv(pid_target, &mut local_iov, &remote_iov) {
            Ok(bytes_read) => bytes_read as c_int,
            Err(_) => -1,
        }
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
        let local_slice = std::slice::from_raw_parts(data, size as usize);
        let local_iov = [std::io::IoSlice::new(local_slice)];
        let remote_iov = [RemoteIoVec {
            base: addr as usize,
            len: size as usize,
        }];

        match process_vm_writev(pid_target, &local_iov, &remote_iov) {
            Ok(bytes_written) => bytes_written as c_int,
            Err(_) => -1,
        }
    }
}

pub unsafe fn impl_platform_single_step(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        if let Err(e) = ptrace::step(pid_target, None) {
            eprintln!("Linux: PTRACE_SINGLESTEP gagal: {}", e);
            return -1;
        }
        // Tunggu sampai single step selesai
        match waitpid(pid_target, None) {
            Ok(status) => {
                if matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)) {
                    0 // Sukses
                } else {
                    eprintln!("Linux: Status waitpid tidak terduga setelah step: {:?}", status);
                    -1
                }
            }
            Err(_) => -1,
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
            Ok(regs) => {
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
                    eflags: regs.eflags,
                };
                0 // Sukses
            }
            Err(_) => -1,
        }
    }
}

pub unsafe fn impl_platform_set_registers(
    state_data: &StateDebuggerInternal,
    registers: *const C_Registers,
) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        // ptrace::setregs butuh user_regs_struct, jadi harus ambil dulu
        match ptrace::getregs(pid_target) {
            Ok(mut regs) => {
                let c_regs = *registers;
                // Mapping dari C_Registers ke libc::user_regs_struct
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

                if ptrace::setregs(pid_target, regs).is_ok() {
                    0 // Sukses
                } else {
                    -1 // Gagal set
                }
            }
            Err(_) => -1, // Gagal get
        }
    }
}

pub unsafe fn impl_platform_continue_proses(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        let pid_target = Pid::from_raw(state_data.pid_target);
        match ptrace::cont(pid_target, None) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }
}

/// Logika internal untuk menangani hit breakpoint di Linux
unsafe fn handle_breakpoint_logic(
    state_data: &mut StateDebuggerInternal,
    pid: Pid,
    alamat_bp: u64,
) -> bool {
    unsafe {
        // Dapatkan byte asli
        let Some(&byte_asli) = state_data.breakpoints_map.get(&alamat_bp) else { return false };

        // Kembalikan byte asli
        if impl_platform_tulis_memory(state_data, alamat_bp, &byte_asli as *const u8, 1) != 1 {
            return false;
        }

        // Mundurkan RIP
        let mut regs = match ptrace::getregs(pid) {
            Ok(r) => r,
            Err(_) => return false,
        };
        regs.rip = alamat_bp; // Set RIP kembali ke alamat breakpoint
        if ptrace::setregs(pid, regs).is_err() {
            return false;
        }

        // Single step
        if impl_platform_single_step(state_data) != 0 {
            // Gagal single step, coba pasang lagi BP
            let int3_byte: u8 = 0xCC;
            impl_platform_tulis_memory(state_data, alamat_bp, &int3_byte, 1);
            return false;
        }
        // impl_platform_singleStep sudah termasuk waitpid()

        // Pasang kembali breakpoint
        let int3_byte: u8 = 0xCC;
        if impl_platform_tulis_memory(state_data, alamat_bp, &int3_byte, 1) != 1 {
            return false; // Gagal pasang kembali
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
                    match status {
                        WaitStatus::Stopped(pid, Signal::SIGTRAP) => {
                            // Dapat SIGTRAP. Cek apakah ini breakpoint atau single step.
                            let regs = match ptrace::getregs(pid) {
                                Ok(r) => r,
                                Err(_) => continue, // Gagal get regs, coba tunggu lagi
                            };
                            
                            // RIP/EIP menunjuk ke *setelah* instruksi 0xCC
                            let alamat_breakpoint_potensial = regs.rip.saturating_sub(1);

                            if state_data.breakpoints_map.contains_key(&alamat_breakpoint_potensial) {
                                // Ini adalah breakpoint!
                                
                                // Jalankan logika penanganan (restore, step, re-insert)
                                if handle_breakpoint_logic(state_data, pid, alamat_breakpoint_potensial) {
                                    // Sukses ditangani
                                    (*event_out).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                                    (*event_out).pid_thread = pid.as_raw();
                                    (*event_out).info_alamat = alamat_breakpoint_potensial;
                                    return 0; // Sukses, kembali ke user
                                } else {
                                    // Gagal menangani, laporkan sebagai unknown
                                    (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                                    (*event_out).info_alamat = alamat_breakpoint_potensial;
                                    return -1; // Gagal
                                }
                            } else {
                                // Ini adalah SINGLE_STEP (dari PTRACE_STEP)
                                (*event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                                (*event_out).pid_thread = pid.as_raw();
                                (*event_out).info_alamat = regs.rip;
                                return 0; // Sukses
                            }
                        }
                        WaitStatus::Stopped(pid, _) => {
                            // Sinyal lain (misal SIGSEGV), lanjutkan saja
                            ptrace::cont(pid, None).ok();
                            continue; // Tunggu event selanjutnya
                        }
                        WaitStatus::Exited(pid, status_code) => {
                            (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                            (*event_out).pid_thread = pid.as_raw();
                            (*event_out).info_alamat = status_code as u64; // Simpan exit code
                            return 0;
                        }
                        WaitStatus::Signaled(pid, signal, _) => {
                            (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                            (*event_out).pid_thread = pid.as_raw();
                            (*event_out).info_alamat = signal as u64; // Simpan sinyal
                            return 0;
                        }
                        _ => {
                            // Status lain (Continued, PtraceEvent), abaikan
                            continue;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Linux: waitpid gagal: {}", e);
                    return -1;
                }
            }
        }
    }
}