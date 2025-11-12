use super::state::StateDebuggerInternal;
use super::types::{u64, u8, C_DebugEvent, C_Registers, DebugEventTipe};
use libc::{c_int, c_void};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, FALSE, HANDLE, LUID};
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, WaitForDebugEvent,
    CONTEXT,
    DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    GetThreadContext, SetThreadContext,
    ReadProcessMemory, WriteProcessMemory,
};
use windows_sys::Win32::Foundation::{
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP,
};

// Alias per-arsitektur untuk flag CONTEXT
#[cfg(target_arch = "x86_64")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_CONTROL_AMD64 as CONTEXT_CONTROL,
    CONTEXT_FULL_AMD64 as CONTEXT_FULL,
};
#[cfg(target_arch = "x86")]
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT_CONTROL_X86 as CONTEXT_CONTROL,
    CONTEXT_FULL_X86 as CONTEXT_FULL,
};

use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, OpenThread, THREAD_GET_CONTEXT,
    THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, PROCESS_ALL_ACCESS,
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
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_attach(state_data: &mut StateDebuggerInternal) -> bool {
    unsafe {
        impl_EnableDebugPrivilege_windows(); // Coba aktifkan

        // Dapatkan Handle Proses dengan hak akses penuh
        let handle_proses = OpenProcess(
            PROCESS_ALL_ACCESS, // Perlu hak akses lebih
            FALSE,              // bInheritHandle
            state_data.pid_target as u32,
        );

        if handle_proses == 0 {
            eprintln!("WinAPI: OpenProcess gagal, error: {}", GetLastError());
            return false;
        }
        state_data.handle_proses = handle_proses;

        // Attach debugger
        if DebugActiveProcess(state_data.pid_target as u32) == 0 {
            eprintln!("WinAPI: DebugActiveProcess gagal, error: {}", GetLastError());
            CloseHandle(handle_proses);
            return false;
        }

        // Tunggu event attach ( breakpoint awal sistem)
        let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
        if WaitForDebugEvent(&mut debug_event, 5000) == 0 {
            // Timeout 5 detik
            eprintln!(
                "WinAPI: Timeout menunggu event attach awal, error: {}",
                GetLastError()
            );
            DebugActiveProcessStop(state_data.pid_target as u32);
            CloseHandle(handle_proses);
            return false;
        }

        // Simpan thread ID event pertama
        state_data.last_event_thread_id = debug_event.dwThreadId;

        // Lanjutkan dari event attach
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
                eprintln!(
                    "WinAPI: DebugActiveProcessStop gagal, error: {}",
                    GetLastError()
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
            return false;
        }

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL; // Perlu CONTEXT_FULL untuk EFlags
        if GetThreadContext(h_thread, &mut context) == 0 {
            CloseHandle(h_thread);
            return false;
        }

        if enable {
            context.EFlags |= 0x100; // Set Trap Flag (TF)
        } else {
            context.EFlags &= !0x100; // Clear Trap Flag (TF)
        }

        let success = SetThreadContext(h_thread, &context);
        CloseHandle(h_thread);
        success != 0
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_singleStep(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        if state_data.last_event_thread_id == 0 {
            return -1;
        } // Belum ada event

        // Set Trap Flag
        if !set_single_step_flag(state_data.last_event_thread_id, true) {
            return -1;
        }

        // Lanjutkan proses
        if impl_platform_continueProses(state_data) != 0 {
            return -1;
        }

        // Tunggu event SINGLE_STEP
        let mut debug_event: DEBUG_EVENT = std::mem::zeroed();
        loop {
            if WaitForDebugEvent(&mut debug_event, u32::MAX) == 0 {
                return -1;
            }

            // Cek apakah itu EXCEPTION_SINGLE_STEP
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
                && debug_event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP
            {
                // Sukses, jangan continue event ini, biarkan rt_tungguEvent yang handle
                // Untuk saat ini, continue saja
                ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    DBG_CONTINUE,
                );
                return 0;
            }

            // Event lain, continue saja
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
            return -1;
        } // Belum ada event

        let h_thread = OpenThread(THREAD_GET_CONTEXT, FALSE, state_data.last_event_thread_id);
        if h_thread == 0 {
            return -1;
        }

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL; // Ambil semua register

        if GetThreadContext(h_thread, &mut context) == 0 {
            CloseHandle(h_thread);
            return -1;
        }
        CloseHandle(h_thread);

        // Mapping dari CONTEXT (Windows) ke C_Registers (ABI)
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
        // TODO: Tambahkan mapping untuk x86

        0 // Sukses
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_setRegisters(
    state_data: &StateDebuggerInternal,
    registers: *const C_Registers,
) -> c_int {
    unsafe {
        if state_data.last_event_thread_id == 0 {
            return -1;
        } // Belum ada event

        let h_thread = OpenThread(THREAD_SET_CONTEXT, FALSE, state_data.last_event_thread_id);
        if h_thread == 0 {
            return -1;
        }

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_FULL; // Set semua register

        let c_regs = &*registers;

        // Mapping dari C_Registers (ABI) ke CONTEXT (Windows)
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
        // TODO: Tambahkan mapping untuk x86

        if SetThreadContext(h_thread, &context) == 0 {
            CloseHandle(h_thread);
            return -1;
        }
        CloseHandle(h_thread);
        0 // Sukses
    }
}

#[allow(non_snake_case)]
pub unsafe fn impl_platform_continueProses(state_data: &StateDebuggerInternal) -> c_int {
    unsafe {
        if state_data.last_event_thread_id == 0 {
            return -1;
        } // Belum ada event

        // Gunakan PID dan TID dari *event terakhir*
        if ContinueDebugEvent(
            state_data.pid_target as u32,
            state_data.last_event_thread_id,
            DBG_CONTINUE,
        ) != 0
        {
            0 // Sukses
        } else {
            -1 // Gagal
        }
    }
}

// Logika internal Windows
#[allow(non_snake_case)]
unsafe fn internal_handle_breakpoint_pre_step(
    state_data: &mut StateDebuggerInternal,
    debug_event: &DEBUG_EVENT,
    alamat_bp: u64,
) -> bool {
    unsafe {
        let Some(&byte_asli) = state_data.breakpoints_map.get(&alamat_bp) else { return false };

        // Kembalikan byte asli
        if impl_platform_tulisMemory(state_data, alamat_bp, &byte_asli, 1) != 1 {
            return false;
        }

        // Buka thread & mundurkan EIP/RIP
        let thread_id = debug_event.dwThreadId;
        let h_thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id);
        if h_thread == 0 {
            return false;
        }

        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_CONTROL;
        if GetThreadContext(h_thread, &mut context) == 0 {
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
            CloseHandle(h_thread);
            return false;
        }

        // Set Trap Flag (TF bit) untuk single step
        context.ContextFlags = CONTEXT_FULL; // Perlu full context untuk EFlags
        if GetThreadContext(h_thread, &mut context) == 0 {
            CloseHandle(h_thread);
            return false;
        }
        context.EFlags |= 0x100; // Set Trap Flag
        if SetThreadContext(h_thread, &context) == 0 {
            CloseHandle(h_thread);
            return false;
        }

        CloseHandle(h_thread);

        // Tandai bahwa sedang menangani BP ini
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
        // Pasang kembali breakpoint 0xCC
        let int3_byte: u8 = 0xCC;
        if impl_platform_tulisMemory(state_data, alamat_bp, &int3_byte, 1) != 1 {
            return false; // Gagal pasang kembali
        }

        // Hapus tanda
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
                eprintln!(
                    "WinAPI: WaitForDebugEvent gagal, error: {}",
                    GetLastError()
                );
                return -1;
            }

            // Simpan PID/TID dari event ini
            state_data.last_event_thread_id = debug_event.dwThreadId;

            // Status untuk melanjutkan event (default: tangani)
            let mut continue_status = DBG_CONTINUE;

            match debug_event.dwDebugEventCode {
                EXCEPTION_DEBUG_EVENT => {
                    let exception_record = &debug_event.u.Exception.ExceptionRecord;
                    let alamat_exception = exception_record.ExceptionAddress as u64;

                    if exception_record.ExceptionCode == EXCEPTION_BREAKPOINT {
                        // --- BREAKPOINT (0xCC) ---
                        if state_data.breakpoints_map.contains_key(&alamat_exception) {
                            // Ini adalah breakpoint!
                            // Panggil pre-step (restore, set RIP, set TF)
                            if internal_handle_breakpoint_pre_step(
                                state_data,
                                &debug_event,
                                alamat_exception,
                            ) {
                                // Lanjutkan (untuk memicu single-step)
                                ContinueDebugEvent(
                                    debug_event.dwProcessId,
                                    debug_event.dwThreadId,
                                    DBG_CONTINUE,
                                );
                                // Langsung loop tunggu event (single step) berikutnya
                                continue;
                            } else {
                                // Gagal handle, laporkan
                                continue_status = DBG_EXCEPTION_NOT_HANDLED;
                            }
                        } else {
                            // Breakpoint yang tidak dikenal (mungkin dari sistem),
                            // jangan ditangani
                            continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        }
                    } else if exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP {
                        // --- SINGLE STEP ---
                        if let Some(alamat_bp_ditangani) = state_data.handling_breakpoint_alamat {
                            // Ini adalah single-step *setelah* breakpoint
                            // Panggil post-step (pasang kembali 0xCC)
                            internal_handle_breakpoint_post_step(state_data, alamat_bp_ditangani);
                            // Laporkan ke user sebagai event BREAKPOINT
                            (*event_out).tipe = DebugEventTipe::EVENT_BREAKPOINT;
                            (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                            (*event_out).info_alamat = alamat_bp_ditangani;
                            return 0; // Sukses
                        } else {
                            // Ini adalah single step normal (dari rt_singleStep)
                            (*event_out).tipe = DebugEventTipe::EVENT_SINGLE_STEP;
                            (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                            (*event_out).info_alamat = alamat_exception;
                            return 0; // Sukses
                        }
                    } else {
                        // Exception lain (misal: C0000005 Access Violation)
                        // TODO: Laporkan sebagai EVENT_EXCEPTION
                        (*event_out).tipe = DebugEventTipe::EVENT_UNKNOWN;
                        (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                        (*event_out).info_alamat = alamat_exception;
                        // Jangan tangani, biarkan proses crash
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                        // return 0; // Kembalikan ke user
                    }
                }

                EXIT_PROCESS_DEBUG_EVENT => {
                    (*event_out).tipe = DebugEventTipe::EVENT_PROSES_EXIT;
                    (*event_out).pid_thread = debug_event.dwThreadId as c_int;
                    (*event_out).info_alamat = debug_event.u.ExitProcess.dwExitCode as u64;
                    state_data.attached_status = false; // Tandai sudah tidak attached
                    return 0;
                }
                _ => {
                    // Event lain (CREATE_PROCESS, CREATE_THREAD, DLL_LOAD, dll)
                    // Abaikan saja untuk saat ini
                }
            }

            // Lanjutkan proses dari event yang ditangani/diabaikan
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status,
            );
        }
    }
}