//! Author: [Seclususs](https://github.com/seclususs)

use crate::error::ReToolsError;
use crate::logic::tracer::types::{u64, C_DebugEvent, C_MemoryRegionInfo, C_Registers, C_SyscallInfo};
use libc::c_int;

pub trait PlatformTracer: Send + Sync {
    fn attach(&mut self) -> Result<(), ReToolsError>;
    fn detach(&mut self) -> Result<(), ReToolsError>;
    fn baca_memory(&self, addr: u64, size: c_int) -> Result<Vec<u8>, ReToolsError>;
    fn tulis_memory(&self, addr: u64, data: &[u8]) -> Result<usize, ReToolsError>;
    fn get_registers(&self) -> Result<C_Registers, ReToolsError>;
    fn set_registers(&self, regs: &C_Registers) -> Result<(), ReToolsError>;
    fn continue_proses(&self) -> Result<(), ReToolsError>;
    fn single_step(&mut self) -> Result<(), ReToolsError>;
    fn tunggu_event(&mut self, event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError>;
    fn poll_event(&mut self, event_out: *mut C_DebugEvent) -> Result<bool, ReToolsError>;
    fn set_software_breakpoint(&mut self, addr: u64) -> Result<(), ReToolsError>;
    fn remove_software_breakpoint(&mut self, addr: u64) -> Result<(), ReToolsError>;
    fn set_hardware_breakpoint(&mut self, addr: u64, index: usize) -> Result<(), ReToolsError>;
    fn remove_hardware_breakpoint(&mut self, index: usize) -> Result<(), ReToolsError>;
    fn list_semua_threads(&self) -> Result<Vec<c_int>, ReToolsError>;
    fn get_memory_regions(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError>;
    fn set_pelacakan_syscall(&mut self, enable: bool) -> Result<(), ReToolsError>;
    fn get_info_syscall(&self, pid_thread: c_int) -> Result<C_SyscallInfo, ReToolsError>;
    fn set_options_multithread(&mut self) -> Result<(), ReToolsError>;
    fn hook_memory_api(
        &mut self,
        api_name: &str,
        on_entry_callback: u64,
        on_exit_callback: u64,
    ) -> Result<(), ReToolsError>;
    fn remove_memory_api_hook(&mut self, api_name: &str) -> Result<(), ReToolsError>;
    fn dump_memory_region(&self, address: u64, size: usize, file_path: &str) -> Result<(), ReToolsError>;
    fn sembunyikan_status_debugger(&mut self) -> Result<(), ReToolsError>;
}