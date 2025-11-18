//! Author: [Seclususs](https://github.com/seclususs)

use crate::error::ReToolsError;
use crate::logic::tracer::types::{u64, C_DebugEvent, C_MemoryRegionInfo, C_Registers, C_SyscallInfo};
use libc::c_int;

pub trait PlatformTracer: Send + Sync {
    fn attach_sasaran(&mut self) -> Result<(), ReToolsError>;
    fn detach_sasaran(&mut self) -> Result<(), ReToolsError>;
    fn read_memori(&self, va_alamat: u64, sz_ukuran: c_int) -> Result<Vec<u8>, ReToolsError>;
    fn write_memori(&self, va_alamat: u64, buf_data: &[u8]) -> Result<usize, ReToolsError>;
    fn get_register(&self) -> Result<C_Registers, ReToolsError>;
    fn set_register(&self, reg_nilai: &C_Registers) -> Result<(), ReToolsError>;
    fn continue_proses(&self) -> Result<(), ReToolsError>;
    fn step_instruksi(&mut self) -> Result<(), ReToolsError>;
    fn wait_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError>;
    fn poll_event(&mut self, ptr_event_out: *mut C_DebugEvent) -> Result<bool, ReToolsError>;
    fn set_titik_henti_sw(&mut self, va_alamat: u64) -> Result<(), ReToolsError>;
    fn remove_titik_henti_sw(&mut self, va_alamat: u64) -> Result<(), ReToolsError>;
    fn set_titik_henti_hw(&mut self, va_alamat: u64, idx_slot: usize) -> Result<(), ReToolsError>;
    fn remove_titik_henti_hw(&mut self, idx_slot: usize) -> Result<(), ReToolsError>;
    fn list_thread(&self) -> Result<Vec<c_int>, ReToolsError>;
    fn get_region_memori(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError>;
    fn set_trace_syscall(&mut self, status_aktif: bool) -> Result<(), ReToolsError>;
    fn get_info_syscall(&self, id_thread: c_int) -> Result<C_SyscallInfo, ReToolsError>;
    fn set_opsi_multithread(&mut self) -> Result<(), ReToolsError>;
    fn hook_api_memori(
        &mut self,
        nama_api: &str,
        va_entry: u64,
        va_exit: u64,
    ) -> Result<(), ReToolsError>;
    fn remove_hook_api_memori(&mut self, nama_api: &str) -> Result<(), ReToolsError>;
    fn dump_region_memori(&self, va_alamat: u64, sz_ukuran: usize, jalur_berkas: &str) -> Result<(), ReToolsError>;
    fn hide_status_debugger(&mut self) -> Result<(), ReToolsError>;
}