//! Author: [Seclususs](https://github.com/seclususs)

use super::platform::PlatformTracer;
use super::types::{u64, C_DebugEvent, C_MemoryRegionInfo, C_Registers, C_SyscallInfo};
use crate::error::ReToolsError;
use libc::c_int;

pub struct UnsupportedTracer;

impl UnsupportedTracer {
    pub fn new(_pid: c_int) -> Result<Self, ReToolsError> {
        Ok(UnsupportedTracer)
    }

    fn unsupported_err() -> ReToolsError {
        ReToolsError::Generic("Fungsi tracer tidak didukung di OS ini".to_string())
    }
}

impl PlatformTracer for UnsupportedTracer {
    fn attach_sasaran(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn detach_sasaran(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn read_memori(&self, _va_alamat: u64, _sz_ukuran: c_int) -> Result<Vec<u8>, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn write_memori(&self, _va_alamat: u64, _buf_data: &[u8]) -> Result<usize, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn get_register(&self) -> Result<C_Registers, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_register(&self, _reg_nilai: &C_Registers) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn continue_proses(&self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn step_instruksi(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn wait_event(&mut self, _ptr_event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn poll_event(&mut self, _ptr_event_out: *mut C_DebugEvent) -> Result<bool, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_titik_henti_sw(&mut self, _va_alamat: u64) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn remove_titik_henti_sw(&mut self, _va_alamat: u64) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_titik_henti_hw(&mut self, _va_alamat: u64, _idx_slot: usize) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn remove_titik_henti_hw(&mut self, _idx_slot: usize) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn list_thread(&self) -> Result<Vec<c_int>, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn get_region_memori(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_trace_syscall(&mut self, _status_aktif: bool) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn get_info_syscall(&self, _id_thread: c_int) -> Result<C_SyscallInfo, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_opsi_multithread(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn hook_api_memori(
        &mut self,
        _nama_api: &str,
        _va_entry: u64,
        _va_exit: u64,
    ) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn remove_hook_api_memori(&mut self, _nama_api: &str) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn dump_region_memori(&self, _va_alamat: u64, _sz_ukuran: usize, _jalur_berkas: &str) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn hide_status_debugger(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
}