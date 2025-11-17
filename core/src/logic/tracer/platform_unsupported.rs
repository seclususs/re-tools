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
    fn attach(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn detach(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn baca_memory(&self, _addr: u64, _size: c_int) -> Result<Vec<u8>, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn tulis_memory(&self, _addr: u64, _data: &[u8]) -> Result<usize, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn get_registers(&self) -> Result<C_Registers, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_registers(&self, _regs: &C_Registers) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn continue_proses(&self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn single_step(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn tunggu_event(&mut self, _event_out: *mut C_DebugEvent) -> Result<c_int, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_software_breakpoint(&mut self, _addr: u64) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn remove_software_breakpoint(&mut self, _addr: u64) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_hardware_breakpoint(&mut self, _addr: u64, _index: usize) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn remove_hardware_breakpoint(&mut self, _index: usize) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }

    fn list_semua_threads(&self) -> Result<Vec<c_int>, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn get_memory_regions(&self) -> Result<Vec<C_MemoryRegionInfo>, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_pelacakan_syscall(&mut self, _enable: bool) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn get_info_syscall(&self, _pid_thread: c_int) -> Result<C_SyscallInfo, ReToolsError> {
        Err(Self::unsupported_err())
    }
    fn set_options_multithread(&mut self) -> Result<(), ReToolsError> {
        Err(Self::unsupported_err())
    }
}