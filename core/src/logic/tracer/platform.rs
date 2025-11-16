use crate::error::ReToolsError;
use crate::logic::tracer::types::{u64, C_DebugEvent, C_Registers};
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
    fn set_software_breakpoint(&mut self, addr: u64) -> Result<(), ReToolsError>;
    fn remove_software_breakpoint(&mut self, addr: u64) -> Result<(), ReToolsError>;
    fn set_hardware_breakpoint(&mut self, addr: u64, index: usize) -> Result<(), ReToolsError>;
    fn remove_hardware_breakpoint(&mut self, index: usize) -> Result<(), ReToolsError>;
}