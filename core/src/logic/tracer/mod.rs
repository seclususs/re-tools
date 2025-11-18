#[cfg(target_os = "linux")]
pub mod platform_linux;
#[cfg(target_os = "macos")]
pub mod platform_macos;
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub mod platform_unsupported;
#[cfg(windows)]
pub mod platform_windows;

pub mod platform;
pub mod types;
pub mod dta;

use crate::error::{set_err_last, ReToolsError};
use libc::c_int;
use platform::PlatformTracer;

#[cfg(target_os = "linux")]
use platform_linux::LinuxTracer;
#[cfg(target_os = "macos")]
use platform_macos::MacosTracer;
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
use platform_unsupported::UnsupportedTracer;
#[cfg(windows)]
use platform_windows::WindowsTracer;

pub type Debugger = Box<dyn PlatformTracer + Send + Sync>;

pub fn new_debugger(pid: c_int) -> Result<Debugger, ReToolsError> {
    let tracer: Result<Debugger, ReToolsError> = {
        #[cfg(target_os = "linux")]
        {
            LinuxTracer::new(pid).map(|t| Box::new(t) as Debugger)
        }
        #[cfg(target_os = "windows")]
        {
            WindowsTracer::new(pid).map(|t| Box::new(t) as Debugger)
        }
        #[cfg(target_os = "macos")]
        {
            MacosTracer::new(pid).map(|t| Box::new(t) as Debugger)
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        {
            UnsupportedTracer::new(pid).map(|t| Box::new(t) as Debugger)
        }
    };
    match tracer {
        Ok(mut t) => {
            if let Err(e) = t.attach_sasaran() {
                set_err_last(e);
                return Err(ReToolsError::Generic(format!(
                    "Gagal attach ke PID {}",
                    pid
                )));
            }
            if let Err(e) = t.set_opsi_multithread() {
                set_err_last(e);
                t.detach_sasaran().ok();
                return Err(ReToolsError::Generic(format!(
                    "Gagal set options multithread untuk PID {}",
                    pid
                )));
            }
            Ok(t)
        }
        Err(e) => {
            set_err_last(e);
            Err(ReToolsError::Generic(format!(
                "Gagal membuat tracer untuk PID {}",
                pid
            )))
        }
    }
}