#[cfg(target_os = "linux")]
pub mod platform_linux;
#[cfg(not(any(target_os = "linux", windows)))]
pub mod platform_unsupported;
#[cfg(windows)]
pub mod platform_windows;
pub mod state;
pub mod types;