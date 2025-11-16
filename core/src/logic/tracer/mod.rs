#[cfg(target_os = "linux")]
pub mod platform_linux;
#[cfg(target_os = "macos")]
pub mod platform_macos;
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub mod platform_unsupported;
#[cfg(windows)]
pub mod platform_windows;
pub mod state;
pub mod types;