use std::fmt;


#[derive(Debug)]
pub enum ReToolsError {
    IoError(std::io::Error),
    ParseError(String),
    NulError(std::ffi::NulError),
    Utf8Error(std::str::Utf8Error),
    RegexError(regex::Error),
    CapstoneError(capstone::Error),
    YaraError(yara::Error),
    Generic(String),
}

impl fmt::Display for ReToolsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReToolsError::IoError(e) => write!(f, "IO Error: {}", e),
            ReToolsError::ParseError(s) => write!(f, "Parse Error: {}", s),
            ReToolsError::NulError(e) => write!(f, "FFI Nul Error: {}", e),
            ReToolsError::Utf8Error(e) => write!(f, "UTF-8 Error: {}", e),
            ReToolsError::RegexError(e) => write!(f, "Regex Error: {}", e),
            ReToolsError::CapstoneError(e) => write!(f, "Capstone Error: {}", e),
            ReToolsError::YaraError(e) => write!(f, "YARA Error: {}", e),
            ReToolsError::Generic(s) => write!(f, "Generic Error: {}", s),
        }
    }
}

impl std::error::Error for ReToolsError {}

impl From<std::io::Error> for ReToolsError {
    fn from(err: std::io::Error) -> ReToolsError {
        ReToolsError::IoError(err)
    }
}

impl From<std::ffi::NulError> for ReToolsError {
    fn from(err: std::ffi::NulError) -> ReToolsError {
        ReToolsError::NulError(err)
    }
}

impl From<std::str::Utf8Error> for ReToolsError {
    fn from(err: std::str::Utf8Error) -> ReToolsError {
        ReToolsError::Utf8Error(err)
    }
}

impl From<regex::Error> for ReToolsError {
    fn from(err: regex::Error) -> ReToolsError {
        ReToolsError::RegexError(err)
    }
}

impl From<capstone::Error> for ReToolsError {
    fn from(err: capstone::Error) -> ReToolsError {
        ReToolsError::CapstoneError(err)
    }
}

impl From<yara::Error> for ReToolsError {
    fn from(err: yara::Error) -> ReToolsError {
        ReToolsError::YaraError(err)
    }
}