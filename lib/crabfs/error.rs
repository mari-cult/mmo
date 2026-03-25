use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },
    #[error("invalid magic: expected 0x{expected:08x}, got 0x{actual:08x}")]
    InvalidMagic { expected: u32, actual: u32 },
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("invalid field {field}: {value}")]
    InvalidField { field: &'static str, value: u64 },
    #[error("crc mismatch in {what}")]
    CrcMismatch { what: &'static str },
    #[error("invalid integer conversion: {0}")]
    InvalidInt(core::num::TryFromIntError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DeviceError {
    #[error("I/O error")]
    Io,
    #[error("short read: expected {expected} bytes, got {actual}")]
    ShortRead { expected: usize, actual: usize },
    #[error("short write: expected {expected} bytes, got {actual}")]
    ShortWrite { expected: usize, actual: usize },
    #[error("offset out of range")]
    OutOfRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReadError {
    #[error("{0}")]
    Device(DeviceError),
    #[error("{0}")]
    Parse(ParseError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WriteError {
    #[error("{0}")]
    Device(DeviceError),
    #[error("{0}")]
    Parse(ParseError),
    #[error("{0}")]
    TryFromInt(core::num::TryFromIntError),
}

impl From<DeviceError> for ReadError {
    fn from(value: DeviceError) -> Self {
        Self::Device(value)
    }
}

impl From<ParseError> for ReadError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}

impl From<DeviceError> for WriteError {
    fn from(value: DeviceError) -> Self {
        Self::Device(value)
    }
}

impl From<ParseError> for WriteError {
    fn from(value: ParseError) -> Self {
        Self::Parse(value)
    }
}
