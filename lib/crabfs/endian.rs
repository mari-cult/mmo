use crate::error::ParseError;

/// Ensures that the byte slice is long enough.
///
/// # Errors
///
/// This function will return an error if the byte slice is not long enough.
#[inline]
pub fn require_len(bytes: &[u8], min_len: usize) -> Result<(), ParseError> {
    if bytes.len() < min_len {
        return Err(ParseError::BufferTooSmall {
            expected: min_len,
            actual: bytes.len(),
        });
    }
    Ok(())
}

#[inline]
#[must_use]
pub fn be_u16(bytes: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([bytes[off], bytes[off + 1]])
}

#[inline]
pub fn put_be16(bytes: &mut [u8], off: usize, val: u16) {
    bytes[off..off + 2].copy_from_slice(&val.to_be_bytes());
}

#[inline]
#[must_use]
pub fn be_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

#[inline]
pub fn put_be32(bytes: &mut [u8], off: usize, val: u32) {
    bytes[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

#[inline]
#[must_use]
pub fn be_u64(bytes: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

#[inline]
pub fn put_be64(bytes: &mut [u8], off: usize, val: u64) {
    bytes[off..off + 8].copy_from_slice(&val.to_be_bytes());
}

#[inline]
#[must_use]
pub fn le_u32(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

#[inline]
pub fn put_le32(bytes: &mut [u8], off: usize, val: u32) {
    bytes[off..off + 4].copy_from_slice(&val.to_le_bytes());
}
