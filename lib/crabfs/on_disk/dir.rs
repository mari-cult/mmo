use crate::endian::{be_u16, be_u32, be_u64, require_len};
use crate::error::ParseError;
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirSfHeader {
    pub count: u8,
    pub i8count: u8,
    pub parent: u64,
}

impl DirSfHeader {
    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`]
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), ParseError> {
        require_len(bytes, 3)?;
        let count = bytes[0];
        let i8count = bytes[1];
        let (parent, consumed) = if i8count == 0 {
            require_len(bytes, 6)?;
            (u64::from(be_u32(bytes, 2)), 6)
        } else {
            require_len(bytes, 10)?;
            (be_u64(bytes, 2), 10)
        };
        Ok((
            Self {
                count,
                i8count,
                parent,
            },
            consumed,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirSfEntry {
    pub namelen: u8,
    pub offset: u16,
    pub name: String,
    pub ftype: u8,
    pub inumber: u64,
}

impl DirSfEntry {
    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`]
    pub fn parse(bytes: &[u8], i8count: u8, has_ftype: bool) -> Result<(Self, usize), ParseError> {
        require_len(bytes, 3)?;
        let namelen = bytes[0];
        let offset = be_u16(bytes, 1);
        let mut pos = 3;
        require_len(bytes, pos + namelen as usize)?;
        let name = String::from_utf8_lossy(&bytes[pos..pos + namelen as usize]).into_owned();
        pos += namelen as usize;
        let ftype = if has_ftype {
            require_len(bytes, pos + 1)?;
            let f = bytes[pos];
            pos += 1;
            f
        } else {
            0
        };
        let (inumber, inosize) = if i8count == 0 {
            require_len(bytes, pos + 4)?;
            (u64::from(be_u32(bytes, pos)), 4)
        } else {
            require_len(bytes, pos + 8)?;
            (be_u64(bytes, pos), 8)
        };
        pos += inosize;
        Ok((
            Self {
                namelen,
                offset,
                name,
                ftype,
                inumber,
            },
            pos,
        ))
    }
}
