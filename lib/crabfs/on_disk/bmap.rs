use crate::endian::{be_u64, require_len};
use crate::error::ParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BmapExtent {
    pub state: u8,
    pub startoff: u64,
    pub startblock: u64,
    pub blockcount: u32,
}

impl BmapExtent {
    pub const SIZE: usize = 16;

    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`]
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        require_len(bytes, Self::SIZE)?;
        let x0 = be_u64(bytes, 0);
        let x1 = be_u64(bytes, 8);

        let state = (x0 >> 63) as u8;
        let startoff = (x0 & 0x7fff_ffff_ffff_ffff) >> 9;
        let startblock = ((x0 & 0x1ff) << 43) | (x1 >> 21);
        let blockcount = (x1 & 0x1f_ffff) as u32;

        Ok(Self {
            state,
            startoff,
            startblock,
            blockcount,
        })
    }
}
