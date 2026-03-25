use crate::endian::{be_u16, be_u32, be_u64};
use crate::error::ParseError;

pub const XFS_IBT_MAGIC: u32 = 0x4941_4254;
pub const XFS_IBT_CRC_MAGIC: u32 = 0x4941_4233;
pub const XFS_FIBT_MAGIC: u32 = 0x4649_4254;
pub const XFS_FIBT_CRC_MAGIC: u32 = 0x4649_4233;
pub const XFS_BTREE_SBLOCK_CRC_OFF: usize = 52;
pub const XFS_BTREE_SBLOCK_CRC_LEN: usize = 56;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeBtreeKind {
    Inobt,
    Finobt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeBtreeRoot {
    pub kind: InodeBtreeKind,
    pub magic: u32,
    pub level: u16,
    pub numrecs: u16,
    pub leftsib: u32,
    pub rightsib: u32,
    pub blkno: u64,
    pub lsn: u64,
    pub uuid: [u8; 16],
    pub owner: u32,
    pub crc: u32,
}

impl InodeBtreeRoot {
    /// Parse an inobt or finobt root from a byte slice.
    ///
    /// # Errors
    ///
    /// * `ParseError::UnsupportedVersion` - If the version is not supported.
    /// * `ParseError::InvalidMagic` - If the magic number is not valid.
    /// * `ParseError::InvalidLength` - If the byte slice is not the correct length.
    pub fn parse(
        bytes: &[u8],
        kind: InodeBtreeKind,
        crc_enabled: bool,
    ) -> Result<Self, ParseError> {
        if !crc_enabled {
            return Err(ParseError::UnsupportedVersion(4));
        }
        {
            if bytes.len() < XFS_BTREE_SBLOCK_CRC_LEN {
                return Err(ParseError::BufferTooSmall {
                    expected: XFS_BTREE_SBLOCK_CRC_LEN,
                    actual: bytes.len(),
                });
            }
            Ok(())
        }?;

        let magic = be_u32(bytes, 0);
        let expected = match kind {
            InodeBtreeKind::Inobt => XFS_IBT_CRC_MAGIC,
            InodeBtreeKind::Finobt => XFS_FIBT_CRC_MAGIC,
        };
        if magic != expected {
            return Err(ParseError::InvalidMagic {
                expected,
                actual: magic,
            });
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[32..48]);

        Ok(Self {
            kind,
            magic,
            level: be_u16(bytes, 4),
            numrecs: be_u16(bytes, 6),
            leftsib: be_u32(bytes, 8),
            rightsib: be_u32(bytes, 12),
            blkno: be_u64(bytes, 16),
            lsn: be_u64(bytes, 24),
            uuid,
            owner: be_u32(bytes, 48),
            crc: u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]),
        })
    }

    /// Serialize the btree root to a byte slice.
    ///
    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`] - If the byte slice is not long enough.
    pub fn serialize(&self, bytes: &mut [u8]) -> Result<(), ParseError> {
        use crate::endian::{put_be16, put_be32, put_be64, require_len};
        require_len(bytes, XFS_BTREE_SBLOCK_CRC_LEN)?;

        put_be32(bytes, 0, self.magic);
        put_be16(bytes, 4, self.level);
        put_be16(bytes, 6, self.numrecs);
        put_be32(bytes, 8, self.leftsib);
        put_be32(bytes, 12, self.rightsib);
        put_be64(bytes, 16, self.blkno);
        put_be64(bytes, 24, self.lsn);
        bytes[32..48].copy_from_slice(&self.uuid);
        put_be32(bytes, 48, self.owner);
        // CRC at 52 is written later

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_be16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_be_bytes());
    }
    fn put_be32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn parse_inobt_crc_header() {
        let mut raw = [0u8; XFS_BTREE_SBLOCK_CRC_LEN];
        put_be32(&mut raw, 0, XFS_IBT_CRC_MAGIC);
        put_be16(&mut raw, 4, 1);
        put_be16(&mut raw, 6, 3);
        put_be32(&mut raw, 8, 0xffff_ffff);
        put_be32(&mut raw, 12, 2);
        put_be32(&mut raw, 48, 0);
        let root = InodeBtreeRoot::parse(&raw, InodeBtreeKind::Inobt, true).expect("parse");
        assert_eq!(root.level, 1);
        assert_eq!(root.numrecs, 3);
        assert_eq!(root.rightsib, 2);
    }
}
