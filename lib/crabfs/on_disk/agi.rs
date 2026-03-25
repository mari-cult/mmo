use crate::endian::{be_u32, be_u64};
use crate::error::ParseError;

pub const XFS_AGI_MAGIC: u32 = 0x5841_4749;
pub const XFS_AGI_VERSION: u32 = 1;
pub const XFS_AGI_UNLINKED_BUCKETS: usize = 64;
pub const XFS_AGI_SIZE: usize = 344;
pub const XFS_AGI_CRC_OFF: usize = 312;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agi {
    pub seqno: u32,
    pub length: u32,
    pub count: u32,
    pub root: u32,
    pub level: u32,
    pub freecount: u32,
    pub newino: u32,
    pub dirino: u32,
    pub unlinked: [u32; XFS_AGI_UNLINKED_BUCKETS],
    pub uuid: [u8; 16],
    pub crc: u32,
    pub lsn: u64,
    pub free_root: u32,
    pub free_level: u32,
    pub iblocks: u32,
    pub fblocks: u32,
}

impl Agi {
    /// Parse an agi from a byte slice.
    ///
    /// # Errors
    ///
    /// * `ParseError::InvalidMagic` - If the magic number is not valid.
    /// * `ParseError::InvalidLength` - If the byte slice is not the correct length.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        {
            if bytes.len() < XFS_AGI_SIZE {
                return Err(ParseError::BufferTooSmall {
                    expected: XFS_AGI_SIZE,
                    actual: bytes.len(),
                });
            }
            Ok(())
        }?;

        let magic = be_u32(bytes, 0);
        if magic != XFS_AGI_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: XFS_AGI_MAGIC,
                actual: magic,
            });
        }

        let version = be_u32(bytes, 4);
        if version != XFS_AGI_VERSION {
            return Err(ParseError::UnsupportedVersion(version));
        }

        let mut unlinked = [0u32; XFS_AGI_UNLINKED_BUCKETS];
        let mut off = 40usize;
        let mut i = 0usize;
        while i < XFS_AGI_UNLINKED_BUCKETS {
            unlinked[i] = be_u32(bytes, off);
            off += 4;
            i += 1;
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[296..312]);

        Ok(Self {
            seqno: be_u32(bytes, 8),
            length: be_u32(bytes, 12),
            count: be_u32(bytes, 16),
            root: be_u32(bytes, 20),
            level: be_u32(bytes, 24),
            freecount: be_u32(bytes, 28),
            newino: be_u32(bytes, 32),
            dirino: be_u32(bytes, 36),
            unlinked,
            uuid,
            crc: be_u32(bytes, 312),
            lsn: be_u64(bytes, 320),
            free_root: be_u32(bytes, 328),
            free_level: be_u32(bytes, 332),
            iblocks: be_u32(bytes, 336),
            fblocks: be_u32(bytes, 340),
        })
    }

    /// Serialize the AGI to a byte slice.
    ///
    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`] - If the byte slice is not long enough.
    pub fn serialize(&self, bytes: &mut [u8]) -> Result<(), ParseError> {
        use crate::endian::{put_be32, put_be64, require_len};
        require_len(bytes, XFS_AGI_SIZE)?;

        put_be32(bytes, 0, XFS_AGI_MAGIC);
        put_be32(bytes, 4, XFS_AGI_VERSION);
        put_be32(bytes, 8, self.seqno);
        put_be32(bytes, 12, self.length);
        put_be32(bytes, 16, self.count);
        put_be32(bytes, 20, self.root);
        put_be32(bytes, 24, self.level);
        put_be32(bytes, 28, self.freecount);
        put_be32(bytes, 32, self.newino);
        put_be32(bytes, 36, self.dirino);

        let mut off = 40;
        for &val in &self.unlinked {
            put_be32(bytes, off, val);
            off += 4;
        }

        bytes[296..312].copy_from_slice(&self.uuid);
        // CRC at 312
        put_be64(bytes, 320, self.lsn);
        put_be32(bytes, 328, self.free_root);
        put_be32(bytes, 332, self.free_level);
        put_be32(bytes, 336, self.iblocks);
        put_be32(bytes, 340, self.fblocks);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_be32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_be_bytes());
    }
    fn put_be64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn parse_valid_agi() {
        let mut raw = [0u8; XFS_AGI_SIZE];
        put_be32(&mut raw, 0, XFS_AGI_MAGIC);
        put_be32(&mut raw, 4, XFS_AGI_VERSION);
        put_be32(&mut raw, 8, 2);
        put_be32(&mut raw, 12, 262_144);
        put_be32(&mut raw, 16, 1000);
        put_be32(&mut raw, 20, 8);
        put_be32(&mut raw, 24, 3);
        put_be32(&mut raw, 28, 150);
        put_be32(&mut raw, 40, 55);
        put_be64(&mut raw, 320, 0x1234);
        put_be32(&mut raw, 328, 9);
        put_be32(&mut raw, 332, 2);
        put_be32(&mut raw, 336, 77);
        put_be32(&mut raw, 340, 11);

        let agi = Agi::parse(&raw).expect("agi should parse");
        assert_eq!(agi.seqno, 2);
        assert_eq!(agi.length, 262_144);
        assert_eq!(agi.count, 1000);
        assert_eq!(agi.freecount, 150);
        assert_eq!(agi.unlinked[0], 55);
        assert_eq!(agi.free_root, 9);
        assert_eq!(agi.iblocks, 77);
        assert_eq!(agi.fblocks, 11);
    }

    #[test]
    fn rejects_invalid_magic() {
        let raw = [0u8; XFS_AGI_SIZE];
        let err = Agi::parse(&raw).expect_err("magic should fail");
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn rejects_invalid_version() {
        let mut raw = [0u8; XFS_AGI_SIZE];
        put_be32(&mut raw, 0, XFS_AGI_MAGIC);
        put_be32(&mut raw, 4, 2);
        let err = Agi::parse(&raw).expect_err("version should fail");
        assert!(matches!(err, ParseError::UnsupportedVersion(2)));
    }

    #[test]
    fn rejects_short_buffer() {
        let raw = [0u8; XFS_AGI_SIZE - 1];
        let err = Agi::parse(&raw).expect_err("short read should fail");
        assert!(matches!(err, ParseError::BufferTooSmall { .. }));
    }
}
