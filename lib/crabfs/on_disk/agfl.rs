use crate::endian::{be_u32, be_u64};
use crate::error::ParseError;

pub const XFS_AGFL_MAGIC: u32 = 0x5841_464c;
pub const XFS_AGFL_HEADER_SIZE: usize = 36;
pub const XFS_AGFL_CRC_OFF: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agfl {
    pub magicnum: u32,
    pub seqno: u32,
    pub uuid: [u8; 16],
    pub lsn: u64,
    pub crc: u32,
    pub entries_total: u32,
}

impl Agfl {
    /// Parse an agfl from a byte slice.
    ///
    /// # Errors
    ///
    /// * `ParseError::InvalidMagic` - If the magic number is not valid.
    /// * `ParseError::InvalidLength` - If the byte slice is not the correct length.
    pub fn parse(bytes: &[u8], sector_size: u16, crc_enabled: bool) -> Result<Self, ParseError> {
        let sector_size = sector_size as usize;
        {
            if bytes.len() < sector_size {
                return Err(ParseError::BufferTooSmall {
                    expected: sector_size,
                    actual: bytes.len(),
                });
            }
            Ok(())
        }?;
        {
            if bytes.len() < XFS_AGFL_HEADER_SIZE {
                return Err(ParseError::BufferTooSmall {
                    expected: XFS_AGFL_HEADER_SIZE,
                    actual: bytes.len(),
                });
            }
            Ok(())
        }?;

        let magic = be_u32(bytes, 0);
        if magic != XFS_AGFL_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: XFS_AGFL_MAGIC,
                actual: magic,
            });
        }

        let entries_bytes = if crc_enabled {
            sector_size.saturating_sub(XFS_AGFL_HEADER_SIZE)
        } else {
            sector_size
        };
        let entries_total = u32::try_from(entries_bytes / 4).map_err(ParseError::InvalidInt)?;

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[8..24]);

        Ok(Self {
            magicnum: magic,
            seqno: be_u32(bytes, 4),
            uuid,
            lsn: be_u64(bytes, 24),
            crc: be_u32(bytes, 32),
            entries_total,
        })
    }

    /// Serialize the AGFL to a byte slice.
    ///
    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`] - If the byte slice is not long enough.
    pub fn serialize(&self, bytes: &mut [u8], crc_enabled: bool) -> Result<(), ParseError> {
        if crc_enabled {
            use crate::endian::{put_be32, put_be64, require_len};
            require_len(bytes, XFS_AGFL_HEADER_SIZE)?;

            put_be32(bytes, 0, XFS_AGFL_MAGIC);
            put_be32(bytes, 4, self.seqno);
            bytes[8..24].copy_from_slice(&self.uuid);
            put_be64(bytes, 24, self.lsn);
            // CRC at 32 is written later
        } else {
            // For V4, there is no header, just entries.
            // We don't need to do anything here as mkfs starts with empty AGFL.
        }
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
    fn parse_agfl_header() {
        let mut raw = [0u8; 512];
        put_be32(&mut raw, 0, XFS_AGFL_MAGIC);
        put_be32(&mut raw, 4, 7);
        put_be64(&mut raw, 24, 0x1234);
        put_be32(&mut raw, 32, 0xabcd_ef01);
        let agfl = Agfl::parse(&raw, 512, true).expect("agfl parse");
        assert_eq!(agfl.seqno, 7);
        assert_eq!(agfl.lsn, 0x1234);
        assert_eq!(
            agfl.entries_total,
            u32::try_from(512 - XFS_AGFL_HEADER_SIZE).expect("agfl entries_total") / 4,
        );
    }
}
