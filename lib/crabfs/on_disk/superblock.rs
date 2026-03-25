use crate::endian::{be_u16, be_u32, be_u64, le_u32, require_len};
use crate::error::ParseError;

pub const XFS_SB_MAGIC: u32 = 0x5846_5342;
pub const XFS_SB_VERSION_5: u16 = 5;

pub const XFS_SB_FEAT_RO_COMPAT_FINOBT: u32 = 1 << 0;
pub const XFS_SB_FEAT_RO_COMPAT_RMAPBT: u32 = 1 << 1;
pub const XFS_SB_FEAT_RO_COMPAT_REFLINK: u32 = 1 << 2;
pub const XFS_SB_FEAT_RO_COMPAT_INOBTCNT: u32 = 1 << 3;

pub const XFS_SB_FEAT_INCOMPAT_FTYPE: u32 = 1 << 0;
pub const XFS_SB_FEAT_INCOMPAT_SPINODES: u32 = 1 << 1;
pub const XFS_SB_FEAT_INCOMPAT_META_UUID: u32 = 1 << 2;
pub const XFS_SB_FEAT_INCOMPAT_BIGTIME: u32 = 1 << 3;
pub const XFS_SB_FEAT_INCOMPAT_NEEDSREPAIR: u32 = 1 << 4;

pub const XFS_DSB_SIZE: usize = 304;
pub const XFS_SB_CRC_OFF: usize = 224;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V5Fields {
    pub features_compat: u32,
    pub features_ro_compat: u32,
    pub features_incompat: u32,
    pub features_log_incompat: u32,
    pub crc: u32,
    pub sparse_inode_align: u32,
    pub pquotino: u64,
    pub lsn: u64,
    pub meta_uuid: [u8; 16],
    pub metadirino: u64,
    pub rgcount: u32,
    pub rgextents: u32,
    pub rgblklog: u8,
    pub rtstart: u64,
    pub rtreserved: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Superblock {
    pub block_size: u32,
    pub dblocks: u64,
    pub rblocks: u64,
    pub rextents: u64,
    pub uuid: [u8; 16],
    pub logstart: u64,
    pub rootino: u64,
    pub rbmino: u64,
    pub rsumino: u64,
    pub rextsize: u32,
    pub ag_blocks: u32,
    pub ag_count: u32,
    pub rbm_blocks: u32,
    pub log_blocks: u32,
    pub version: u16,
    pub sector_size: u16,
    pub inode_size: u16,
    pub inode_per_block: u16,
    pub fname: [u8; 12],
    pub block_log: u8,
    pub sect_log: u8,
    pub inode_log: u8,
    pub inopblog: u8,
    pub agblklog: u8,
    pub rextslog: u8,
    pub inprogress: bool,
    pub imax_pct: u8,
    pub icount: u64,
    pub ifree: u64,
    pub fdblocks: u64,
    pub frextents: u64,
    pub uquotino: u64,
    pub gquotino: u64,
    pub qflags: u16,
    pub flags: u8,
    pub shared_vn: u8,
    pub inoalignmt: u32,
    pub unit: u32,
    pub width: u32,
    pub log_sector_size: u16,
    pub log_sunit: u32,
    pub features2: u32,
    pub bad_features2: u32,
    pub v5: Option<V5Fields>,
}

impl Superblock {
    /// Parse a superblock from a byte slice.
    ///
    /// # Errors
    ///
    /// * `ParseError::InvalidMagic` - If the magic number is not valid.
    /// * `ParseError::InvalidField` - If the block size, sector size, or inode size is invalid.
    /// * `ParseError::InvalidLength` - If the byte slice is not the correct length.
    #[allow(clippy::too_many_lines)]
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        require_len(bytes, XFS_DSB_SIZE)?;

        let magic = be_u32(bytes, 0);
        if magic != XFS_SB_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: XFS_SB_MAGIC,
                actual: magic,
            });
        }

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[32..48]);

        let mut fname = [0u8; 12];
        fname.copy_from_slice(&bytes[108..120]);

        let version = be_u16(bytes, 100) & 0x000f;
        let block_size = be_u32(bytes, 4);
        let sector_size = be_u16(bytes, 102);
        let inode_size = be_u16(bytes, 104);

        if block_size == 0 {
            return Err(ParseError::InvalidField {
                field: "sb_blocksize",
                value: u64::from(block_size),
            });
        }
        if sector_size == 0 {
            return Err(ParseError::InvalidField {
                field: "sb_sectsize",
                value: u64::from(sector_size),
            });
        }
        if inode_size == 0 {
            return Err(ParseError::InvalidField {
                field: "sb_inodesize",
                value: u64::from(inode_size),
            });
        }

        let v5 = if version == XFS_SB_VERSION_5 {
            let mut meta_uuid = [0u8; 16];
            meta_uuid.copy_from_slice(&bytes[248..264]);
            Some(V5Fields {
                features_compat: be_u32(bytes, 208),
                features_ro_compat: be_u32(bytes, 212),
                features_incompat: be_u32(bytes, 216),
                features_log_incompat: be_u32(bytes, 220),
                crc: le_u32(bytes, 224),
                sparse_inode_align: be_u32(bytes, 228),
                pquotino: be_u64(bytes, 232),
                lsn: be_u64(bytes, 240),
                meta_uuid,
                metadirino: be_u64(bytes, 264),
                rgcount: be_u32(bytes, 272),
                rgextents: be_u32(bytes, 276),
                rgblklog: bytes[280],
                rtstart: be_u64(bytes, 288),
                rtreserved: be_u64(bytes, 296),
            })
        } else {
            None
        };

        Ok(Self {
            block_size,
            dblocks: be_u64(bytes, 8),
            rblocks: be_u64(bytes, 16),
            rextents: be_u64(bytes, 24),
            uuid,
            logstart: be_u64(bytes, 48),
            rootino: be_u64(bytes, 56),
            rbmino: be_u64(bytes, 64),
            rsumino: be_u64(bytes, 72),
            rextsize: be_u32(bytes, 80),
            ag_blocks: be_u32(bytes, 84),
            ag_count: be_u32(bytes, 88),
            rbm_blocks: be_u32(bytes, 92),
            log_blocks: be_u32(bytes, 96),
            version,
            sector_size,
            inode_size,
            inode_per_block: be_u16(bytes, 106),
            fname,
            block_log: bytes[120],
            sect_log: bytes[121],
            inode_log: bytes[122],
            inopblog: bytes[123],
            agblklog: bytes[124],
            rextslog: bytes[125],
            inprogress: bytes[126] != 0,
            imax_pct: bytes[127],
            icount: be_u64(bytes, 128),
            ifree: be_u64(bytes, 136),
            fdblocks: be_u64(bytes, 144),
            frextents: be_u64(bytes, 152),
            uquotino: be_u64(bytes, 160),
            gquotino: be_u64(bytes, 168),
            qflags: be_u16(bytes, 176),
            flags: bytes[178],
            shared_vn: bytes[179],
            inoalignmt: be_u32(bytes, 180),
            unit: be_u32(bytes, 184),
            width: be_u32(bytes, 188),
            log_sector_size: be_u16(bytes, 194),
            log_sunit: be_u32(bytes, 196),
            features2: be_u32(bytes, 200),
            bad_features2: be_u32(bytes, 204),
            v5,
        })
    }

    #[inline]
    #[must_use]
    pub fn is_v5(&self) -> bool {
        self.version == XFS_SB_VERSION_5
    }

    #[inline]
    #[must_use]
    pub fn has_incompat_feature(&self, feature: u32) -> bool {
        self.v5
            .is_some_and(|v| (v.features_incompat & feature) != 0)
    }

    #[inline]
    #[must_use]
    pub fn has_ro_compat_feature(&self, feature: u32) -> bool {
        self.v5
            .is_some_and(|v| (v.features_ro_compat & feature) != 0)
    }

    /// Serialize the superblock to a byte slice.
    ///
    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`] - If the byte slice is not long enough.
    pub fn serialize(&self, bytes: &mut [u8]) -> Result<(), ParseError> {
        use crate::endian::{put_be16, put_be32, put_be64};
        require_len(bytes, XFS_DSB_SIZE)?;

        put_be32(bytes, 0, XFS_SB_MAGIC);
        put_be32(bytes, 4, self.block_size);
        put_be64(bytes, 8, self.dblocks);
        put_be64(bytes, 16, self.rblocks);
        put_be64(bytes, 24, self.rextents);
        bytes[32..48].copy_from_slice(&self.uuid);
        put_be64(bytes, 48, self.logstart);
        put_be64(bytes, 56, self.rootino);
        put_be64(bytes, 64, self.rbmino);
        put_be64(bytes, 72, self.rsumino);
        put_be32(bytes, 80, self.rextsize);
        put_be32(bytes, 84, self.ag_blocks);
        put_be32(bytes, 88, self.ag_count);
        put_be32(bytes, 92, self.rbm_blocks);
        put_be32(bytes, 96, self.log_blocks);
        put_be16(bytes, 100, self.version);
        put_be16(bytes, 102, self.sector_size);
        put_be16(bytes, 104, self.inode_size);
        put_be16(bytes, 106, self.inode_per_block);
        bytes[108..120].copy_from_slice(&self.fname);
        bytes[120] = self.block_log;
        bytes[121] = self.sect_log;
        bytes[122] = self.inode_log;
        bytes[123] = self.inopblog;
        bytes[124] = self.agblklog;
        bytes[125] = self.rextslog;
        bytes[126] = u8::from(self.inprogress);
        bytes[127] = self.imax_pct;
        put_be64(bytes, 128, self.icount);
        put_be64(bytes, 136, self.ifree);
        put_be64(bytes, 144, self.fdblocks);
        put_be64(bytes, 152, self.frextents);
        put_be64(bytes, 160, self.uquotino);
        put_be64(bytes, 168, self.gquotino);
        put_be16(bytes, 176, self.qflags);
        bytes[178] = self.flags;
        bytes[179] = self.shared_vn;
        put_be32(bytes, 180, self.inoalignmt);
        put_be32(bytes, 184, self.unit);
        put_be32(bytes, 188, self.width);
        bytes[192] = 0; // dirblklog
        bytes[193] = 0; // logsectlog
        put_be16(bytes, 194, self.log_sector_size);
        put_be32(bytes, 196, self.log_sunit);
        put_be32(bytes, 200, self.features2);
        put_be32(bytes, 204, self.bad_features2);

        if let Some(v5) = &self.v5 {
            put_be32(bytes, 208, v5.features_compat);
            put_be32(bytes, 212, v5.features_ro_compat);
            put_be32(bytes, 216, v5.features_incompat);
            put_be32(bytes, 220, v5.features_log_incompat);
            // CRC is written later by write_xfs_crc
            put_be32(bytes, 228, v5.sparse_inode_align);
            put_be64(bytes, 232, v5.pquotino);
            put_be64(bytes, 240, v5.lsn);
            bytes[248..264].copy_from_slice(&v5.meta_uuid);
            put_be64(bytes, 264, v5.metadirino);
            put_be32(bytes, 272, v5.rgcount);
            put_be32(bytes, 276, v5.rgextents);
            bytes[280] = v5.rgblklog;
            put_be64(bytes, 288, v5.rtstart);
            put_be64(bytes, 296, v5.rtreserved);
        }

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
    fn put_be64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_be_bytes());
    }
    fn put_le32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn parse_v5_superblock() {
        let mut raw = [0u8; XFS_DSB_SIZE];
        put_be32(&mut raw, 0, XFS_SB_MAGIC);
        put_be32(&mut raw, 4, 4096);
        put_be64(&mut raw, 8, 1_000_000);
        put_be32(&mut raw, 84, 262_144);
        put_be32(&mut raw, 88, 4);
        put_be16(&mut raw, 100, XFS_SB_VERSION_5);
        put_be16(&mut raw, 102, 512);
        put_be16(&mut raw, 104, 512);
        raw[108..112].copy_from_slice(b"test");
        put_be32(&mut raw, 212, XFS_SB_FEAT_RO_COMPAT_RMAPBT);
        put_be32(&mut raw, 216, XFS_SB_FEAT_INCOMPAT_BIGTIME);
        put_le32(&mut raw, 224, 0x1234_5678);
        put_be64(&mut raw, 296, 12_345);

        let sb = Superblock::parse(&raw).expect("superblock should parse");
        assert!(sb.is_v5());
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.ag_count, 4);
        assert!(sb.has_ro_compat_feature(XFS_SB_FEAT_RO_COMPAT_RMAPBT));
        assert!(sb.has_incompat_feature(XFS_SB_FEAT_INCOMPAT_BIGTIME));
        assert_eq!(sb.v5.expect("v5 fields").crc, 0x1234_5678);
    }

    #[test]
    fn rejects_bad_magic() {
        let raw = [0u8; XFS_DSB_SIZE];
        let err = Superblock::parse(&raw).expect_err("bad magic should fail");
        assert!(matches!(err, ParseError::InvalidMagic { .. }));
    }

    #[test]
    fn rejects_short_buffer() {
        let raw = [0u8; XFS_DSB_SIZE - 1];
        let err = Superblock::parse(&raw).expect_err("short buffer should fail");
        assert!(matches!(err, ParseError::BufferTooSmall { .. }));
    }
}
