use crate::endian::{be_u16, be_u32, be_u64, put_be16, put_be32, put_be64, require_len};
use crate::error::ParseError;

pub const XFS_DINODE_MAGIC: u16 = 0x494e;
pub const XFS_DINODE_SIZE_V3: usize = 176;
pub const XFS_DINODE_CRC_OFF: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeFormat {
    Dev,
    Local,
    Extents,
    Btree,
    Uuid,
}

impl InodeFormat {
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Dev,
            1 => Self::Local,
            2 => Self::Extents,
            3 => Self::Btree,
            _ => Self::Uuid,
        }
    }

    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Dev => 0,
            Self::Local => 1,
            Self::Extents => 2,
            Self::Btree => 3,
            Self::Uuid => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inode {
    pub magic: u16,
    pub mode: u16,
    pub version: u8,
    pub format: InodeFormat,
    pub onlink: u16, // V1/V2 link count
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,  // V3 link count
    pub projid: u32, // Combined projid_lo/hi
    pub flushiter: u16,
    pub atime: (i32, u32),
    pub mtime: (i32, u32),
    pub ctime: (i32, u32),
    pub size: i64,
    pub nblocks: u64,
    pub extsize: u32,
    pub nextents: u32,
    pub anextents: u16,
    pub forkoff: u8,
    pub aformat: InodeFormat,
    pub dmevmask: u32,
    pub dmstate: u16,
    pub flags: u16,
    pub generation: u32,
    pub next_unlinked: u32,

    // V3 fields
    pub crc: u32,
    pub change_count: u64,
    pub lsn: u64,
    pub flags2: u64,
    pub cowextsize: u32,
    pub crtime: (i32, u32),
    pub ino: u64,
    pub uuid: [u8; 16],
}

impl Inode {
    /// # Errors
    ///
    /// * [`ParseError::InvalidMagic`]
    /// * [`ParseError::BufferTooSmall`]
    ///
    /// # Panics
    ///
    /// * If the `meta_uuid` slice is not 16 bytes.
    #[allow(clippy::cast_possible_wrap)]
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        require_len(bytes, XFS_DINODE_SIZE_V3)?;

        let magic = be_u16(bytes, 0);
        if magic != XFS_DINODE_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: u32::from(XFS_DINODE_MAGIC),
                actual: u32::from(magic),
            });
        }

        let projid_lo = be_u16(bytes, 20);
        let projid_hi = be_u16(bytes, 22);
        let projid = (u32::from(projid_hi) << 16) | u32::from(projid_lo);

        Ok(Self {
            magic,
            mode: be_u16(bytes, 2),
            version: bytes[4],
            format: InodeFormat::from_u8(bytes[5]),
            onlink: be_u16(bytes, 6),
            uid: be_u32(bytes, 8),
            gid: be_u32(bytes, 12),
            nlink: be_u32(bytes, 16),
            projid,
            flushiter: be_u16(bytes, 30),
            atime: (be_u32(bytes, 32) as i32, be_u32(bytes, 36)),
            mtime: (be_u32(bytes, 40) as i32, be_u32(bytes, 44)),
            ctime: (be_u32(bytes, 48) as i32, be_u32(bytes, 52)),
            size: be_u64(bytes, 56) as i64,
            nblocks: be_u64(bytes, 64),
            extsize: be_u32(bytes, 72),
            nextents: be_u32(bytes, 76),
            anextents: be_u16(bytes, 80),
            forkoff: bytes[82],
            aformat: InodeFormat::from_u8(bytes[83]),
            dmevmask: be_u32(bytes, 84),
            dmstate: be_u16(bytes, 88),
            flags: be_u16(bytes, 90),
            generation: be_u32(bytes, 92),
            next_unlinked: be_u32(bytes, 96),
            crc: u32::from_le_bytes([bytes[100], bytes[101], bytes[102], bytes[103]]),
            change_count: be_u64(bytes, 104),
            lsn: be_u64(bytes, 112),
            flags2: be_u64(bytes, 120),
            cowextsize: be_u32(bytes, 128),
            crtime: (be_u32(bytes, 144) as i32, be_u32(bytes, 148)),
            ino: be_u64(bytes, 152),
            uuid: bytes[160..176].try_into().unwrap(),
        })
    }

    /// # Errors
    ///
    /// * [`ParseError::BufferTooSmall`]
    #[allow(clippy::cast_sign_loss)]
    pub fn serialize(&self, bytes: &mut [u8]) -> Result<(), ParseError> {
        require_len(bytes, XFS_DINODE_SIZE_V3)?;

        put_be16(bytes, 0, self.magic);
        put_be16(bytes, 2, self.mode);
        bytes[4] = self.version;
        bytes[5] = self.format.to_u8();
        put_be16(bytes, 6, self.onlink);
        put_be32(bytes, 8, self.uid);
        put_be32(bytes, 12, self.gid);
        put_be32(bytes, 16, self.nlink);
        put_be16(bytes, 20, (self.projid & 0xffff) as u16);
        put_be16(bytes, 22, (self.projid >> 16) as u16);
        // padding at 24..30
        bytes[24..30].fill(0);
        put_be16(bytes, 30, self.flushiter);
        put_be32(bytes, 32, self.atime.0 as u32);
        put_be32(bytes, 36, self.atime.1);
        put_be32(bytes, 40, self.mtime.0 as u32);
        put_be32(bytes, 44, self.mtime.1);
        put_be32(bytes, 48, self.ctime.0 as u32);
        put_be32(bytes, 52, self.ctime.1);
        put_be64(bytes, 56, self.size as u64);
        put_be64(bytes, 64, self.nblocks);
        put_be32(bytes, 72, self.extsize);
        put_be32(bytes, 76, self.nextents);
        put_be16(bytes, 80, self.anextents);
        bytes[82] = self.forkoff;
        bytes[83] = self.aformat.to_u8();
        put_be32(bytes, 84, self.dmevmask);
        put_be16(bytes, 88, self.dmstate);
        put_be16(bytes, 90, self.flags);
        put_be32(bytes, 92, self.generation);
        put_be32(bytes, 96, self.next_unlinked);
        // CRC at 100 written later
        put_be64(bytes, 104, self.change_count);
        put_be64(bytes, 112, self.lsn);
        put_be64(bytes, 120, self.flags2);
        put_be32(bytes, 128, self.cowextsize);
        // padding at 132..144
        bytes[132..144].fill(0);
        put_be32(bytes, 144, self.crtime.0 as u32);
        put_be32(bytes, 148, self.crtime.1);
        put_be64(bytes, 152, self.ino);
        bytes[160..176].copy_from_slice(&self.uuid);

        Ok(())
    }
}
