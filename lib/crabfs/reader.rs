use crate::crc::verify_xfs_crc;
use crate::device::BlockDevice;
use crate::error::{DeviceError, ParseError, ReadError};
use crate::on_disk::agf::{Agf, XFS_AGF_CRC_OFF, XFS_AGF_SIZE};
use crate::on_disk::agfl::{Agfl, XFS_AGFL_CRC_OFF};
use crate::on_disk::agi::{Agi, XFS_AGI_CRC_OFF, XFS_AGI_SIZE};
use crate::on_disk::bmap::BmapExtent;
use crate::on_disk::dir::{DirSfEntry, DirSfHeader};
use crate::on_disk::inobt::{InodeBtreeKind, InodeBtreeRoot, XFS_BTREE_SBLOCK_CRC_OFF};
use crate::on_disk::inode::{Inode, XFS_DINODE_CRC_OFF};
use crate::on_disk::superblock::{
    Superblock, XFS_DSB_SIZE, XFS_SB_CRC_OFF, XFS_SB_FEAT_INCOMPAT_FTYPE,
};
use alloc::string::{String, ToString};
use alloc::{vec, vec::Vec};

const XFS_MAX_SECTOR_SIZE: usize = 4096;

#[inline]
fn ag_start(sb: &Superblock, agno: u32) -> Result<u64, ReadError> {
    if agno >= sb.ag_count {
        return Err(ReadError::Device(DeviceError::OutOfRange));
    }
    let ag_blocks = u64::from(sb.ag_blocks);
    let block_size = u64::from(sb.block_size);
    Ok(u64::from(agno)
        .saturating_mul(ag_blocks)
        .saturating_mul(block_size))
}

fn ensure_sector_size(sector_size: u16) -> Result<usize, ReadError> {
    let size = sector_size as usize;
    if size > XFS_MAX_SECTOR_SIZE {
        return Err(ReadError::Parse(ParseError::InvalidField {
            field: "sector_size",
            value: size as u64,
        }));
    }
    Ok(size)
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_superblock<D: BlockDevice>(dev: &mut D) -> Result<Superblock, ReadError> {
    let mut raw = [0u8; XFS_DSB_SIZE];
    dev.read_at(0, &mut raw)?;
    let sb = Superblock::parse(&raw)?;

    if sb.is_v5() {
        let sector_size = ensure_sector_size(sb.sector_size)?;
        let mut sector = [0u8; XFS_MAX_SECTOR_SIZE];
        dev.read_at(0, &mut sector[..sector_size])?;
        if !verify_xfs_crc(&sector[..sector_size], XFS_SB_CRC_OFF) {
            return Err(ReadError::Parse(ParseError::CrcMismatch {
                what: "superblock",
            }));
        }
    }

    Ok(sb)
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_agf<D: BlockDevice>(dev: &mut D, sb: &Superblock, agno: u32) -> Result<Agf, ReadError> {
    let mut raw = [0u8; XFS_AGF_SIZE];
    let offset = ag_start(sb, agno)? + u64::from(sb.sector_size);
    dev.read_at(offset, &mut raw)?;
    let agf = Agf::parse(&raw)?;

    if sb.is_v5() {
        let sector_size = ensure_sector_size(sb.sector_size)?;
        let mut sector = [0u8; XFS_MAX_SECTOR_SIZE];
        dev.read_at(offset, &mut sector[..sector_size])?;
        if !verify_xfs_crc(&sector[..sector_size], XFS_AGF_CRC_OFF) {
            return Err(ReadError::Parse(ParseError::CrcMismatch { what: "agf" }));
        }
    }

    Ok(agf)
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_agi<D: BlockDevice>(dev: &mut D, sb: &Superblock, agno: u32) -> Result<Agi, ReadError> {
    let mut raw = [0u8; XFS_AGI_SIZE];
    let offset = ag_start(sb, agno)? + 2 * u64::from(sb.sector_size);
    dev.read_at(offset, &mut raw)?;
    let agi = Agi::parse(&raw)?;

    if sb.is_v5() {
        let sector_size = ensure_sector_size(sb.sector_size)?;
        let mut sector = [0u8; XFS_MAX_SECTOR_SIZE];
        dev.read_at(offset, &mut sector[..sector_size])?;
        if !verify_xfs_crc(&sector[..sector_size], XFS_AGI_CRC_OFF) {
            return Err(ReadError::Parse(ParseError::CrcMismatch { what: "agi" }));
        }
    }

    Ok(agi)
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_agfl<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    agno: u32,
) -> Result<Agfl, ReadError> {
    let sector_size = ensure_sector_size(sb.sector_size)?;
    let offset = ag_start(sb, agno)? + 3 * u64::from(sb.sector_size);
    let mut sector = [0u8; XFS_MAX_SECTOR_SIZE];
    dev.read_at(offset, &mut sector[..sector_size])?;

    if sb.is_v5() && !verify_xfs_crc(&sector[..sector_size], XFS_AGFL_CRC_OFF) {
        return Err(ReadError::Parse(ParseError::CrcMismatch { what: "agfl" }));
    }

    Ok(Agfl::parse(
        &sector[..sector_size],
        sb.sector_size,
        sb.is_v5(),
    )?)
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_inobt_root<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    agi: &Agi,
    agno: u32,
    scratch: &mut [u8],
) -> Result<InodeBtreeRoot, ReadError> {
    let blksz = sb.block_size as usize;
    if scratch.len() < blksz {
        return Err(ReadError::Device(DeviceError::ShortRead {
            expected: blksz,
            actual: scratch.len(),
        }));
    }
    let offset = ag_start(sb, agno)? + u64::from(agi.root) * u64::from(sb.block_size);
    dev.read_at(offset, &mut scratch[..blksz])?;
    if sb.is_v5() && !verify_xfs_crc(&scratch[..blksz], XFS_BTREE_SBLOCK_CRC_OFF) {
        return Err(ReadError::Parse(ParseError::CrcMismatch {
            what: "inobt root",
        }));
    }
    Ok(InodeBtreeRoot::parse(
        &scratch[..blksz],
        InodeBtreeKind::Inobt,
        sb.is_v5(),
    )?)
}

#[allow(clippy::similar_names)]
#[inline]
fn inode_offset(sb: &Superblock, ino: u64) -> Result<u64, ReadError> {
    #[allow(clippy::cast_possible_truncation)]
    let agno = (ino >> (u32::from(sb.agblklog) + u32::from(sb.inopblog))) as u32;
    let agbno = (ino >> sb.inopblog) & ((1u64 << sb.agblklog) - 1);
    let offset = (ino & ((1u64 << sb.inopblog) - 1)) * u64::from(sb.inode_size);

    Ok(ag_start(sb, agno)? + agbno * u64::from(sb.block_size) + offset)
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_inode<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    ino: u64,
    scratch: &mut [u8],
) -> Result<Inode, ReadError> {
    let inosz = sb.inode_size as usize;
    if scratch.len() < inosz {
        return Err(ReadError::Device(crate::error::DeviceError::ShortRead {
            expected: inosz,
            actual: scratch.len(),
        }));
    }

    let offset = inode_offset(sb, ino)?;
    dev.read_at(offset, &mut scratch[..inosz])?;

    if sb.is_v5() && !verify_xfs_crc(&scratch[..inosz], XFS_DINODE_CRC_OFF) {
        return Err(ReadError::Parse(ParseError::CrcMismatch { what: "inode" }));
    }

    Ok(Inode::parse(&scratch[..inosz])?)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u64,
    pub name: String,
    pub ftype: u8,
}

/// # Errors
///
/// * [`ReadError`]
pub fn list_dir_entries<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    ino_num: u64,
) -> Result<Vec<DirEntry>, ReadError> {
    let inosz = sb.inode_size as usize;
    let mut scratch = vec![0u8; inosz];
    let inode = read_inode(dev, sb, ino_num, &mut scratch)?;

    if (inode.mode & 0xf000) != 0x4000 {
        return Err(ReadError::Parse(ParseError::InvalidField {
            field: "mode",
            value: u64::from(inode.mode),
        }));
    }

    match inode.format {
        crate::on_disk::inode::InodeFormat::Local => {
            let data = &scratch[176..]; // After V3 header
            let (hdr, mut pos) = DirSfHeader::parse(data)?;
            let mut entries = Vec::new();

            // Root doesn't have a "real" parent in shortform if its parent is itself,
            // but XFS always stores it.
            entries.push(DirEntry {
                ino: ino_num,
                name: ".".to_string(),
                ftype: 2, // Directory
            });
            entries.push(DirEntry {
                ino: hdr.parent,
                name: "..".to_string(),
                ftype: 2, // Directory
            });

            let has_ftype = sb.has_incompat_feature(XFS_SB_FEAT_INCOMPAT_FTYPE);
            for _ in 0..hdr.count {
                let (entry, consumed) = DirSfEntry::parse(&data[pos..], hdr.i8count, has_ftype)?;
                entries.push(DirEntry {
                    ino: entry.inumber,
                    name: entry.name,
                    ftype: entry.ftype,
                });
                pos += consumed;
            }
            Ok(entries)
        }
        _ => {
            // TODO: implement Block/Extent formats
            Ok(vec![
                DirEntry {
                    ino: ino_num,
                    name: ".".to_string(),
                    ftype: 2,
                },
                DirEntry {
                    ino: ino_num, // Placeholder parent
                    name: "..".to_string(),
                    ftype: 2,
                },
            ])
        }
    }
}

fn extent_to_physical_offset(sb: &Superblock, ext: &BmapExtent) -> u64 {
    let ag_blocks = u64::from(sb.ag_blocks);
    let block_size = u64::from(sb.block_size);
    let agno = ext.startblock >> sb.agblklog;
    let agblk = ext.startblock & ((1u64 << sb.agblklog) - 1);
    (agno * ag_blocks + agblk) * block_size
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_file_data<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    ino_num: u64,
    offset: u64,
    size: u32,
) -> Result<Vec<u8>, ReadError> {
    let inosz = sb.inode_size as usize;
    let mut scratch = vec![0u8; inosz];
    let inode = read_inode(dev, sb, ino_num, &mut scratch)?;

    // Regular file (0x8000) or Symlink (0xa000)
    let mode_type = inode.mode & 0xf000;
    if mode_type != 0x8000 && mode_type != 0xa000 {
        return Ok(Vec::new());
    }

    match inode.format {
        crate::on_disk::inode::InodeFormat::Local => {
            let data = &scratch[176..];
            #[allow(clippy::cast_sign_loss)]
            let file_size = inode.size as u64;
            if offset >= file_size {
                return Ok(Vec::new());
            }
            let end = (offset + u64::from(size)).min(file_size);
            #[allow(clippy::cast_possible_truncation)]
            Ok(data[offset as usize..end as usize].to_vec())
        }
        crate::on_disk::inode::InodeFormat::Extents => {
            let fork = &scratch[176..];
            let mut extents = Vec::new();
            for i in 0..inode.nextents {
                #[allow(clippy::cast_possible_truncation)]
                let ext_bytes = &fork[i as usize * 16..];
                extents.push(BmapExtent::parse(ext_bytes)?);
            }

            let mut result = Vec::new();
            let mut remaining = u64::from(size);
            let mut current_off = offset;
            #[allow(clippy::cast_sign_loss)]
            let file_size = inode.size as u64;

            if current_off >= file_size {
                return Ok(Vec::new());
            }
            remaining = remaining.min(file_size - current_off);

            for ext in extents {
                let ext_start_bytes = ext.startoff * u64::from(sb.block_size);
                let ext_len_bytes = u64::from(ext.blockcount) * u64::from(sb.block_size);

                if current_off >= ext_start_bytes && current_off < ext_start_bytes + ext_len_bytes {
                    let in_ext_off = current_off - ext_start_bytes;
                    let to_read = (ext_len_bytes - in_ext_off).min(remaining);

                    let phy_off = extent_to_physical_offset(sb, &ext) + in_ext_off;
                    #[allow(clippy::cast_possible_truncation)]
                    let mut buf = vec![0u8; to_read as usize];
                    dev.read_at(phy_off, &mut buf)?;
                    result.extend_from_slice(&buf);

                    remaining -= to_read;
                    current_off += to_read;
                    if remaining == 0 {
                        break;
                    }
                }
            }
            Ok(result)
        }
        _ => Ok(Vec::new()),
    }
}

/// # Errors
///
/// * [`ReadError`]
pub fn read_finobt_root<D: BlockDevice>(
    dev: &mut D,
    sb: &Superblock,
    agi: &Agi,
    agno: u32,
    scratch: &mut [u8],
) -> Result<InodeBtreeRoot, ReadError> {
    let blksz = sb.block_size as usize;
    if scratch.len() < blksz {
        return Err(ReadError::Device(DeviceError::ShortRead {
            expected: blksz,
            actual: scratch.len(),
        }));
    }
    let offset = ag_start(sb, agno)? + u64::from(agi.free_root) * u64::from(sb.block_size);
    dev.read_at(offset, &mut scratch[..blksz])?;
    if sb.is_v5() && !verify_xfs_crc(&scratch[..blksz], XFS_BTREE_SBLOCK_CRC_OFF) {
        return Err(ReadError::Parse(ParseError::CrcMismatch {
            what: "finobt root",
        }));
    }
    Ok(InodeBtreeRoot::parse(
        &scratch[..blksz],
        InodeBtreeKind::Finobt,
        sb.is_v5(),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DeviceError;
    use crate::on_disk::agf::XFS_AGF_MAGIC;
    use crate::on_disk::agi::{XFS_AGI_MAGIC, XFS_AGI_VERSION};
    use crate::on_disk::superblock::{XFS_SB_MAGIC, XFS_SB_VERSION_5};

    struct MockDevice {
        data: [u8; 4096],
        last_offset: u64,
    }

    impl BlockDevice for MockDevice {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
            self.last_offset = offset;
            let start = usize::try_from(offset).unwrap();
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(DeviceError::OutOfRange);
            }
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), DeviceError> {
            self.last_offset = offset;
            let start = usize::try_from(offset).unwrap();
            let end = start + buf.len();
            if end > self.data.len() {
                return Err(DeviceError::OutOfRange);
            }
            self.data[start..end].copy_from_slice(buf);
            Ok(())
        }
    }

    fn put_be16(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_be_bytes());
    }
    fn put_be32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn mock_fs() -> MockDevice {
        let mut data = [0u8; 4096];
        put_be32(&mut data, 0, XFS_SB_MAGIC);
        put_be32(&mut data, 4, 4096);
        put_be32(&mut data, 84, 100);
        put_be32(&mut data, 88, 2);
        put_be16(&mut data, 100, XFS_SB_VERSION_5);
        put_be16(&mut data, 102, 512);
        put_be16(&mut data, 104, 512);

        put_be32(&mut data, 512, XFS_AGF_MAGIC);
        put_be32(&mut data, 516, 1);
        put_be32(&mut data, 520, 0);
        put_be32(&mut data, 524, 100);
        put_be32(&mut data, 564, 77);
        put_be32(&mut data, 568, 88);

        put_be32(&mut data, 1024, XFS_AGI_MAGIC);
        put_be32(&mut data, 1028, XFS_AGI_VERSION);
        put_be32(&mut data, 1032, 0);
        put_be32(&mut data, 1036, 100);
        put_be32(&mut data, 1040, 12);
        put_be32(&mut data, 1052, 5);
        put_be32(&mut data, 1352, 6);
        put_be32(&mut data, 1360, 8);
        put_be32(&mut data, 1364, 9);

        MockDevice {
            data,
            last_offset: 0,
        }
    }

    #[test]
    fn parse_errors_are_wrapped() {
        let mut dev = MockDevice {
            data: [0u8; 4096],
            last_offset: 0,
        };
        let err = read_superblock(&mut dev).expect_err("should fail");
        assert!(matches!(err, ReadError::Parse(_)));
    }

    #[test]
    fn ag_out_of_range() {
        let mut dev = mock_fs();
        let sb = Superblock {
            block_size: 4096,
            dblocks: 0,
            rblocks: 0,
            rextents: 0,
            uuid: [0u8; 16],
            logstart: 0,
            rootino: 0,
            rbmino: 0,
            rsumino: 0,
            rextsize: 0,
            ag_blocks: 100,
            ag_count: 2,
            rbm_blocks: 0,
            log_blocks: 0,
            version: 4,
            sector_size: 512,
            inode_size: 512,
            inode_per_block: 8,
            fname: [0u8; 12],
            block_log: 12,
            sect_log: 9,
            inode_log: 9,
            inopblog: 3,
            agblklog: 7,
            rextslog: 0,
            inprogress: false,
            imax_pct: 25,
            icount: 0,
            ifree: 0,
            fdblocks: 0,
            frextents: 0,
            uquotino: 0,
            gquotino: 0,
            qflags: 0,
            flags: 0,
            shared_vn: 0,
            inoalignmt: 0,
            unit: 0,
            width: 0,
            log_sector_size: 0,
            log_sunit: 0,
            features2: 0,
            bad_features2: 0,
            v5: None,
        };
        let err = read_agf(&mut dev, &sb, 2).expect_err("out of range");
        assert!(matches!(err, ReadError::Device(DeviceError::OutOfRange)));
    }
}
