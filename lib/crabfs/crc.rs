use crate::endian::le_u32;

pub const XFS_CRC_SEED: u32 = !0u32;

#[inline]
#[must_use]
pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        let mut i = 0;
        while i < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
            i += 1;
        }
    }
    crc
}

#[must_use]
pub fn verify_xfs_crc(bytes: &[u8], cksum_offset: usize) -> bool {
    if bytes.len() < cksum_offset + 4 {
        return false;
    }
    let mut crc = crc32c(XFS_CRC_SEED, &bytes[..cksum_offset]);
    crc = crc32c(crc, &[0u8; 4]);
    crc = crc32c(crc, &bytes[cksum_offset + 4..]);
    let expected = !crc;
    let actual = le_u32(bytes, cksum_offset);
    expected == actual
}

pub fn write_xfs_crc(bytes: &mut [u8], cksum_offset: usize) {
    use crate::endian::put_le32;
    if bytes.len() < cksum_offset + 4 {
        return;
    }
    put_le32(bytes, cksum_offset, 0);
    let mut crc = crc32c(XFS_CRC_SEED, &bytes[..cksum_offset]);
    crc = crc32c(crc, &[0u8; 4]);
    crc = crc32c(crc, &bytes[cksum_offset + 4..]);
    put_le32(bytes, cksum_offset, !crc);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_xfs_crc(buf: &mut [u8], off: usize) {
        buf[off..off + 4].copy_from_slice(&[0, 0, 0, 0]);
        let mut crc = crc32c(XFS_CRC_SEED, &buf[..off]);
        crc = crc32c(crc, &[0u8; 4]);
        crc = crc32c(crc, &buf[off + 4..]);
        let stored = (!crc).to_le_bytes();
        buf[off..off + 4].copy_from_slice(&stored);
    }

    #[test]
    fn verifies_crc() {
        let mut buf = [0u8; 128];
        let mut i = 0usize;
        while i < buf.len() {
            #[allow(clippy::cast_possible_truncation)]
            {
                buf[i] = (i as u8).wrapping_mul(7);
            }
            i += 1;
        }
        write_xfs_crc(&mut buf, 20);
        assert!(verify_xfs_crc(&buf, 20));
        buf[99] ^= 0x55;
        assert!(!verify_xfs_crc(&buf, 20));
    }
}
