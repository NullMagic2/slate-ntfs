//! Module: ntfs_rs::boot
//! Purpose: Parse NTFS boot sectors and validate volume geometry.
//! Created: 2026-10-01
//! Architecture: Readers and writers use the checked sector, cluster and MFT dimensions.

use super::bytes::{nonzero_power_of_two, range, u16_at, u64_at, u8_at};
use super::{Error, Result};

/// Bytes of the boot sector proper, independent of the volume's sector size.
pub const BOOT_SECTOR_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootSector {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u32,
    pub cluster_bytes: u32,
    pub total_sectors: u64,
    pub mft_lcn: u64,
    pub mft_mirror_lcn: u64,
    pub record_bytes: u32,
    pub index_block_bytes: u32,
    pub serial_number: u64,
}

impl BootSector {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 512 {
            return Err(Error::Truncated);
        }
        if range(data, 3, 8)? != b"NTFS    " || range(data, 510, 2)? != [0x55, 0xaa] {
            return Err(Error::InvalidBoot);
        }

        let bytes_per_sector = u16_at(data, 0x0b)?;
        let encoded = u8_at(data, 0x0d)?;
        let sectors_per_cluster = if encoded > 128 {
            1_u32.checked_shl(u32::from(256_u16 - u16::from(encoded))).ok_or(Error::InvalidGeometry)?
        } else {
            u32::from(encoded)
        };
        if !(512..=4096).contains(&bytes_per_sector)
            || !nonzero_power_of_two(u64::from(bytes_per_sector))
            || !nonzero_power_of_two(u64::from(sectors_per_cluster))
        {
            return Err(Error::InvalidGeometry);
        }
        let cluster_bytes = u32::from(bytes_per_sector).checked_mul(sectors_per_cluster).ok_or(Error::Overflow)?;
        if cluster_bytes > 2 * 1024 * 1024 {
            return Err(Error::InvalidGeometry);
        }
        let total_sectors = u64_at(data, 0x28)?;
        let clusters = total_sectors / u64::from(sectors_per_cluster);
        let mft_lcn = u64_at(data, 0x30)?;
        let mft_mirror_lcn = u64_at(data, 0x38)?;
        if clusters == 0 || mft_lcn >= clusters || mft_mirror_lcn >= clusters {
            return Err(Error::InvalidGeometry);
        }
        let record_bytes = decode_record_size(u8_at(data, 0x40)? as i8, cluster_bytes)?;
        let index_block_bytes = decode_record_size(u8_at(data, 0x44)? as i8, cluster_bytes)?;
        if record_bytes < 512
            || record_bytes > 64 * 1024
            || index_block_bytes < 512
            || index_block_bytes > 64 * 1024
            || record_bytes % u32::from(bytes_per_sector) != 0
            || index_block_bytes % u32::from(bytes_per_sector) != 0
        {
            return Err(Error::InvalidGeometry);
        }
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            cluster_bytes,
            total_sectors,
            mft_lcn,
            mft_mirror_lcn,
            record_bytes,
            index_block_bytes,
            serial_number: u64_at(data, 0x48)?,
        })
    }

    pub fn mft_byte_offset(&self) -> Result<u64> {
        self.mft_lcn.checked_mul(u64::from(self.cluster_bytes)).ok_or(Error::Overflow)
    }
}

fn decode_record_size(encoded: i8, cluster_bytes: u32) -> Result<u32> {
    if encoded == 0 {
        return Err(Error::InvalidGeometry);
    }
    if encoded > 0 {
        cluster_bytes.checked_mul(u32::from(encoded as u8)).ok_or(Error::Overflow)
    } else {
        let shift = u32::from(encoded.unsigned_abs());
        1_u32.checked_shl(shift).ok_or(Error::InvalidGeometry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_boot() -> [u8; 512] {
        let mut b = [0_u8; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
        b[0x0d] = 8;
        b[0x28..0x30].copy_from_slice(&8192_u64.to_le_bytes());
        b[0x30..0x38].copy_from_slice(&4_u64.to_le_bytes());
        b[0x38..0x40].copy_from_slice(&8_u64.to_le_bytes());
        b[0x40] = (-10_i8) as u8;
        b[0x44] = (-12_i8) as u8;
        b[510..512].copy_from_slice(&[0x55, 0xaa]);
        b
    }

    #[test]
    fn parses_valid_geometry() {
        let parsed = BootSector::parse(&valid_boot()).unwrap();
        assert_eq!(parsed.cluster_bytes, 4096);
        assert_eq!(parsed.record_bytes, 1024);
        assert_eq!(parsed.index_block_bytes, 4096);
        assert_eq!(parsed.mft_byte_offset().unwrap(), 16384);
    }

    #[test]
    fn rejects_bad_cluster_geometry() {
        let mut b = valid_boot();
        b[0x0d] = 3;
        assert_eq!(BootSector::parse(&b), Err(Error::InvalidGeometry));
    }
}
