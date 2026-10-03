//! Module: ntfs_rs::bytes
//! Purpose: Read and write bounded little-endian integers and byte ranges.
//! Created: 2026-10-01
//! Architecture: Format parsers, mutation planners and offline replay share
//! these checked accessors; callers own format validation and publication.

use super::{Error, Result};

pub fn range(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start.checked_add(len).ok_or(Error::Overflow)?;
    data.get(start..end).ok_or(Error::Truncated)
}

pub fn range_mut(data: &mut [u8], start: usize, len: usize) -> Result<&mut [u8]> {
    let end = start.checked_add(len).ok_or(Error::Overflow)?;
    data.get_mut(start..end).ok_or(Error::Truncated)
}

pub fn u8_at(data: &[u8], offset: usize) -> Result<u8> {
    data.get(offset).copied().ok_or(Error::Truncated)
}

pub fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    let bytes: [u8; 2] = range(data, offset, 2)?.try_into().map_err(|_| Error::Truncated)?;
    Ok(u16::from_le_bytes(bytes))
}

pub fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes: [u8; 4] = range(data, offset, 4)?.try_into().map_err(|_| Error::Truncated)?;
    Ok(u32::from_le_bytes(bytes))
}

pub fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    let bytes: [u8; 8] = range(data, offset, 8)?.try_into().map_err(|_| Error::Truncated)?;
    Ok(u64::from_le_bytes(bytes))
}

pub fn p16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let bytes = value.to_le_bytes();
    range_mut(data, offset, bytes.len())?.copy_from_slice(&bytes);
    Ok(())
}

pub fn p32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let bytes = value.to_le_bytes();
    range_mut(data, offset, bytes.len())?.copy_from_slice(&bytes);
    Ok(())
}

pub fn p64(data: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let bytes = value.to_le_bytes();
    range_mut(data, offset, bytes.len())?.copy_from_slice(&bytes);
    Ok(())
}

/// Code units of an encoded UTF-16LE buffer.
pub fn units(utf16le: &[u8]) -> impl Iterator<Item = u16> + '_ {
    utf16le.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]))
}

pub fn nonzero_power_of_two(value: u64) -> bool {
    value != 0 && value.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: u8 = 0xa5;
    const WRITE_OFFSET: usize = 3;
    const BUFFER_BYTES: usize = 16;

    fn assert_written_bytes(data: &[u8], written: &[u8]) {
        let mut expected = [SENTINEL; BUFFER_BYTES];
        expected[WRITE_OFFSET..WRITE_OFFSET + written.len()].copy_from_slice(written);
        assert_eq!(data, expected);
    }

    #[test]
    fn integer_reads_reject_truncation_and_offset_overflow() {
        let data = [SENTINEL; BUFFER_BYTES];

        assert_eq!(u16_at(&data, BUFFER_BYTES - 1), Err(Error::Truncated));
        assert_eq!(u32_at(&data, BUFFER_BYTES - 1), Err(Error::Truncated));
        assert_eq!(u64_at(&data, BUFFER_BYTES - 1), Err(Error::Truncated));
        assert_eq!(u16_at(&data, usize::MAX), Err(Error::Overflow));
        assert_eq!(u32_at(&data, usize::MAX), Err(Error::Overflow));
        assert_eq!(u64_at(&data, usize::MAX), Err(Error::Overflow));
    }

    #[test]
    fn integer_writes_preserve_surrounding_bytes() {
        let mut data = [SENTINEL; BUFFER_BYTES];
        let small = 0x1234_u16;
        let medium = 0x1234_5678_u32;
        let large = 0x1234_5678_9abc_def0_u64;

        p16(&mut data, WRITE_OFFSET, small).unwrap();
        assert_eq!(u16_at(&data, WRITE_OFFSET), Ok(small));
        assert_written_bytes(&data, &small.to_le_bytes());

        data.fill(SENTINEL);
        p32(&mut data, WRITE_OFFSET, medium).unwrap();
        assert_eq!(u32_at(&data, WRITE_OFFSET), Ok(medium));
        assert_written_bytes(&data, &medium.to_le_bytes());

        data.fill(SENTINEL);
        p64(&mut data, WRITE_OFFSET, large).unwrap();
        assert_eq!(u64_at(&data, WRITE_OFFSET), Ok(large));
        assert_written_bytes(&data, &large.to_le_bytes());
    }

    #[test]
    fn truncated_integer_writes_leave_bytes_unchanged() {
        let original = [SENTINEL; BUFFER_BYTES];
        let mut data = original;

        assert_eq!(p16(&mut data, BUFFER_BYTES - 1, 0), Err(Error::Truncated));
        assert_eq!(data, original);
        assert_eq!(p32(&mut data, BUFFER_BYTES - 1, 0), Err(Error::Truncated));
        assert_eq!(data, original);
        assert_eq!(p64(&mut data, BUFFER_BYTES - 1, 0), Err(Error::Truncated));
        assert_eq!(data, original);
    }

    #[test]
    fn overflowing_integer_writes_leave_bytes_unchanged() {
        let original = [SENTINEL; BUFFER_BYTES];
        let mut data = original;

        assert_eq!(p16(&mut data, usize::MAX, 0), Err(Error::Overflow));
        assert_eq!(data, original);
        assert_eq!(p32(&mut data, usize::MAX, 0), Err(Error::Overflow));
        assert_eq!(data, original);
        assert_eq!(p64(&mut data, usize::MAX, 0), Err(Error::Overflow));
        assert_eq!(data, original);
    }
}
