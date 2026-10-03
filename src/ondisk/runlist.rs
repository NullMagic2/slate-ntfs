//! Module: ntfs_rs::runlist
//! Purpose: Encode mapping pairs and decode checked sparse or physical extents.
//! Created: 2026-10-01
//! Architecture: Volume reads, allocation planning and family assembly use checked
//! extents. Offline width repair shares byte frames and owns its stricter defect
//! admission; this module does not allocate, repair or publish mappings.

use super::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Extent {
    pub vcn: u64,
    pub len: u64,
    /// None denotes a sparse run.
    pub lcn: Option<u64>,
}

const MAPPING_HEADER_BYTES: usize = core::mem::size_of::<u8>();
const MAPPING_WORD_BYTES: usize = core::mem::size_of::<u64>();
const MAPPING_NIBBLE_BITS: u32 = 4;
const MAPPING_LENGTH_WIDTH_MASK: u8 = (1 << MAPPING_NIBBLE_BITS) - 1;
const MAPPING_SIGN_BIT: u8 = 1 << (u8::BITS - 1);

// Positive lengths and signed deltas both reserve one bit for their sign.
pub(crate) fn mapping_pair_widths(length: u64, delta: Option<i64>) -> Result<(usize, usize)> {
    if length == 0 || length > i64::MAX as u64 {
        return Err(Error::InvalidRunlist);
    }
    let length_width = (u64::BITS + 1 - length.leading_zeros()).div_ceil(u8::BITS) as usize;
    let delta_width = delta.map_or(0, |value| {
        let magnitude = if value < 0 { !value } else { value };
        (i64::BITS + 1 - magnitude.leading_zeros()).div_ceil(u8::BITS) as usize
    });
    Ok((length_width, delta_width))
}

pub(crate) fn encode_mapping_pair(length: u64, delta: Option<i64>, out: &mut [u8]) -> Result<usize> {
    let (length_width, delta_width) = mapping_pair_widths(length, delta)?;
    let size = MAPPING_HEADER_BYTES + length_width + delta_width;
    let frame = out.get_mut(..size).ok_or(Error::NoSpace)?;
    frame[0] = (length_width | (delta_width << MAPPING_NIBBLE_BITS)) as u8;
    frame[MAPPING_HEADER_BYTES..MAPPING_HEADER_BYTES + length_width]
        .copy_from_slice(&length.to_le_bytes()[..length_width]);
    frame[MAPPING_HEADER_BYTES + length_width..].copy_from_slice(&delta.unwrap_or(0).to_le_bytes()[..delta_width]);
    Ok(size)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPairError {
    MissingHeader,
    InvalidWidths,
    OffsetOverflow,
    Truncated,
}

impl MappingPairError {
    fn core_error(self) -> Error {
        match self {
            Self::OffsetOverflow => Error::Overflow,
            _ => Error::InvalidRunlist,
        }
    }
}

/// A checked header permits caller-specific admission before reading its body.
/// Ordinary streams allow sparse deltas; repair can refuse them before any I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPairHeader {
    cursor: usize,
    length_width: usize,
    delta_width: usize,
}

/// Encoding facts only; positive-length and physical-range policy stays with callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPair {
    pub length: u64,
    pub negative_length: bool,
    pub delta: Option<i64>,
    pub next_offset: usize,
}

impl MappingPairHeader {
    pub fn read(bytes: &[u8], cursor: usize) -> core::result::Result<Option<Self>, MappingPairError> {
        let header = *bytes.get(cursor).ok_or(MappingPairError::MissingHeader)?;
        if header == 0 {
            return Ok(None);
        }
        let length_width = usize::from(header & MAPPING_LENGTH_WIDTH_MASK);
        let delta_width = usize::from(header >> MAPPING_NIBBLE_BITS);
        if length_width == 0 || length_width > MAPPING_WORD_BYTES || delta_width > MAPPING_WORD_BYTES {
            return Err(MappingPairError::InvalidWidths);
        }
        Ok(Some(Self { cursor, length_width, delta_width }))
    }

    pub fn delta_width(&self) -> usize {
        self.delta_width
    }

    pub fn decode(&self, bytes: &[u8]) -> core::result::Result<MappingPair, MappingPairError> {
        let next_offset = self
            .cursor
            .checked_add(MAPPING_HEADER_BYTES + self.length_width + self.delta_width)
            .ok_or(MappingPairError::OffsetOverflow)?;
        let body = bytes.get(self.cursor + MAPPING_HEADER_BYTES..next_offset).ok_or(MappingPairError::Truncated)?;
        Ok(MappingPair {
            length: unsigned_le(&body[..self.length_width]),
            negative_length: body[self.length_width - 1] & MAPPING_SIGN_BIT != 0,
            delta: (self.delta_width != 0).then(|| signed_le(&body[self.length_width..])),
            next_offset,
        })
    }
}

pub struct DataRuns<'a> {
    bytes: &'a [u8],
    cursor: usize,
    next_vcn: u64,
    previous_lcn: i64,
    done: bool,
}

impl<'a> DataRuns<'a> {
    pub fn new(bytes: &'a [u8], first_vcn: u64) -> Self {
        Self { bytes, cursor: 0, next_vcn: first_vcn, previous_lcn: 0, done: false }
    }
}

impl Iterator for DataRuns<'_> {
    type Item = Result<Extent>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let header = match MappingPairHeader::read(self.bytes, self.cursor) {
            Ok(Some(header)) => header,
            Ok(None) => {
                self.done = true;
                return None;
            }
            Err(error) => {
                self.done = true;
                return Some(Err(error.core_error()));
            }
        };
        let result = (|| {
            let pair = header.decode(self.bytes).map_err(MappingPairError::core_error)?;
            if pair.length == 0 || pair.negative_length {
                return Err(Error::InvalidRunlist);
            }
            let lcn = if let Some(delta) = pair.delta {
                let next = self.previous_lcn.checked_add(delta).ok_or(Error::Overflow)?;
                if next < 0 {
                    return Err(Error::InvalidRunlist);
                }
                self.previous_lcn = next;
                Some(next as u64)
            } else {
                None
            };
            let extent = Extent { vcn: self.next_vcn, len: pair.length, lcn };
            self.next_vcn = self.next_vcn.checked_add(pair.length).ok_or(Error::Overflow)?;
            self.cursor = pair.next_offset;
            Ok(extent)
        })();
        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

fn unsigned_le(bytes: &[u8]) -> u64 {
    let mut value = 0_u64;
    for (i, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (i * u8::BITS as usize);
    }
    value
}

fn signed_le(bytes: &[u8]) -> i64 {
    let raw = unsigned_le(bytes);
    let shift = (MAPPING_WORD_BYTES - bytes.len()) * u8::BITS as usize;
    ((raw << shift) as i64) >> shift
}

#[cfg(test)]
#[path = "../tests/core/runlist.rs"]
mod tests;
