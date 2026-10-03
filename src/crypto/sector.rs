//! Module: ntfs_rs::sector
//! Purpose: Transform BitLocker sectors with XTS, CBC or Elephant-diffuser CBC.
//! Created: 2026-10-01
//! Architecture: Volume readers and adapters supply the physical ciphertext sector position.
//! XTS tweaks use its sector number; CBC IVs use AES(FVEK, byte offset).
//! Elephant applies a sector-key XOR, diffusers A then B, and CBC; its key uses
//! AES(TWEAK, offset) and AES(TWEAK, offset with byte 15 set to 0x80).

use super::aes::{wipe_bytes, AesAccel, AesKey, BLOCK};
use super::{Error, Result};

/// Sector data kept together for one accelerator call (the kernel bounds each
/// FPU section to this size).
pub const GROUP_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Aes128Diffuser,
    Aes256Diffuser,
    Aes128Cbc,
    Aes256Cbc,
    Aes128Xts,
    Aes256Xts,
}

impl Method {
    pub fn from_code(code: u16) -> Result<Self> {
        Ok(match code {
            0x8000 => Self::Aes128Diffuser,
            0x8001 => Self::Aes256Diffuser,
            0x8002 => Self::Aes128Cbc,
            0x8003 => Self::Aes256Cbc,
            0x8004 => Self::Aes128Xts,
            0x8005 => Self::Aes256Xts,
            _ => return Err(Error::Unsupported),
        })
    }

    pub fn code(self) -> u16 {
        match self {
            Self::Aes128Diffuser => 0x8000,
            Self::Aes256Diffuser => 0x8001,
            Self::Aes128Cbc => 0x8002,
            Self::Aes256Cbc => 0x8003,
            Self::Aes128Xts => 0x8004,
            Self::Aes256Xts => 0x8005,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Diffuser => "AES-CBC-128 + Elephant diffuser",
            Self::Aes256Diffuser => "AES-CBC-256 + Elephant diffuser",
            Self::Aes128Cbc => "AES-CBC-128",
            Self::Aes256Cbc => "AES-CBC-256",
            Self::Aes128Xts => "XTS-AES-128",
            Self::Aes256Xts => "XTS-AES-256",
        }
    }

    /// Minimum FVEK key-data length and the (data, tweak) key slices.
    fn layout(self) -> (usize, (usize, usize), Option<(usize, usize)>) {
        match self {
            Self::Aes128Diffuser => (48, (0, 16), Some((32, 48))),
            Self::Aes256Diffuser => (64, (0, 32), Some((32, 64))),
            Self::Aes128Cbc => (16, (0, 16), None),
            Self::Aes256Cbc => (32, (0, 32), None),
            Self::Aes128Xts => (32, (0, 16), Some((16, 32))),
            Self::Aes256Xts => (64, (0, 32), Some((32, 64))),
        }
    }

    fn is_xts(self) -> bool {
        matches!(self, Self::Aes128Xts | Self::Aes256Xts)
    }

    fn has_diffuser(self) -> bool {
        matches!(self, Self::Aes128Diffuser | Self::Aes256Diffuser)
    }
}

pub struct SectorCipher {
    method: Method,
    sector: usize,
    data: AesKey,
    /// XTS K2 or Elephant sector-key key; unused (and zero-keyed) for plain CBC.
    tweak: AesKey,
}

impl SectorCipher {
    pub(super) const EMPTY: Self =
        Self { method: Method::Aes128Xts, sector: 512, data: AesKey::EMPTY, tweak: AesKey::EMPTY };

    /// key is the FVEK key data exactly as unwrapped from the metadata.
    pub fn new(method: Method, key: &[u8], sector: usize) -> Result<Self> {
        let mut cipher = Self::EMPTY;
        cipher.set_key(method, key, sector)?;
        Ok(cipher)
    }

    /// Initialize schedules in their final storage instead of stacking copies.
    pub(super) fn set_key(&mut self, method: Method, key: &[u8], sector: usize) -> Result<()> {
        if !matches!(sector, 512 | 1024 | 2048 | 4096) {
            return Err(Error::Unsupported);
        }
        let (minimum, (a, b), tweak) = method.layout();
        if key.len() < minimum {
            return Err(Error::InvalidSecurity);
        }
        self.data.expand(&key[a..b])?;
        match tweak {
            Some((c, d)) => self.tweak.expand(&key[c..d])?,
            None => self.tweak.expand(&[0; 16])?,
        }
        self.method = method;
        self.sector = sector;
        Ok(())
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn sector_bytes(&self) -> usize {
        self.sector
    }

    /// Decrypt whole sectors in place; first is the physical sector number
    /// of buffer[0].
    pub fn decrypt(&self, accel: &dyn AesAccel, first: u64, buffer: &mut [u8]) -> Result<()> {
        self.run(accel, first, buffer, true)
    }

    /// Encrypt whole sectors in place; first is the physical sector number
    /// where buffer[0] will be stored.
    pub fn encrypt(&self, accel: &dyn AesAccel, first: u64, buffer: &mut [u8]) -> Result<()> {
        self.run(accel, first, buffer, false)
    }

    fn run(&self, accel: &dyn AesAccel, first: u64, buffer: &mut [u8], decrypt: bool) -> Result<()> {
        if buffer.len() % self.sector != 0 {
            return Err(Error::InvalidGeometry);
        }
        let count = (buffer.len() / self.sector) as u64;
        first.checked_add(count).ok_or(Error::Overflow)?;
        let per_group = (GROUP_BYTES / self.sector).max(1);
        for (index, group) in buffer.chunks_mut(per_group * self.sector).enumerate() {
            let sector = first + (index * per_group) as u64;
            if self.method.is_xts() {
                self.xts_group(accel, sector, group, decrypt);
            } else {
                self.cbc_group(accel, sector, group, decrypt)?;
            }
        }
        Ok(())
    }

    fn xts_group(&self, accel: &dyn AesAccel, first: u64, group: &mut [u8], decrypt: bool) {
        // Encrypt every initial tweak of the group in one call.
        let sectors = group.len() / self.sector;
        let mut tweaks = [0_u8; BLOCK * (GROUP_BYTES / 512)];
        let tweaks = &mut tweaks[..sectors * BLOCK];
        for (i, tweak) in tweaks.chunks_exact_mut(BLOCK).enumerate() {
            tweak[..8].copy_from_slice(&(first + i as u64).to_le_bytes());
        }
        self.tweak.encrypt_blocks(accel, tweaks);
        xor_tweaks(group, tweaks, self.sector);
        if decrypt {
            self.data.decrypt_blocks(accel, group);
        } else {
            self.data.encrypt_blocks(accel, group);
        }
        xor_tweaks(group, tweaks, self.sector);
        wipe_bytes(tweaks);
    }

    fn cbc_group(&self, accel: &dyn AesAccel, number: u64, group: &mut [u8], decrypt: bool) -> Result<()> {
        let count = group.len() / self.sector;
        let mut ivs = [0_u8; BLOCK * (GROUP_BYTES / 512)];
        let ivs = &mut ivs[..count * BLOCK];
        let mut keys = [[0_u8; 2 * BLOCK]; GROUP_BYTES / 512];
        for (i, iv) in ivs.chunks_exact_mut(BLOCK).enumerate() {
            let offset = (number + i as u64).checked_mul(self.sector as u64).ok_or(Error::Overflow)?;
            iv[..8].copy_from_slice(&offset.to_le_bytes());
            if self.method.has_diffuser() {
                keys[i][..8].copy_from_slice(&offset.to_le_bytes());
                keys[i][16..24].copy_from_slice(&offset.to_le_bytes());
                keys[i][31] = 0x80;
            }
        }
        if self.method.has_diffuser() {
            self.tweak.encrypt_blocks(accel, &mut keys.as_flattened_mut()[..count * 2 * BLOCK]);
        }
        self.data.encrypt_blocks(accel, ivs);
        let accelerated_decrypt = decrypt && accel.cbc(&self.data, group, self.sector, ivs, true);
        for (i, sector) in group.chunks_exact_mut(self.sector).enumerate() {
            if decrypt {
                if !accelerated_decrypt {
                    cbc_decrypt(&self.data, accel, &ivs[i * BLOCK..(i + 1) * BLOCK], sector);
                }
                if self.method.has_diffuser() {
                    diffuser_512(sector, true);
                    xor_repeat(sector, &keys[i]);
                }
            } else if self.method.has_diffuser() {
                xor_repeat(sector, &keys[i]);
                diffuser_512(sector, false);
            }
        }
        let accelerated_encrypt = !decrypt && accel.cbc(&self.data, group, self.sector, ivs, false);
        if !decrypt && !accelerated_encrypt && count == 1 {
            for block in group.chunks_exact_mut(BLOCK) {
                for (byte, previous) in block.iter_mut().zip(ivs.iter()) {
                    *byte ^= previous;
                }
                self.data.encrypt_blocks(accel, block);
                ivs.copy_from_slice(block);
            }
        } else if !decrypt && !accelerated_encrypt {
            // CBC is serial within a sector. Independent sectors can share
            // an accelerator call while retaining their own chaining values.
            let mut blocks = [0_u8; BLOCK * (GROUP_BYTES / 512)];
            let blocks = &mut blocks[..count * BLOCK];
            for at in (0..self.sector).step_by(BLOCK) {
                for (i, sector) in group.chunks_exact(self.sector).enumerate() {
                    for j in 0..BLOCK {
                        blocks[i * BLOCK + j] = sector[at + j] ^ ivs[i * BLOCK + j];
                    }
                }
                self.data.encrypt_blocks(accel, blocks);
                for (i, sector) in group.chunks_exact_mut(self.sector).enumerate() {
                    sector[at..at + BLOCK].copy_from_slice(&blocks[i * BLOCK..(i + 1) * BLOCK]);
                }
                ivs.copy_from_slice(blocks);
            }
            wipe_bytes(blocks);
        }
        wipe_bytes(ivs);
        for key in &mut keys {
            wipe_bytes(key);
        }
        Ok(())
    }
}

/// Multiply a tweak by x in GF(2^128) (little-endian convention, 0x87).
#[inline(always)]
fn mul_x(tweak: u128) -> u128 {
    (tweak << 1) ^ (0_u128.wrapping_sub(tweak >> 127) & 0x87)
}

fn xor_tweaks(group: &mut [u8], tweaks: &[u8], sector: usize) {
    for (data, start) in group.chunks_exact_mut(sector).zip(tweaks.chunks_exact(BLOCK)) {
        let mut initial = [0_u8; BLOCK];
        initial.copy_from_slice(start);
        let mut tweak = u128::from_le_bytes(initial);
        for block in data.chunks_exact_mut(BLOCK) {
            let mut value = [0_u8; BLOCK];
            value.copy_from_slice(block);
            let mixed = u128::from_le_bytes(value) ^ tweak;
            block.copy_from_slice(&mixed.to_le_bytes());
            tweak = mul_x(tweak);
        }
    }
}

fn xor_repeat(data: &mut [u8], key: &[u8; 2 * BLOCK]) {
    for chunk in data.chunks_mut(key.len()) {
        for (byte, mask) in chunk.iter_mut().zip(key) {
            *byte ^= mask;
        }
    }
}

fn cbc_decrypt(key: &AesKey, accel: &dyn AesAccel, iv: &[u8], data: &mut [u8]) {
    const CHUNK: usize = 16 * BLOCK;
    let mut previous = [0_u8; BLOCK];
    previous.copy_from_slice(iv);
    for chunk in data.chunks_mut(CHUNK) {
        let mut saved = [0_u8; CHUNK];
        saved[..chunk.len()].copy_from_slice(chunk);
        key.decrypt_blocks(accel, chunk);
        for (index, block) in chunk.chunks_exact_mut(BLOCK).enumerate() {
            let chain = if index == 0 { &previous[..] } else { &saved[(index - 1) * BLOCK..index * BLOCK] };
            for (byte, value) in block.iter_mut().zip(chain) {
                *byte ^= value;
            }
        }
        previous.copy_from_slice(&saved[chunk.len() - BLOCK..chunk.len()]);
    }
}

// Elephant diffusers operate on little-endian 32-bit words, n = sector / 4.
const ROTATE_A: [u32; 4] = [9, 0, 13, 0];
const ROTATE_B: [u32; 4] = [0, 10, 0, 25];

// The common 512-byte sector path works on decoded words so
// the dependent rounds do not repeatedly unpack the same little-endian bytes.
// Keep the byte-oriented path for the other supported sector sizes.
fn diffuser_512(data: &mut [u8], decrypt: bool) {
    if data.len() != 512 {
        if decrypt {
            diffuser_b_decrypt(data);
            diffuser_a_decrypt(data);
        } else {
            diffuser_a_encrypt(data);
            diffuser_b_encrypt(data);
        }
        return;
    }
    let mut words = [0_u32; 128];
    for (word, bytes) in words.iter_mut().zip(data.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let mask = words.len() - 1;
    // The four-word rotation pattern is constant. Preserve the sequential
    // updates within each group: later words can depend on earlier results.
    if decrypt {
        for _ in 0..3 {
            for i in (0..120).step_by(4) {
                words[i] = words[i].wrapping_add(words[i + 2] ^ words[i + 5]);
                words[i + 1] = words[i + 1].wrapping_add(words[i + 3] ^ words[i + 6].rotate_left(10));
                words[i + 2] = words[i + 2].wrapping_add(words[i + 4] ^ words[i + 7]);
                words[i + 3] = words[i + 3].wrapping_add(words[i + 5] ^ words[i + 8].rotate_left(25));
            }
            for i in [120, 124] {
                words[i] = words[i].wrapping_add(words[(i + 2) & mask] ^ words[(i + 5) & mask]);
                words[i + 1] = words[i + 1].wrapping_add(words[(i + 3) & mask] ^ words[(i + 6) & mask].rotate_left(10));
                words[i + 2] = words[i + 2].wrapping_add(words[(i + 4) & mask] ^ words[(i + 7) & mask]);
                words[i + 3] = words[i + 3].wrapping_add(words[(i + 5) & mask] ^ words[(i + 8) & mask].rotate_left(25));
            }
        }
        for _ in 0..5 {
            let (mut a, mut b, mut c, mut d, mut e) = (words[123], words[124], words[125], words[126], words[127]);
            for chunk in words.chunks_exact_mut(4) {
                let w0 = chunk[0].wrapping_add(d ^ a.rotate_left(9));
                let w1 = chunk[1].wrapping_add(e ^ b);
                let w2 = chunk[2].wrapping_add(w0 ^ c.rotate_left(13));
                let w3 = chunk[3].wrapping_add(w1 ^ d);
                chunk.copy_from_slice(&[w0, w1, w2, w3]);
                (a, b, c, d, e) = (e, w0, w1, w2, w3);
            }
        }
    } else {
        for _ in 0..5 {
            for i in (8..words.len()).step_by(4).rev() {
                words[i + 3] = words[i + 3].wrapping_sub(words[i + 1] ^ words[i - 2]);
                words[i + 2] = words[i + 2].wrapping_sub(words[i] ^ words[i - 3].rotate_left(13));
                words[i + 1] = words[i + 1].wrapping_sub(words[i - 1] ^ words[i - 4]);
                words[i] = words[i].wrapping_sub(words[i - 2] ^ words[i - 5].rotate_left(9));
            }
            for i in [4, 0] {
                words[i + 3] = words[i + 3].wrapping_sub(words[i + 1] ^ words[(i + 126) & mask]);
                words[i + 2] = words[i + 2].wrapping_sub(words[i] ^ words[(i + 125) & mask].rotate_left(13));
                words[i + 1] = words[i + 1].wrapping_sub(words[(i + 127) & mask] ^ words[(i + 124) & mask]);
                words[i] = words[i].wrapping_sub(words[(i + 126) & mask] ^ words[(i + 123) & mask].rotate_left(9));
            }
        }
        for _ in 0..3 {
            let (mut a, mut b, mut c, mut d, mut e) = (words[0], words[1], words[2], words[3], words[4]);
            for chunk in words.chunks_exact_mut(4).rev() {
                let w3 = chunk[3].wrapping_sub(b ^ e.rotate_left(25));
                let w2 = chunk[2].wrapping_sub(a ^ d);
                let w1 = chunk[1].wrapping_sub(w3 ^ c.rotate_left(10));
                let w0 = chunk[0].wrapping_sub(w2 ^ b);
                chunk.copy_from_slice(&[w0, w1, w2, w3]);
                (a, b, c, d, e) = (w0, w1, w2, w3, a);
            }
        }
    }
    for (word, bytes) in words.iter().zip(data.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    words.fill(0);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(always)]
fn word(data: &[u8], index: usize) -> u32 {
    let at = 4 * index;
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

#[inline(always)]
fn set_word(data: &mut [u8], index: usize, value: u32) {
    data[4 * index..4 * index + 4].copy_from_slice(&value.to_le_bytes());
}

/// d[i] += d[i-2] ^ rotl(d[i-5], Ra[i mod 4]) for i ascending, 5 cycles.
fn diffuser_a_decrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    debug_assert!(n.is_power_of_two());
    for _ in 0..5 {
        let (mut a, mut b, mut c, mut d, mut e) =
            (word(data, n - 5), word(data, n - 4), word(data, n - 3), word(data, n - 2), word(data, n - 1));
        for chunk in data.chunks_exact_mut(16) {
            let w0 = word(chunk, 0).wrapping_add(d ^ a.rotate_left(9));
            let w1 = word(chunk, 1).wrapping_add(e ^ b);
            let w2 = word(chunk, 2).wrapping_add(w0 ^ c.rotate_left(13));
            let w3 = word(chunk, 3).wrapping_add(w1 ^ d);
            set_word(chunk, 0, w0);
            set_word(chunk, 1, w1);
            set_word(chunk, 2, w2);
            set_word(chunk, 3, w3);
            (a, b, c, d, e) = (e, w0, w1, w2, w3);
        }
    }
}

fn diffuser_a_encrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    debug_assert!(n.is_power_of_two());
    for _ in 0..5 {
        for i in (0..n).rev() {
            let mix =
                word(data, (i + n - 2) & (n - 1)) ^ word(data, (i + n - 5) & (n - 1)).rotate_left(ROTATE_A[i & 3]);
            set_word(data, i, word(data, i).wrapping_sub(mix));
        }
    }
}

/// d[i] += d[i+2] ^ rotl(d[i+5], Rb[i mod 4]) for i ascending, 3 cycles.
fn diffuser_b_decrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    debug_assert!(n.is_power_of_two());
    for _ in 0..3 {
        for i in 0..n {
            let mix = word(data, (i + 2) & (n - 1)) ^ word(data, (i + 5) & (n - 1)).rotate_left(ROTATE_B[i & 3]);
            set_word(data, i, word(data, i).wrapping_add(mix));
        }
    }
}

fn diffuser_b_encrypt(data: &mut [u8]) {
    let n = data.len() / 4;
    debug_assert!(n.is_power_of_two());
    for _ in 0..3 {
        let (mut a, mut b, mut c, mut d, mut e) =
            (word(data, 0), word(data, 1), word(data, 2), word(data, 3), word(data, 4));
        for chunk in data.chunks_exact_mut(16).rev() {
            let w3 = word(chunk, 3).wrapping_sub(b ^ e.rotate_left(25));
            let w2 = word(chunk, 2).wrapping_sub(a ^ d);
            let w1 = word(chunk, 1).wrapping_sub(w3 ^ c.rotate_left(10));
            let w0 = word(chunk, 0).wrapping_sub(w2 ^ b);
            set_word(chunk, 0, w0);
            set_word(chunk, 1, w1);
            set_word(chunk, 2, w2);
            set_word(chunk, 3, w3);
            (a, b, c, d, e) = (w0, w1, w2, w3, a);
        }
    }
}

/// IEEE 1619 XTS-AES-128 vector 1 (all-zero keys, tweak 0) and diffuser
/// inversion. Run by unlock paths together with aes::self_test.
#[inline(never)] // Mount initialization must not absorb these temporaries.
pub fn self_test(accel: &dyn AesAccel) -> bool {
    const XTS_VECTOR1: [u8; 32] = [
        0x91, 0x7c, 0xf6, 0x9e, 0xbd, 0x68, 0xb2, 0xec, 0x9b, 0x9f, 0xe9, 0xa3, 0xea, 0xdd, 0xa6, 0x92, 0xcd, 0x43,
        0xd2, 0xf5, 0x95, 0x98, 0xed, 0x85, 0x8c, 0x02, 0xc2, 0x65, 0x2f, 0xbf, 0x92, 0x2e,
    ];
    let mut cipher = SectorCipher::EMPTY;
    if cipher.set_key(Method::Aes128Xts, &[0; 32], 512).is_err() {
        return false;
    };
    let mut sector = [0_u8; 512];
    if cipher.encrypt(accel, 0, &mut sector).is_err() || sector[..32] != XTS_VECTOR1 {
        return false;
    }
    if cipher.decrypt(accel, 0, &mut sector).is_err() || sector.iter().any(|&b| b != 0) {
        return false;
    }
    // AES-128-XTS, key bytes 0..31, sector 77, plaintext byte i = i*7.
    // Reference ciphertext generated independently with OpenSSL's XTS mode.
    const XTS_NONZERO: [u8; 64] = [
        0xf8, 0x65, 0x8b, 0xc4, 0xaa, 0x5e, 0x3a, 0x09, 0x7b, 0xe6, 0x27, 0xba, 0xac, 0xf9, 0x35, 0x54, 0x45, 0x16,
        0xfa, 0x05, 0x1d, 0x90, 0xe6, 0xec, 0x78, 0x14, 0x57, 0x41, 0xee, 0x5d, 0x8f, 0x52, 0x65, 0x88, 0x35, 0x79,
        0xe5, 0x3a, 0x92, 0x00, 0xc6, 0xf5, 0x18, 0xcf, 0xa1, 0x80, 0x2f, 0x4b, 0x53, 0x70, 0x12, 0x40, 0x40, 0x97,
        0x9a, 0x7a, 0x9a, 0xa8, 0x53, 0xaf, 0xad, 0x0e, 0x37, 0x8e,
    ];
    let mut key = [0_u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }
    if cipher.set_key(Method::Aes128Xts, &key, 512).is_err() {
        return false;
    };
    for (i, byte) in sector.iter_mut().enumerate() {
        *byte = (i * 7) as u8;
    }
    if cipher.encrypt(accel, 77, &mut sector).is_err() || sector[..64] != XTS_NONZERO {
        return false;
    }
    for method in [Method::Aes128Diffuser, Method::Aes256Cbc] {
        let mut key = [0_u8; 64];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        if cipher.set_key(method, &key, 512).is_err() {
            return false;
        };
        let mut data = [0_u8; 512];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i * 7) as u8;
        }
        let original = data;
        if cipher.encrypt(accel, 77, &mut data).is_err() || data == original {
            return false;
        }
        if cipher.decrypt(accel, 77, &mut data).is_err() || data != original {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // Scalar specification, with a different traversal and storage layout
    // from the production four-word loops and their carried dependencies.
    fn reference_diffuser(data: &mut [u8], decrypt: bool) {
        let mut words: std::vec::Vec<u32> =
            data.chunks_exact(4).map(|b| u32::from_le_bytes(b.try_into().unwrap())).collect();
        let n = words.len();
        for phase in 0..2 {
            let a = (phase == 0) != decrypt;
            let (cycles, first, second, rotations) =
                if a { (5, n - 2, n - 5, [9, 0, 13, 0]) } else { (3, 2, 5, [0, 10, 0, 25]) };
            for _ in 0..cycles {
                for step in 0..n {
                    let i = if decrypt { step } else { n - 1 - step };
                    let mix = words[(i + first) % n] ^ words[(i + second) % n].rotate_left(rotations[i % 4]);
                    words[i] = if decrypt { words[i].wrapping_add(mix) } else { words[i].wrapping_sub(mix) };
                }
            }
        }
        for (word, out) in words.into_iter().zip(data.chunks_exact_mut(4)) {
            out.copy_from_slice(&word.to_le_bytes());
        }
    }

    #[test]
    fn word_diffuser_matches_byte_rounds() {
        let mut state = 0x7f34_512a_u32;
        for size in [512, 1024, 2048, 4096] {
            for _ in 0..32 {
                let mut fast = std::vec![0_u8; size];
                for byte in &mut fast {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    *byte = state as u8;
                }
                for decrypt in [false, true] {
                    let mut reference = fast.clone();
                    reference_diffuser(&mut reference, decrypt);
                    diffuser_512(&mut fast, decrypt);
                    assert_eq!(fast, reference, "size={size}, decrypt={decrypt}");
                }
            }
        }
    }

    #[test]
    fn cbc_batches_match_scalar_sectors() {
        use super::super::aes::Software;
        for method in [Method::Aes128Cbc, Method::Aes256Cbc, Method::Aes128Diffuser, Method::Aes256Diffuser] {
            for size in [512, 1024, 2048, 4096] {
                let cipher = SectorCipher::new(method, &[0x6d; 64], size).unwrap();
                // Nine sectors cross a group; three test a partial final group.
                for count in [1, 3, 9] {
                    let first = 0x1_0000_0007_u64;
                    let plain: std::vec::Vec<u8> = (0..size * count).map(|i| (i * 73 + i / 17) as u8).collect();
                    let mut reference = plain.clone();
                    for (i, sector) in reference.chunks_exact_mut(size).enumerate() {
                        let offset = ((first + i as u64) * size as u64).to_le_bytes();
                        let mut previous = [0; BLOCK];
                        previous[..8].copy_from_slice(&offset);
                        cipher.data.encrypt_block(&Software, &mut previous);
                        if method.has_diffuser() {
                            let mut key = [0; 2 * BLOCK];
                            key[..8].copy_from_slice(&offset);
                            key[16..24].copy_from_slice(&offset);
                            key[31] = 0x80;
                            cipher.tweak.encrypt_blocks(&Software, &mut key);
                            xor_repeat(sector, &key);
                            reference_diffuser(sector, false);
                        }
                        for block in sector.chunks_exact_mut(BLOCK) {
                            for (byte, mask) in block.iter_mut().zip(previous) {
                                *byte ^= mask;
                            }
                            cipher.data.encrypt_blocks(&Software, block);
                            previous.copy_from_slice(block);
                        }
                    }
                    let mut actual = plain.clone();
                    cipher.encrypt(&Software, first, &mut actual).unwrap();
                    assert_eq!(actual, reference, "{method:?}, size={size}, count={count}");
                    cipher.decrypt(&Software, first, &mut actual).unwrap();
                    assert_eq!(actual, plain);
                }
            }
        }
    }
}
