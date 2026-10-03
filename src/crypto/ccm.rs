//! Module: ntfs_rs::ccm
//! Purpose: Authenticate BitLocker key protectors with AES-CCM.
//! Created: 2026-10-01
//! Architecture: BitLocker readers use a 12-byte nonce, 16-byte tag and no associated data.
//! The encoded encrypted tag, T xor S0, precedes the ciphertext.

use super::aes::{ct_eq, wipe_bytes, AesAccel, AesKey, BLOCK};
use super::{Error, Result};

pub const NONCE: usize = 12;
pub const TAG: usize = 16;
const MAX_PAYLOAD: usize = (1 << 24) - 1;

fn counter_block(nonce: &[u8; NONCE], counter: u32) -> [u8; BLOCK] {
    let mut block = [0_u8; BLOCK];
    block[0] = 2; // L - 1
    block[1..13].copy_from_slice(nonce);
    block[13..16].copy_from_slice(&counter.to_be_bytes()[1..]);
    block
}

fn apply_keystream(key: &AesKey, accel: &dyn AesAccel, nonce: &[u8; NONCE], data: &mut [u8]) {
    for (index, chunk) in data.chunks_mut(BLOCK).enumerate() {
        let mut stream = counter_block(nonce, index as u32 + 1);
        key.encrypt_block(accel, &mut stream);
        for (byte, mask) in chunk.iter_mut().zip(stream) {
            *byte ^= mask;
        }
        wipe_bytes(&mut stream);
    }
}

fn cbc_mac(key: &AesKey, accel: &dyn AesAccel, nonce: &[u8; NONCE], plain: &[u8]) -> [u8; BLOCK] {
    let mut mac = [0_u8; BLOCK];
    // Flags: no AAD, M' = (16 - 2) / 2 = 7, L' = 2.
    mac[0] = 0x3a;
    mac[1..13].copy_from_slice(nonce);
    mac[13..16].copy_from_slice(&(plain.len() as u32).to_be_bytes()[1..]);
    key.encrypt_block(accel, &mut mac);
    for chunk in plain.chunks(BLOCK) {
        for (byte, value) in mac.iter_mut().zip(chunk) {
            *byte ^= value;
        }
        key.encrypt_block(accel, &mut mac);
    }
    mac
}

/// Decrypt data in place and verify tag. On failure the buffer is wiped.
pub fn decrypt(
    key: &AesKey,
    accel: &dyn AesAccel,
    nonce: &[u8; NONCE],
    tag: &[u8; TAG],
    data: &mut [u8],
) -> Result<()> {
    if data.len() > MAX_PAYLOAD {
        return Err(Error::Unsupported);
    }
    apply_keystream(key, accel, nonce, data);
    let mut expected = cbc_mac(key, accel, nonce, data);
    let mut s0 = counter_block(nonce, 0);
    key.encrypt_block(accel, &mut s0);
    for (byte, mask) in expected.iter_mut().zip(s0) {
        *byte ^= mask;
    }
    let valid = ct_eq(&expected, tag);
    wipe_bytes(&mut s0);
    if !valid {
        wipe_bytes(data);
        return Err(Error::AccessDenied);
    }
    Ok(())
}

/// Encrypt data in place and return the encrypted tag.
pub fn encrypt(key: &AesKey, accel: &dyn AesAccel, nonce: &[u8; NONCE], data: &mut [u8]) -> Result<[u8; TAG]> {
    if data.len() > MAX_PAYLOAD {
        return Err(Error::Unsupported);
    }
    let mut tag = cbc_mac(key, accel, nonce, data);
    let mut s0 = counter_block(nonce, 0);
    key.encrypt_block(accel, &mut s0);
    for (byte, mask) in tag.iter_mut().zip(s0) {
        *byte ^= mask;
    }
    wipe_bytes(&mut s0);
    apply_keystream(key, accel, nonce, data);
    Ok(tag)
}

/// Independently generated AES-256-CCM vector (12-byte nonce, 16-byte tag).
/// Exercise both directions and authentication failure before accepting a key.
#[inline(never)] // Do not retain this storage across the other mount self-tests.
pub fn self_test(accel: &dyn AesAccel) -> bool {
    const CIPHER: [u8; 37] = [
        0x8a, 0xd4, 0xba, 0x15, 0x3a, 0x2a, 0xcf, 0x90, 0xa4, 0xc0, 0xbb, 0x28, 0x01, 0x3d, 0x52, 0x4b, 0x2d, 0x65,
        0x04, 0x66, 0x2d, 0x60, 0x4e, 0xae, 0x7d, 0xbc, 0x99, 0x4e, 0x89, 0x05, 0x3c, 0x6c, 0xe5, 0xed, 0xe8, 0x57,
        0x96,
    ];
    const TAG_VECTOR: [u8; TAG] =
        [0x61, 0x45, 0x26, 0x72, 0xc0, 0x83, 0xb7, 0x63, 0x8a, 0x53, 0x75, 0x74, 0x56, 0x6a, 0x57, 0x6c];
    let mut key = [0_u8; 32];
    let mut nonce = [0_u8; NONCE];
    let mut plain = [0_u8; 37];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }
    for (i, byte) in nonce.iter_mut().enumerate() {
        *byte = i as u8;
    }
    for (i, byte) in plain.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let Ok(aes) = AesKey::new(&key) else {
        return false;
    };
    let original = plain;
    let Ok(tag) = encrypt(&aes, accel, &nonce, &mut plain) else {
        return false;
    };
    if plain != CIPHER || tag != TAG_VECTOR {
        return false;
    }
    if decrypt(&aes, accel, &nonce, &tag, &mut plain).is_err() || plain != original {
        return false;
    }
    let mut invalid = tag;
    invalid[0] ^= 1;
    decrypt(&aes, accel, &nonce, &invalid, &mut plain).is_err() && plain.iter().all(|&byte| byte == 0)
}
