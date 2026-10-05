//! Module: ntfs_rs::aesni
//! Purpose: AES-NI block engine for x86_64.
//! Created: 2026-10-01
//! Architecture: BitLocker format readers and kernel or userspace adapters share these
//! primitives.

// SPDX-License-Identifier: MIT
//! AES-NI block engine for x86_64.
//!
//! This file is deliberately not part of the forbid(unsafe_code) core. The
//! kernel adapter and the userspace tools include it with #[path] and wrap
//! it in an aes::AesAccel implementation that checks CPU support (and, in
//! the kernel, owns the kernel_fpu_begin/kernel_fpu_end section).
//!
//! Eight independent blocks are kept in flight to cover the AESENC latency.
//! Callers pass the FIPS-197 expanded encryption key; decryption derives the
//! equivalent-inverse-cipher keys with AESIMC on each call (13 instructions).
#![allow(clippy::missing_safety_doc)]

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aesimc_si128,
    _mm_loadu_si128, _mm_setzero_si128, _mm_storeu_si128, _mm_xor_si128,
};

#[cfg(target_arch = "x86_64")]
const LANES: usize = 8;
#[cfg(target_arch = "x86_64")]
const MAX_ROUNDS: usize = 14;

#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "aes,sse2")]
unsafe fn wipe(keys: &mut [__m128i; MAX_ROUNDS + 1]) {
    for key in keys.iter_mut() {
        unsafe { core::ptr::write_volatile(key, _mm_setzero_si128()) };
    }
}

#[cfg(target_arch = "x86_64")]
fn valid(round_keys: &[u8], rounds: usize, blocks: &[u8]) -> bool {
    matches!(rounds, 10 | 12 | 14) && round_keys.len() >= 16 * (rounds + 1) && blocks.len() % 16 == 0
}

/// Encrypt whole 16-byte blocks in place.
///
/// # Safety
/// The CPU must support AES-NI and SSE2, and (in the kernel) the caller must
/// hold the FPU via kernel_fpu_begin.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
pub unsafe fn encrypt(round_keys: &[u8], rounds: usize, blocks: &mut [u8]) -> bool {
    if !valid(round_keys, rounds, blocks) {
        return false;
    }
    let mut keys = [_mm_setzero_si128(); MAX_ROUNDS + 1];
    for (i, key) in keys.iter_mut().enumerate().take(rounds + 1) {
        *key = unsafe { _mm_loadu_si128(round_keys.as_ptr().add(16 * i).cast()) };
    }
    let mut chunks = blocks.chunks_exact_mut(16 * LANES);
    for chunk in &mut chunks {
        let base = chunk.as_mut_ptr();
        let mut state = [_mm_setzero_si128(); LANES];
        for (lane, value) in state.iter_mut().enumerate() {
            *value = _mm_xor_si128(unsafe { _mm_loadu_si128(base.add(16 * lane).cast()) }, keys[0]);
        }
        for key in &keys[1..rounds] {
            for value in state.iter_mut() {
                *value = _mm_aesenc_si128(*value, *key);
            }
        }
        for (lane, value) in state.iter().enumerate() {
            let out = _mm_aesenclast_si128(*value, keys[rounds]);
            unsafe { _mm_storeu_si128(base.add(16 * lane).cast(), out) };
        }
    }
    for block in chunks.into_remainder().chunks_exact_mut(16) {
        let pointer = block.as_mut_ptr();
        let mut value = _mm_xor_si128(unsafe { _mm_loadu_si128(pointer.cast()) }, keys[0]);
        for key in &keys[1..rounds] {
            value = _mm_aesenc_si128(value, *key);
        }
        value = _mm_aesenclast_si128(value, keys[rounds]);
        unsafe { _mm_storeu_si128(pointer.cast(), value) };
    }
    unsafe { wipe(&mut keys) };
    true
}

/// Decrypt whole 16-byte blocks in place.
///
/// # Safety
/// Same requirements as [encrypt].
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes,sse2")]
pub unsafe fn decrypt(round_keys: &[u8], rounds: usize, blocks: &mut [u8]) -> bool {
    if !valid(round_keys, rounds, blocks) {
        return false;
    }
    let mut forward = [_mm_setzero_si128(); MAX_ROUNDS + 1];
    for (i, key) in forward.iter_mut().enumerate().take(rounds + 1) {
        *key = unsafe { _mm_loadu_si128(round_keys.as_ptr().add(16 * i).cast()) };
    }
    let mut keys = [_mm_setzero_si128(); MAX_ROUNDS + 1];
    keys[0] = forward[rounds];
    for i in 1..rounds {
        keys[i] = _mm_aesimc_si128(forward[rounds - i]);
    }
    keys[rounds] = forward[0];
    unsafe { wipe(&mut forward) };
    let mut chunks = blocks.chunks_exact_mut(16 * LANES);
    for chunk in &mut chunks {
        let base = chunk.as_mut_ptr();
        let mut state = [_mm_setzero_si128(); LANES];
        for (lane, value) in state.iter_mut().enumerate() {
            *value = _mm_xor_si128(unsafe { _mm_loadu_si128(base.add(16 * lane).cast()) }, keys[0]);
        }
        for key in &keys[1..rounds] {
            for value in state.iter_mut() {
                *value = _mm_aesdec_si128(*value, *key);
            }
        }
        for (lane, value) in state.iter().enumerate() {
            let out = _mm_aesdeclast_si128(*value, keys[rounds]);
            unsafe { _mm_storeu_si128(base.add(16 * lane).cast(), out) };
        }
    }
    for block in chunks.into_remainder().chunks_exact_mut(16) {
        let pointer = block.as_mut_ptr();
        let mut value = _mm_xor_si128(unsafe { _mm_loadu_si128(pointer.cast()) }, keys[0]);
        for key in &keys[1..rounds] {
            value = _mm_aesdec_si128(value, *key);
        }
        value = _mm_aesdeclast_si128(value, keys[rounds]);
        unsafe { _mm_storeu_si128(pointer.cast(), value) };
    }
    unsafe { wipe(&mut keys) };
    true
}

/// Non-x86_64 builds never select this engine.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn encrypt(_: &[u8], _: usize, _: &mut [u8]) -> bool {
    false
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn decrypt(_: &[u8], _: usize, _: &mut [u8]) -> bool {
    false
}
