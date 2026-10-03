//! Module: ntfs_rs::aes
//! Purpose: Provide constant-time AES for BitLocker sectors and key wrapping.
//! Created: 2026-10-01
//! Architecture: Format readers share the portable bitsliced engine: four blocks become
//! eight bit planes without secret-dependent lookups, branches or SIMD.
//! Adapters may provide AES-NI through AesAccel and decline unsafe FPU contexts;
//! the portable engine handles declined calls. Unlock requires self_test to pass.

use super::{Error, Result};

pub const BLOCK: usize = 16;
const BATCH: usize = 4 * BLOCK;
const MAX_ROUNDS: usize = 14;

/// Optional hardware implementation of whole-block AES.
///
/// blocks.len() is always a multiple of 16. Returning false means the
/// blocks are untouched and the portable engine must be used instead.
pub trait AesAccel {
    fn encrypt(&self, key: &AesKey, blocks: &mut [u8]) -> bool;
    fn decrypt(&self, key: &AesKey, blocks: &mut [u8]) -> bool;
    /// Optional whole-sector CBC transform. ivs holds one 16-byte IV per
    /// sector and may be updated with the last ciphertext block. Returning
    /// false must leave blocks and ivs untouched for the portable path.
    fn cbc(&self, _: &AesKey, _: &mut [u8], _: usize, _: &mut [u8], _: bool) -> bool {
        false
    }
}

/// Portable engine only.
pub struct Software;

impl AesAccel for Software {
    fn encrypt(&self, _: &AesKey, _: &mut [u8]) -> bool {
        false
    }
    fn decrypt(&self, _: &AesKey, _: &mut [u8]) -> bool {
        false
    }
}

/// Expanded AES-128/192/256 key in byte and bitsliced forms.
///
/// The type holds secret material. It has no heap storage; Drop and
/// [AesKey::wipe] overwrite it. Kernel copies live in C-owned memory that
/// the bridge clears with memzero_explicit instead.
#[derive(Clone)]
pub struct AesKey {
    rounds: usize,
    bytes: [u8; BLOCK * (MAX_ROUNDS + 1)],
    planes: [[u64; 8]; MAX_ROUNDS + 1],
}

impl AesKey {
    // Construction storage only; expand() installs the key before use.
    pub(super) const EMPTY: Self =
        Self { rounds: 0, bytes: [0; BLOCK * (MAX_ROUNDS + 1)], planes: [[0; 8]; MAX_ROUNDS + 1] };

    /// Expand a 16, 24 or 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        let mut out = Self::EMPTY;
        out.expand(key)?;
        Ok(out)
    }

    /// Expand directly in caller storage, avoiding temporary key schedules
    /// on the small kernel stack. Invalid key lengths leave it unchanged.
    pub(super) fn expand(&mut self, key: &[u8]) -> Result<()> {
        let nk = match key.len() {
            16 => 4,
            24 => 6,
            32 => 8,
            _ => return Err(Error::Unsupported),
        };
        let rounds = nk + 6;
        self.wipe();
        self.rounds = rounds;
        let out = self;
        let words = 4 * (rounds + 1);
        out.bytes[..key.len()].copy_from_slice(key);
        let mut rcon = 1_u8;
        for i in nk..words {
            let mut temp = [0_u8; 4];
            temp.copy_from_slice(&out.bytes[4 * (i - 1)..4 * i]);
            if i % nk == 0 {
                temp.rotate_left(1);
                temp = sub_word(temp);
                temp[0] ^= rcon;
                rcon = xtime_byte(rcon);
            } else if nk > 6 && i % nk == 4 {
                temp = sub_word(temp);
            }
            for j in 0..4 {
                out.bytes[4 * i + j] = out.bytes[4 * (i - nk) + j] ^ temp[j];
            }
        }
        for round in 0..=rounds {
            let mut wide = [0_u8; BATCH];
            for lane in 0..4 {
                wide[lane * BLOCK..(lane + 1) * BLOCK].copy_from_slice(&out.bytes[round * BLOCK..(round + 1) * BLOCK]);
            }
            out.planes[round] = pack(&wide);
            wipe_bytes(&mut wide);
        }
        Ok(())
    }

    pub fn rounds(&self) -> usize {
        self.rounds
    }

    /// FIPS-197 expanded encryption key, 16 * (rounds + 1) bytes.
    pub fn round_key_bytes(&self) -> &[u8] {
        &self.bytes[..BLOCK * (self.rounds + 1)]
    }

    pub fn encrypt_blocks(&self, accel: &dyn AesAccel, blocks: &mut [u8]) {
        debug_assert_eq!(blocks.len() % BLOCK, 0);
        if blocks.is_empty() || accel.encrypt(self, blocks) {
            return;
        }
        self.soft(blocks, false);
    }

    pub fn decrypt_blocks(&self, accel: &dyn AesAccel, blocks: &mut [u8]) {
        debug_assert_eq!(blocks.len() % BLOCK, 0);
        if blocks.is_empty() || accel.decrypt(self, blocks) {
            return;
        }
        self.soft(blocks, true);
    }

    pub fn encrypt_block(&self, accel: &dyn AesAccel, block: &mut [u8; BLOCK]) {
        self.encrypt_blocks(accel, block);
    }

    fn soft(&self, blocks: &mut [u8], decrypt: bool) {
        let mut chunks = blocks.chunks_exact_mut(BATCH);
        for chunk in &mut chunks {
            let mut wide = [0_u8; BATCH];
            wide.copy_from_slice(chunk);
            let mut q = pack(&wide);
            if decrypt {
                self.decrypt_planes(&mut q);
            } else {
                self.encrypt_planes(&mut q);
            }
            unpack(&q, &mut wide);
            chunk.copy_from_slice(&wide);
            wipe_bytes(&mut wide);
            wipe_words(&mut q);
        }
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            let mut wide = [0_u8; BATCH];
            wide[..tail.len()].copy_from_slice(tail);
            let mut q = pack(&wide);
            if decrypt {
                self.decrypt_planes(&mut q);
            } else {
                self.encrypt_planes(&mut q);
            }
            unpack(&q, &mut wide);
            tail.copy_from_slice(&wide[..tail.len()]);
            wipe_bytes(&mut wide);
            wipe_words(&mut q);
        }
    }

    fn encrypt_planes(&self, q: &mut [u64; 8]) {
        add_round_key(q, &self.planes[0]);
        for round in 1..self.rounds {
            sbox(q);
            shift_rows(q);
            mix_columns(q);
            add_round_key(q, &self.planes[round]);
        }
        sbox(q);
        shift_rows(q);
        add_round_key(q, &self.planes[self.rounds]);
    }

    fn decrypt_planes(&self, q: &mut [u64; 8]) {
        add_round_key(q, &self.planes[self.rounds]);
        for round in (1..self.rounds).rev() {
            inv_shift_rows(q);
            inv_sbox(q);
            add_round_key(q, &self.planes[round]);
            inv_mix_columns(q);
        }
        inv_shift_rows(q);
        inv_sbox(q);
        add_round_key(q, &self.planes[0]);
    }

    /// Overwrite all key material.
    pub fn wipe(&mut self) {
        wipe_bytes(&mut self.bytes);
        for plane in &mut self.planes {
            wipe_words(plane);
        }
        self.rounds = 0;
    }
}

impl Drop for AesKey {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Best-effort secret erasure without unsafe volatile stores: the fence
/// keeps the compiler from sinking or eliding the zeroing past this point.
pub fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = 0;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn wipe_words(words: &mut [u64]) {
    for word in words.iter_mut() {
        *word = 0;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Constant-time byte comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

const fn xtime_byte(value: u8) -> u8 {
    (value << 1) ^ (((value >> 7) & 1) * 0x1b)
}

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    let mut wide = [0_u8; BATCH];
    wide[..4].copy_from_slice(&word);
    let mut q = pack(&wide);
    sbox(&mut q);
    unpack(&q, &mut wide);
    let out = [wide[0], wide[1], wide[2], wide[3]];
    wipe_bytes(&mut wide);
    wipe_words(&mut q);
    out
}

// ---------------------------------------------------------------------------
// Bitsliced representation.
//
// Byte j of the 64-byte batch (block j / 16, state index j % 16, FIPS column-
// major order: index = 4 * column + row) is stored at bit j of every plane;
// plane i holds bit i of each byte. Each block occupies a 16-bit lane.

/// 8x8 bit-matrix transpose within one u64 (bit 8r+c <-> bit 8c+r).
#[inline(always)]
fn transpose8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^= t ^ (t << 28);
    x
}

fn pack(bytes: &[u8; BATCH]) -> [u64; 8] {
    let mut rows = [0_u64; 8];
    for (k, row) in rows.iter_mut().enumerate() {
        let mut word = [0_u8; 8];
        word.copy_from_slice(&bytes[8 * k..8 * k + 8]);
        // After the transpose, byte c holds bit c of bytes 8k..8k+7.
        *row = transpose8(u64::from_le_bytes(word));
    }
    let mut q = [0_u64; 8];
    for (c, plane) in q.iter_mut().enumerate() {
        let mut value = 0_u64;
        for (k, row) in rows.iter().enumerate() {
            value |= ((row >> (8 * c)) & 0xff) << (8 * k);
        }
        *plane = value;
    }
    wipe_words(&mut rows);
    q
}

fn unpack(q: &[u64; 8], bytes: &mut [u8; BATCH]) {
    for k in 0..8 {
        let mut row = 0_u64;
        for (c, plane) in q.iter().enumerate() {
            row |= ((plane >> (8 * k)) & 0xff) << (8 * c);
        }
        bytes[8 * k..8 * k + 8].copy_from_slice(&transpose8(row).to_le_bytes());
    }
}

#[inline(always)]
fn add_round_key(q: &mut [u64; 8], key: &[u64; 8]) {
    for (plane, key) in q.iter_mut().zip(key) {
        *plane ^= key;
    }
}

/// Bits of row for columns first..last, replicated in all four lanes.
const fn lane_mask(row: u32, first: u32, last: u32) -> u64 {
    let mut mask = 0_u64;
    let mut lane = 0;
    while lane < 4 {
        let mut column = first;
        while column < last {
            mask |= 1_u64 << (lane * 16 + row + 4 * column);
            column += 1;
        }
        lane += 1;
    }
    mask
}

const ROW0: u64 = lane_mask(0, 0, 4);

/// Row r rotates left by r columns: new[r][c] = old[r][(c + r) mod 4].
#[inline(always)]
fn shift_rows_plane(x: u64) -> u64 {
    (x & ROW0)
        | ((x >> 4) & lane_mask(1, 0, 3))
        | ((x << 12) & lane_mask(1, 3, 4))
        | ((x >> 8) & lane_mask(2, 0, 2))
        | ((x << 8) & lane_mask(2, 2, 4))
        | ((x >> 12) & lane_mask(3, 0, 1))
        | ((x << 4) & lane_mask(3, 1, 4))
}

/// new[r][c] = old[r][(c - r) mod 4].
#[inline(always)]
fn inv_shift_rows_plane(x: u64) -> u64 {
    (x & ROW0)
        | ((x << 4) & lane_mask(1, 1, 4))
        | ((x >> 12) & lane_mask(1, 0, 1))
        | ((x << 8) & lane_mask(2, 2, 4))
        | ((x >> 8) & lane_mask(2, 0, 2))
        | ((x << 12) & lane_mask(3, 3, 4))
        | ((x >> 4) & lane_mask(3, 0, 3))
}

fn shift_rows(q: &mut [u64; 8]) {
    for plane in q.iter_mut() {
        *plane = shift_rows_plane(*plane);
    }
}

fn inv_shift_rows(q: &mut [u64; 8]) {
    for plane in q.iter_mut() {
        *plane = inv_shift_rows_plane(*plane);
    }
}

const NIBBLE_LOW: [u64; 4] = [0, 0x7777_7777_7777_7777, 0x3333_3333_3333_3333, 0x1111_1111_1111_1111];

/// Within every column (nibble), row r receives row (r + k) mod 4.
#[inline(always)]
fn rotate_rows(x: u64, k: u32) -> u64 {
    let low = NIBBLE_LOW[k as usize];
    ((x >> k) & low) | ((x << (4 - k)) & !low)
}

/// Multiply every byte by x in GF(2^8) (bit-plane form, polynomial 0x11b).
#[inline(always)]
fn xtime(t: &[u64; 8]) -> [u64; 8] {
    [t[7], t[0] ^ t[7], t[1], t[2] ^ t[7], t[3] ^ t[7], t[4], t[5], t[6]]
}

/// out_r = 2 a_r + 3 a_{r+1} + a_{r+2} + a_{r+3}
///       = xtime(a_r + a_{r+1}) + a_{r+1} + rot2(a_r + a_{r+1}).
fn mix_columns(q: &mut [u64; 8]) {
    let mut next = [0_u64; 8];
    let mut sum = [0_u64; 8];
    for i in 0..8 {
        next[i] = rotate_rows(q[i], 1);
        sum[i] = q[i] ^ next[i];
    }
    let doubled = xtime(&sum);
    for i in 0..8 {
        q[i] = doubled[i] ^ next[i] ^ rotate_rows(sum[i], 2);
    }
}

/// InvMixColumns = MixColumns after a_r += 4 (a_r + a_{r+2}).
fn inv_mix_columns(q: &mut [u64; 8]) {
    let mut u = [0_u64; 8];
    for i in 0..8 {
        u[i] = q[i] ^ rotate_rows(q[i], 2);
    }
    let u = xtime(&xtime(&u));
    for i in 0..8 {
        q[i] ^= u[i];
    }
    mix_columns(q);
}

/// Boyar-Peralta depth-16 S-box circuit (113 gates). q[i] is bit i.
fn sbox(q: &mut [u64; 8]) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// Inverse of the affine map's linear part, applied to x ^ 0x63:
/// b_i = y_{i+2} ^ y_{i+5} ^ y_{i+7} with y = x ^ 0x63 (indices mod 8).
#[inline(always)]
fn inverse_affine(q: &mut [u64; 8]) {
    let y0 = !q[0];
    let y1 = !q[1];
    let y2 = q[2];
    let y3 = q[3];
    let y4 = q[4];
    let y5 = !q[5];
    let y6 = !q[6];
    let y7 = q[7];
    q[7] = y1 ^ y4 ^ y6;
    q[6] = y0 ^ y3 ^ y5;
    q[5] = y7 ^ y2 ^ y4;
    q[4] = y6 ^ y1 ^ y3;
    q[3] = y5 ^ y0 ^ y2;
    q[2] = y4 ^ y7 ^ y1;
    q[1] = y3 ^ y6 ^ y0;
    q[0] = y2 ^ y5 ^ y7;
}

/// S(x) = A(I(x)) ^ 0x63, so InvS(y) = B(S(B(y ^ 0x63)) ^ 0x63), with B = A^-1.
fn inv_sbox(q: &mut [u64; 8]) {
    inverse_affine(q);
    sbox(q);
    inverse_affine(q);
}

// ---------------------------------------------------------------------------
// Self test (run by unlock paths; not a unit test).

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = xtime_byte(a);
        b >>= 1;
    }
    product
}

fn reference_sbox(x: u8) -> u8 {
    // x^254 is the multiplicative inverse (0 maps to 0).
    let mut inverse = 1_u8;
    for _ in 0..254 {
        inverse = gf_mul(inverse, x);
    }
    if x == 0 {
        inverse = 0;
    }
    inverse ^ inverse.rotate_left(1) ^ inverse.rotate_left(2) ^ inverse.rotate_left(3) ^ inverse.rotate_left(4) ^ 0x63
}

/// Verify the circuit and both directions against FIPS-197 Appendix C.
/// Uses public inputs only; timing is irrelevant here.
#[inline(never)] // Keep self-test storage out of the kernel mount frame.
pub fn self_test(accel: &dyn AesAccel) -> bool {
    for base in (0..256).step_by(BATCH) {
        let mut wide = [0_u8; BATCH];
        for (i, byte) in wide.iter_mut().enumerate() {
            *byte = (base + i) as u8;
        }
        let mut q = pack(&wide);
        sbox(&mut q);
        let mut forward = [0_u8; BATCH];
        unpack(&q, &mut forward);
        inv_sbox(&mut q);
        let mut back = [0_u8; BATCH];
        unpack(&q, &mut back);
        for i in 0..BATCH {
            if forward[i] != reference_sbox(wide[i]) || back[i] != wide[i] {
                return false;
            }
        }
    }
    const PLAIN: [u8; 16] =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const C128: [u8; 16] =
        [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a];
    const C256: [u8; 16] =
        [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89];
    let mut key = [0_u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }
    for (length, expected) in [(16, C128), (32, C256)] {
        let Ok(aes) = AesKey::new(&key[..length]) else {
            return false;
        };
        // Five blocks cover a full bitsliced batch and a padded tail.
        for engine in [&Software as &dyn AesAccel, accel] {
            let mut blocks = [0_u8; 5 * BLOCK];
            for block in blocks.chunks_exact_mut(BLOCK) {
                block.copy_from_slice(&PLAIN);
            }
            aes.encrypt_blocks(engine, &mut blocks);
            if blocks.chunks_exact(BLOCK).any(|block| block != expected) {
                return false;
            }
            aes.decrypt_blocks(engine, &mut blocks);
            if blocks.chunks_exact(BLOCK).any(|block| block != PLAIN) {
                return false;
            }
        }
    }
    true
}
