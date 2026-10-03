//! Module: ntfs_rs::bitlocker
//! Purpose: BitLocker (FVE, Windows 7 and later) volume format, unlock and sector I/O.
//! Created: 2026-10-01
//! Architecture: Volume readers, the writer and offline tools consume these checked format
//! views.

//! BitLocker (FVE, Windows 7 and later) volume format, unlock and sector I/O.
//!
//! On-disk layout (all integers little-endian):
//!
//! * The first sector carries -FVE-FS- at byte 3 (or MSWIN4.1 for the
//!   BitLocker To Go layout), the sector size at byte 11, and three FVE
//!   metadata block byte offsets after a GUID at byte 160 (To Go: 424).
//! * Each FVE metadata block starts with a 64-byte block header (state,
//!   encrypted size, relocated volume-header location/size, copies of the three
//!   offsets), then a 48-byte metadata header (size, volume GUID, encryption
//!   method) and a list of typed entries ("datums").
//! * The first header_sectors logical sectors (the NTFS boot region) are
//!   stored encrypted at header_offset; physical sector 0 holds the FVE
//!   header instead. The three metadata areas and the relocated header area
//!   are presented as zeros and must never be written through the volume.
//! * Every other sector is encrypted in place, keyed by its own physical
//!   sector number (see sector).
//!
//! Key hierarchy: a protector (password, recovery password, startup key
//! file or clear key) decrypts a volume master key (VMK) with AES-256-CCM;
//! the VMK decrypts the full volume encryption key (FVEK). Password and
//! recovery protectors stretch their secret with 2^20 SHA-256 rounds.
//! TPM protectors cannot be satisfied off the original machine.
//!
//! This module needs no allocation, so the same code parses metadata in the
//! kernel and unlocks volumes in userspace.

use super::aes::{self, wipe_bytes, AesAccel, AesKey};
use super::bytes::{range, u16_at, u32_at, u64_at};
use super::ccm;
use super::sector::{self, Method, SectorCipher};
use super::sha256::{self, Sha256};
use super::volume::ReadAt;
use super::{Error, Result};

pub const SIGNATURE: &[u8; 8] = b"-FVE-FS-";
const TOGO_SIGNATURE: &[u8; 8] = b"MSWIN4.1";
const BLOCK_HEADER: usize = 64;
const METADATA_HEADER: usize = 48;
/// Largest metadata block this implementation reads (header plus entries).
pub const METADATA_BYTES: usize = 0x10000;
/// Size of each area reserved by Windows for an FVE metadata copy.
const METADATA_AREA: u64 = 0x10000;
const MAX_HEADER_BYTES: u64 = 0x10000;
/// FVE state value for a completely encrypted, idle volume.
pub const STATE_ENCRYPTED: u16 = 0x0004;

pub const ENTRY_VMK: u16 = 0x0002;
pub const ENTRY_FVEK: u16 = 0x0003;
pub const ENTRY_STARTUP_KEY: u16 = 0x0006;
pub const ENTRY_DESCRIPTION: u16 = 0x0007;

pub const VALUE_KEY: u16 = 0x0001;
pub const VALUE_UNICODE: u16 = 0x0002;
pub const VALUE_STRETCH_KEY: u16 = 0x0003;
pub const VALUE_AES_CCM: u16 = 0x0005;
pub const VALUE_VMK: u16 = 0x0008;
pub const VALUE_EXTERNAL_KEY: u16 = 0x0009;

pub const PROTECTION_CLEAR_KEY: u16 = 0x0000;
pub const PROTECTION_TPM: u16 = 0x0100;
pub const PROTECTION_STARTUP_KEY: u16 = 0x0200;
pub const PROTECTION_TPM_PIN: u16 = 0x0500;
pub const PROTECTION_RECOVERY_PASSWORD: u16 = 0x0800;
pub const PROTECTION_PASSWORD: u16 = 0x2000;

const STRETCH_ROUNDS: u64 = 0x10_0000;
const GUID_BYTES: usize = 16;

fn guid_at(bytes: &[u8], at: usize) -> Result<[u8; GUID_BYTES]> {
    let slice = range(bytes, at, GUID_BYTES)?;
    let mut guid = [0_u8; GUID_BYTES];
    guid.copy_from_slice(slice);
    Ok(guid)
}

/// All cryptographic self tests. Unlock and mount paths refuse to run when
/// this fails, so a broken engine can never write wrong ciphertext.
#[inline(never)] // Run before constructing the mounted volume's key schedules.
pub fn self_test(accel: &dyn AesAccel) -> bool {
    sha256::self_test() && aes::self_test(accel) && ccm::self_test(accel) && sector::self_test(accel)
}

// ---------------------------------------------------------------------------
// Volume header

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub sector_bytes: u32,
    pub metadata_offsets: [u64; 3],
    pub to_go: bool,
}

/// Recognize a BitLocker volume from its first 512 bytes. None means the
/// sector is not a BitLocker header (for example, a plain NTFS boot sector).
pub fn probe(sector0: &[u8]) -> Option<Header> {
    let signature = sector0.get(3..11)?;
    let (to_go, offsets_at) = if signature == SIGNATURE {
        (false, 176)
    } else if signature == TOGO_SIGNATURE {
        (true, 440)
    } else {
        return None;
    };
    let sector_bytes = u32::from(u16_at(sector0, 11).ok()?);
    if !matches!(sector_bytes, 512 | 1024 | 2048 | 4096) {
        return None;
    }
    let mut metadata_offsets = [0_u64; 3];
    for (i, slot) in metadata_offsets.iter_mut().enumerate() {
        *slot = u64_at(sector0, offsets_at + 8 * i).ok()?;
    }
    if metadata_offsets.iter().all(|&offset| offset == 0) {
        return None;
    }
    Some(Header { sector_bytes, metadata_offsets, to_go })
}

// ---------------------------------------------------------------------------
// Metadata

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    pub version: u16,
    pub state: u16,
    pub next_state: u16,
    pub encrypted_bytes: u64,
    pub header_sectors: u32,
    pub metadata_offsets: [u64; 3],
    pub header_offset: u64,
    pub metadata_size: u32,
    pub volume_guid: [u8; 16],
    pub next_nonce: u32,
    pub method_code: u16,
    pub creation_time: u64,
}

impl Info {
    fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < BLOCK_HEADER + METADATA_HEADER || &block[..8] != SIGNATURE {
            return Err(Error::InvalidBoot);
        }
        let version = u16_at(block, 10)?;
        if version != 2 {
            // Version 1 is the Windows Vista layout.
            return Err(Error::Unsupported);
        }
        let mut metadata_offsets = [0_u64; 3];
        for (i, slot) in metadata_offsets.iter_mut().enumerate() {
            *slot = u64_at(block, 32 + 8 * i)?;
        }
        let info = Self {
            version,
            state: u16_at(block, 12)?,
            next_state: u16_at(block, 14)?,
            encrypted_bytes: u64_at(block, 16)?,
            header_sectors: u32_at(block, 28)?,
            metadata_offsets,
            header_offset: u64_at(block, 56)?,
            metadata_size: u32_at(block, 64)?,
            volume_guid: guid_at(block, 80)?,
            next_nonce: u32_at(block, 96)?,
            method_code: u16_at(block, 100)?,
            creation_time: u64_at(block, 104)?,
        };
        if u32_at(block, 68)? != 1
            || u32_at(block, 72)? as usize != METADATA_HEADER
            || u32_at(block, 76)? != info.metadata_size
            || (info.metadata_size as usize) < METADATA_HEADER
            || BLOCK_HEADER + info.metadata_size as usize > METADATA_BYTES
        {
            return Err(Error::InvalidBoot);
        }
        Ok(info)
    }

    pub fn fully_encrypted(&self) -> bool {
        self.state == STATE_ENCRYPTED && self.next_state == STATE_ENCRYPTED
    }
}

/// One FVE metadata entry (datum). body excludes the 8-byte entry header.
#[derive(Clone, Copy, Debug)]
pub struct Datum<'a> {
    pub entry_type: u16,
    pub value_type: u16,
    pub version: u16,
    pub body: &'a [u8],
}

pub struct Datums<'a> {
    bytes: &'a [u8],
    at: usize,
    failed: bool,
}

impl<'a> Datums<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0, failed: false }
    }
}

impl<'a> Iterator for Datums<'a> {
    type Item = Result<Datum<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.bytes.len().saturating_sub(self.at) < 8 {
            return None;
        }
        let rest = &self.bytes[self.at..];
        let size = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
        if size == 0 {
            // Zero padding after the last entry.
            return None;
        }
        if size < 8 || size > rest.len() {
            self.failed = true;
            return Some(Err(Error::InvalidAttribute));
        }
        self.at += size;
        Some(Ok(Datum {
            entry_type: u16::from_le_bytes([rest[2], rest[3]]),
            value_type: u16::from_le_bytes([rest[4], rest[5]]),
            version: u16::from_le_bytes([rest[6], rest[7]]),
            body: &rest[8..size],
        }))
    }
}

/// Offset of nested datums inside a datum body, by value type.
fn nested<'a>(datum: &Datum<'a>) -> Result<&'a [u8]> {
    let skip = match datum.value_type {
        VALUE_STRETCH_KEY => 20,
        VALUE_VMK => 28,
        VALUE_EXTERNAL_KEY => 24,
        _ => return Err(Error::InvalidAttribute),
    };
    datum.body.get(skip..).ok_or(Error::InvalidAttribute)
}

/// A volume master key protector.
#[derive(Clone, Copy, Debug)]
pub struct Protector<'a> {
    pub guid: [u8; 16],
    pub modified: u64,
    pub protection: u16,
    nested: &'a [u8],
}

impl<'a> Protector<'a> {
    fn from_datum(datum: &Datum<'a>) -> Result<Self> {
        Ok(Self {
            guid: guid_at(datum.body, 0)?,
            modified: u64_at(datum.body, 16)?,
            protection: u16_at(datum.body, 26)?,
            nested: nested(datum)?,
        })
    }

    pub fn protection_name(&self) -> &'static str {
        match self.protection {
            PROTECTION_CLEAR_KEY => "clear key (protection suspended)",
            PROTECTION_TPM => "TPM",
            PROTECTION_STARTUP_KEY => "startup key (.BEK)",
            PROTECTION_TPM_PIN => "TPM and PIN",
            PROTECTION_RECOVERY_PASSWORD => "recovery password",
            PROTECTION_PASSWORD => "password",
            _ => "unsupported",
        }
    }

    fn find(&self, value_type: u16) -> Result<Option<Datum<'a>>> {
        for datum in Datums::new(self.nested) {
            let datum = datum?;
            if datum.value_type == value_type {
                return Ok(Some(datum));
            }
        }
        Ok(None)
    }
}

/// A parsed metadata block borrowing the caller's buffer.
pub struct Metadata<'a> {
    pub header: Header,
    pub info: Info,
    entries: &'a [u8],
}

/// Raw access to the underlying (encrypted) device.
pub trait RawIo {
    fn read_raw(&mut self, offset: u64, output: &mut [u8]) -> Result<()>;
    fn write_raw(&mut self, _offset: u64, _data: &[u8]) -> Result<()> {
        Err(Error::Unsupported)
    }
}

/// Read-only raw access through an existing [ReadAt] implementation.
pub struct ReadOnly<R>(pub R);

impl<R: ReadAt> RawIo for ReadOnly<R> {
    fn read_raw(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        self.0.read_exact_at(offset, output)
    }
}

impl<'a> Metadata<'a> {
    /// Read and validate the first usable of the three metadata copies.
    /// buffer must hold [METADATA_BYTES].
    pub fn read<D: RawIo>(device: &mut D, header: Header, buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < METADATA_BYTES {
            return Err(Error::Unsupported);
        }
        let mut chosen = None;
        let mut last = Error::InvalidBoot;
        for &offset in &header.metadata_offsets {
            if offset == 0 {
                continue;
            }
            let prefix = BLOCK_HEADER + METADATA_HEADER;
            if let Err(error) = device.read_raw(offset, &mut buffer[..prefix]) {
                last = error;
                continue;
            }
            let info = match Info::parse(&buffer[..prefix]) {
                Ok(info) => info,
                Err(error) => {
                    last = error;
                    continue;
                }
            };
            // The logical view masks these exact physical ranges. A stale or
            // inconsistent copy must not allow later NTFS writes into FVE
            // metadata that the header still identifies as reserved.
            if info.metadata_offsets != header.metadata_offsets {
                last = Error::InvalidGeometry;
                continue;
            }
            let end = BLOCK_HEADER + info.metadata_size as usize;
            if let Err(error) = device.read_raw(offset + prefix as u64, &mut buffer[prefix..end]) {
                last = error;
                continue;
            }
            if Datums::new(&buffer[prefix..end]).any(|datum| datum.is_err()) {
                last = Error::InvalidAttribute;
                continue;
            }
            chosen = Some(info);
            break;
        }
        let info = chosen.ok_or(last)?;
        let end = BLOCK_HEADER + info.metadata_size as usize;
        Ok(Self { header, info, entries: &buffer[BLOCK_HEADER + METADATA_HEADER..end] })
    }

    pub fn datums(&self) -> Datums<'a> {
        Datums::new(self.entries)
    }

    pub fn method(&self) -> Result<Method> {
        Method::from_code(self.info.method_code)
    }

    pub fn protectors(&self) -> impl Iterator<Item = Result<Protector<'a>>> + 'a {
        Datums::new(self.entries).filter_map(|datum| match datum {
            Err(error) => Some(Err(error)),
            Ok(datum) if datum.entry_type == ENTRY_VMK && datum.value_type == VALUE_VMK => {
                Some(Protector::from_datum(&datum))
            }
            Ok(_) => None,
        })
    }

    /// UTF-16LE bytes of the volume description, if present.
    pub fn description(&self) -> Option<&'a [u8]> {
        Datums::new(self.entries).filter_map(|datum| datum.ok()).find_map(|datum| {
            (datum.entry_type == ENTRY_DESCRIPTION && datum.value_type == VALUE_UNICODE).then_some(datum.body)
        })
    }

    fn wrapped_fvek(&self) -> Result<Datum<'a>> {
        for datum in self.datums() {
            let datum = datum?;
            if datum.entry_type == ENTRY_FVEK && datum.value_type == VALUE_AES_CCM {
                return Ok(datum);
            }
        }
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Unlocking

/// A secret that can satisfy one protector type.
pub enum Secret<'a> {
    /// User password (protection 0x2000).
    Password(&'a str),
    /// 48-digit recovery password (protection 0x0800); dashes optional.
    RecoveryPassword(&'a str),
    /// Contents of a startup/recovery key .BEK file (protection 0x0200).
    StartupKey(&'a [u8]),
    /// Unprotected volume (BitLocker suspended; protection 0x0000).
    ClearKey,
}

/// The full volume encryption key and the identity it belongs to.
pub struct VolumeKey {
    pub method: Method,
    pub volume_guid: [u8; 16],
    length: usize,
    key: [u8; 64],
}

impl Drop for VolumeKey {
    fn drop(&mut self) {
        wipe_bytes(&mut self.key);
    }
}

impl VolumeKey {
    pub fn key_bytes(&self) -> &[u8] {
        &self.key[..self.length]
    }
}

/// 2^20 rounds of SHA-256 over {last, initial, salt, counter}.
fn stretch(initial: &[u8; 32], salt: &[u8]) -> Result<[u8; 32]> {
    if salt.len() != 16 {
        return Err(Error::InvalidSecurity);
    }
    let mut state = [0_u8; 88];
    state[32..64].copy_from_slice(initial);
    state[64..80].copy_from_slice(salt);
    for counter in 0..STRETCH_ROUNDS {
        state[80..88].copy_from_slice(&counter.to_le_bytes());
        let next = sha256::digest(&state);
        state[..32].copy_from_slice(&next);
    }
    let mut out = [0_u8; 32];
    out.copy_from_slice(&state[..32]);
    wipe_bytes(&mut state);
    Ok(out)
}

fn password_hash(password: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    for unit in password.encode_utf16() {
        hash.update(&unit.to_le_bytes());
    }
    let mut first = hash.finish();
    let second = sha256::digest(&first);
    wipe_bytes(&mut first);
    second
}

/// Decode a 48-digit recovery password into its 128-bit key.
pub fn recovery_key(text: &str) -> Result<[u8; 16]> {
    let mut key = [0_u8; 16];
    let mut group = 0_u32;
    let mut digits = 0_usize;
    for byte in text.bytes() {
        match byte {
            b'0'..=b'9' => {
                if digits == 48 {
                    return Err(Error::InvalidSecurity);
                }
                group = group * 10 + u32::from(byte - b'0');
                digits += 1;
                if digits % 6 == 0 {
                    if group % 11 != 0 || group / 11 > 0xffff {
                        wipe_bytes(&mut key);
                        return Err(Error::InvalidSecurity);
                    }
                    let index = digits / 6 - 1;
                    key[2 * index..2 * index + 2].copy_from_slice(&((group / 11) as u16).to_le_bytes());
                    group = 0;
                }
            }
            b'-' | b' ' | b'\t' | b'\n' | b'\r' => {}
            _ => {
                wipe_bytes(&mut key);
                return Err(Error::InvalidSecurity);
            }
        }
    }
    if digits != 48 {
        wipe_bytes(&mut key);
        return Err(Error::InvalidSecurity);
    }
    Ok(key)
}

/// Extract (identifier, 256-bit key) from a .BEK startup key file.
pub fn startup_key(bek: &[u8]) -> Result<([u8; 16], [u8; 32])> {
    if bek.len() < METADATA_HEADER || u32_at(bek, 4)? != 1 || u32_at(bek, 8)? as usize != METADATA_HEADER {
        return Err(Error::InvalidSecurity);
    }
    let size = u32_at(bek, 0)? as usize;
    if size < METADATA_HEADER {
        return Err(Error::InvalidSecurity);
    }
    let entries = &bek[METADATA_HEADER..size.min(bek.len())];
    for datum in Datums::new(entries) {
        let datum = datum?;
        if datum.value_type != VALUE_EXTERNAL_KEY {
            continue;
        }
        let guid = guid_at(datum.body, 0)?;
        for inner in Datums::new(nested(&datum)?) {
            let inner = inner?;
            if inner.value_type == VALUE_KEY && inner.body.len() >= 4 + 32 {
                let mut key = [0_u8; 32];
                key.copy_from_slice(&inner.body[4..36]);
                return Ok((guid, key));
            }
        }
    }
    Err(Error::NotFound)
}

/// Decrypt an AES-CCM datum body (nonce, tag, ciphertext) into output
/// and return the plaintext length.
fn unwrap(key: &[u8; 32], accel: &dyn AesAccel, body: &[u8], output: &mut [u8]) -> Result<usize> {
    if body.len() < ccm::NONCE + ccm::TAG {
        return Err(Error::InvalidSecurity);
    }
    let length = body.len() - ccm::NONCE - ccm::TAG;
    if length > output.len() {
        return Err(Error::Unsupported);
    }
    let mut nonce = [0_u8; ccm::NONCE];
    nonce.copy_from_slice(&body[..ccm::NONCE]);
    let mut tag = [0_u8; ccm::TAG];
    tag.copy_from_slice(&body[ccm::NONCE..ccm::NONCE + ccm::TAG]);
    output[..length].copy_from_slice(&body[ccm::NONCE + ccm::TAG..]);
    let aes = AesKey::new(key)?;
    ccm::decrypt(&aes, accel, &nonce, &tag, &mut output[..length])?;
    Ok(length)
}

/// Interpret an unwrapped key datum: size(2) type(2) value(2) version(2)
/// method(4) key. Returns (method code, key range within plain).
fn key_datum(plain: &[u8]) -> Result<(u32, core::ops::Range<usize>)> {
    let size = usize::from(u16_at(plain, 0)?);
    if size < 12 || size > plain.len() || u16_at(plain, 4)? != VALUE_KEY {
        return Err(Error::InvalidSecurity);
    }
    Ok((u32_at(plain, 8)?, 12..size))
}

fn open_vmk(protector: &Protector<'_>, key: &[u8; 32], accel: &dyn AesAccel) -> Result<[u8; 32]> {
    let wrapped = protector.find(VALUE_AES_CCM)?.ok_or(Error::InvalidSecurity)?;
    let mut plain = [0_u8; 128];
    let result = (|| {
        let length = unwrap(key, accel, wrapped.body, &mut plain)?;
        let (_, range) = key_datum(&plain[..length])?;
        if range.len() != 32 {
            return Err(Error::InvalidSecurity);
        }
        let mut vmk = [0_u8; 32];
        vmk.copy_from_slice(&plain[range]);
        Ok(vmk)
    })();
    wipe_bytes(&mut plain);
    result
}

fn stretched_key(protector: &Protector<'_>, initial: &[u8; 32]) -> Result<[u8; 32]> {
    let stretch_datum = protector.find(VALUE_STRETCH_KEY)?.ok_or(Error::InvalidSecurity)?;
    stretch(initial, stretch_datum.body.get(4..20).ok_or(Error::InvalidSecurity)?)
}

/// Try secret against every matching protector and return the VMK.
fn volume_master_key(metadata: &Metadata<'_>, secret: &Secret<'_>, accel: &dyn AesAccel) -> Result<[u8; 32]> {
    let wanted = match secret {
        Secret::Password(_) => PROTECTION_PASSWORD,
        Secret::RecoveryPassword(_) => PROTECTION_RECOVERY_PASSWORD,
        Secret::StartupKey(_) => PROTECTION_STARTUP_KEY,
        Secret::ClearKey => PROTECTION_CLEAR_KEY,
    };
    let mut initial = [0_u8; 32];
    let mut external = None;
    match secret {
        Secret::Password(text) => initial = password_hash(text),
        Secret::RecoveryPassword(text) => {
            let mut key = recovery_key(text)?;
            initial = sha256::digest(&key);
            wipe_bytes(&mut key);
        }
        Secret::StartupKey(bek) => external = Some(startup_key(bek)?),
        Secret::ClearKey => {}
    }
    let mut outcome = Err(Error::NotFound);
    // Startup keys: try the protector named by the file first, then the rest.
    for pass in 0..2 {
        for protector in metadata.protectors() {
            let protector = protector?;
            if protector.protection != wanted {
                continue;
            }
            if let Some((guid, _)) = &external {
                if (pass == 0) != (protector.guid == *guid) {
                    continue;
                }
            } else if pass == 1 {
                continue;
            }
            let attempt = (|| {
                let mut key = match (&external, secret) {
                    (Some((_, key)), _) => *key,
                    (None, Secret::ClearKey) => {
                        let datum = protector.find(VALUE_KEY)?.ok_or(Error::InvalidSecurity)?;
                        let bytes = datum.body.get(4..36).ok_or(Error::InvalidSecurity)?;
                        let mut key = [0_u8; 32];
                        key.copy_from_slice(bytes);
                        key
                    }
                    (None, _) => stretched_key(&protector, &initial)?,
                };
                let vmk = open_vmk(&protector, &key, accel);
                wipe_bytes(&mut key);
                vmk
            })();
            match attempt {
                Ok(vmk) => {
                    wipe_bytes(&mut initial);
                    if let Some((_, key)) = external.as_mut() {
                        wipe_bytes(key);
                    }
                    return Ok(vmk);
                }
                // A wrong secret fails authentication; remember the most
                // specific failure for the caller.
                Err(error) => outcome = Err(error),
            }
        }
    }
    wipe_bytes(&mut initial);
    if let Some((_, key)) = external.as_mut() {
        wipe_bytes(key);
    }
    outcome
}

/// Unlock the full volume encryption key with one protector secret.
pub fn unlock(metadata: &Metadata<'_>, secret: &Secret<'_>, accel: &dyn AesAccel) -> Result<VolumeKey> {
    if !self_test(accel) {
        return Err(Error::Unsupported);
    }
    let mut vmk = volume_master_key(metadata, secret, accel)?;
    let wrapped = metadata.wrapped_fvek();
    let mut plain = [0_u8; 128];
    let result = (|| {
        let length = unwrap(&vmk, accel, wrapped?.body, &mut plain)?;
        let (code, range) = key_datum(&plain[..length])?;
        let method = Method::from_code((code & 0xffff) as u16)?;
        if Method::from_code(metadata.info.method_code).is_ok_and(|expected| expected != method) {
            return Err(Error::InvalidSecurity);
        }
        if range.len() > 64 {
            return Err(Error::InvalidSecurity);
        }
        let mut key = [0_u8; 64];
        key[..range.len()].copy_from_slice(&plain[range.clone()]);
        // Construct once to validate the key-data length for the method.
        SectorCipher::new(method, &key[..range.len()], metadata.header.sector_bytes as usize)?;
        Ok(VolumeKey { method, volume_guid: metadata.info.volume_guid, length: range.len(), key })
    })();
    wipe_bytes(&mut plain);
    wipe_bytes(&mut vmk);
    result
}

// ---------------------------------------------------------------------------
// Logical volume view

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Segment {
    /// Ciphertext stored at this physical offset.
    Crypt(u64),
    /// Reserved FVE area; reads as zeros and refuses writes.
    Zero,
    /// Not yet encrypted (conversion paused); stored as plaintext.
    Plain(u64),
}

/// Unlocked geometry and sector cipher. Contains no pointers and needs no
/// destructor beyond wiping, so kernel code may keep it in C-owned memory.
pub struct FveVolume {
    cipher: SectorCipher,
    sector: u64,
    header_bytes: u64,
    header_offset: u64,
    protected: [(u64, u64); 4],
    encrypted_limit: u64,
    device_bytes: u64,
    writable: bool,
    volume_guid: [u8; 16],
}

fn round_down(value: u64, unit: u64) -> u64 {
    value - value % unit
}

impl FveVolume {
    /// Construction storage, never published before initialize succeeds.
    pub(crate) const EMPTY: Self = Self {
        cipher: SectorCipher::EMPTY,
        sector: 512,
        header_bytes: 0,
        header_offset: 0,
        protected: [(0, 0); 4],
        encrypted_limit: 0,
        device_bytes: 0,
        writable: false,
        volume_guid: [0; 16],
    };

    /// Build the logical view. Callers run [self_test] first ([unlock]
    /// already does); it is not repeated here to keep kernel stack use low.
    pub fn new(metadata: &Metadata<'_>, key: &VolumeKey, device_bytes: u64) -> Result<Self> {
        let mut volume = Self::EMPTY;
        volume.initialize(metadata, key, device_bytes)?;
        Ok(volume)
    }

    /// Build in the kernel's heap allocation, without stacked volume copies.
    pub(crate) fn initialize(&mut self, metadata: &Metadata<'_>, key: &VolumeKey, device_bytes: u64) -> Result<()> {
        let info = &metadata.info;
        if key.volume_guid != info.volume_guid {
            return Err(Error::AccessDenied);
        }
        if Method::from_code(info.method_code)? != key.method {
            return Err(Error::AccessDenied);
        }
        let sector = u64::from(metadata.header.sector_bytes);
        // Only whole encryption sectors are addressable.
        let device_bytes = round_down(device_bytes, sector);
        let header_bytes = u64::from(info.header_sectors).checked_mul(sector).ok_or(Error::Overflow)?;
        let in_device = |offset: u64, length: u64| {
            offset % sector == 0 && offset.checked_add(length).is_some_and(|end| end <= device_bytes)
        };
        if header_bytes == 0
            || header_bytes > MAX_HEADER_BYTES
            || info.header_offset < header_bytes
            || !in_device(info.header_offset, header_bytes)
        {
            return Err(Error::InvalidGeometry);
        }
        let area =
            METADATA_AREA.max(round_down(BLOCK_HEADER as u64 + u64::from(info.metadata_size) + sector - 1, sector));
        let mut protected = [(0_u64, 0_u64); 4];
        for (slot, &offset) in protected.iter_mut().zip(&metadata.header.metadata_offsets) {
            if offset == 0 {
                continue;
            }
            let start = round_down(offset, sector);
            let length = (area + offset - start).min(device_bytes.saturating_sub(start));
            if start < header_bytes || !in_device(start, round_down(length + sector - 1, sector)) {
                return Err(Error::InvalidGeometry);
            }
            *slot = (start, round_down(length + sector - 1, sector));
        }
        let header_end = info.header_offset + header_bytes;
        for (index, &(start, length)) in protected[..3].iter().enumerate() {
            if length == 0 {
                continue;
            }
            let end = start + length;
            if start < header_end && info.header_offset < end {
                return Err(Error::InvalidGeometry);
            }
            if protected[..index].iter().any(|&(other, size)| size != 0 && start < other + size && other < end) {
                return Err(Error::InvalidGeometry);
            }
        }
        protected[3] = (info.header_offset, header_bytes);
        let writable = info.fully_encrypted();
        let encrypted_limit = if writable { u64::MAX } else { round_down(info.encrypted_bytes, sector) };
        self.cipher.set_key(key.method, key.key_bytes(), sector as usize)?;
        self.sector = sector;
        self.header_bytes = header_bytes;
        self.header_offset = info.header_offset;
        self.protected = protected;
        self.encrypted_limit = encrypted_limit;
        self.device_bytes = device_bytes;
        self.writable = writable;
        self.volume_guid = info.volume_guid;
        Ok(())
    }

    pub fn sector_bytes(&self) -> u64 {
        self.sector
    }

    pub fn header_mapping(&self) -> (u64, u64) {
        (self.header_bytes, self.header_offset)
    }

    pub fn protected_ranges(&self) -> &[(u64, u64); 4] {
        &self.protected
    }

    pub fn encrypted_limit(&self) -> u64 {
        self.encrypted_limit
    }

    pub fn device_bytes(&self) -> u64 {
        self.device_bytes
    }

    pub fn method(&self) -> Method {
        self.cipher.method()
    }

    /// Only a completely encrypted, idle volume accepts writes.
    pub fn writable(&self) -> bool {
        self.writable
    }

    pub fn volume_guid(&self) -> [u8; 16] {
        self.volume_guid
    }

    /// Classify a sector-aligned logical offset; also returns the logical end
    /// of the uniform run containing it.
    fn segment(&self, logical: u64) -> (Segment, u64) {
        if logical < self.header_bytes {
            return (Segment::Crypt(self.header_offset + logical), self.header_bytes);
        }
        let mut end = self.device_bytes;
        for &(start, length) in &self.protected {
            if length == 0 {
                continue;
            }
            if logical >= start && logical - start < length {
                return (Segment::Zero, start + length);
            }
            if start > logical {
                end = end.min(start);
            }
        }
        if logical >= self.encrypted_limit {
            return (Segment::Plain(logical), end);
        }
        (Segment::Crypt(logical), end.min(self.encrypted_limit))
    }

    fn fill<D: RawIo>(&self, device: &mut D, accel: &dyn AesAccel, segment: Segment, buffer: &mut [u8]) -> Result<()> {
        match segment {
            Segment::Zero => {
                buffer.fill(0);
                Ok(())
            }
            Segment::Plain(physical) => device.read_raw(physical, buffer),
            Segment::Crypt(physical) => {
                device.read_raw(physical, buffer)?;
                self.cipher.decrypt(accel, physical / self.sector, buffer)
            }
        }
    }

    /// Read decrypted logical bytes. scratch (at least one sector) is used
    /// only for sectors the request covers partially.
    pub fn read<D: RawIo>(
        &self,
        device: &mut D,
        accel: &dyn AesAccel,
        mut offset: u64,
        mut output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<()> {
        let end = offset.checked_add(output.len() as u64).ok_or(Error::Overflow)?;
        if end > self.device_bytes {
            return Err(Error::Io);
        }
        let sector = self.sector as usize;
        while !output.is_empty() {
            let within = (offset % self.sector) as usize;
            let base = offset - within as u64;
            let (segment, run_end) = self.segment(base);
            let taken = if within == 0 && output.len() >= sector {
                let length = (output.len() - output.len() % sector).min((run_end - base) as usize);
                self.fill(device, accel, segment, &mut output[..length])?;
                length
            } else {
                let buffer = scratch.get_mut(..sector).ok_or(Error::Unsupported)?;
                self.fill(device, accel, segment, buffer)?;
                let length = (sector - within).min(output.len());
                output[..length].copy_from_slice(&buffer[within..within + length]);
                wipe_bytes(buffer);
                length
            };
            offset += taken as u64;
            output = &mut output[taken..];
        }
        Ok(())
    }

    /// Encrypt and write logical bytes, reading back partial sectors first.
    /// bounce (at least one sector; 64 KiB recommended) receives plaintext
    /// and then ciphertext before each raw write.
    pub fn write<D: RawIo>(
        &self,
        device: &mut D,
        accel: &dyn AesAccel,
        mut offset: u64,
        mut data: &[u8],
        bounce: &mut [u8],
    ) -> Result<()> {
        if !self.writable {
            return Err(Error::NotPermitted);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Overflow)?;
        if end > self.device_bytes {
            return Err(Error::Io);
        }
        let sector = self.sector as usize;
        let usable = (bounce.len() - bounce.len() % sector) as u64;
        if usable == 0 {
            return Err(Error::Unsupported);
        }
        while !data.is_empty() {
            let within = (offset % self.sector) as usize;
            let base = offset - within as u64;
            let (segment, run_end) = self.segment(base);
            let physical = match segment {
                Segment::Crypt(physical) => physical,
                Segment::Zero => return Err(Error::AccessDenied),
                Segment::Plain(_) => return Err(Error::NotPermitted),
            };
            let wanted = offset + data.len() as u64;
            let wanted = round_down(wanted + self.sector - 1, self.sector);
            let span = run_end.min(base + usable).min(wanted) - base;
            let span = span as usize;
            let buffer = &mut bounce[..span];
            let taken = (span - within).min(data.len());
            let head_partial = within != 0;
            let tail_partial = (within + taken) % sector != 0;
            if head_partial || (tail_partial && span == sector) {
                device.read_raw(physical, &mut buffer[..sector])?;
                self.cipher.decrypt(accel, physical / self.sector, &mut buffer[..sector])?;
            }
            if tail_partial && span > sector {
                let last = span - sector;
                let at = physical + last as u64;
                device.read_raw(at, &mut buffer[last..])?;
                self.cipher.decrypt(accel, at / self.sector, &mut buffer[last..])?;
            }
            buffer[within..within + taken].copy_from_slice(&data[..taken]);
            self.cipher.encrypt(accel, physical / self.sector, buffer)?;
            device.write_raw(physical, buffer)?;
            offset += taken as u64;
            data = &data[taken..];
        }
        Ok(())
    }

    /// Decrypt the logical NTFS boot sector (512 bytes) and require its OEM
    /// signature; a wrong key or volume never yields "NTFS    ".
    pub fn read_boot<D: RawIo>(
        &self,
        device: &mut D,
        accel: &dyn AesAccel,
        output: &mut [u8; 512],
        scratch: &mut [u8],
    ) -> Result<()> {
        self.read(device, accel, 0, output, scratch)?;
        if &output[3..11] != b"NTFS    " {
            wipe_bytes(output);
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
}

/// A decrypted, read-only [ReadAt] view for userspace tools.
pub struct Unlocked<D, A> {
    device: D,
    volume: FveVolume,
    accel: A,
    scratch: [u8; 4096],
}

impl<D: RawIo, A: AesAccel> Unlocked<D, A> {
    pub fn new(device: D, volume: FveVolume, accel: A) -> Self {
        Self { device, volume, accel, scratch: [0; 4096] }
    }

    pub fn volume(&self) -> &FveVolume {
        &self.volume
    }

    pub fn into_parts(self) -> (D, FveVolume) {
        (self.device, self.volume)
    }

    /// Encrypting write through the same view (writable volumes only).
    pub fn write_at(&mut self, offset: u64, data: &[u8], bounce: &mut [u8]) -> Result<()> {
        self.volume.write(&mut self.device, &self.accel, offset, data, bounce)
    }
}

impl<D: RawIo, A: AesAccel> ReadAt for Unlocked<D, A> {
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
        self.volume.read(&mut self.device, &self.accel, offset, output, &mut self.scratch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_reads_preserve_bytes_and_reject_invalid_ranges() {
        const GUID_OFFSET: usize = 3;
        const GUID_BYTE: u8 = 0x59;
        const SENTINEL: u8 = 0xa5;
        let expected = [GUID_BYTE; GUID_BYTES];
        let mut data = [SENTINEL; GUID_OFFSET + GUID_BYTES];
        data[GUID_OFFSET..].copy_from_slice(&expected);

        assert_eq!(guid_at(&data, GUID_OFFSET), Ok(expected));
        assert_eq!(guid_at(&data, GUID_OFFSET + 1), Err(Error::Truncated));
        assert_eq!(guid_at(&data, usize::MAX), Err(Error::Overflow));
        assert_eq!(guid_at(&[], 0), Err(Error::Truncated));
    }

    struct Device([u8; 128 * 512]);

    impl RawIo for Device {
        fn read_raw(&mut self, offset: u64, output: &mut [u8]) -> Result<()> {
            let at = offset as usize;
            output.copy_from_slice(self.0.get(at..at + output.len()).ok_or(Error::Io)?);
            Ok(())
        }

        fn write_raw(&mut self, offset: u64, data: &[u8]) -> Result<()> {
            let at = offset as usize;
            self.0.get_mut(at..at + data.len()).ok_or(Error::Io)?.copy_from_slice(data);
            Ok(())
        }
    }

    #[test]
    fn crypto_vectors_and_authentication() {
        assert!(self_test(&aes::Software));
    }

    #[test]
    #[ignore = "manual throughput profile"]
    fn profile_portable_sector_decryption() {
        use std::time::Instant;
        let mut key = [0_u8; 64];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        for method in [Method::Aes128Xts, Method::Aes256Xts, Method::Aes128Cbc, Method::Aes128Diffuser] {
            let cipher = SectorCipher::new(method, &key, 512).unwrap();
            let mut data = [0_u8; 64 * 1024];
            let start = Instant::now();
            for _ in 0..16 {
                cipher.decrypt(&aes::Software, 64, &mut data).unwrap();
            }
            std::eprintln!("{:?}: {:.1} MiB/s", method, 1.0 / start.elapsed().as_secs_f64());
        }
    }

    #[test]
    fn translated_partial_writes_preserve_neighbors_and_reserved_bytes() {
        let mut key = [0_u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let cipher = SectorCipher::new(Method::Aes128Xts, &key, 512).unwrap();
        let mut device = Device([0_u8; 128 * 512]);
        cipher.encrypt(&aes::Software, 96, &mut device.0[96 * 512..98 * 512]).unwrap();
        let volume = FveVolume {
            cipher,
            sector: 512,
            header_bytes: 1024,
            header_offset: 96 * 512,
            protected: [(16 * 512, 2 * 512), (96 * 512, 2 * 512), (0, 0), (0, 0)],
            encrypted_limit: u64::MAX,
            device_bytes: 128 * 512,
            writable: true,
            volume_guid: [0; 16],
        };
        let mut bounce = [0_u8; 2048];
        let message = [0x59_u8; 700];
        volume.write(&mut device, &aes::Software, 100, &message, &mut bounce).unwrap();
        assert!(device.0[..1024].iter().all(|&byte| byte == 0));
        assert!(device.0[16 * 512..18 * 512].iter().all(|&byte| byte == 0));
        assert!(device.0[96 * 512..98 * 512].iter().any(|&byte| byte != 0));
        let mut readback = [0_u8; 1024];
        let mut scratch = [0_u8; 512];
        volume.read(&mut device, &aes::Software, 0, &mut readback, &mut scratch).unwrap();
        assert!(readback[..100].iter().all(|&byte| byte == 0));
        assert_eq!(&readback[100..800], &message);
        assert!(readback[800..].iter().all(|&byte| byte == 0));
        assert_eq!(volume.write(&mut device, &aes::Software, 16 * 512, b"x", &mut bounce), Err(Error::AccessDenied));
    }

    #[test]
    fn refuses_overlapping_reserved_areas_and_unknown_method() {
        let offsets = [128 * 1024, 256 * 1024, 384 * 1024];
        let metadata = Metadata {
            header: Header { sector_bytes: 512, metadata_offsets: offsets, to_go: false },
            info: Info {
                version: 2,
                state: STATE_ENCRYPTED,
                next_state: STATE_ENCRYPTED,
                encrypted_bytes: 1024 * 1024,
                header_sectors: 16,
                metadata_offsets: offsets,
                header_offset: 512 * 1024,
                metadata_size: METADATA_HEADER as u32,
                volume_guid: [7; 16],
                next_nonce: 0,
                method_code: Method::Aes128Xts.code(),
                creation_time: 0,
            },
            entries: &[],
        };
        let mut key = VolumeKey { method: Method::Aes128Xts, volume_guid: [7; 16], length: 32, key: [0; 64] };
        assert!(FveVolume::new(&metadata, &key, 1024 * 1024).is_ok());
        let mut bad = metadata;
        bad.info.header_offset = offsets[0];
        assert!(matches!(FveVolume::new(&bad, &key, 1024 * 1024), Err(Error::InvalidGeometry)));
        bad.info.header_offset = 512 * 1024;
        bad.info.method_code = 0xffff;
        assert!(matches!(FveVolume::new(&bad, &key, 1024 * 1024), Err(Error::Unsupported)));
        key.key.fill(0);
    }
}
