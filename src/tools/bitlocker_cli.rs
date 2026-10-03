//! Module: slate_ntfs_tools::bitlocker_cli
//! Purpose: Share BitLocker secret input, unlocking and decrypting image I/O.
//! Created: 2026-10-01
//! Architecture: Inspect, bitlocker and mount commands use checked core formats and geometry.
//! Secrets come from descriptors or a no-echo tty and are wiped after use;
//! mount passes the FVEK to dm-crypt through a pipe, never command arguments.

use crate::checker::Image;
use ntfs_rs::aes::{wipe_bytes, AesAccel, AesKey};
use ntfs_rs::bitlocker::{self, FveVolume, Header, Metadata, ReadOnly, Secret, Unlocked, VolumeKey, METADATA_BYTES};
use ntfs_rs::boot::BootSector;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

#[path = "../crypto/aesni.rs"]
mod aesni;

/// AES-NI when the CPU has it, otherwise the portable bitsliced engine.
#[derive(Clone, Copy, Debug, Default)]
pub struct UserAccel {
    aes_ni: bool,
}

impl UserAccel {
    pub fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self { aes_ni: std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("sse2") }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self { aes_ni: false }
        }
    }

    pub fn engine_name(&self) -> &'static str {
        if self.aes_ni {
            "AES-NI"
        } else {
            "portable bitsliced"
        }
    }
}

impl AesAccel for UserAccel {
    fn encrypt(&self, key: &AesKey, blocks: &mut [u8]) -> bool {
        // SAFETY: CPU support was detected at runtime; user space owns the FPU.
        self.aes_ni && unsafe { aesni::encrypt(key.round_key_bytes(), key.rounds(), blocks) }
    }
    fn decrypt(&self, key: &AesKey, blocks: &mut [u8]) -> bool {
        // SAFETY: as for encrypt.
        self.aes_ni && unsafe { aesni::decrypt(key.round_key_bytes(), key.rounds(), blocks) }
    }
}

/// Which protector to satisfy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretSource {
    Password,
    RecoveryPassword,
    StartupKey(PathBuf),
    ClearKey,
}

impl SecretSource {
    /// password, recovery, bek=PATH or clear.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "password" => Some(Self::Password),
            "recovery" | "recovery-password" => Some(Self::RecoveryPassword),
            "clear" | "clear-key" => Some(Self::ClearKey),
            _ => text
                .strip_prefix("bek=")
                .filter(|path| !path.is_empty())
                .map(|path| Self::StartupKey(PathBuf::from(path))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretInput {
    pub source: SecretSource,
    /// Read the password/recovery password from this descriptor (first line)
    /// instead of prompting on the terminal.
    pub fd: Option<i32>,
}

impl SecretInput {
    /// Parse --bitlocker=KIND and --secret-fd=N from one argument.
    /// Returns Ok(true) if the argument was consumed.
    pub fn accept(slot: &mut Option<Self>, fd: &mut Option<i32>, arg: &str) -> Result<bool, String> {
        if let Some(kind) = arg.strip_prefix("--bitlocker=") {
            let source = SecretSource::parse(kind).ok_or_else(|| format!("invalid --bitlocker value: {kind}"))?;
            if slot.replace(Self { source, fd: None }).is_some() {
                return Err("--bitlocker given twice".into());
            }
            return Ok(true);
        }
        if let Some(number) = arg.strip_prefix("--secret-fd=") {
            let number = number.parse::<i32>().map_err(|_| "invalid --secret-fd".to_string())?;
            if number < 0 || fd.replace(number).is_some() {
                return Err("invalid --secret-fd".into());
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub fn finish(slot: Option<Self>, fd: Option<i32>) -> Result<Option<Self>, String> {
        match (slot, fd) {
            (Some(mut input), fd) => {
                input.fd = fd;
                Ok(Some(input))
            }
            (None, Some(_)) => Err("--secret-fd requires --bitlocker".into()),
            (None, None) => Ok(None),
        }
    }
}

pub const USAGE: &str = "--bitlocker=password|recovery|bek=FILE|clear [--secret-fd=N]";

#[cfg(test)]
mod throughput_profile {
    use super::UserAccel;
    use ntfs_rs::sector::{Method, SectorCipher};
    use std::hint::black_box;
    use std::time::Instant;

    #[test]
    fn cbc_acceleration_matches_software() {
        let accel = UserAccel::detect();
        for method in [Method::Aes128Cbc, Method::Aes256Cbc, Method::Aes128Diffuser, Method::Aes256Diffuser] {
            for size in [512, 1024, 2048, 4096] {
                let cipher = SectorCipher::new(method, &[0x35; 64], size).unwrap();
                let plain: Vec<u8> = (0..9 * size + 2).map(|i| (i * 31 + i / 7) as u8).collect();
                let mut reference = plain.clone();
                cipher.encrypt(&ntfs_rs::aes::Software, 12345, &mut reference[1..9 * size + 1]).unwrap();
                let mut actual = plain.clone();
                cipher.encrypt(&accel, 12345, &mut actual[1..9 * size + 1]).unwrap();
                assert_eq!(actual, reference);
                cipher.decrypt(&accel, 12345, &mut actual[1..9 * size + 1]).unwrap();
                assert_eq!(actual, plain);
            }
        }
    }

    #[test]
    #[ignore = "manual full-sector throughput profile"]
    fn bitlocker_sectors() {
        let accel = UserAccel::detect();
        let key = [0x5a; 64];
        eprintln!("engine={}", accel.engine_name());
        for (method, sector) in [
            (Method::Aes128Xts, 512),
            (Method::Aes128Diffuser, 512),
            (Method::Aes256Diffuser, 512),
            (Method::Aes128Diffuser, 4096),
        ] {
            let cipher = SectorCipher::new(method, &key, sector).unwrap();
            let mut data = vec![0x69; 64 * 1024];
            for decrypt in [true, false] {
                let mut rates = [0.0_f64; 5];
                for rate in &mut rates {
                    let start = Instant::now();
                    for round in 0..1024 {
                        if decrypt {
                            cipher.decrypt(&accel, round * 128, &mut data).unwrap();
                        } else {
                            cipher.encrypt(&accel, round * 128, &mut data).unwrap();
                        }
                        black_box(&data);
                    }
                    *rate = 64.0 / start.elapsed().as_secs_f64();
                }
                rates.sort_by(f64::total_cmp);
                eprintln!(
                    "{:?} {}B {}: {:.1} MiB/s [{:.1}..{:.1}]",
                    method,
                    sector,
                    if decrypt { "decrypt" } else { "encrypt" },
                    rates[2],
                    rates[0],
                    rates[4]
                );
            }
        }
    }
}

/// Heap bytes wiped on drop.
pub struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        let capacity = self.0.capacity();
        self.0.resize(capacity, 0);
        wipe_bytes(&mut self.0);
    }
}

impl SecretBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn read_line_from(reader: &mut dyn BufRead) -> io::Result<SecretBytes> {
    let mut line = SecretBytes(Vec::with_capacity(256));
    reader.read_until(b'\n', &mut line.0)?;
    while matches!(line.0.last(), Some(b'\n' | b'\r')) {
        line.0.pop();
    }
    if line.0.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty BitLocker secret"));
    }
    Ok(line)
}

/// Prompt on the controlling terminal with echo disabled.
fn prompt(message: &str) -> io::Result<SecretBytes> {
    let mut tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    // SAFETY: plain termios calls on an owned, open descriptor.
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut quiet = saved;
    quiet.c_lflag &= !(libc::ECHO | libc::ECHONL);
    quiet.c_lflag |= libc::ICANON;
    if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        tty.write_all(message.as_bytes())?;
        tty.flush()?;
        let mut reader = BufReader::new(tty.try_clone()?);
        read_line_from(&mut reader)
    })();
    unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &saved) };
    let _ = tty.write_all(b"\n");
    result
}

fn secret_text(input: &SecretInput, what: &str) -> io::Result<SecretBytes> {
    match input.fd {
        Some(fd) => {
            // SAFETY: the caller named this descriptor explicitly; ownership is
            // released again below so it is not closed twice.
            let file = unsafe { File::from_raw_fd(fd) };
            let mut reader = BufReader::new(file);
            let line = read_line_from(&mut reader);
            let file = reader.into_inner();
            std::mem::forget(file);
            line
        }
        None => prompt(&format!("BitLocker {what}: ")),
    }
}

fn describe_error(error: ntfs_rs::Error) -> io::Error {
    let message = match error {
        ntfs_rs::Error::AccessDenied => "wrong BitLocker secret or key for this volume",
        ntfs_rs::Error::NotFound => "no matching BitLocker protector on this volume",
        ntfs_rs::Error::Unsupported => "unsupported BitLocker layout or failed cryptographic self test",
        ntfs_rs::Error::InvalidSecurity => "malformed BitLocker secret or key protector",
        ntfs_rs::Error::InvalidGeometry => "BitLocker metadata describes an invalid geometry",
        _ => return io::Error::new(io::ErrorKind::InvalidData, format!("BitLocker: {error}")),
    };
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// Size in bytes of an image file or block device.
pub fn device_bytes(file: &mut File) -> io::Result<u64> {
    let length = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;
    Ok(length)
}

/// Read the first sector and recognize a BitLocker header.
pub fn probe_file(file: &mut File) -> io::Result<Option<Header>> {
    let mut sector = [0_u8; 512];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut sector)?;
    Ok(bitlocker::probe(&sector))
}

/// Everything needed after a successful unlock.
pub struct UnlockedVolume {
    pub header: Header,
    pub info: bitlocker::Info,
    pub key: VolumeKey,
    pub device_bytes: u64,
}

/// Unlock the FVEK of the volume in file and verify it by decrypting the
/// NTFS boot sector.
pub fn unlock(file: File, header: Header, input: &SecretInput) -> io::Result<(UnlockedVolume, File)> {
    let accel = UserAccel::detect();
    let mut file = file;
    let device_bytes = device_bytes(&mut file)?;
    let mut device = ReadOnly(Image(file));
    let mut buffer = vec![0_u8; METADATA_BYTES];
    let metadata = Metadata::read(&mut device, header, &mut buffer).map_err(describe_error)?;
    let key = match &input.source {
        SecretSource::Password => {
            let text = secret_text(input, "password")?;
            let text = std::str::from_utf8(text.as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "password is not UTF-8"))?;
            bitlocker::unlock(&metadata, &Secret::Password(text), &accel)
        }
        SecretSource::RecoveryPassword => {
            let text = secret_text(input, "recovery password")?;
            let text = std::str::from_utf8(text.as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "recovery password is not ASCII"))?;
            bitlocker::unlock(&metadata, &Secret::RecoveryPassword(text), &accel)
        }
        SecretSource::StartupKey(path) => {
            let bek = SecretBytes(std::fs::read(path)?);
            bitlocker::unlock(&metadata, &Secret::StartupKey(bek.as_bytes()), &accel)
        }
        SecretSource::ClearKey => bitlocker::unlock(&metadata, &Secret::ClearKey, &accel),
    }
    .map_err(describe_error)?;
    let volume = FveVolume::new(&metadata, &key, device_bytes).map_err(describe_error)?;
    let mut boot = [0_u8; 512];
    let mut scratch = [0_u8; 4096];
    volume.read_boot(&mut device, &accel, &mut boot, &mut scratch).map_err(describe_error)?;
    let info = metadata.info;
    drop(volume);
    Ok((UnlockedVolume { header, info, key, device_bytes }, device.0 .0))
}

/// Re-read and validate the unlocked physical layout for a mounted device.
pub fn volume_geometry(file: File, unlocked: &UnlockedVolume) -> io::Result<FveVolume> {
    let mut device = ReadOnly(Image(file));
    let mut buffer = vec![0_u8; METADATA_BYTES];
    let metadata = Metadata::read(&mut device, unlocked.header, &mut buffer).map_err(describe_error)?;
    FveVolume::new(&metadata, &unlocked.key, unlocked.device_bytes).map_err(describe_error)
}

/// Decrypting reader over the unlocked volume, plus its NTFS boot sector.
pub fn open_reader(
    file: File,
    header: Header,
    input: &SecretInput,
) -> io::Result<(Unlocked<ReadOnly<Image>, UserAccel>, BootSector, UnlockedVolume)> {
    let (unlocked, file) = unlock(file, header, input)?;
    let accel = UserAccel::detect();
    let mut device = ReadOnly(Image(file));
    let mut buffer = vec![0_u8; METADATA_BYTES];
    let metadata = Metadata::read(&mut device, header, &mut buffer).map_err(describe_error)?;
    let volume = FveVolume::new(&metadata, &unlocked.key, unlocked.device_bytes).map_err(describe_error)?;
    let mut boot = [0_u8; 512];
    let mut scratch = [0_u8; 4096];
    volume.read_boot(&mut device, &accel, &mut boot, &mut scratch).map_err(describe_error)?;
    let parsed = BootSector::parse(&boot)?;
    Ok((Unlocked::new(device, volume, accel), parsed, unlocked))
}

/// Open path; plain NTFS returns None, BitLocker requires input.
pub fn open_path(
    path: &Path,
    input: Option<&SecretInput>,
) -> io::Result<Option<(Unlocked<ReadOnly<Image>, UserAccel>, BootSector, UnlockedVolume)>> {
    let mut file = File::open(path)?;
    let Some(header) = probe_file(&mut file)? else {
        return Ok(None);
    };
    let input = input.ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, format!("BitLocker volume; unlock with {USAGE}"))
    })?;
    open_reader(file, header, input).map(Some)
}

/// Windows textual GUID (first three fields little-endian).
pub fn guid_string(guid: &[u8; 16]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
        u16::from_le_bytes([guid[4], guid[5]]),
        u16::from_le_bytes([guid[6], guid[7]]),
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

fn utf16_text(bytes: &[u8]) -> String {
    let units: Vec<u16> = ntfs_rs::bytes::units(&bytes).collect();
    String::from_utf16_lossy(&units).trim_end_matches('\0').to_string()
}

/// Human-readable, non-secret metadata summary.
pub fn describe(path: &Path) -> io::Result<String> {
    use std::fmt::Write as _;
    let mut file = File::open(path)?;
    let size = device_bytes(&mut file)?;
    let header =
        probe_file(&mut file)?.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a BitLocker volume"))?;
    let mut device = ReadOnly(Image(file));
    let mut buffer = vec![0_u8; METADATA_BYTES];
    let metadata = Metadata::read(&mut device, header, &mut buffer).map_err(describe_error)?;
    let info = &metadata.info;
    let mut out = String::new();
    let method = metadata.method().map(|m| m.name()).unwrap_or("unsupported");
    let _ = writeln!(out, "layout: {}", if header.to_go { "BitLocker To Go" } else { "BitLocker (Windows 7+)" });
    let _ = writeln!(out, "device bytes: {size}");
    let _ = writeln!(out, "sector bytes: {}", header.sector_bytes);
    let _ = writeln!(out, "volume guid: {}", guid_string(&info.volume_guid));
    let _ = writeln!(out, "encryption: {method} (0x{:04x})", info.method_code);
    let _ = writeln!(
        out,
        "state: current=0x{:04x} next=0x{:04x} fully_encrypted={}",
        info.state,
        info.next_state,
        u8::from(info.fully_encrypted())
    );
    let _ = writeln!(out, "encrypted bytes: {}", info.encrypted_bytes);
    let _ = writeln!(
        out,
        "metadata offsets: {:#x} {:#x} {:#x}",
        info.metadata_offsets[0], info.metadata_offsets[1], info.metadata_offsets[2]
    );
    let _ = writeln!(out, "relocated boot region: {} sectors at {:#x}", info.header_sectors, info.header_offset);
    if let Some(text) = metadata.description() {
        let _ = writeln!(out, "description: {}", utf16_text(text));
    }
    for protector in metadata.protectors() {
        let protector = protector.map_err(describe_error)?;
        let _ = writeln!(
            out,
            "protector {}: {} (0x{:04x})",
            guid_string(&protector.guid),
            protector.protection_name(),
            protector.protection
        );
    }
    let _ = writeln!(out, "volume GUID: {}", guid_string(&info.volume_guid));
    let _ = writeln!(out, "aes engine: {}", UserAccel::detect().engine_name());
    Ok(out)
}

/// Offline check/repair/replay tools operate on raw NTFS sectors and have no
/// encrypting write path yet. Exit with a clear message (status 8) instead of
/// reporting ciphertext as a corrupt NTFS volume.
pub fn refuse_encrypted<'a>(tool: &str, paths: impl IntoIterator<Item = &'a std::ffi::OsStr>) {
    for path in paths {
        if path.to_str().is_some_and(|text| text.starts_with('-')) {
            continue;
        }
        let Ok(mut file) = File::open(path) else {
            continue;
        };
        if matches!(probe_file(&mut file), Ok(Some(_))) {
            eprintln!(
                "{tool}: {} is a BitLocker volume; offline checks and repairs are not supported on encrypted volumes (use ntfs-inspect {USAGE}, or mount it)",
                Path::new(path).display()
            );
            std::process::exit(8);
        }
    }
}
