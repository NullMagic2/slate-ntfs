//! Module: slate_ntfs_tools::boot_repair
//! Purpose: Persist explicitly requested offline checks and run them before mounting.
//! Created: 2026-11-24
//! Architecture: The CLI, boot generator and initramfs adapter share protected
//! volume jobs. The existing offline checker owns repair sequencing and journals.

use crate::checker::consistency::{AuditOptions, IndexCachePasses, IndexCheck};
use crate::{linux, progress_display, recovery_io};
use ntfs_rs::boot::BOOT_SECTOR_BYTES;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONFIG_DIRECTORY: &str = "/etc/slate-ntfs/boot-repair";
pub const DEFAULT_STORAGE: &str = "/var/lib/slate-ntfs/boot-repair";
pub const JOURNAL_ROOT_ENV: &str = "SLATE_NTFS_RECOVERY_DIRECTORY";
pub const SERIAL_ENV: &str = "SLATE_NTFS_SCHEDULED_SERIAL";
pub const LENGTH_ENV: &str = "SLATE_NTFS_SCHEDULED_BYTES";
const LEGACY_RECORD_VERSION: &str = "SLATE_BOOT_REPAIR_1";
const RECORD_VERSION: &str = "SLATE_BOOT_REPAIR_2";
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const WRITABLE_BY_OTHERS: u32 = 0o022;
const PRIVATE_FORBIDDEN_MODE: u32 = 0o077;
const UUID_DIGITS: usize = 16;
const JOB_ID_BYTES: usize = 16;
const HEX_DIGITS_PER_BYTE: usize = 2;
const FSCK_REPAIRED: i32 = 1;
const FSCK_UNRESOLVED: i32 = 4;
const FSCK_FAILED: i32 = 8;
const SUPPORTED_STORAGE: &[&str] = &["ext2", "ext3", "ext4", "xfs"];

fn reject(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SurfaceIntent {
    #[default]
    None,
    Recover,
    Reassess,
}

impl SurfaceIntent {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Recover => "recover",
            Self::Reassess => "reassess",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Intent {
    pub surface: SurfaceIntent,
    pub audit: AuditOptions,
    pub log_bytes: Option<u64>,
}

impl Intent {
    pub fn validate(self) -> io::Result<()> {
        if self.audit.skip_directory_cycles {
            return Err(reject("offline repair requires cycle checking; --skip-cycles is read-only"));
        }
        if self.surface != SurfaceIntent::None && self.audit != AuditOptions::default() {
            return Err(reject("surface recovery requires full default index checking; omit index/cache overrides"));
        }
        if AuditOptions::from_index_policy_word(self.audit.index_policy_word()) != Some(self.audit) {
            return Err(reject("unsupported scheduled index policy"));
        }
        if let Some(bytes) = self.log_bytes {
            recovery_io::validate_log_size(bytes)?;
        }
        Ok(())
    }

    fn stages(self) -> Vec<&'static str> {
        let mut stages = Vec::new();
        if self.surface != SurfaceIntent::None {
            stages.push("surface");
        }
        stages.push("repair");
        if self.log_bytes.is_some() {
            stages.push("resize");
        }
        stages.extend(["verify", "complete"]);
        stages
    }
}

pub(crate) fn index_arguments(command: &mut Command, options: AuditOptions) {
    let mode = match options.index_check {
        IndexCheck::Full => "full",
        IndexCheck::Quick => "quick",
    };
    let passes = match options.index_cache_passes {
        IndexCachePasses::Auto => "auto".to_owned(),
        IndexCachePasses::Streaming => "0".to_owned(),
        IndexCachePasses::Count(count) => count.to_string(),
    };
    command.arg(format!("--index-check={mode}")).arg(format!("--index-cache-passes={passes}"));
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Job {
    uuid: String,
    bytes: u64,
    storage_uuid: String,
    storage_type: String,
    storage_mount: PathBuf,
    storage_relative: PathBuf,
    storage_directory: PathBuf,
    job_id: String,
    intent: Intent,
    legacy: bool,
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:0width$x}", width = HEX_DIGITS_PER_BYTE)).collect()
}

fn unhex(text: &str) -> io::Result<Vec<u8>> {
    if text.len() % HEX_DIGITS_PER_BYTE != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(reject("invalid scheduled-repair path encoding"));
    }
    (0..text.len())
        .step_by(HEX_DIGITS_PER_BYTE)
        .map(|at| u8::from_str_radix(&text[at..at + HEX_DIGITS_PER_BYTE], 16).map_err(io::Error::other))
        .collect()
}

fn valid_uuid(text: &str) -> bool {
    text.len() == UUID_DIGITS && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn path_text(path: &Path) -> io::Result<&str> {
    let text = path.to_str().ok_or_else(|| reject("scheduled-repair paths must be valid UTF-8"))?;
    if text.chars().any(char::is_control) {
        return Err(reject("scheduled-repair paths cannot contain control characters"));
    }
    Ok(text)
}

impl Job {
    fn encode(&self) -> io::Result<String> {
        self.intent.validate()?;
        if self.legacy && self.intent != Intent::default() {
            return Err(reject("legacy jobs cannot carry specialized repair intent"));
        }
        let version = if self.legacy { LEGACY_RECORD_VERSION } else { RECORD_VERSION };
        let mut record = format!(
            "{version}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.uuid,
            self.bytes,
            self.storage_uuid,
            self.storage_type,
            hexadecimal(path_text(&self.storage_mount)?.as_bytes()),
            hexadecimal(path_text(&self.storage_relative)?.as_bytes()),
            hexadecimal(path_text(&self.storage_directory)?.as_bytes()),
            self.job_id,
        );
        if !self.legacy {
            let surface = self.intent.surface.name();
            record.push_str(&format!(
                "{surface}\n{}\n{}\n",
                self.intent.audit.index_policy_word(),
                self.intent.log_bytes.unwrap_or(0)
            ));
        }
        Ok(record)
    }

    fn decode(text: &str) -> io::Result<Self> {
        let fields: Vec<_> = text.lines().collect();
        let [version, uuid, bytes, storage_uuid, storage_type, mount, relative, directory, job_id, options @ ..] =
            fields.as_slice()
        else {
            return Err(reject("invalid scheduled-repair record"));
        };
        let legacy = *version == LEGACY_RECORD_VERSION;
        if (!legacy && *version != RECORD_VERSION) || !valid_uuid(uuid) {
            return Err(reject("invalid scheduled-repair record"));
        }
        let intent = match (legacy, options) {
            (true, []) => Intent::default(),
            (false, [surface, policy, log_bytes]) => {
                let surface = match *surface {
                    "none" => SurfaceIntent::None,
                    "recover" => SurfaceIntent::Recover,
                    "reassess" => SurfaceIntent::Reassess,
                    _ => return Err(reject("invalid scheduled surface intent")),
                };
                let audit = policy
                    .parse::<u64>()
                    .ok()
                    .and_then(AuditOptions::from_index_policy_word)
                    .ok_or_else(|| reject("invalid scheduled index policy"))?;
                let bytes = log_bytes.parse::<u64>().map_err(io::Error::other)?;
                Intent { surface, audit, log_bytes: (bytes != 0).then_some(bytes) }
            }
            _ => return Err(reject("unsupported scheduled-repair record version or options")),
        };
        intent.validate()?;
        let path = |encoded: &str| -> io::Result<PathBuf> {
            let bytes = unhex(encoded)?;
            let text = String::from_utf8(bytes).map_err(io::Error::other)?;
            let path = PathBuf::from(text);
            path_text(&path)?;
            if path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
                return Err(reject("scheduled-repair paths must be normalized"));
            }
            Ok(path)
        };
        let job = Self {
            uuid: (*uuid).to_owned(),
            bytes: bytes.parse().map_err(io::Error::other)?,
            storage_uuid: (*storage_uuid).to_owned(),
            storage_type: (*storage_type).to_owned(),
            storage_mount: path(mount)?,
            storage_relative: path(relative)?,
            storage_directory: path(directory)?,
            job_id: (*job_id).to_owned(),
            intent,
            legacy,
        };
        if job.job_id.len() != JOB_ID_BYTES * HEX_DIGITS_PER_BYTE
            || !job.job_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || job.bytes < BOOT_SECTOR_BYTES as u64
            || job.storage_uuid.is_empty()
            || !job.storage_uuid.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
            || !SUPPORTED_STORAGE.contains(&job.storage_type.as_str())
            || !job.storage_mount.is_absolute()
            || job.storage_relative.is_absolute()
            || job.storage_mount.join(&job.storage_relative) != job.storage_directory
        {
            return Err(reject("invalid scheduled-repair storage identity"));
        }
        Ok(job)
    }

    fn config_path(&self) -> PathBuf {
        Path::new(CONFIG_DIRECTORY).join(format!("{}.job", self.uuid))
    }

    fn directory(&self, mounted_storage: Option<&Path>) -> PathBuf {
        mounted_storage
            .map(|mount| mount.join(&self.storage_relative))
            .unwrap_or_else(|| self.storage_directory.clone())
            .join(&self.uuid)
            .join(&self.job_id)
    }

    fn device(&self) -> PathBuf {
        Path::new("/dev/disk/by-uuid").join(&self.uuid)
    }
}

fn require_root() -> io::Result<()> {
    if linux::effective_uid() != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "scheduled repairs require root"));
    }
    Ok(())
}

fn protected_directory(path: &Path, create: bool, private: bool) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(reject("repair storage must be an absolute path"));
    }
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(ancestor) {
            Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                fs::DirBuilder::new().mode(PRIVATE_DIRECTORY_MODE).create(ancestor)?;
                File::open(linux::parent_directory(ancestor))?.sync_all()?;
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        let metadata = fs::symlink_metadata(ancestor)?;
        let forbidden = if private && ancestor == path { PRIVATE_FORBIDDEN_MODE } else { WRITABLE_BY_OTHERS };
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & forbidden != 0 {
            return Err(reject(&format!(
                "repair storage has unsafe ownership, permissions or symlinks: {}",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

fn read_protected(path: &Path) -> io::Result<String> {
    let file = OpenOptions::new().read(true).custom_flags(linux::NO_FOLLOW_NONBLOCK).open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & PRIVATE_FORBIDDEN_MODE != 0 {
        return Err(reject("unsafe scheduled-repair record"));
    }
    if metadata.len() > MAX_RECORD_BYTES {
        return Err(reject("scheduled-repair record is too large"));
    }
    let mut text = String::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_string(&mut text)?;
    Ok(text)
}

fn publish(path: &Path, text: &str) -> io::Result<()> {
    let parent = linux::parent_directory(path);
    protected_directory(parent, true, true)?;
    if path.exists() {
        read_protected(path)?;
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_nanos();
    let temporary = parent.join(format!(".job-{}-{stamp}.tmp", std::process::id()));
    let result = (|| {
        let mut file =
            OpenOptions::new().create_new(true).write(true).mode(linux::PRIVATE_FILE_MODE).open(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn root_lock(directory: &Path) -> io::Result<File> {
    protected_directory(directory, true, true)?;
    let path = directory.join(".lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(linux::PRIVATE_FILE_MODE)
        .custom_flags(linux::NO_FOLLOW_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & PRIVATE_FORBIDDEN_MODE != 0 {
        return Err(reject("unsafe scheduled-repair lock"));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn unique_device(uuid: &str, expected: u64) -> io::Result<()> {
    let matches = Command::new("/sbin/blkid")
        .args(["-c", "/dev/null", "-t", &format!("UUID={uuid}"), "-o", "device"])
        .output()?;
    if !matches.status.success() {
        return Err(reject("cannot discover the scheduled filesystem UUID"));
    }
    let mut identities = std::collections::BTreeSet::new();
    for path in String::from_utf8(matches.stdout).map_err(io::Error::other)?.lines() {
        identities.insert(fs::metadata(path)?.rdev());
    }
    if identities.len() != 1 || !identities.contains(&expected) {
        return Err(reject("filesystem UUID is ambiguous or identifies another device"));
    }
    Ok(())
}

fn checked_storage(job: &Job, mounted: Option<&Path>) -> io::Result<PathBuf> {
    let directory = job.directory(mounted);
    protected_directory(&directory, false, true)?;
    let expected = fs::metadata(&directory)?.dev();
    let alias = Path::new("/dev/disk/by-uuid").join(&job.storage_uuid);
    if fs::metadata(alias)?.rdev() != expected {
        return Err(reject("scheduled journal filesystem identity changed"));
    }
    unique_device(&job.storage_uuid, expected)?;
    Ok(directory)
}

fn target_identity(path: &Path) -> io::Result<(String, u64)> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path)?;
    if !file.metadata()?.file_type().is_block_device() {
        return Err(reject("boot scheduling requires an NTFS block device"));
    }
    let (boot, _) = recovery_io::bootstrap_boot(&linux::fd_path(&file))?;
    let length = linux::image_length(&file)?;
    if boot.total_sectors.checked_mul(u64::from(boot.bytes_per_sector)).is_none_or(|size| size > length) {
        return Err(reject("scheduled device length differs from NTFS geometry"));
    }
    let uuid = format!("{:0width$X}", boot.serial_number, width = UUID_DIGITS);
    unique_device(&uuid, file.metadata()?.rdev())?;
    let alias = Path::new("/dev/disk/by-uuid").join(&uuid);
    if fs::metadata(alias)?.rdev() != file.metadata()?.rdev() {
        return Err(reject("NTFS UUID alias does not identify the requested block device"));
    }
    Ok((uuid, length))
}

fn identifier(path: &Path) -> io::Result<String> {
    if path.to_str().is_some_and(valid_uuid) {
        return Ok(path_text(path)?.to_ascii_uppercase());
    }
    target_identity(path).map(|identity| identity.0)
}

fn load(uuid: &str) -> io::Result<Option<Job>> {
    if !valid_uuid(uuid) {
        return Err(reject("invalid scheduled volume UUID"));
    }
    if !Path::new(CONFIG_DIRECTORY).exists() {
        return Ok(None);
    }
    protected_directory(Path::new(CONFIG_DIRECTORY), false, true)?;
    let path = Path::new(CONFIG_DIRECTORY).join(format!("{uuid}.job"));
    match read_protected(&path) {
        Ok(text) => {
            let job = Job::decode(&text)?;
            if job.uuid != uuid {
                return Err(reject("scheduled-repair filename and UUID differ"));
            }
            Ok(Some(job))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn mount_path(text: &str) -> PathBuf {
    PathBuf::from(text.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\"))
}

fn storage_identity(directory: &Path, target: &Path) -> io::Result<(String, String, PathBuf, PathBuf)> {
    let device = fs::metadata(directory)?.dev();
    if device == fs::metadata(target)?.rdev() {
        return Err(reject("repair storage must be on another filesystem; use --repair-storage DIRECTORY"));
    }
    let sysfs = format!("/sys/dev/block/{}:{}/uevent", libc::major(device), libc::minor(device));
    let name = fs::read_to_string(sysfs)?
        .lines()
        .find_map(|line| line.strip_prefix("DEVNAME=").map(str::to_owned))
        .ok_or_else(|| reject("cannot identify persistent repair storage device"))?;
    let block = format!("/dev/{name}");
    let query = |field: &str| -> io::Result<String> {
        let result = Command::new("/sbin/blkid").args(["-s", field, "-o", "value", &block]).output()?;
        if !result.status.success() {
            return Err(reject("repair storage must be on a persistent block filesystem"));
        }
        Ok(String::from_utf8(result.stdout).map_err(io::Error::other)?.trim().to_owned())
    };
    let uuid = query("UUID")?;
    let kind = query("TYPE")?;
    unique_device(&uuid, device)?;
    if !SUPPORTED_STORAGE.contains(&kind.as_str()) {
        return Err(reject("repair storage requires ext2, ext3, ext4 or XFS"));
    }
    let mut mount = None;
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if let [_, _, _, _, point, _, ..] = fields.as_slice() {
            let point = mount_path(point);
            if directory.starts_with(&point)
                && mount.as_ref().is_none_or(|old: &PathBuf| point.as_os_str().len() > old.as_os_str().len())
            {
                mount = Some(point);
            }
        }
    }
    let mount = mount.ok_or_else(|| reject("cannot identify repair storage mount"))?;
    let relative = directory.strip_prefix(&mount).map_err(io::Error::other)?.to_owned();
    Ok((uuid, kind, mount, relative))
}

fn refresh_boot_configuration() -> io::Result<()> {
    let status = Command::new("/usr/bin/systemctl").args(["daemon-reload"]).status()?;
    if !status.success() {
        return Err(reject("scheduled repair saved, but systemd configuration reload failed"));
    }
    Ok(())
}

fn refresh_initramfs() -> io::Result<()> {
    let status = Command::new("/usr/sbin/update-initramfs").args(["-u", "-k", "all"]).status()?;
    if !status.success() {
        return Err(reject("scheduled repair saved, but initramfs update failed; resolve this before reboot"));
    }
    Ok(())
}

/// Test the same exclusive open required by publication; only EBUSY requests
/// deferral. Permission and device errors remain operational failures.
pub fn busy(device: &Path) -> io::Result<bool> {
    let canonical = fs::canonicalize(device)?;
    if !fs::metadata(&canonical)?.file_type().is_block_device() {
        return Err(reject("offline repair requires a block device"));
    }
    match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_EXCL | linux::NO_FOLLOW_NONBLOCK)
        .open(canonical)
    {
        Ok(_) => Ok(false),
        Err(error) if error.raw_os_error() == Some(libc::EBUSY) => Ok(true),
        Err(error) => Err(error),
    }
}

pub fn schedule(device: &Path, storage: Option<&Path>, intent: Intent) -> io::Result<()> {
    intent.validate()?;
    require_root()?;
    if !Path::new("/usr/lib/systemd/system-generators/slate-ntfs-repair-generator").is_file() {
        return Err(reject("boot scheduling requires the installed systemd repair generator"));
    }
    let _lock = root_lock(Path::new(CONFIG_DIRECTORY))?;
    let (uuid, bytes) = target_identity(device)?;
    if load(&uuid)?.is_some() {
        return Err(reject(
            "volume already has a scheduled repair; use --schedule-status or --cancel-scheduled-repair",
        ));
    }
    let directory = storage.unwrap_or(Path::new(DEFAULT_STORAGE));
    let existing = directory
        .ancestors()
        .find(|path| path.exists())
        .ok_or_else(|| reject("repair storage has no existing parent"))?;
    if fs::metadata(existing)?.dev() == fs::metadata(device)?.rdev() {
        return Err(reject("repair storage must be on another filesystem; use --repair-storage DIRECTORY"));
    }
    protected_directory(directory, true, true)?;
    let directory = fs::canonicalize(directory)?;
    let (storage_uuid, storage_type, storage_mount, storage_relative) = storage_identity(&directory, device)?;
    let mut random = [0u8; JOB_ID_BYTES];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    let job = Job {
        uuid,
        bytes,
        storage_uuid,
        storage_type,
        storage_mount,
        storage_relative,
        storage_directory: directory,
        job_id: hexadecimal(&random),
        intent,
        legacy: false,
    };
    let target = fs::metadata(device)?.rdev();
    let root_job = fs::metadata("/")?.dev() == target;
    if root_job
        && !Path::new("/usr/share/initramfs-tools/scripts/local-premount/ntfsrs-repair").is_file()
        && !Path::new("/etc/initramfs-tools/scripts/local-premount/ntfsrs-repair").is_file()
    {
        return Err(reject("NTFS root scheduling requires the installed pre-mount repair hook"));
    }
    let state = job.directory(None);
    protected_directory(&state, true, true)?;
    publish(&state.join("intent"), &job.encode()?)?;
    publish(&state.join("step"), job.intent.stages()[0])?;
    publish(&state.join("state"), "pending\n")?;
    publish(&job.config_path(), &job.encode()?)?;
    if root_job {
        refresh_initramfs()?;
    }
    refresh_boot_configuration()?;
    println!("scheduled_repair={} storage={} repair_started=0", job.uuid, job.storage_directory.display());
    Ok(())
}

fn phase(job: &Job, mounted_storage: Option<&Path>) -> io::Result<String> {
    let directory = checked_storage(job, mounted_storage)?;
    verify_intent(job, &directory)?;
    let state = read_protected(&directory.join("state"))?;
    if !matches!(state.lines().next(), Some("pending" | "running" | "failed" | "complete" | "cancelled")) {
        return Err(reject("invalid scheduled repair state"));
    }
    Ok(state)
}

pub fn pending(device: &Path) -> io::Result<bool> {
    if !Path::new(CONFIG_DIRECTORY).exists() {
        return Ok(false);
    }
    if !fs::read_dir(CONFIG_DIRECTORY)?
        .filter_map(Result::ok)
        .any(|entry| entry.path().extension().is_some_and(|suffix| suffix == "job"))
    {
        return Ok(false);
    }
    let Some(job) = load(&identifier(device)?)? else {
        return Ok(false);
    };
    Ok(!matches!(phase(&job, None)?.lines().next(), Some("complete" | "cancelled")))
}

pub fn status(device: &Path) -> io::Result<()> {
    require_root()?;
    let uuid = identifier(device)?;
    match load(&uuid)? {
        Some(job) => println!(
            "volume={} state={} storage={} surface={} index_policy={} log_size_bytes={}",
            job.uuid,
            phase(&job, None)?.trim().replace('\n', " "),
            job.storage_directory.display(),
            job.intent.surface.name(),
            job.intent.audit.index_policy_word(),
            job.intent.log_bytes.map(|bytes| bytes.to_string()).unwrap_or_else(|| "unchanged".to_owned()),
        ),
        None => println!("volume={uuid} state=not-scheduled"),
    }
    Ok(())
}

fn unfinished_journal(directory: &Path) -> io::Result<bool> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if metadata.is_symlink() {
            return Err(reject("unexpected symlink in scheduled repair storage"));
        }
        if metadata.is_dir() && unfinished_journal(&entry.path())? {
            return Ok(true);
        }
        if metadata.is_file() && entry.path().extension().is_some_and(|suffix| suffix == "journal") {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn cancel(device: &Path) -> io::Result<()> {
    require_root()?;
    let _lock = root_lock(Path::new(CONFIG_DIRECTORY))?;
    let uuid = identifier(device)?;
    let job = load(&uuid)?.ok_or_else(|| reject("volume has no scheduled repair"))?;
    let directory = checked_storage(&job, None)?;
    let _job_lock = root_lock(&directory)?;
    if unfinished_journal(&directory)? {
        return Err(reject("repair publication has started; retain the schedule and resume its journal"));
    }
    publish(&directory.join("state"), "cancelled\n")?;
    fs::remove_file(job.config_path())?;
    File::open(CONFIG_DIRECTORY)?.sync_all()?;
    if fs::metadata(job.device()).is_ok_and(|device| fs::metadata("/").is_ok_and(|root| root.dev() == device.rdev())) {
        refresh_initramfs()?;
    }
    refresh_boot_configuration()?;
    println!("cancelled_repair={uuid} repair_started=0");
    Ok(())
}

fn retire_configuration(job: &Job, mounted_storage: Option<&Path>) -> io::Result<()> {
    if mounted_storage.is_some() {
        return Ok(());
    }
    if job.config_path().exists() {
        fs::remove_file(job.config_path())?;
        File::open(CONFIG_DIRECTORY)?.sync_all()?;
        if fs::metadata("/")?.dev() == fs::metadata(job.device())?.rdev() {
            refresh_initramfs()?;
        }
    }
    Ok(())
}

fn validate_pending_stage(directory: &Path, step: &str) -> io::Result<()> {
    fn visit(root: &Path, directory: &Path, step: &str) -> io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_symlink() {
                return Err(reject("unexpected symlink in scheduled state"));
            }
            if entry.file_type()?.is_dir() {
                visit(root, &entry.path(), step)?;
            }
            if entry.path().extension().is_some_and(|extension| extension == "journal") {
                let path = entry.path();
                let relative = path.strip_prefix(root).map_err(io::Error::other)?;
                let allowed = match step {
                    "surface" => relative == Path::new("surface.journal"),
                    "repair" => relative.starts_with("fsck") || relative.starts_with("replay"),
                    "resize" => relative == Path::new("log-size.journal"),
                    _ => false,
                };
                if !allowed {
                    return Err(reject("unfinished publication belongs to another scheduled stage"));
                }
            }
        }
        Ok(())
    }
    visit(directory, directory, step)
}

fn verify_intent(job: &Job, directory: &Path) -> io::Result<()> {
    let intent = directory.join("intent");
    if job.legacy && !intent.exists() {
        return Ok(());
    }
    if read_protected(&intent)? != job.encode()? {
        return Err(reject("scheduled repair intent changed; retain its original configuration and journals"));
    }
    Ok(())
}

fn seal_legacy(job: &Job, directory: &Path) -> io::Result<()> {
    if job.legacy && !directory.join("intent").exists() {
        // Version one can only mean ordinary repair. Seal that fixed intent
        // before resuming; inspection commands never create scheduling state.
        publish(&directory.join("intent"), &job.encode()?)?;
        publish(&directory.join("step"), "repair")?;
    }
    Ok(())
}

fn command(job: &Job, directory: &Path) -> Command {
    let mut command = Command::new("/usr/sbin/ntfs-chkdsk");
    command
        .arg("--progress")
        .env(JOURNAL_ROOT_ENV, directory)
        .env(SERIAL_ENV, &job.uuid)
        .env(LENGTH_ENV, job.bytes.to_string());
    command
}

fn step_command(job: &Job, directory: &Path, step: &str) -> io::Result<Command> {
    let mut command = command(job, directory);
    match step {
        "surface" => {
            let journal = directory.join("surface.journal");
            let resume = journal.exists() || directory.join("surface.journal.completed").exists();
            if job.intent.surface == SurfaceIntent::Reassess {
                command.arg("--rescan-bad");
            }
            command
                .arg(if resume { "--resume-device-recovery" } else { "--recover-in-place" })
                .arg(job.device())
                .arg("--archive")
                .arg(directory.join("surface.archive"))
                .arg("--loss-map")
                .arg(directory.join("surface.loss-map"))
                .arg("--journal")
                .arg(journal);
        }
        "repair" => {
            index_arguments(&mut command, job.intent.audit);
            command.args(["--force", "--repair"]).arg(job.device());
        }
        "resize" => {
            let journal = directory.join("log-size.journal");
            let resume = journal.exists() || directory.join("log-size.journal.completed").exists();
            command
                .arg(if resume { "--resume-log-resize" } else { "--resize-log-in-place" })
                .arg(job.intent.log_bytes.ok_or_else(|| reject("missing scheduled log size"))?.to_string())
                .arg(job.device())
                .arg(journal);
        }
        "verify" => {
            index_arguments(&mut command, job.intent.audit);
            command.arg("--check").arg(job.device());
        }
        _ => return Err(reject("invalid scheduled repair stage")),
    }
    Ok(command)
}

pub fn ensure_intent(device: &Path, requested: Intent) -> io::Result<()> {
    if let Some(job) = load(&identifier(device)?)? {
        if job.intent != requested {
            return Err(reject("requested options differ from the scheduled repair intent"));
        }
    }
    Ok(())
}

pub fn run(device: &Path, mounted_storage: Option<&Path>) -> io::Result<i32> {
    require_root()?;
    let uuid = identifier(device)?;
    let Some(job) = load(&uuid)? else {
        return Ok(0);
    };
    let directory = checked_storage(&job, mounted_storage)?;
    let _job_lock = root_lock(&directory)?;
    seal_legacy(&job, &directory)?;
    verify_intent(&job, &directory)?;
    let current = phase(&job, mounted_storage)?;
    if matches!(current.lines().next(), Some("complete" | "cancelled")) {
        retire_configuration(&job, mounted_storage)?;
        return Ok(0);
    }
    let (actual_uuid, bytes) = target_identity(&job.device())?;
    if actual_uuid != job.uuid || bytes != job.bytes {
        return Err(reject("scheduled volume identity changed; no repair started"));
    }
    let stages = job.intent.stages();
    let step = read_protected(&directory.join("step"))?;
    let start = stages
        .iter()
        .position(|value| *value == step.trim())
        .ok_or_else(|| reject("invalid scheduled repair stage"))?;
    validate_pending_stage(&directory, step.trim())?;
    publish(&directory.join("state"), "running\n")?;
    let mut repaired = start != 0;
    for (index, step) in stages.iter().enumerate().skip(start) {
        if *step == "complete" {
            break;
        }
        println!("scheduled_stage={step} volume={uuid}");
        {
            let mut command = step_command(&job, &directory, step)?;
            let code = match progress_display::run(&mut command) {
                Ok(status) => status.code().unwrap_or(FSCK_FAILED),
                Err(error) => {
                    publish(&directory.join("state"), &format!("failed\nexit={FSCK_FAILED}\n"))?;
                    return Err(error);
                }
            };
            if !matches!(code, 0 | FSCK_REPAIRED) {
                publish(&directory.join("state"), &format!("failed\nexit={code}\n"))?;
                return Ok(if code == FSCK_UNRESOLVED || code >= crate::cancellation::SIGNAL_EXIT_BASE {
                    code
                } else {
                    FSCK_FAILED
                });
            }
            repaired |= code == FSCK_REPAIRED || matches!(*step, "surface" | "resize");
        }
        if std::env::var("SLATE_NTFS_TEST_SCHEDULE_STOP_AFTER_STAGE").ok().as_deref() == Some(*step) {
            publish(&directory.join("state"), &format!("failed\nexit={FSCK_FAILED}\n"))?;
            return Ok(FSCK_FAILED);
        }
        if *step == "verify" && crate::offline_check::requests_attention(&job.device())? {
            publish(&directory.join("state"), &format!("failed\nexit={FSCK_UNRESOLVED}\n"))?;
            return Ok(FSCK_UNRESOLVED);
        }
        publish(&directory.join("step"), stages[index + 1])?;
    }
    publish(&directory.join("state"), "complete\n")?;
    retire_configuration(&job, mounted_storage)?;
    println!("scheduled_repair_complete={uuid} preimages_retained=1");
    Ok(if repaired { FSCK_REPAIRED } else { 0 })
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Operation {
    Repair(AuditOptions),
    Replay,
    Surface(bool),
    Resize(u64),
    Other,
}

fn operation_matches(intent: Intent, step: &str, operation: Operation) -> bool {
    match (step, operation) {
        ("repair", Operation::Repair(audit)) => audit == intent.audit,
        // Ordinary repair also answers an on-disk log resize request through
        // the existing checker sequence and its retained repair journal.
        ("repair", Operation::Replay | Operation::Resize(_)) => true,
        ("surface", Operation::Surface(reassess)) => {
            reassess == (intent.surface == SurfaceIntent::Reassess) && intent.surface != SurfaceIntent::None
        }
        ("resize", Operation::Resize(bytes)) => intent.log_bytes == Some(bytes),
        _ => false,
    }
}

pub(crate) fn authorize_recovery_artifacts(archive: &Path, loss_map: &Path, journal: &Path) -> io::Result<()> {
    if std::env::var_os(SERIAL_ENV).is_none() {
        return Ok(());
    }
    let directory = PathBuf::from(std::env::var_os(JOURNAL_ROOT_ENV).ok_or_else(|| reject("missing scheduled store"))?);
    if archive != directory.join("surface.archive")
        || loss_map != directory.join("surface.loss-map")
        || journal != directory.join("surface.journal")
    {
        return Err(reject("recovery artifacts differ from the protected scheduled intent"));
    }
    Ok(())
}

pub(crate) fn authorize_operation(operation: Operation, journal: &Path) -> io::Result<()> {
    let Some(serial) = std::env::var_os(SERIAL_ENV) else {
        return Ok(());
    };
    let uuid = serial.to_str().ok_or_else(|| reject("invalid scheduled serial"))?;
    let job = load(uuid)?.ok_or_else(|| reject("missing scheduled repair job"))?;
    let directory = PathBuf::from(std::env::var_os(JOURNAL_ROOT_ENV).ok_or_else(|| reject("missing scheduled store"))?);
    verify_intent(&job, &directory)?;
    let step = read_protected(&directory.join("step"))?;
    let relative =
        journal.strip_prefix(&directory).map_err(|_| reject("scheduled journal is outside its protected job"))?;
    let expected_path = match (step.trim(), operation) {
        ("surface", _) => relative == Path::new("surface.journal"),
        ("resize", _) => relative == Path::new("log-size.journal"),
        ("repair", Operation::Replay) => relative.parent() == Some(Path::new("replay")),
        ("repair", _) => relative.parent() == Some(Path::new("fsck")),
        _ => false,
    };
    let allowed = expected_path && operation_matches(job.intent, step.trim(), operation);
    if !allowed {
        return Err(reject("publication operation differs from the scheduled stage or repair intent"));
    }
    Ok(())
}

pub fn locator(device: &Path) -> io::Result<()> {
    require_root()?;
    if let Some(job) = load(&identifier(device)?)? {
        println!("{} {} {}", job.uuid, job.storage_uuid, job.storage_type);
    }
    Ok(())
}

fn unit_path(path: &Path) -> io::Result<String> {
    let result = Command::new("/usr/bin/systemd-escape").args(["--path", "--suffix=mount"]).arg(path).output()?;
    if !result.status.success() {
        return Err(reject("cannot encode mount unit name"));
    }
    Ok(String::from_utf8(result.stdout).map_err(io::Error::other)?.trim().to_owned())
}

fn fsck_unit(device: &Path) -> io::Result<String> {
    let result = Command::new("/usr/bin/systemd-escape")
        .args(["--path", "--template=systemd-fsck@.service"])
        .arg(device)
        .output()?;
    if !result.status.success() {
        return Err(reject("cannot encode filesystem check unit name"));
    }
    Ok(String::from_utf8(result.stdout).map_err(io::Error::other)?.trim().to_owned())
}

fn mount_source(text: &str) -> PathBuf {
    for (tag, directory) in
        [("UUID=", "by-uuid"), ("LABEL=", "by-label"), ("PARTUUID=", "by-partuuid"), ("PARTLABEL=", "by-partlabel")]
    {
        if let Some(value) = text.strip_prefix(tag) {
            return Path::new("/dev/disk").join(directory).join(value);
        }
    }
    mount_path(text)
}

fn order_before(output: &Path, dependent: &str, repair: &str) -> io::Result<()> {
    let dropin = output.join(format!("{dependent}.d"));
    fs::create_dir_all(&dropin)?;
    fs::write(dropin.join("20-slate-repair.conf"), format!("[Unit]\nRequires={repair}\nAfter={repair}\n"))
}

fn quote_unit(path: &Path) -> io::Result<String> {
    Ok(format!("\"{}\"", path_text(path)?.replace('\\', "\\\\").replace('"', "\\\"").replace('%', "%%")))
}

pub fn generate(output: &Path) -> io::Result<()> {
    require_root()?;
    if !Path::new(CONFIG_DIRECTORY).exists() {
        return Ok(());
    }
    protected_directory(Path::new(CONFIG_DIRECTORY), false, true)?;
    let fstab = fs::read_to_string("/etc/fstab")?;
    for entry in fs::read_dir(CONFIG_DIRECTORY)? {
        let path = entry?.path();
        if path.extension().is_none_or(|suffix| suffix != "job") {
            continue;
        }
        let job = Job::decode(&read_protected(&path)?)?;
        if path.file_stem().is_none_or(|stem| stem != job.uuid.as_str()) {
            return Err(reject("scheduled-repair filename and UUID differ"));
        }
        let unit = format!("slate-ntfs-repair-{}.service", job.uuid);
        let device_unit = format!("dev-disk-by\\x2duuid-{}.device", job.uuid);
        let content = format!(
            "[Unit]\nDescription=Scheduled NTFS repair {}\nDefaultDependencies=no\nRequires={device_unit}\nAfter={device_unit} systemd-remount-fs.service\nBefore=local-fs.target\nRequiresMountsFor={}\n\n[Service]\nType=oneshot\nSuccessExitStatus=1\nTimeoutStartSec=infinity\nExecStart=/usr/sbin/ntfs-chkdsk --run-scheduled-repair {}\n",
            job.uuid, quote_unit(&job.storage_directory)?, job.uuid,
        );
        fs::create_dir_all(output)?;
        fs::write(output.join(&unit), content)?;
        let wants = output.join("local-fs.target.wants");
        fs::create_dir_all(&wants)?;
        std::os::unix::fs::symlink(Path::new("..").join(&unit), wants.join(&unit))?;
        order_before(output, &fsck_unit(&job.device())?, &unit)?;
        for line in fstab.lines().filter(|line| !line.trim_start().starts_with('#')) {
            let fields: Vec<_> = line.split_whitespace().collect();
            let [entry_device, entry_mount, _, ..] = fields.as_slice() else {
                continue;
            };
            if *entry_mount == "/" {
                continue;
            }
            let source = mount_source(entry_device);
            let matches = entry_device.strip_prefix("UUID=").is_some_and(|uuid| uuid.eq_ignore_ascii_case(&job.uuid))
                || *entry_device == job.device().to_string_lossy()
                || fs::metadata(&source).ok().zip(fs::metadata(job.device()).ok()).is_some_and(|(source, target)| {
                    source.file_type().is_block_device() && source.rdev() == target.rdev()
                });
            if matches {
                order_before(output, &unit_path(&mount_path(entry_mount))?, &unit)?;
                order_before(output, &fsck_unit(&source)?, &unit)?;
            }
        }
    }
    Ok(())
}

/// A scheduled process binds each exclusive publication to the saved serial and
/// length. Ordinary callers retain the existing device-number requirement.
pub(crate) fn authorized_identity(device: &File) -> io::Result<bool> {
    let serial = std::env::var(SERIAL_ENV).ok();
    let length = std::env::var(LENGTH_ENV).ok();
    if serial.is_none() && length.is_none() {
        return Ok(false);
    }
    let (Some(serial), Some(length)) = (serial, length) else {
        return Err(reject("incomplete scheduled volume identity"));
    };
    if !valid_uuid(&serial) {
        return Err(reject("invalid scheduled volume serial"));
    }
    require_root()?;
    let length = length.parse::<u64>().map_err(io::Error::other)?;
    let job = load(&serial)?.ok_or_else(|| reject("scheduled publication has no protected job"))?;
    if job.bytes != length {
        return Err(reject("scheduled publication length differs from its protected job"));
    }
    let directory = std::env::var_os(JOURNAL_ROOT_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| reject("scheduled publication has no external journal store"))?;
    protected_directory(&directory, false, true)?;
    verify_intent(&job, &directory)?;
    let suffix = job.storage_relative.join(&job.uuid).join(&job.job_id);
    if !directory.ends_with(&suffix) || read_protected(&directory.join("state"))?.lines().next() != Some("running") {
        return Err(reject("scheduled publication does not match its active protected job"));
    }
    let storage_device = fs::metadata(Path::new("/dev/disk/by-uuid").join(&job.storage_uuid))?.rdev();
    if fs::metadata(&directory)?.dev() != storage_device {
        return Err(reject("scheduled publication journal store identity changed"));
    }
    unique_device(&job.storage_uuid, storage_device)?;
    unique_device(&serial, device.metadata()?.rdev())?;
    let (boot, _) = recovery_io::bootstrap_boot(&linux::fd_path(device))?;
    if boot.serial_number != u64::from_str_radix(&serial, 16).map_err(io::Error::other)?
        || linux::image_length(device)? != length
    {
        return Err(reject("claimed device differs from the scheduled volume identity"));
    }
    Ok(true)
}

#[cfg(test)]
#[path = "../tests/checker/boot_repair.rs"]
mod tests;
