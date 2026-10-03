//! Module: ntfs_permissions::core
//! Purpose: resolve accounts, store access policies and apply them to mounted drives.
//! Created: 2026-10-01
//! Architecture: The policy helper calls this backend; mount.rs handles live state
//! and remount results, while the driver owns actual NTFS access enforcement.

use ntfs_rs::identity::MAX_MAP_ENTRIES;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const POLICY_DIR: &str = "/etc/slate-ntfs/permissions";

// Fixed scratch capacity for the reentrant passwd lookups below.
const NSS_PASSWD_BUFFER_BYTES: usize = 65536;

/// Query current effective identity; callers still enforce each operation's privileges.
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

pub type Result<T> = std::result::Result<T, String>;

// ------------------------------------------------------------------ model ---
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Desktop,
    Windows,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Desktop => "desktop",
            Mode::Windows => "windows",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "desktop" => Some(Mode::Desktop),
            "windows" => Some(Mode::Windows),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    None,
    Read,
    Write,
    Full,
}

impl Level {
    pub const ALL: [Level; 4] = [Level::None, Level::Read, Level::Write, Level::Full];
    pub fn name(self) -> &'static str {
        match self {
            Level::None => "none",
            Level::Read => "read",
            Level::Write => "write",
            Level::Full => "full",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        Level::ALL.into_iter().find(|level| level.name() == text)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub mode: Mode,
    /// None: whoever the drive is opened for.
    pub owner: Option<u32>,
    /// None: the owner's own (primary) group.
    pub group: Option<u32>,
    pub file_mode: u32,
    pub dir_mode: u32,
    /// Windows mode levels.
    pub users: BTreeMap<u32, Level>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            mode: Mode::Desktop,
            owner: None,
            group: None,
            file_mode: 0o600,
            dir_mode: 0o700,
            users: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Ssd,
    Hdd,
    Portable,
}

#[derive(Clone, Debug)]
pub struct Drive {
    pub device: String,
    pub uuid: String,
    pub label: String,
    pub size: u64,
    pub kind: Kind,
    pub model: String,
    pub mountpoints: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub real_name: String,
    pub icon: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct Group {
    pub gid: u32,
    pub name: String,
    pub members: Vec<String>,
}

// ----------------------------------------------------------------- drives ---
fn flag(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_u64() == Some(1),
        Some(Value::String(s)) => s == "1" || s == "true",
        _ => false,
    }
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.trim().to_owned(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

/// Portable / SSD / HDD, judged from the physical disk.
pub fn classify(disk: &Value, part: &Value) -> Kind {
    let tran = text(disk.get("tran")).to_lowercase();
    if ["usb", "mmc", "ieee1394", "sdio", "memstick"].contains(&tran.as_str())
        || flag(disk.get("rm"))
        || flag(disk.get("hotplug"))
        || flag(part.get("hotplug"))
    {
        return Kind::Portable;
    }
    if flag(disk.get("rota")) {
        Kind::Hdd
    } else {
        Kind::Ssd
    }
}

/// Parse lsblk -J -b output (separated out so it can be tested).
pub fn drives_from_lsblk(json_text: &str) -> Result<Vec<Drive>> {
    let root: Value = serde_json::from_str(json_text).map_err(|e| format!("lsblk output: {e}"))?;
    let mut drives = Vec::new();
    fn walk(node: &Value, disk: Option<&Value>, drives: &mut Vec<Drive>) {
        let disk = if node.get("type").and_then(Value::as_str) == Some("disk") { Some(node) } else { disk };
        let fstype = text(node.get("fstype")).to_lowercase();
        let uuid = text(node.get("uuid"));
        if (fstype == "ntfs" || fstype == "ntfsrs") && !uuid.is_empty() {
            let d = disk.unwrap_or(node);
            let (mut vendor, product) = (text(d.get("vendor")), text(d.get("model")));
            if vendor.eq_ignore_ascii_case("ATA") {
                vendor.clear(); // SATA disks report the bus, not the maker
            }
            // "Example" + "Example SSD" must not read "Example Example …".
            let model = if vendor.is_empty() || product.to_lowercase().starts_with(&vendor.to_lowercase()) {
                product
            } else if product.is_empty() {
                vendor
            } else {
                format!("{vendor} {product}")
            };
            let mountpoints = node
                .get("mountpoints")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter().filter_map(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned).collect()
                })
                .unwrap_or_default();
            let device = match text(node.get("path")) {
                p if !p.is_empty() => p,
                _ => format!("/dev/{}", text(node.get("name"))),
            };
            drives.push(Drive {
                device,
                uuid,
                label: text(node.get("label")),
                size: text(node.get("size")).parse().unwrap_or(0),
                kind: classify(d, node),
                model,
                mountpoints,
            });
        }
        if let Some(children) = node.get("children").and_then(Value::as_array) {
            for child in children {
                walk(child, disk, drives);
            }
        }
    }
    for top in root.get("blockdevices").and_then(Value::as_array).into_iter().flatten() {
        walk(top, None, &mut drives);
    }
    Ok(drives)
}

pub fn list_drives() -> Result<Vec<Drive>> {
    let output = Command::new("lsblk")
        .args(["-J", "-b", "-o", "NAME,PATH,TYPE,FSTYPE,LABEL,UUID,SIZE,ROTA,RM,HOTPLUG,TRAN,MODEL,VENDOR,MOUNTPOINTS"])
        .output()
        .map_err(|e| format!("lsblk: {e}"))?;
    if !output.status.success() {
        return Err(format!("lsblk: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    drives_from_lsblk(&String::from_utf8_lossy(&output.stdout))
}

pub fn human_size(size: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = size as f64;
    for (index, unit) in units.iter().enumerate() {
        if value < 1000.0 || index == units.len() - 1 {
            return if index <= 1 || value >= 100.0 {
                format!("{value:.0} {unit}")
            } else {
                format!("{value:.1} {unit}")
            };
        }
        value /= 1000.0;
    }
    format!("{size} B")
}

// ------------------------------------------------------------ accounts ---
fn login_range(min_key: &str, max_key: &str) -> (u32, u32) {
    let (mut low, mut high) = (1000, 60000);
    if let Ok(text) = std::fs::read_to_string("/etc/login.defs") {
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next().and_then(|v| v.parse().ok())) {
                (Some(key), Some(value)) if key == min_key => low = value,
                (Some(key), Some(value)) if key == max_key => high = value,
                _ => {}
            }
        }
    }
    (low, high)
}

unsafe fn c_text(pointer: *const libc::c_char) -> String {
    if pointer.is_null() {
        String::new()
    } else {
        CStr::from_ptr(pointer).to_string_lossy().into_owned()
    }
}

struct Account {
    uid: u32,
    gid: u32,
    name: String,
    gecos: String,
    shell: String,
}

/// Every account the system knows (NSS), like Python's pwd.getpwall().
fn all_accounts() -> Vec<Account> {
    let mut accounts = Vec::new();
    // SAFETY: the passwd iterator is used from one thread and copied at once.
    unsafe {
        libc::setpwent();
        loop {
            let entry = libc::getpwent();
            if entry.is_null() {
                break;
            }
            let e = &*entry;
            accounts.push(Account {
                uid: e.pw_uid,
                gid: e.pw_gid,
                name: c_text(e.pw_name),
                gecos: c_text(e.pw_gecos),
                shell: c_text(e.pw_shell),
            });
        }
        libc::endpwent();
    }
    accounts
}

/// People with a login on this computer.
pub fn list_users() -> Vec<User> {
    let (low, high) = login_range("UID_MIN", "UID_MAX");
    let mut users: Vec<User> = all_accounts()
        .into_iter()
        .filter(|a| (low..=high).contains(&a.uid))
        .filter(|a| !(a.shell.ends_with("nologin") || a.shell.ends_with("/false")))
        .map(|a| {
            let real = a.gecos.split(',').next().unwrap_or("").trim().to_owned();
            let icon = PathBuf::from(format!("/var/lib/AccountsService/icons/{}", a.name));
            User {
                uid: a.uid,
                gid: a.gid,
                real_name: if real.is_empty() { a.name.clone() } else { real },
                icon: icon.is_file().then_some(icon),
                name: a.name,
            }
        })
        .collect();
    users.sort_by(|a, b| (a.real_name.to_lowercase(), a.uid).cmp(&(b.real_name.to_lowercase(), b.uid)));
    users
}

pub struct PasswdEntry {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
}

pub fn getpwuid(uid: u32) -> Option<PasswdEntry> {
    let mut buffer = vec![0u8; NSS_PASSWD_BUFFER_BYTES];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: buffers are owned here and outlive the call.
    let error = unsafe { libc::getpwuid_r(uid, &mut entry, buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
    if error != 0 || found.is_null() {
        return None;
    }
    Some(PasswdEntry { uid: entry.pw_uid, gid: entry.pw_gid, name: unsafe { c_text(entry.pw_name) } })
}

pub fn getpwnam(name: &str) -> Option<PasswdEntry> {
    let name = CString::new(name).ok()?;
    let mut buffer = vec![0u8; NSS_PASSWD_BUFFER_BYTES];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: as above.
    let error =
        unsafe { libc::getpwnam_r(name.as_ptr(), &mut entry, buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
    if error != 0 || found.is_null() {
        return None;
    }
    Some(PasswdEntry { uid: entry.pw_uid, gid: entry.pw_gid, name: unsafe { c_text(entry.pw_name) } })
}

/// (name, members) of a group.
pub fn getgrgid(gid: u32) -> Option<(String, Vec<String>)> {
    let mut buffer = vec![0u8; 1 << 20];
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: as above; gr_mem is a NULL-terminated array inside buffer.
    let error = unsafe { libc::getgrgid_r(gid, &mut entry, buffer.as_mut_ptr().cast(), buffer.len(), &mut found) };
    if error != 0 || found.is_null() {
        return None;
    }
    let mut members = Vec::new();
    unsafe {
        let mut member = entry.gr_mem;
        while !member.is_null() && !(*member).is_null() {
            members.push(c_text(*member));
            member = member.add(1);
        }
        Some((c_text(entry.gr_name), members))
    }
}

/// All groups a user belongs to (like os.getgrouplist).
pub fn grouplist(name: &str, gid: u32) -> Vec<u32> {
    let Ok(cname) = CString::new(name) else {
        return vec![gid];
    };
    let mut count: libc::c_int = 64;
    loop {
        let mut groups = vec![0 as libc::gid_t; count as usize];
        let before = count;
        // SAFETY: groups holds count entries.
        let result = unsafe { libc::getgrouplist(cname.as_ptr(), gid, groups.as_mut_ptr(), &mut count) };
        if result >= 0 {
            groups.truncate(count as usize);
            return groups;
        }
        if count <= before {
            count = before * 2;
        }
        if count > 65536 {
            return vec![gid];
        }
    }
}

/// Groups that make sense to share a drive with: regular groups (in the
/// GID_MIN..GID_MAX range, including each user's personal group) and "users".
pub fn list_groups(users: &[User]) -> Vec<Group> {
    let (low, high) = login_range("GID_MIN", "GID_MAX");
    let humans: BTreeSet<&str> = users.iter().map(|u| u.name.as_str()).collect();
    let mut groups = Vec::new();
    // SAFETY: the group iterator is used from one thread and copied at once.
    unsafe {
        libc::setgrent();
        loop {
            let entry = libc::getgrent();
            if entry.is_null() {
                break;
            }
            let e = &*entry;
            let name = c_text(e.gr_name);
            if !((low..=high).contains(&e.gr_gid) || name == "users") {
                continue;
            }
            let mut members = BTreeSet::new();
            let mut member = e.gr_mem;
            while !member.is_null() && !(*member).is_null() {
                members.insert(c_text(*member));
                member = member.add(1);
            }
            for user in users {
                if user.gid == e.gr_gid {
                    members.insert(user.name.clone());
                }
            }
            let members = members.into_iter().filter(|m| humans.contains(m.as_str())).collect();
            groups.push(Group { gid: e.gr_gid, name, members });
        }
        libc::endgrent();
    }
    groups.sort_by(|a, b| (a.name != "users", a.name.clone()).cmp(&(b.name != "users", b.name.clone())));
    groups.dedup_by_key(|g| g.gid);
    groups
}

// ----------------------------------------------------------------- policy ---
fn valid_uuid(uuid: &str) -> bool {
    !uuid.is_empty() && uuid.len() <= 64 && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

pub fn policy_path(dir: &Path, uuid: &str) -> Result<PathBuf> {
    if !valid_uuid(uuid) {
        return Err(format!("invalid volume UUID {uuid:?}"));
    }
    Ok(dir.join(format!("{}.conf", uuid.to_uppercase())))
}

fn octal(text: &str, place: &str) -> Result<u32> {
    match u32::from_str_radix(text, 8) {
        Ok(value) if value <= 0o777 => Ok(value),
        _ => Err(format!("{place}: expected permission bits like 0660")),
    }
}

/// The saved policy, or None when this drive has none (defaults apply).
pub fn read_policy(dir: &Path, uuid: &str) -> Result<Option<Policy>> {
    let path = policy_path(dir, uuid)?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut policy = Policy::default();
    let mut saw_mode = false;
    for (number, line) in text.lines().enumerate() {
        let place = format!("{}:{}", path.display(), number + 1);
        let fields: Vec<&str> = line.split('#').next().unwrap_or("").split_whitespace().collect();
        match fields.as_slice() {
            [] => {}
            ["mode", mode] if Mode::parse(mode).is_some() => {
                policy.mode = Mode::parse(mode).unwrap();
                saw_mode = true;
            }
            [key @ ("owner" | "group"), value] if *value == "auto" || value.parse::<u32>().is_ok() => {
                let value = value.parse::<u32>().ok();
                if *key == "owner" {
                    policy.owner = value
                } else {
                    policy.group = value
                }
            }
            ["files", value] => policy.file_mode = octal(value, &place)?,
            ["folders", value] => policy.dir_mode = octal(value, &place)?,
            ["user", uid, level] if uid.parse::<u32>().is_ok() && Level::parse(level).is_some() => {
                policy.users.insert(uid.parse().unwrap(), Level::parse(level).unwrap());
            }
            _ => return Err(format!("{place}: cannot understand {:?}", line.trim())),
        }
    }
    if !saw_mode {
        policy.mode = Mode::Windows;
    } // version-1 files were strict per-user levels
    Ok(Some(policy))
}

pub fn validate_policy(policy: &Policy) -> Result<()> {
    if policy.file_mode > 0o777 {
        return Err("file_mode must be within 0777".into());
    }
    if policy.dir_mode > 0o777 {
        return Err("dir_mode must be within 0777".into());
    }
    if policy.users.keys().any(|uid| *uid == 0) {
        return Err("invalid entry for UID 0".into());
    }
    if policy.users.values().filter(|l| **l == Level::Full).count() > 1 {
        return Err("only one user per drive can have full control".into());
    }
    Ok(())
}

pub fn write_policy(dir: &Path, uuid: &str, policy: &Policy) -> Result<()> {
    validate_policy(policy)?;
    let auto = |v: Option<u32>| v.map_or("auto".to_owned(), |v| v.to_string());
    let mut lines = vec![
        "# NTFS drive permissions, managed by slate-ntfs-permissions.".to_owned(),
        format!("mode {}", policy.mode.name()),
        format!("owner {}", auto(policy.owner)),
        format!("group {}", auto(policy.group)),
        format!("files {:04o}", policy.file_mode),
        format!("folders {:04o}", policy.dir_mode),
    ];
    for (uid, level) in &policy.users {
        lines.push(format!("user {uid} {}", level.name()));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    let target = policy_path(dir, uuid)?;
    let temporary = PathBuf::from(format!("{}.{}.tmp", target.display(), std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all((lines.join("\n") + "\n").as_bytes())?;
        file.sync_all()?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(&temporary, &target)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("{}: {e}", target.display()));
    }
    Ok(())
}

/// Wire form shared by the interface and the root helper.
pub fn policy_to_json(policy: &Policy) -> Value {
    let users: Map<String, Value> =
        policy.users.iter().map(|(uid, level)| (uid.to_string(), Value::from(level.name()))).collect();
    json!({"mode": policy.mode.name(), "owner": policy.owner, "group": policy.group,
           "file_mode": policy.file_mode, "dir_mode": policy.dir_mode, "users": users})
}

pub fn policy_from_json(value: &Value) -> Result<Policy> {
    let number = |key: &str| -> Result<Option<u32>> {
        match value.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .filter(|n| *n < u32::MAX as u64)
                .map(|n| Some(n as u32))
                .ok_or_else(|| format!("invalid {key}")),
        }
    };
    let mut policy = Policy::default();
    if let Some(mode) = value.get("mode") {
        policy.mode = mode.as_str().and_then(Mode::parse).ok_or("mode must be desktop or windows")?;
    }
    policy.owner = number("owner")?;
    policy.group = number("group")?;
    policy.file_mode = number("file_mode")?.unwrap_or(0o600);
    policy.dir_mode = number("dir_mode")?.unwrap_or(0o700);
    if let Some(users) = value.get("users").and_then(Value::as_object) {
        for (uid, level) in users {
            let uid = uid.parse::<u32>().map_err(|_| format!("invalid entry for UID {uid}"))?;
            let level = level.as_str().and_then(Level::parse).ok_or(format!("invalid entry for UID {uid}"))?;
            policy.users.insert(uid, level);
        }
    }
    validate_policy(&policy)?;
    Ok(policy)
}

// ---------------------------------------------------- friendly permissions ---
/// Read / Write / Execute for one class. Read gives folders r+x, Write needs
/// Read, Execute runs programs from the drive.
pub type Rwx = [bool; 3];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Owner,
    Group,
    Others,
}

impl Class {
    pub const ALL: [Class; 3] = [Class::Owner, Class::Group, Class::Others];
    fn shift(self) -> u32 {
        match self {
            Class::Owner => 6,
            Class::Group => 3,
            Class::Others => 0,
        }
    }
}

pub fn modes_from_rwx(rwx: &[Rwx; 3]) -> (u32, u32) {
    let (mut file_mode, mut dir_mode) = (0, 0);
    for (class, [read, write, execute]) in Class::ALL.iter().zip(rwx) {
        let write = *write && *read;
        let shift = class.shift();
        file_mode |=
            ((if *read { 4 } else { 0 }) | (if write { 2 } else { 0 }) | (if *execute { 1 } else { 0 })) << shift;
        dir_mode |= ((if *read { 5 } else { 0 }) | (if write { 2 } else { 0 })) << shift;
    }
    (file_mode, dir_mode)
}

pub fn rwx_from_modes(file_mode: u32, dir_mode: u32) -> [Rwx; 3] {
    Class::ALL.map(|class| {
        let (f, d) = ((file_mode >> class.shift()) & 7, (dir_mode >> class.shift()) & 7);
        [f & 4 != 0 || d & 4 != 0, f & 2 != 0 || d & 2 != 0, f & 1 != 0]
    })
}

/// (key, English name, file mode, folder mode)
pub const PRESETS: [(&str, &str, u32, u32); 4] = [
    ("private", "Only the owner", 0o600, 0o700),
    ("group", "Owner and group", 0o660, 0o770),
    ("read-all", "Everyone can read", 0o644, 0o755),
    ("everyone", "Everyone can read and write", 0o666, 0o777),
];

// ---------------------------------------------------- mount-time options ---
/// (uid, gid) for a desktop-mode mount.
pub fn resolve_owner(policy: &Policy, mount_uid: u32, mount_gid: Option<u32>) -> (u32, u32) {
    let uid = policy.owner.unwrap_or(mount_uid);
    let gid = match (policy.group, mount_gid) {
        (Some(gid), _) => gid,
        (None, Some(gid)) if uid == mount_uid => gid,
        _ => getpwuid(uid).map(|p| p.gid).unwrap_or(mount_gid.unwrap_or(0)),
    };
    (uid, gid)
}

/// Windows-mode levels, with the mounting user full by default.
pub fn effective_levels(policy: &Policy, owner_uid: Option<u32>) -> BTreeMap<u32, Level> {
    let mut levels = policy.users.clone();
    if let Some(owner) = owner_uid.filter(|uid| *uid != 0) {
        if !levels.contains_key(&owner) && !levels.values().any(|l| *l == Level::Full) {
            levels.insert(owner, Level::Full);
        }
    }
    levels
}

/// Whether the selected policy requests any write access. The filesystem may
/// still refuse a writable mount independently of these permission bits.
pub fn policy_wants_write(policy: &Policy, owner_uid: Option<u32>) -> bool {
    match policy.mode {
        Mode::Desktop => (policy.file_mode | policy.dir_mode) & 0o222 != 0,
        Mode::Windows => {
            effective_levels(policy, owner_uid).values().any(|level| matches!(level, Level::Write | Level::Full))
        }
    }
}

pub fn build_sidmap(levels: &BTreeMap<u32, Level>, extra_groups: &[u32]) -> Result<String> {
    let mut entries = vec!["u:0:S-1-5-18".to_owned()];
    let mut groups: BTreeSet<u32> = std::iter::once(0).chain(extra_groups.iter().copied()).collect();
    let mut full_given = false;
    for (&uid, &level) in levels {
        if uid == 0 || level == Level::None {
            continue;
        }
        let Some(account) = getpwuid(uid) else {
            continue;
        }; // deleted account: never map it
        let sid = if level == Level::Full && !full_given {
            full_given = true;
            "S-1-5-32-544".to_owned()
        } else {
            format!("S-1-22-1-{uid}")
        };
        entries.push(format!("u:{uid}:{sid}{}", if level == Level::Read { ":low-integrity" } else { "" }));
        groups.extend(grouplist(&account.name, account.gid));
    }
    for gid in groups {
        let name = getgrgid(gid).map(|(name, _)| name).unwrap_or_default();
        let sid = if gid == 0 {
            "S-1-5-32-544".to_owned()
        } else if name == "users" {
            "S-1-5-32-545".to_owned()
        } else {
            format!("S-1-22-2-{gid}")
        };
        entries.push(format!("g:{gid}:{sid}"));
    }
    if entries.len() > MAX_MAP_ENTRIES {
        return Err(format!(
            "{} identities needed; the driver supports {MAX_MAP_ENTRIES}. \
                            Grant access to fewer users.",
            entries.len()
        ));
    }
    let map = entries.join(";");
    // The driver will parse exactly this text; refuse anything it would reject.
    ntfs_rs::identity::validate_sidmap(&map).map_err(|e| format!("identity map rejected: {e:?}"))?;
    Ok(map)
}

/// Only the access part (no SID map): used for live remounts.
pub fn access_options(policy: &Policy, mount_uid: u32, mount_gid: Option<u32>) -> String {
    if policy.mode == Mode::Windows {
        return "permissions=windows".to_owned();
    }
    let (uid, gid) = resolve_owner(policy, mount_uid, mount_gid);
    format!(
        "permissions=desktop,uid={uid},gid={gid},fmask={:04o},dmask={:04o}",
        0o777 & !policy.file_mode,
        0o777 & !policy.dir_mode
    )
}

/// Complete fs-specific options for mount.ntfs: SID map plus access policy.
/// In desktop mode the map holds the owner (recorded as owner of every new
/// file) and the chosen group; access itself is decided by the bits.
pub fn mount_options(policy: &Policy, mount_uid: u32, mount_gid: Option<u32>) -> Result<String> {
    let sidmap = if policy.mode == Mode::Desktop {
        let (uid, gid) = resolve_owner(policy, mount_uid, mount_gid);
        let levels = if uid != 0 { BTreeMap::from([(uid, Level::Full)]) } else { BTreeMap::new() };
        build_sidmap(&levels, &[gid])?
    } else {
        build_sidmap(&effective_levels(policy, Some(mount_uid)), &[])?
    };
    Ok(format!("sidmap={sidmap},{}", access_options(policy, mount_uid, mount_gid)))
}

pub fn effective_policy(dir: &Path, uuid: &str) -> Result<Policy> {
    Ok(read_policy(dir, uuid)?.unwrap_or_default())
}

/// uids that can reach the drive (for /media/<user> traverse rights).
pub fn who_can_access(policy: &Policy, owner_uid: Option<u32>, users: &[User]) -> BTreeSet<u32> {
    if policy.mode == Mode::Windows {
        return effective_levels(policy, owner_uid)
            .into_iter()
            .filter(|(_, level)| *level != Level::None)
            .map(|(uid, _)| uid)
            .collect();
    }
    let (uid, gid) = resolve_owner(policy, owner_uid.unwrap_or(0), None);
    let mut allowed = BTreeSet::from([uid]);
    if (policy.dir_mode >> 3) & 7 != 0 {
        let members: BTreeSet<String> = getgrgid(gid).map(|(_, m)| m.into_iter().collect()).unwrap_or_default();
        allowed.extend(users.iter().filter(|u| members.contains(&u.name) || u.gid == gid).map(|u| u.uid));
    }
    if policy.dir_mode & 7 != 0 {
        allowed.extend(users.iter().map(|u| u.uid));
    }
    allowed
}

pub fn device_uuid(device: &str) -> Option<String> {
    let output = Command::new("blkid").args(["-o", "value", "-s", "UUID", device]).output().ok()?;
    let uuid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!uuid.is_empty()).then_some(uuid)
}

// --------------------------------------------------------------- applying ---
fn fstab_owner(uuid: &str) -> (Option<u32>, Option<String>) {
    let Ok(text) = std::fs::read_to_string("/etc/fstab") else {
        return (None, None);
    };
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[0].to_uppercase() == format!("UUID={}", uuid.to_uppercase()) {
            let target = fields[1].replace("\\040", " ");
            let uid = fields[3].split(',').find_map(|o| o.strip_prefix("uid=")).and_then(|v| v.parse().ok());
            return (uid, Some(target));
        }
    }
    (None, None)
}

/// Resolve the default filesystem access owner from fstab, a desktop path or
/// the live UID projection. This does not identify UDisks unmount ownership.
pub fn drive_owner(drive: &Drive) -> Option<u32> {
    if let (Some(uid), _) = fstab_owner(&drive.uuid) {
        return Some(uid);
    }
    for target in &drive.mountpoints {
        let parts: Vec<&str> = target.split('/').collect();
        let name = if parts.len() >= 4 && parts[1] == "media" {
            Some(parts[2])
        } else if parts.len() >= 5 && parts[1] == "run" && parts[2] == "media" {
            Some(parts[3])
        } else {
            None
        };
        if let Some(entry) = name.and_then(getpwnam) {
            return Some(entry.uid);
        }
    }
    // Desktop mounts outside /media still have a filesystem owner. Do not
    // replace it with root when applying an "auto" policy to /mnt or a bind.
    for target in &drive.mountpoints {
        if let Ok(state) = crate::mount::query(target) {
            if let Some(uid) = state.owner_uid {
                return Some(uid);
            }
        }
    }
    None
}

/// Capture the subprocess diagnostic on failure and stdout on quiet commands.
/// Mount-state inspection and mutation share this runner for testable outcomes.
pub(crate) fn run(program: &str, args: &[&str]) -> (bool, String) {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let text = if output.stderr.is_empty() { &output.stdout } else { &output.stderr };
            (output.status.success(), String::from_utf8_lossy(text).trim().to_owned())
        }
        Err(e) => (false, format!("{program}: {e}")),
    }
}

/// Let permitted users walk into /media/<owner>/ (udisks makes it 0750).
/// Only '--x' entries are managed, so udisks' own r-x grants stay intact.
fn sync_traverse_acls(dir: &Path, parents: &BTreeSet<String>) {
    if parents.is_empty() || !Path::new("/usr/bin/setfacl").exists() {
        return;
    }
    let users = list_users();
    let mut wanted: BTreeMap<&String, BTreeSet<u32>> = parents.iter().map(|p| (p, BTreeSet::new())).collect();
    for drive in list_drives().unwrap_or_default() {
        let owner = drive_owner(&drive);
        let policy = effective_policy(dir, &drive.uuid).unwrap_or_default();
        for target in &drive.mountpoints {
            let parent = Path::new(target).parent().map(|p| p.display().to_string()).unwrap_or_default();
            if let Some(set) = wanted.get_mut(&parent) {
                set.extend(who_can_access(&policy, owner, &users));
            }
        }
    }
    for (parent, wanted) in wanted {
        let (ok, text) = run("getfacl", &["-cpn", parent]);
        let mut existing = BTreeMap::new();
        if ok {
            for line in text.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if let [kind, id, perms] = parts.as_slice() {
                    if *kind == "user" {
                        if let Ok(uid) = id.parse::<u32>() {
                            existing.insert(uid, perms.to_string());
                        }
                    }
                }
            }
        }
        let owner = std::fs::metadata(parent).map(|m| m.uid()).unwrap_or(0);
        for uid in wanted.iter().filter(|uid| **uid != 0 && **uid != owner) {
            if !existing.contains_key(uid) {
                run("setfacl", &["-m", &format!("u:{uid}:--x"), parent]);
            }
        }
        for (uid, perms) in &existing {
            if perms == "--x" && !wanted.contains(uid) {
                run("setfacl", &["-x", &format!("u:{uid}"), parent]);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    Applied,
    ReadOnly,
    Pending,
    Error,
}

impl Applied {
    pub fn name(self) -> &'static str {
        match self {
            Applied::Applied => "applied",
            Applied::ReadOnly => "read-only",
            Applied::Pending => "pending",
            Applied::Error => "error",
        }
    }
}

/// Outcome of applying one drive: a fixed English message (translated by the
/// interface) plus optional detail from the system, in its own language.
pub struct Outcome {
    pub status: Applied,
    pub message: &'static str,
    pub detail: String,
}

impl Outcome {
    pub fn new(status: Applied, message: &'static str, detail: impl Into<String>) -> Self {
        Self { status, message, detail: detail.into() }
    }
}

/// Make a mounted drive use its saved policy now, without unmounting it:
/// the driver swaps the identity map and the mounting permissions on a live
/// remount, so open files and windows on the drive are not disturbed.
pub fn apply_drive(dir: &Path, uuid: &str) -> Outcome {
    let drives = list_drives().unwrap_or_default();
    let Some(drive) = drives.iter().find(|d| d.uuid.eq_ignore_ascii_case(uuid)) else {
        return Outcome::new(Applied::Pending, "Saved. It applies the next time the drive is connected.", "");
    };
    let Some(target) = drive.mountpoints.iter().min_by_key(|t| t.len()).cloned() else {
        return Outcome::new(Applied::Pending, "Saved. It applies the next time the drive is opened.", "");
    };
    let policy = match effective_policy(dir, uuid) {
        Ok(policy) => policy,
        Err(e) => return Outcome::new(Applied::Error, "Could not apply the new permissions:", e),
    };
    let owner = drive_owner(drive);
    let owner_gid = owner.and_then(getpwuid).map(|p| p.gid);
    let options = match mount_options(&policy, owner.unwrap_or(0), owner_gid) {
        Ok(options) => options,
        Err(e) => return Outcome::new(Applied::Error, "Could not apply the new permissions:", e),
    };
    let current = match crate::mount::query_with(&target, &mut run) {
        Ok(state) => state,
        Err(error) => return Outcome::new(Applied::Error, "Could not apply the new permissions:", error),
    };
    let result = crate::mount::apply_with(&target, &options, policy_wants_write(&policy, owner), &current, &mut run);
    if !matches!(result.status, Applied::Applied | Applied::ReadOnly) {
        return result;
    }
    let parents: BTreeSet<String> =
        drive.mountpoints.iter().filter_map(|t| Path::new(t).parent().map(|p| p.display().to_string())).collect();
    sync_traverse_acls(dir, &parents);
    // The driver already told file managers (inotify "attributes changed");
    // also let udisks and desktop device lists refresh their view of the drive.
    run("udevadm", &["trigger", "--action=change", &drive.device]);
    result
}

/// {uuid: policy-json} → {uuid: {"status", "message", "detail"}}
pub fn save_and_apply(dir: &Path, changes: &Map<String, Value>) -> Value {
    let mut results = Map::new();
    for (uuid, data) in changes {
        let result = match policy_from_json(data).and_then(|p| write_policy(dir, uuid, &p)) {
            Ok(()) => apply_drive(dir, uuid),
            Err(e) => Outcome::new(Applied::Error, "Could not save permissions:", e),
        };
        results.insert(
            uuid.clone(),
            json!({"status": result.status.name(), "message": result.message,
                                            "detail": result.detail}),
        );
    }
    Value::Object(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rwx_round_trip_and_presets() {
        let (f, d) = modes_from_rwx(&[[true, true, false], [true, true, false], [false, false, false]]);
        assert_eq!((f, d), (0o660, 0o770));
        assert_eq!(rwx_from_modes(0o660, 0o770)[1], [true, true, false]);
        // Write without Read is dropped; Execute alone is kept for files only.
        assert_eq!(modes_from_rwx(&[[false, true, true], [false; 3], [false; 3]]), (0o100, 0));
        for (_, _, f, d) in PRESETS {
            assert_eq!(modes_from_rwx(&rwx_from_modes(f, d)), (f, d));
        }
    }

    #[test]
    fn policy_file_round_trip_and_version_one() {
        let dir = std::env::temp_dir().join(format!("slate-perm-test-{}", std::process::id()));
        let mut policy = Policy { group: Some(1103), file_mode: 0o660, dir_mode: 0o770, ..Policy::default() };
        write_policy(&dir, "abcd1234", &policy).unwrap();
        assert_eq!(read_policy(&dir, "ABCD1234").unwrap(), Some(policy.clone()));
        policy.mode = Mode::Windows;
        policy.users.insert(1001, Level::Full);
        write_policy(&dir, "abcd1234", &policy).unwrap();
        assert_eq!(read_policy(&dir, "abcd1234").unwrap(), Some(policy));
        std::fs::write(dir.join("00FF.conf"), "user 1001 full\nuser 1101 read\n").unwrap();
        let v1 = read_policy(&dir, "00ff").unwrap().unwrap();
        assert_eq!(v1.mode, Mode::Windows);
        assert_eq!(v1.users.get(&1101), Some(&Level::Read));
        std::fs::write(dir.join("BAD0.conf"), "files 1777\n").unwrap();
        assert!(read_policy(&dir, "bad0").is_err());
        assert!(read_policy(&dir, "../etc").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn only_one_full_control() {
        let policy = Policy { users: BTreeMap::from([(1001, Level::Full), (1002, Level::Full)]), ..Policy::default() };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn desktop_options_use_ntfs3g_spelling() {
        let policy =
            Policy { owner: Some(1000), group: Some(1500), file_mode: 0o660, dir_mode: 0o770, ..Policy::default() };
        assert_eq!(
            access_options(&policy, 1000, Some(1000)),
            "permissions=desktop,uid=1000,gid=1500,fmask=0117,dmask=0007"
        );
        assert_eq!(
            access_options(&Policy::default(), 1000, Some(1000)),
            "permissions=desktop,uid=1000,gid=1000,fmask=0177,dmask=0077"
        );
        assert_eq!(
            access_options(&Policy { mode: Mode::Windows, ..Policy::default() }, 1000, None),
            "permissions=windows"
        );
    }

    #[test]
    fn write_intent_uses_the_active_permission_mode() {
        let readonly = Policy { file_mode: 0o444, dir_mode: 0o555, ..Policy::default() };
        assert!(!policy_wants_write(&readonly, Some(1000)));
        assert!(policy_wants_write(&Policy { dir_mode: 0o557, ..readonly }, None));
        let mut windows = Policy { mode: Mode::Windows, ..Policy::default() };
        windows.users.insert(1000, Level::Read);
        assert!(!policy_wants_write(&windows, Some(1000)));
        windows.users.insert(1000, Level::Write);
        assert!(policy_wants_write(&windows, Some(1000)));
        windows.users.insert(1000, Level::None);
        assert!(!policy_wants_write(&windows, Some(1000)));
        assert!(policy_wants_write(&windows, Some(1001))); // implicit full owner
    }

    #[test]
    fn json_wire_format() {
        let policy = Policy { mode: Mode::Windows, users: BTreeMap::from([(1001, Level::Read)]), ..Policy::default() };
        assert_eq!(policy_from_json(&policy_to_json(&policy)).unwrap(), policy);
        assert!(policy_from_json(&json!({"mode": "x"})).is_err());
        assert!(policy_from_json(&json!({"file_mode": 0o1777})).is_err());
    }

    #[test]
    fn lsblk_classification() {
        let text = r#"{"blockdevices":[
          {"name":"sda","path":"/dev/sda","type":"disk","rota":true,"rm":false,"tran":"sata","model":"ST1000","vendor":"ATA","size":1000,"children":[
            {"name":"sda2","path":"/dev/sda2","type":"part","fstype":"ntfs","uuid":"0A1B","label":"Novo volume","size":"500","mountpoints":["/media/x/Novo_volume"]}]},
          {"name":"nvme0n1","type":"disk","rota":"0","tran":"nvme","size":1,"children":[
            {"name":"nvme0n1p3","type":"part","fstype":"ntfs","uuid":"1122","size":2,"mountpoints":[null]}]},
          {"name":"sdb","type":"disk","rota":"1","rm":"1","tran":"usb","vendor":"Example ","model":"Example SSD 1TB","children":[
            {"name":"sdb1","type":"part","fstype":"ntfs","uuid":"99AA"},
            {"name":"sdb2","type":"part","fstype":"vfat","uuid":"FFFF"}]}]}"#;
        let drives = drives_from_lsblk(text).unwrap();
        assert_eq!(drives.len(), 3);
        assert_eq!((drives[0].kind, drives[0].size, drives[0].model.as_str()), (Kind::Hdd, 500, "ST1000"));
        assert_eq!(drives[0].mountpoints, vec!["/media/x/Novo_volume"]);
        assert_eq!((drives[1].kind, drives[1].device.as_str()), (Kind::Ssd, "/dev/nvme0n1p3"));
        assert!(drives[1].mountpoints.is_empty());
        assert_eq!(drives[2].kind, Kind::Portable);
        assert_eq!(drives[2].model, "Example SSD 1TB");
    }

    #[test]
    fn sizes() {
        assert_eq!(human_size(1_000_204_886_016), "1.0 TB");
        assert_eq!(human_size(499_000_000_000), "499 GB");
        assert_eq!(human_size(32_010_928_128), "32.0 GB");
        assert_eq!(human_size(512), "512 B");
    }

    #[test]
    fn root_only_sidmap_is_valid() {
        let map = build_sidmap(&BTreeMap::new(), &[]).unwrap();
        assert!(map.starts_with("u:0:S-1-5-18;g:0:S-1-5-32-544"));
    }
}
