//! Module: slate_ntfs_permissions::model
//! Purpose: track saved policies, edits, local accounts and live mount state.
//! Created: 2026-10-01
//! Architecture: The GTK window reads this model; core resolves access policy
//! and mount.rs supplies verified state without granting the GUI root access.

use ntfs_permissions::core::{self, Class, Drive, Group, Level, Mode, Policy, User};
use ntfs_permissions::i18n::{tr, trf};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

pub fn policy_dir() -> PathBuf {
    // Reading only; the root helper always uses the real directory.
    std::env::var_os("SLATE_NTFS_POLICY_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(core::POLICY_DIR))
}

#[derive(Default)]
pub struct Model {
    pub drives: Vec<Drive>,
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    saved: HashMap<String, Policy>,
    pub edits: HashMap<String, Policy>,
    /// uuid → uid the drive is opened for (the "auto" owner).
    pub owner_hint: HashMap<String, Option<u32>>,
    pub errors: Vec<String>,
    pub mounts: HashMap<String, ntfs_permissions::mount::MountState>,
}

#[derive(PartialEq, Eq)]
enum Normal {
    Windows(Vec<(u32, Level)>),
    Desktop(Option<u32>, Option<u32>, u32, u32),
}

impl Model {
    pub fn load(&mut self) -> Result<(), String> {
        self.errors.clear();
        self.users = core::list_users();
        self.groups = core::list_groups(&self.users);
        self.drives = core::list_drives()?;
        self.saved.clear();
        self.owner_hint.clear();
        self.mounts.clear();
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let dir = policy_dir();
        for drive in &self.drives {
            let policy = match core::read_policy(&dir, &drive.uuid) {
                Ok(policy) => policy,
                Err(error) => {
                    self.errors.push(error);
                    None
                }
            };
            self.saved.insert(drive.uuid.clone(), policy.unwrap_or_default());
            let hint = core::drive_owner(drive).or_else(|| self.users.iter().any(|u| u.uid == me).then_some(me));
            self.owner_hint.insert(drive.uuid.clone(), hint);
            for target in &drive.mountpoints {
                match ntfs_permissions::mount::query(target) {
                    Ok(state) => {
                        self.mounts.insert(target.clone(), state);
                    }
                    Err(error) => self.errors.push(format!("{}: {error}", drive.device)),
                }
            }
        }
        let known: Vec<String> = self.drives.iter().map(|d| d.uuid.clone()).collect();
        self.edits.retain(|uuid, _| known.contains(uuid));
        Ok(())
    }

    pub fn drive(&self, uuid: &str) -> Option<&Drive> {
        self.drives.iter().find(|d| d.uuid == uuid)
    }

    /// Warn if any mounted view refuses writes; saved permission bits alone
    /// cannot describe what Files can currently do on that view.
    pub fn drive_read_only(&self, uuid: &str) -> bool {
        self.drive(uuid).is_some_and(|drive| {
            drive.mountpoints.iter().any(|target| self.mounts.get(target).is_some_and(|state| state.read_only))
        })
    }

    pub fn policy(&self, uuid: &str, saved: bool) -> Policy {
        let stored = || self.saved.get(uuid).cloned().unwrap_or_default();
        if saved {
            stored()
        } else {
            self.edits.get(uuid).cloned().unwrap_or_else(stored)
        }
    }

    pub fn edit(&mut self, uuid: &str) -> &mut Policy {
        let saved = self.saved.get(uuid).cloned().unwrap_or_default();
        self.edits.entry(uuid.to_owned()).or_insert(saved)
    }

    pub fn owner(&self, uuid: &str, saved: bool) -> Option<u32> {
        self.policy(uuid, saved).owner.or_else(|| self.owner_hint.get(uuid).copied().flatten())
    }

    pub fn group(&self, uuid: &str, saved: bool) -> Option<u32> {
        if let Some(gid) = self.policy(uuid, saved).group {
            return Some(gid);
        }
        self.owner(uuid, saved).and_then(core::getpwuid).map(|p| p.gid)
    }

    pub fn group_info(&self, gid: u32) -> Option<&Group> {
        self.groups.iter().find(|g| g.gid == gid)
    }

    pub fn group_name(&self, gid: Option<u32>) -> String {
        let Some(gid) = gid else {
            return tr("The owner’s own group");
        };
        if let Some(info) = self.group_info(gid) {
            return info.name.clone();
        }
        core::getgrgid(gid).map(|(name, _)| name).unwrap_or_else(|| format!("{gid}"))
    }

    pub fn user(&self, uid: u32) -> Option<&User> {
        self.users.iter().find(|u| u.uid == uid)
    }

    pub fn user_by_name(&self, name: &str) -> Option<&User> {
        self.users.iter().find(|u| u.name == name)
    }

    pub fn in_group(&self, uid: u32, gid: Option<u32>) -> bool {
        let (Some(user), Some(gid)) = (self.user(uid), gid) else {
            return false;
        };
        if user.gid == gid {
            return true;
        }
        if let Some(info) = self.group_info(gid) {
            if info.members.contains(&user.name) {
                return true;
            }
        }
        core::getgrgid(gid).is_some_and(|(_, members)| members.contains(&user.name))
    }

    pub fn strict_level(&self, uuid: &str, uid: u32, saved: bool) -> Level {
        let hint = self.owner_hint.get(uuid).copied().flatten();
        core::effective_levels(&self.policy(uuid, saved), hint).get(&uid).copied().unwrap_or(Level::None)
    }

    /// (level, why) for one person, whatever the drive's mode.
    pub fn access(&self, uuid: &str, uid: u32, saved: bool) -> (Level, String) {
        let policy = self.policy(uuid, saved);
        if policy.mode == Mode::Windows {
            return (self.strict_level(uuid, uid, saved), tr("Windows permissions"));
        }
        let gid = self.group(uuid, saved);
        let class = if Some(uid) == self.owner(uuid, saved) {
            Class::Owner
        } else if self.in_group(uid, gid) {
            Class::Group
        } else {
            Class::Others
        };
        let index = Class::ALL.iter().position(|c| *c == class).unwrap();
        let [read, write, _] = core::rwx_from_modes(policy.file_mode, policy.dir_mode)[index];
        let level = if !read {
            Level::None
        } else if write {
            Level::Write
        } else {
            Level::Read
        };
        let why = match class {
            Class::Owner => tr("as the owner"),
            Class::Group => trf("as a member of “{group}”", &[("group", &self.group_name(gid))]),
            Class::Others => tr("as everyone else"),
        };
        (level, why)
    }

    fn normal(&self, uuid: &str, saved: bool) -> Normal {
        let policy = self.policy(uuid, saved);
        match policy.mode {
            Mode::Windows => {
                Normal::Windows(self.users.iter().map(|u| (u.uid, self.strict_level(uuid, u.uid, saved))).collect())
            }
            Mode::Desktop => {
                Normal::Desktop(self.owner(uuid, saved), self.group(uuid, saved), policy.file_mode, policy.dir_mode)
            }
        }
    }

    pub fn is_changed(&self, uuid: &str) -> bool {
        self.edits.contains_key(uuid) && self.normal(uuid, false) != self.normal(uuid, true)
    }

    pub fn user_changed(&self, uuid: &str, uid: u32) -> bool {
        self.is_changed(uuid) && self.access(uuid, uid, false) != self.access(uuid, uid, true)
    }

    pub fn changed_drives(&self) -> Vec<String> {
        self.drives.iter().filter(|d| self.is_changed(&d.uuid)).map(|d| d.uuid.clone()).collect()
    }

    pub fn change_count(&self) -> usize {
        self.changed_drives().len()
    }

    pub fn set_mode(&mut self, uuid: &str, mode: Mode) {
        self.edit(uuid).mode = mode;
    }

    /// Strict mode. Returns the uid demoted from full control, if any.
    pub fn set_level(&mut self, uuid: &str, uid: u32, level: Level) -> Option<u32> {
        let mut current: std::collections::BTreeMap<u32, Level> =
            self.users.iter().map(|u| (u.uid, self.strict_level(uuid, u.uid, false))).collect();
        let mut demoted = None;
        if level == Level::Full {
            for (other, value) in current.iter_mut() {
                if *other != uid && *value == Level::Full {
                    *value = Level::Write;
                    demoted = Some(*other);
                }
            }
        }
        current.insert(uid, level);
        self.edit(uuid).users = current;
        demoted
    }

    pub fn set_rwx(&mut self, uuid: &str, class: Class, index: usize, value: bool) {
        let policy = self.edit(uuid);
        let mut rwx = core::rwx_from_modes(policy.file_mode, policy.dir_mode);
        let row = &mut rwx[Class::ALL.iter().position(|c| *c == class).unwrap()];
        row[index] = value;
        if index == 1 && value {
            row[0] = true; // writing needs reading
        }
        if index == 0 && !value {
            row[1] = false; // no reading, no writing
        }
        (policy.file_mode, policy.dir_mode) = core::modes_from_rwx(&rwx);
    }

    pub fn set_preset(&mut self, uuid: &str, key: &str) {
        if let Some((_, _, file_mode, dir_mode)) = core::PRESETS.iter().find(|p| p.0 == key) {
            let policy = self.edit(uuid);
            policy.file_mode = *file_mode;
            policy.dir_mode = *dir_mode;
        }
    }

    pub fn payload(&self, uuid: &str) -> Value {
        let mut policy = self.policy(uuid, false);
        if policy.mode == Mode::Windows {
            policy.users = self.users.iter().map(|u| (u.uid, self.strict_level(uuid, u.uid, false))).collect();
        }
        core::policy_to_json(&policy)
    }
}
