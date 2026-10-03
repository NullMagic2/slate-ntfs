//! Module: ntfs_permissions
//! Purpose: Expose shared drive-policy and user-interface services.
//! Created: 2026-10-01
//! Architecture: The GTK application and root helper share core policy and mount validation.
//! Policies under /etc/slate-ntfs/permissions select desktop ownership or
//! Windows ACL identity mapping. Desktop defaults restrict access to the
//! mounting user; strict mode maps every identity and group, with root as SYSTEM.

pub mod core;
pub mod i18n;
pub mod label;
pub mod mount;
