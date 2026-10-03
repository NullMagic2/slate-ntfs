//! Module: ntfs_rs::format
//! Purpose: Assemble the checked NTFS modules and common error types.
//! Created: 2026-10-01
//! Architecture: This facade connects on-disk views, crypto, write planning and native
//! transactions.

#![deny(unsafe_code)]

#[path = "crypto/aes.rs"]
pub mod aes;
#[path = "engine/allocation.rs"]
pub mod allocation;
#[path = "ondisk/attrlist.rs"]
pub mod attrlist;
#[path = "engine/batch.rs"]
pub mod batch;
#[path = "ondisk/bitlocker.rs"]
pub mod bitlocker;
#[path = "ondisk/boot.rs"]
pub mod boot;
#[path = "ondisk/bytes.rs"]
pub mod bytes;
#[path = "crypto/ccm.rs"]
pub mod ccm;
#[path = "ops/ea.rs"]
pub mod ea;
#[path = "ops/file_lifecycle.rs"]
pub mod file_lifecycle;
#[path = "ops/filename_metadata.rs"]
pub mod filename_metadata;
/// Compatibility path for the shared filename views and layout constants.
pub use filename_metadata as filename;
#[path = "ondisk/hibernation.rs"]
pub mod hibernation;
#[path = "ops/identity.rs"]
pub mod identity;
#[path = "ondisk/index.rs"]
pub mod index;
#[path = "ops/index_tree.rs"]
pub mod index_tree;
#[path = "engine/journal.rs"]
pub mod journal;
#[path = "ops/linux_names.rs"]
pub mod linux_names;
#[path = "ondisk/logfile.rs"]
pub mod logfile;
#[path = "engine/metadata_tx.rs"]
pub mod metadata_tx;
#[path = "ondisk/mft.rs"]
pub mod mft;
#[path = "engine/mft_growth.rs"]
pub mod mft_growth;
#[path = "engine/namespace_family.rs"]
mod namespace_family;
#[path = "ops/namespace_writer.rs"]
pub mod namespace_writer;
#[path = "engine/record_edit.rs"]
pub mod record_edit;
#[path = "ondisk/reparse.rs"]
pub mod reparse;
#[path = "engine/replay.rs"]
pub mod replay;
#[path = "engine/resident_writer.rs"]
pub mod resident_writer;
#[path = "ondisk/runlist.rs"]
pub mod runlist;
#[path = "crypto/sector.rs"]
pub mod sector;
#[path = "ondisk/security.rs"]
pub mod security;
#[path = "ops/security_create.rs"]
pub mod security_create;
#[path = "ondisk/security_store.rs"]
pub mod security_store;
#[path = "ops/security_writer.rs"]
pub mod security_writer;
#[path = "crypto/sha256.rs"]
pub mod sha256;
#[path = "ondisk/std_info.rs"]
pub mod std_info;
#[path = "engine/stream_writer.rs"]
pub mod stream_writer;
#[path = "engine/tx.rs"]
pub mod tx;
#[path = "ops/unix_metadata.rs"]
pub mod unix_metadata;
#[path = "ondisk/upcase.rs"]
pub mod upcase;
#[path = "ondisk/volume.rs"]
pub mod volume;
#[path = "ondisk/volume_info.rs"]
pub mod volume_info;
#[path = "engine/write_plan.rs"]
pub mod write_plan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Truncated,
    InvalidBoot,
    InvalidGeometry,
    InvalidFixup,
    InvalidRecord,
    InvalidAttribute,
    InvalidAttributeList,
    InvalidRunlist,
    InvalidSecurity,
    InvalidLog,
    InvalidIndex,
    AccessDenied,
    Overflow,
    Io,
    Unsupported,
    NoSpace,
    /// An index key (for example a case-insensitive file name) already exists.
    Exists,
    /// A requested index key or name is absent.
    NotFound,
    /// The operation needs a privilege the caller's mapped token cannot hold.
    NotPermitted,
    /// A directory that must be empty still has entries.
    NotEmpty,
}

pub type Result<T> = core::result::Result<T, Error>;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Userspace callers report every core validation failure as invalid data.
#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, std::string::ToString::to_string(&error))
    }
}
