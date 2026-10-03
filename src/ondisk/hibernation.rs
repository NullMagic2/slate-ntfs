//! Module: ntfs_rs::hibernation
//! Purpose: Classify hibernation headers without modifying them.
//! Created: 2026-10-01
//! Architecture: Writer admission consumes this result; callers separately verify recovery
//! state before allowing writes. Unsupported headers never imply safe access.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HibernationState {
    Absent,
    ActiveImage,
    InterruptedResume,
    InvalidatedImage,
    ZeroedHeader,
    Unknown,
}

/// The hibernation part of the write gate. DiscardRequired is never write
/// permission: the caller must first delete the saved session through a
/// durable NTFS metadata transaction, then inspect the volume again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HibernationWriteGate {
    Clear,
    DiscardRequired,
    Blocked,
}

/// Decide only the hibernation prerequisite. Dirty state, $LogFile, NTFS
/// permissions and all other write checks remain independent requirements.
pub fn write_gate(state: HibernationState, override_hibernation: bool) -> HibernationWriteGate {
    match (state, override_hibernation) {
        (HibernationState::Absent, _) => HibernationWriteGate::Clear,
        (HibernationState::ActiveImage, true) => HibernationWriteGate::DiscardRequired,
        _ => HibernationWriteGate::Blocked,
    }
}

pub fn classify_header(first_page: &[u8]) -> HibernationState {
    if first_page.len() != 4096 {
        return HibernationState::Unknown;
    }
    match &first_page[..4] {
        b"HIBR" | b"hibr" => HibernationState::ActiveImage,
        b"RSTR" => HibernationState::InterruptedResume,
        b"WAKE" | b"wake" => HibernationState::InvalidatedImage,
        _ if first_page.iter().all(|byte| *byte == 0) => HibernationState::ZeroedHeader,
        _ => HibernationState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_headers_and_refuses_unknown_or_short_data() {
        let mut page = [0_u8; 4096];
        assert_eq!(classify_header(&page), HibernationState::ZeroedHeader);
        for (signature, state) in [
            (b"HIBR", HibernationState::ActiveImage),
            (b"hibr", HibernationState::ActiveImage),
            (b"RSTR", HibernationState::InterruptedResume),
            (b"WAKE", HibernationState::InvalidatedImage),
            (b"wake", HibernationState::InvalidatedImage),
        ] {
            page[..4].copy_from_slice(signature);
            assert_eq!(classify_header(&page), state);
        }
        page[..4].copy_from_slice(b"oops");
        assert_eq!(classify_header(&page), HibernationState::Unknown);
        assert_eq!(classify_header(&page[..512]), HibernationState::Unknown);
    }

    #[test]
    fn override_never_grants_write_access_before_discard() {
        assert_eq!(write_gate(HibernationState::Absent, false), HibernationWriteGate::Clear);
        assert_eq!(write_gate(HibernationState::Absent, true), HibernationWriteGate::Clear);
        assert_eq!(write_gate(HibernationState::ActiveImage, false), HibernationWriteGate::Blocked);
        assert_eq!(write_gate(HibernationState::ActiveImage, true), HibernationWriteGate::DiscardRequired);
        for state in [
            HibernationState::InterruptedResume,
            HibernationState::InvalidatedImage,
            HibernationState::ZeroedHeader,
            HibernationState::Unknown,
        ] {
            assert_eq!(write_gate(state, true), HibernationWriteGate::Blocked);
        }
    }
}
