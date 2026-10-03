// Module: slate_ntfs_tools::recovery_io::models::replay::state_tests
// Purpose: Exercise replay recovery contracts with independent regression fixtures.
// Created: 2026-10-02
// Architecture: Extracted unchanged from the owner's inline tests; recovery.rs
// includes this file in the original private scope so production internals stay private.

use super::*;

#[test]
fn target_codec_preserves_page_lsn_and_raw_sector_evidence() {
    let word = (1_u64 << 63) | 1;
    for kind in [ReplayTargetKind::Mft, ReplayTargetKind::Index, ReplayTargetKind::Raw] {
        let target = ReplayTarget {
            spans: vec![WriteSpan { physical_offset: 4096, source_offset: 0, length: 512 }],
            mirror: None,
            before: 2,
            bytes: 3,
            state: ReplayState::from_word(kind, word),
            changed: true,
            undo: false,
        };
        let bytes = TargetTable::encode(&target).unwrap();
        // The scratch descriptor layout remains byte-for-byte compatible.
        assert_eq!(bytes.len(), 80);
        assert_eq!(&bytes[32..40], &word.to_le_bytes());
        assert_eq!(
            bytes[48],
            match kind {
                ReplayTargetKind::Mft => 0,
                ReplayTargetKind::Index => 1,
                ReplayTargetKind::Raw => 2,
            }
        );
        let restored = TargetTable::decode(&bytes).unwrap();
        assert!(restored.state.kind() == kind);
        assert_eq!(restored.state.word(), word);
        assert_eq!(restored.state.page_lsn(), if kind == ReplayTargetKind::Raw { None } else { Some(word) });
        assert_eq!(TargetTable::encode(&restored).unwrap(), bytes);
        if kind == ReplayTargetKind::Raw {
            assert!(restored.state.sector_verified(0));
            assert!(restored.state.sector_verified(63));
            assert!(!restored.state.sector_verified(64));
        }
    }
}
