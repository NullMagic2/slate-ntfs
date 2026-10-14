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

#[test]
#[ignore = "requires SLATE_REFUSED_LOG with an immutable refused recovery capture"]
fn saved_journal_mapping_lifetimes() {
    let path = std::path::PathBuf::from(std::env::var_os("SLATE_REFUSED_LOG").unwrap());
    let boot = ntfs_rs::boot::BootSector::parse(&std::fs::read(path.join("boot.bin")).unwrap()).unwrap();
    let original = std::fs::read(path.join("logfile.bin")).unwrap();
    let mut log_bytes = original.clone();
    let history = log::discover(&mut log_bytes, boot.bytes_per_sector).unwrap();
    let schedule = transactions::analyze(&history.records, history.checkpoint_lsn, &history.transactions).unwrap();
    let (bound, _) = bind_history(&history).unwrap();
    let mut mappings = super::super::dirty::DirtyMappings::analyze(&history, &bound, boot, &schedule).unwrap();
    let mut retired = 0;
    for step in 0..schedule.redo.len() {
        let i = schedule.redo.index(step).unwrap();
        let raw = history.records.view(i).unwrap();
        let r = LfsRecord::parse(&raw).unwrap();
        let op = r.ntfs_operation().unwrap();
        let open = OpenAttribute::decode(&bound.get(i).unwrap()).unwrap();
        let lcns = mappings.redo_lcns(&open, op, r.this_lsn).unwrap();
        if !lcns.is_empty() && lcns.iter().all(|byte| *byte == 0) {
            retired += 1;
        }
    }
    eprintln!(
        "records={} redo={} undo={} retired={}",
        history.records.len(),
        schedule.redo.len(),
        schedule.undo.len(),
        retired
    );
    assert_eq!(std::fs::read(path.join("logfile.bin")).unwrap(), original);
}
