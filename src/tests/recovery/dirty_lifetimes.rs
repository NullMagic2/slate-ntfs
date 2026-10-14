// Module: recovery_dirty::lifetime_tests
// Purpose: Exercise transaction-aware retirement and replacement of dirty mappings.
// Created: 2026-10-09
// Architecture: Independent log records drive production transaction and mapping analyzers.
use super::super::log::{OpenAttributeStore, PageBits, TransactionSeedStore};
use super::*;
use ntfs_rs::logfile::*;
use ntfs_rs::{boot::BootSector, mft::*, record_edit as edit, runlist::Extent};

const OWNER: u64 = (7 << 48) | 48;
const OLD_LCN: u64 = 100;
const NEW_LCN: u64 = 700;
const NAME: &[u8] = b"$\0I\03\00\0";

fn boot() -> BootSector {
    BootSector {
        bytes_per_sector: 512,
        sectors_per_cluster: 8,
        cluster_bytes: 4096,
        total_sectors: 32768,
        mft_lcn: 4,
        mft_mirror_lcn: 2,
        record_bytes: 1024,
        index_block_bytes: 4096,
        serial_number: 1,
    }
}

fn mft_image(mapped: bool) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    edit::format_empty(&mut raw, reference_number(OWNER)).unwrap();
    edit::p16(&mut raw, record_layout::SEQUENCE_OFFSET, reference_sequence(OWNER)).unwrap();
    edit::p16(&mut raw, record_layout::FLAGS_OFFSET, record_layout::IN_USE).unwrap();
    if mapped {
        let mut attr = vec![0; 256];
        let n = edit::build_nonresident(
            ATTR_INDEX_ALLOCATION,
            NAME,
            &[Extent { vcn: 0, lcn: Some(OLD_LCN), len: 1 }],
            4096,
            4096,
            4096,
            &mut attr,
        )
        .unwrap();
        edit::insert(&mut raw, &attr[..n]).unwrap();
    }
    raw
}

struct Fixture {
    history: History,
    bound: RecordStore,
}

impl Fixture {
    fn new() -> Self {
        let mut template = vec![0; 4096];
        encode_initial_restart(&mut template, 262144, 0x10808).unwrap();
        let restart = RestartPage::parse(&mut template.clone(), 512).unwrap();
        Self {
            history: History {
                records: RecordStore::new().unwrap(),
                restart,
                template,
                opens: OpenAttributeStore::new().unwrap(),
                transactions: TransactionSeedStore::new().unwrap(),
                dirty: RecordStore::new().unwrap(),
                tail_pages: 0,
                checkpoint_lsn: 0,
                occupied_pages: PageBits::new(262144, 4096).unwrap(),
                discarded_pages: PageBits::new(262144, 4096).unwrap(),
                end_page: 16384,
            },
            bound: RecordStore::new().unwrap(),
        }
    }

    fn append(&mut self, input: NtfsOperationInput<'_>, open: &OpenAttribute, tx: u32, previous: u64) -> usize {
        let i = self.history.records.len();
        let mut payload = vec![0; 8192];
        let n = encode_ntfs_operation(&input, &mut payload).unwrap();
        let mut raw = vec![0; n + 48];
        let n = encode_lfs_record(
            &LfsRecordInput {
                this_lsn: i as u64 + 1,
                previous_lsn: previous,
                undo_next_lsn: previous,
                client_sequence: 0,
                client_index: 0,
                record_type: 1,
                transaction_id: tx,
                flags: 0,
                payload: &payload[..n],
            },
            &mut raw,
        )
        .unwrap();
        self.history.records.push(&raw[..n]).unwrap();
        self.bound.push(&open.encode()).unwrap();
        i
    }

    fn commit(&mut self, tx: u32, previous: usize) {
        self.append(
            NtfsOperationInput {
                redo_code: operation::COMMIT_TRANSACTION,
                undo_code: 0,
                target_attribute: 24,
                target_vcn: 0,
                lcns: &[],
                redo: &[],
                undo: &[],
            },
            &index(),
            tx,
            previous as u64 + 1,
        );
    }

    fn update(&mut self, lcn: u64, tx: u32) -> usize {
        self.append(
            NtfsOperationInput {
                redo_code: operation::UPDATE_NONRESIDENT_VALUE,
                undo_code: operation::UPDATE_NONRESIDENT_VALUE,
                target_attribute: 24,
                target_vcn: 0,
                lcns: &[lcn],
                redo: &[1],
                undo: &[0],
            },
            &index(),
            tx,
            0,
        )
    }

    fn remove(&mut self, committed: bool) {
        let open =
            OpenAttribute { reference: file_reference(0, 1).unwrap(), kind: ATTR_DATA, name: vec![], index_bytes: 0 };
        let i = self.append(
            NtfsOperationInput {
                redo_code: operation::INITIALIZE_FILE_RECORD,
                undo_code: operation::INITIALIZE_FILE_RECORD,
                target_attribute: 24,
                target_vcn: reference_number(OWNER) / 4,
                lcns: &[16],
                redo: &mft_image(false),
                undo: &mft_image(true),
            },
            &open,
            64,
            0,
        );
        if committed {
            self.commit(64, i);
        }
    }

    fn analyze(&self) -> Result<DirtyMappings> {
        let h = &self.history;
        let schedule = transactions::analyze(&h.records, h.checkpoint_lsn, &h.transactions)?;
        DirtyMappings::analyze(h, &self.bound, boot(), &schedule)
    }

    fn lcns(&self, mappings: &mut DirtyMappings, i: usize) -> Vec<u8> {
        let raw = self.history.records.view(i).unwrap();
        let r = LfsRecord::parse(&raw).unwrap();
        mappings.redo_lcns(&index(), r.ntfs_operation().unwrap(), r.this_lsn).unwrap()
    }
}

fn index() -> OpenAttribute {
    OpenAttribute { reference: OWNER, kind: ATTR_INDEX_ALLOCATION, name: NAME.to_vec(), index_bytes: 4096 }
}

#[test]
fn committed_removal_retires_old_redo_before_cluster_reuse() {
    for replacement in [OLD_LCN, NEW_LCN] {
        let mut fixture = Fixture::new();
        let old = fixture.update(OLD_LCN, 24);
        fixture.commit(24, old);
        fixture.remove(true);
        let new = fixture.update(replacement, 104);
        fixture.commit(104, new);
        let mut mappings = fixture.analyze().unwrap();
        assert_eq!(fixture.lcns(&mut mappings, old), 0_u64.to_le_bytes());
        assert_eq!(fixture.lcns(&mut mappings, new), replacement.to_le_bytes());
    }
}

#[test]
fn mapping_changes_require_committed_lifecycle_evidence() {
    for removal in [None, Some(false)] {
        let mut fixture = Fixture::new();
        let old = fixture.update(OLD_LCN, 24);
        fixture.commit(24, old);
        if let Some(committed) = removal {
            fixture.remove(committed);
        }
        let new = fixture.update(NEW_LCN, 104);
        fixture.commit(104, new);
        assert!(matches!(fixture.analyze(), Err(Error::InvalidLog)));
    }
}

#[test]
fn retirement_refuses_to_discard_a_mapping_needed_by_undo() {
    let mut fixture = Fixture::new();
    fixture.update(OLD_LCN, 24);
    fixture.remove(true);
    assert!(matches!(fixture.analyze(), Err(Error::Unsupported)));
}

impl Fixture {
    fn release(&mut self, committed: bool) {
        let mut ranges = [0; log_operation::CLUSTER_RANGE_BYTES];
        ranges[..8].copy_from_slice(&OLD_LCN.to_le_bytes());
        ranges[8..].copy_from_slice(&1_u64.to_le_bytes());
        let i = self.append(
            NtfsOperationInput {
                redo_code: operation::DELETE_DIRTY_CLUSTERS,
                undo_code: operation::NOOP,
                target_attribute: 0,
                target_vcn: 0,
                lcns: &[],
                redo: &ranges,
                undo: &[],
            },
            &index(),
            64,
            0,
        );
        if committed {
            self.commit(64, i);
        }
    }
}

#[test]
fn explicit_deallocation_distinguishes_committed_and_loser_lifetimes() {
    for committed in [false, true] {
        for replacement in [OLD_LCN, NEW_LCN] {
            let mut fixture = Fixture::new();
            let old = fixture.update(OLD_LCN, 24);
            fixture.commit(24, old);
            fixture.release(committed);
            if committed {
                // An unfinished update of the NEW owner must not keep old redo alive.
                let new = fixture.update(replacement, 104);
                let mut mappings = fixture.analyze().unwrap();
                assert_eq!(fixture.lcns(&mut mappings, old), 0_u64.to_le_bytes());
                assert_eq!(fixture.lcns(&mut mappings, new), replacement.to_le_bytes());
            } else {
                let mut mappings = fixture.analyze().unwrap();
                assert_eq!(fixture.lcns(&mut mappings, old), OLD_LCN.to_le_bytes());
            }
        }
    }
}

#[test]
fn explicit_deallocation_cannot_discard_earlier_undo() {
    let mut fixture = Fixture::new();
    fixture.update(OLD_LCN, 24);
    fixture.release(true);
    assert!(matches!(fixture.analyze(), Err(Error::Unsupported)));
}

#[test]
fn completed_transaction_can_retire_clusters_after_its_commit() {
    let mut fixture = Fixture::new();
    let old = fixture.update(OLD_LCN, 24);
    fixture.commit(24, old);
    let mut ranges = [0; log_operation::CLUSTER_RANGE_BYTES];
    ranges[..8].copy_from_slice(&OLD_LCN.to_le_bytes());
    ranges[8..].copy_from_slice(&1_u64.to_le_bytes());
    fixture.append(
        NtfsOperationInput {
            redo_code: operation::DELETE_DIRTY_CLUSTERS,
            undo_code: operation::NOOP,
            target_attribute: 0,
            target_vcn: 0,
            lcns: &[],
            redo: &ranges,
            undo: &[],
        },
        &index(),
        24,
        2,
    );
    let mut mappings = fixture.analyze().unwrap();
    assert_eq!(fixture.lcns(&mut mappings, old), 0_u64.to_le_bytes());
}

#[test]
fn logged_removal_allows_undo_in_a_later_lifetime() {
    for replacement in [OLD_LCN, NEW_LCN] {
        let mut fixture = Fixture::new();
        let old = fixture.update(OLD_LCN, 24);
        fixture.commit(24, old);
        fixture.remove(true);
        let new = fixture.update(replacement, 104);
        let mut mappings = fixture.analyze().unwrap();
        assert_eq!(fixture.lcns(&mut mappings, old), 0_u64.to_le_bytes());
        assert_eq!(fixture.lcns(&mut mappings, new), replacement.to_le_bytes());
    }
}
