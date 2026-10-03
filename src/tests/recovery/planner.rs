//! Module: slate_ntfs_tools::recovery_io::recovery_semantic_checks
//! Purpose: Exercise semantic repair planning and refusal boundaries.
//! Created: 2026-09-30
//! Architecture: Tools-crate tests build disposable fixtures and invoke checker and
//!     recovery planners without mounting a filesystem.

use super::*;
use ntfs_rs::{record_edit as e, runlist::Extent};

#[test]
#[ignore = "requires SLATE_SCAN_WRITE_VIEW_SOURCE with an immutable damaged NTFS image"]
fn cached_frozen_preflight_preserves_the_complete_repair_plan() {
    let source = std::path::PathBuf::from(std::env::var_os("SLATE_SCAN_WRITE_VIEW_SOURCE").unwrap());
    let original = std::fs::read(&source).unwrap();
    for index_check in [checker::consistency::IndexCheck::Full, checker::consistency::IndexCheck::Quick] {
        let options = RepairOptions {
            index_audit: checker::consistency::AuditOptions { index_check, ..Default::default() },
            ..Default::default()
        };
        let budget = checker::ScanBudget { read_buffer_bytes: 0, index_cache_bytes: 0, write_view_cache_bytes: 0 };
        let streamed = structural_repair_plan(
            &source,
            &mut |_| {},
            PlanInputs {
                frozen_preflight: true,
                options,
                recovery_created: Some(42),
                budget: Some(budget),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!streamed.is_empty());
        for bytes in [WRITE_VIEW_BYTES as u64, 1310720, 134217728] {
            let budget = checker::ScanBudget { write_view_cache_bytes: bytes, ..budget };
            let cached = structural_repair_plan(
                &source,
                &mut |_| {},
                PlanInputs {
                    frozen_preflight: true,
                    options,
                    recovery_created: Some(42),
                    budget: Some(budget),
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(cached.matches(&streamed).unwrap());
            let stats = cached.write_view_stats();
            assert!(stats.hits > 0);
            assert!(stats.peak_bytes <= bytes);
            if bytes == WRITE_VIEW_BYTES as u64 && streamed.payload_len() > bytes {
                assert!(stats.spills > 0);
            }
            eprintln!(
                "write_view_budget={bytes} peak={} hits={} spills={} index_check={index_check:?}",
                stats.peak_bytes, stats.hits, stats.spills
            );
        }
    }
    assert_eq!(std::fs::read(source).unwrap(), original);
}

struct Fixture {
    boot: ntfs_rs::boot::BootSector,
    records: Vec<Vec<u8>>,
    image: Vec<u8>,
    path: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let boot = ntfs_rs::boot::BootSector {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_bytes: 4096,
            total_sectors: 1024,
            mft_lcn: 4,
            mft_mirror_lcn: 2,
            record_bytes: 1024,
            index_block_bytes: 4096,
            serial_number: 1,
        };
        let mut records = Vec::new();
        for number in 0..64 {
            let mut raw = vec![0; 1024];
            e::format_empty(&mut raw, number).unwrap();
            e::p16(&mut raw, 16, 1).unwrap();
            e::p16(&mut raw, 22, 0).unwrap();
            records.push(raw);
        }
        let mut result = Self {
            boot,
            records,
            image: vec![0; 512 * 1024],
            path: std::env::temp_dir().join(format!(
                "slate-semantic-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            )),
        };
        result.active(0);
        result.active(6);
        result.active(11);
        e::p16(&mut result.records[11], 22, 3).unwrap();
        result.nonresident(0, ATTR_DATA, &[], 4, 16, 65536);
        result.nonresident(0, ATTR_BITMAP, &[], 24, 1, 8);
        let mut allocation = [0; 16];
        allocation[..4].fill(255);
        result.resident(6, ATTR_DATA, &[], &allocation);
        result
    }
    fn active(&mut self, n: usize) {
        e::p16(&mut self.records[n], 22, 1).unwrap();
    }
    fn resident(&mut self, n: usize, kind: u32, name: &[u8], value: &[u8]) {
        let attr = StreamChange::resident(kind, name, value).unwrap().attribute.unwrap();
        e::insert(&mut self.records[n], &attr).unwrap();
    }
    fn nonresident(&mut self, n: usize, kind: u32, name: &[u8], lcn: u64, len: u64, bytes: u64) {
        let mut attr = vec![0; 1024];
        let used = e::build_nonresident(
            kind,
            name,
            &[Extent { vcn: 0, lcn: Some(lcn), len }],
            len * 4096,
            bytes,
            bytes,
            &mut attr,
        )
        .unwrap();
        e::insert(&mut self.records[n], &attr[..used]).unwrap();
    }
    fn metadata(&mut self, n: usize, name: &str) {
        self.active(n);
        let utf: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut value = vec![0; 66 + utf.len()];
        e::p64(&mut value, 0, (1_u64 << 48) | 11).unwrap();
        value[64] = (utf.len() / 2) as u8;
        value[65] = 1;
        value[66..].copy_from_slice(&utf);
        self.resident(n, 0x30, &[], &value);
    }
    fn family(&mut self, base: usize, extension: usize) {
        self.active(extension);
        e::p64(&mut self.records[extension], 32, (1_u64 << 48) | base as u64).unwrap();
        let mut keys = Vec::new();
        for n in [base, extension] {
            for a in MftRecord::from_decoded(&self.records[n]).unwrap().attributes() {
                let a = a.unwrap();
                keys.push(FamilyKey {
                    kind: a.kind,
                    name: a.name_utf16le().unwrap().to_vec(),
                    vcn: if a.nonresident { a.first_vcn().unwrap() } else { 0 },
                    reference: (1_u64 << 48) | n as u64,
                    id: a.id,
                });
            }
        }
        keys.sort_by(family_key_order);
        let mut list = Vec::new();
        for key in keys {
            let size = (26 + key.name.len() + 7) & !7;
            let at = list.len();
            list.resize(at + size, 0);
            let row = &mut list[at..];
            e::p32(row, 0, key.kind).unwrap();
            e::p16(row, 4, size as u16).unwrap();
            row[6] = (key.name.len() / 2) as u8;
            row[7] = 26;
            e::p64(row, 8, key.vcn).unwrap();
            e::p64(row, 16, key.reference).unwrap();
            e::p16(row, 24, key.id).unwrap();
            row[26..26 + key.name.len()].copy_from_slice(&key.name);
        }
        self.resident(base, ATTR_ATTRIBUTE_LIST, &[], &list);
    }
    fn root(&mut self, n: usize, name: &[u8], collation: u32, rows: &[Vec<u8>]) {
        let mut file = checker::consistency::scratch_file().unwrap();
        for row in rows {
            repair_entry_write(&mut file, row).unwrap();
        }
        let (root, _, pages) = rebuilt_index(
            self.boot,
            file,
            rows.len() as u64,
            rows.iter().map(|r| r.len() as u64).sum(),
            800,
            if collation == 1 { 0x30 } else { 0 },
            collation,
        )
        .unwrap();
        assert_eq!(pages, 0);
        self.resident(n, 0x90, name, &root);
    }
    fn save(&mut self) {
        for (n, record) in self.records.iter().enumerate() {
            let mut raw = record.clone();
            if ntfs_rs::bytes::u16_at(record, 22).unwrap() & 1 != 0 {
                self.image[24 * 4096 + n / 8] |= 1 << (n % 8);
            }
            protect_mft_record(&mut raw, 512).unwrap();
            self.image[16384 + n * 1024..16384 + (n + 1) * 1024].copy_from_slice(&raw);
        }
        std::fs::write(&self.path, &self.image).unwrap();
    }
    fn logical(&self, plan: &RepairPlan, n: u64) -> Vec<u8> {
        let mut volume =
            Volume::new(PlannedImage { image: Image(File::open(&self.path).unwrap()), patches: plan }, self.boot)
                .unwrap();
        let zero = checker::consistency::mft_image(&mut volume).unwrap();
        let mft = MftRecord::from_decoded(&zero).unwrap();
        RepairFamily::load(&mut volume, &mft, n).unwrap().logical
    }
    fn view(&self, plan: &RepairPlan, n: u64, name: &[u8], collation: u32) -> Vec<Vec<u8>> {
        let logical = self.logical(plan, n);
        let record = MftRecord::from_decoded(&logical).unwrap();
        let mut volume =
            Volume::new(PlannedImage { image: Image(File::open(&self.path).unwrap()), patches: plan }, self.boot)
                .unwrap();
        let mut rows = Vec::new();
        visit_view_index(
            &mut volume,
            record.local_attribute(0x90, name).unwrap().unwrap().resident_value().unwrap(),
            record.local_attribute(0xa0, name).unwrap(),
            record.local_attribute(ATTR_BITMAP, name).unwrap(),
            0,
            collation,
            &mut |row| {
                rows.push(row.to_vec());
                Ok(())
            },
        )
        .unwrap();
        rows
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn missing_volume_bitmap_rebuilds_into_fragmented_unowned_storage() {
    let mut f = Fixture::new();
    let clusters = 70000;
    f.boot.total_sectors = clusters * 8;
    let at = e::require(&f.records[6], ATTR_DATA, &[]).unwrap();
    e::remove(&mut f.records[6], at).unwrap();
    for n in [24, 25, 26] {
        f.active(n);
    }
    f.nonresident(24, ATTR_DATA, &[], 1, 3, 3 * 4096);
    f.nonresident(25, ATTR_DATA, &[], 20, 4, 4 * 4096);
    let mut runs = Vec::new();
    for (vcn, lcn) in [25, 27, 29].into_iter().enumerate() {
        runs.push(Extent { vcn: vcn as u64, lcn: Some(lcn), len: 1 });
    }
    runs.push(Extent { vcn: 3, lcn: Some(31), len: clusters - 31 });
    let bytes = (clusters - 28) * 4096;
    let mut attr = vec![0; 1024];
    let n = e::build_nonresident(ATTR_DATA, &[], &runs, bytes, bytes, bytes, &mut attr).unwrap();
    e::insert(&mut f.records[26], &attr[..n]).unwrap();
    f.save();
    OpenOptions::new().write(true).open(&f.path).unwrap().set_len(clusters * 4096).unwrap();
    let mut plan = RepairPlan::new(clusters * 4096).unwrap();
    reserved::ensure_bitmap(&f.path, f.boot, &mut plan).unwrap();
    let logical = f.logical(&plan, 6);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let data = record.stream(ATTR_DATA, &[]).unwrap();
    let runs: Vec<_> = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).map(Result::unwrap).collect();
    assert_eq!(runs.iter().map(|r| r.lcn.unwrap()).collect::<Vec<_>>(), vec![26, 28, 30]);
    let mut volume =
        Volume::new(PlannedImage { image: Image(File::open(&f.path).unwrap()), patches: &plan }, f.boot).unwrap();
    let mut bits = vec![0; data.data_size().unwrap() as usize];
    volume.read_attribute(data, 0, &mut bits).unwrap();
    assert!(bits.iter().all(|&b| b == 255));
    let mut original = vec![0; f.image.len()];
    File::open(&f.path).unwrap().read_exact(&mut original).unwrap();
    assert_eq!(original, f.image);
}

#[test]
fn badclus_family_preserves_reservations_and_spills_large_new_mapping() {
    let mut f = Fixture::new();
    f.boot.total_sectors = 8192;
    f.image.resize(1024 * 4096, 0);
    let at = e::require(&f.records[6], ATTR_DATA, &[]).unwrap();
    e::remove(&mut f.records[6], at).unwrap();
    let mut bits = [0; 128];
    bits[..4].fill(255);
    f.resident(6, ATTR_DATA, &[], &bits);
    f.active(8);
    f.resident(8, 0x10, &[], &[0; 72]);
    let mut attr = vec![0; 1024];
    let runs = [
        Extent { vcn: 0, lcn: None, len: 100 },
        Extent { vcn: 100, lcn: Some(100), len: 1 },
        Extent { vcn: 101, lcn: None, len: 923 },
    ];
    let n = e::build_nonresident(ATTR_DATA, b"$\0B\0a\0d\0", &runs, 1024 * 4096, 1024 * 4096, 0, &mut attr).unwrap();
    e::insert(&mut f.records[25], &attr[..n]).unwrap();
    f.family(8, 25);
    f.save();
    let mut bad = checker::consistency::scratch_file().unwrap();
    for lcn in (102_u64..900).step_by(2) {
        for word in [lcn, 0, 0, 0] {
            bad.write_all(&word.to_le_bytes()).unwrap();
        }
    }
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    // Match normal repair policy: retain previously declared bad clusters.
    badclus_repairs(&f.path, f.boot, &mut plan, &bad, false).unwrap();
    let logical = f.logical(&plan, 8);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let data = record.local_attribute(ATTR_DATA, b"$\0B\0a\0d\0").unwrap().unwrap();
    let runs: Vec<_> = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).map(Result::unwrap).collect();
    assert_eq!(runs.iter().map(|r| r.len).sum::<u64>(), 1024);
    let reserved: Vec<_> = runs.iter().filter_map(|r| r.lcn).collect();
    assert_eq!(reserved, (100..900).step_by(2).collect::<Vec<_>>());
    assert_eq!(u64_at(&logical, data.record_offset() + 64).unwrap(), 400 * 4096);
    let count = plan.len();
    badclus_repairs(&f.path, f.boot, &mut plan, &bad, false).unwrap();
    assert_eq!(plan.len(), count);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn damaged_allocated_object_page_is_rebuilt_from_file_attributes() {
    let mut f = Fixture::new();
    f.metadata(24, "$ObjId");
    for n in 26..44 {
        f.active(n);
        f.resident(n, 0x40, &[], &[n as u8; 16]);
    }
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    object_id_repairs(&f.path, f.boot, &mut plan, checker::consistency::IndexCheck::Full).unwrap();
    let logical = f.logical(&plan, 24);
    let file = MftRecord::from_decoded(&logical).unwrap();
    let allocation = file.local_attribute(0xa0, b"$\0O\0").unwrap().unwrap();
    let run = ntfs_rs::runlist::DataRuns::new(allocation.data_runs().unwrap(), 0).next().unwrap().unwrap();
    let physical = run.lcn.unwrap() * 4096;
    let mut before = vec![0; 4];
    {
        let mut volume =
            Volume::new(PlannedImage { image: Image(File::open(&f.path).unwrap()), patches: &plan }, f.boot).unwrap();
        volume.read_physical(physical, &mut before).unwrap();
    }
    plan.compose(Patch::new(physical, before, vec![0; 4])).unwrap();
    object_id_repairs(&f.path, f.boot, &mut plan, checker::consistency::IndexCheck::Full).unwrap();
    let rows = f.view(&plan, 24, b"$\0O\0", 19);
    assert_eq!(rows.len(), 18);
    for row in rows {
        assert_eq!(&row[40..88], &[0; 48]);
    }
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn damaged_object_tree_keeps_surviving_birth_fields_and_rebuilds_missing_rows() {
    let mut f = Fixture::new();
    f.metadata(24, "$ObjId");
    let mut rows = Vec::new();
    for n in [26, 27] {
        f.active(n);
        let id = vec![n as u8; 16];
        f.resident(n, 0x40, &[], &id);
        let mut payload = ((1_u64 << 48) | n as u64).to_le_bytes().to_vec();
        payload.extend_from_slice(&[n as u8 + 1; 48]);
        rows.push(semantic::view_entry(&id[..16], &payload).unwrap());
    }
    f.root(24, b"$\0O\0", 19, &rows);
    let at = e::require(&f.records[24], 0x90, b"$\0O\0").unwrap();
    let value = at + ntfs_rs::bytes::u16_at(&f.records[24], at + 20).unwrap() as usize;
    // A broken second slot must not hide the first row's independent birth IDs.
    e::p16(&mut f.records[24], value + 32 + rows[0].len() + 8, 0).unwrap();
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    object_id_repairs(&f.path, f.boot, &mut plan, checker::consistency::IndexCheck::Full).unwrap();
    let repaired = f.view(&plan, 24, b"$\0O\0", 19);
    assert_eq!(repaired.len(), 2);
    assert_eq!(&repaired[0][40..88], &[27; 48]);
    assert_eq!(&repaired[1][40..88], &[0; 48]);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
    let count = plan.len();
    object_id_repairs(&f.path, f.boot, &mut plan, checker::consistency::IndexCheck::Full).unwrap();
    assert_eq!(plan.len(), count);
}

#[test]
fn fragmented_crosslink_relocation_spills_mapping_into_extension_records() {
    let mut f = Fixture::new();
    f.boot.total_sectors = 8192;
    f.image.resize(1024 * 4096, 0);
    let at = e::require(&f.records[6], ATTR_DATA, &[]).unwrap();
    e::remove(&mut f.records[6], at).unwrap();
    let mut allocation = [255; 128];
    for cluster in (400..1000).step_by(2) {
        allocation[cluster / 8] &= !(1 << (cluster % 8));
    }
    f.resident(6, ATTR_DATA, &[], &allocation);
    for n in [26, 27] {
        f.active(n);
        f.nonresident(n, ATTR_DATA, &[], 32, 220, 220 * 4096);
    }
    for (n, byte) in f.image[32 * 4096..252 * 4096].iter_mut().enumerate() {
        *byte = (n % 251) as u8;
    }
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    crosslink_repairs(&f.path, f.boot, &mut plan, None).unwrap();
    let mut relocated = 0;
    for n in [26, 27] {
        let logical = f.logical(&plan, n);
        let file = MftRecord::from_decoded(&logical).unwrap();
        let data = file.stream(ATTR_DATA, &[]).unwrap();
        let runs: Vec<_> = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).map(Result::unwrap).collect();
        if runs[0].lcn == Some(32) {
            continue;
        }
        relocated += 1;
        assert_eq!(runs.len(), 220);
        assert!(runs.iter().all(|r| r.len == 1 && r.lcn.unwrap() >= 400 && r.lcn.unwrap() % 2 == 0));
        let mut volume =
            Volume::new(PlannedImage { image: Image(File::open(&f.path).unwrap()), patches: &plan }, f.boot).unwrap();
        let mut bytes = vec![0; 220 * 4096];
        volume.read_attribute(data, 0, &mut bytes).unwrap();
        assert_eq!(bytes, f.image[32 * 4096..252 * 4096]);
        let zero = checker::consistency::mft_image(&mut volume).unwrap();
        let mft = MftRecord::from_decoded(&zero).unwrap();
        let mut raw = vec![0; 1024];
        volume.read_mft_record(&mft, n, &mut raw).unwrap();
        assert!(MftRecord::parse(&mut raw, 512).unwrap().attributes().any(|a| a.unwrap().kind == ATTR_ATTRIBUTE_LIST));
    }
    assert_eq!(relocated, 1);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn rebuild_missing_quota_lookup_from_extension_controls_preserving_limits() {
    let mut f = Fixture::new();
    f.metadata(24, "$Quota");
    let mut defaults = vec![0; 48];
    e::p32(&mut defaults, 0, 2).unwrap();
    let mut control = vec![0; 64];
    e::p32(&mut control, 0, 2).unwrap();
    e::p64(&mut control, 24, 123456).unwrap();
    e::p64(&mut control, 32, 654321).unwrap();
    control[48..60].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]);
    let rows = vec![
        semantic::view_entry(&1_u32.to_le_bytes(), &defaults).unwrap(),
        semantic::view_entry(&256_u32.to_le_bytes(), &control).unwrap(),
    ];
    f.root(25, b"$\0Q\0", 16, &rows);
    f.family(24, 25);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    quota_repairs(&f.path, f.boot, &mut plan).unwrap();
    let q = f.view(&plan, 24, b"$\0Q\0", 16);
    assert_eq!(q, rows);
    let o = f.view(&plan, 24, b"$\0O\0", 17);
    assert_eq!(o.len(), 1);
    assert_eq!(&o[0][16..28], &control[48..60]);
    assert_eq!(u32_at(&o[0], ntfs_rs::bytes::u16_at(&o[0], 0).unwrap() as usize).unwrap(), 256);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
    let count = plan.iter().count();
    quota_repairs(&f.path, f.boot, &mut plan).unwrap();
    assert_eq!(plan.iter().count(), count);
}

#[test]
fn rebuild_object_lookup_from_extension_and_allocate_index_pages() {
    let mut f = Fixture::new();
    f.metadata(24, "$ObjId");
    f.root(25, b"$\0O\0", 19, &[]);
    f.family(24, 25);
    for n in 26..45 {
        f.active(n);
        let mut id = vec![0; 16];
        e::p32(&mut id, 0, n as u32).unwrap();
        f.resident(n, 0x40, &[], &id);
    }
    // Identity lives in an extension, while the base has no OBJECT_ID.
    // One identity per family: remove the old base's identity before listing it.
    let at = e::require(&f.records[43], 0x40, &[]).unwrap();
    e::remove(&mut f.records[43], at).unwrap();
    f.resident(43, 0x10, &[], &[0; 72]);
    f.family(43, 44);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    object_id_repairs(&f.path, f.boot, &mut plan, checker::consistency::IndexCheck::Full).unwrap();
    let rows = f.view(&plan, 24, b"$\0O\0", 19);
    assert_eq!(rows.len(), 18);
    assert!(MftRecord::from_decoded(&f.logical(&plan, 24))
        .unwrap()
        .local_attribute(0xa0, b"$\0O\0")
        .unwrap()
        .is_some());
    let last = rows.last().unwrap();
    let at = ntfs_rs::bytes::u16_at(last, 0).unwrap() as usize;
    assert_eq!(u64_at(last, at).unwrap(), (1_u64 << 48) | 43);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
    let count = plan.iter().count();
    object_id_repairs(&f.path, f.boot, &mut plan, checker::consistency::IndexCheck::Full).unwrap();
    assert_eq!(plan.iter().count(), count);
}

#[test]
fn restore_missing_object_attributes_from_unique_live_lookup() {
    let mut f = Fixture::new();
    f.metadata(24, "$ObjId");
    let mut rows = Vec::new();
    for n in 26..29 {
        f.active(n);
        let mut id = [0; 16];
        e::p32(&mut id, 0, n as u32).unwrap();
        rows.push(
            semantic::view_entry(&id, &{
                let mut payload = ((1_u64 << 48) | n as u64).to_le_bytes().to_vec();
                payload.extend_from_slice(&[n as u8; 48]);
                payload
            })
            .unwrap(),
        );
    }
    f.root(24, b"$\0O\0", 19, &rows);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    object_id_repairs(&f.path, f.boot, &mut plan, checker::consistency::IndexCheck::Full).unwrap();
    for n in 26..29 {
        let raw = f.logical(&plan, n);
        let record = MftRecord::from_decoded(&raw).unwrap();
        assert_eq!(
            u32_at(record.local_attribute(0x40, &[]).unwrap().unwrap().resident_value().unwrap(), 0).unwrap(),
            n as u32
        );
    }
    let repaired = f.view(&plan, 24, b"$\0O\0", 19);
    assert_eq!(repaired.len(), rows.len());
    for (old, new) in rows.iter().zip(&repaired) {
        assert_eq!(&old[16..88], &new[16..88]);
        assert_eq!(ntfs_rs::bytes::u16_at(new, 2).unwrap(), 56);
    }
    for n in 26..29 {
        let raw = f.logical(&plan, n);
        let record = MftRecord::from_decoded(&raw).unwrap();
        assert_eq!(record.local_attribute(0x40, &[]).unwrap().unwrap().resident_value().unwrap().len(), 16);
    }
}

#[test]
fn exhausted_mft_repack_moves_crowded_metadata_to_new_slots() {
    let mut f = Fixture::new();
    for n in 16..64 {
        f.active(n);
    }
    f.resident(0, 0xe0, &[], &[0x5a; 744]);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    growth::repack(&f.path, f.boot, &mut plan).unwrap();
    let logical = f.logical(&plan, 0);
    let record = MftRecord::from_decoded(&logical).unwrap();
    assert_eq!(record.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap(), 128 * 1024);
    assert_eq!(record.local_attribute(0xe0, &[]).unwrap().unwrap().resident_value().unwrap(), &[0x5a; 744]);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
    let mut volume =
        Volume::new(PlannedImage { image: Image(File::open(&f.path).unwrap()), patches: &plan }, f.boot).unwrap();
    let mut raw = vec![0; 1024];
    volume.read_mft_record(&record, 64, &mut raw).unwrap();
    let extension = MftRecord::parse(&mut raw, 512).unwrap();
    assert_eq!(extension.base_file_reference().unwrap(), 1_u64 << 48);
}

#[test]
fn reserved_bitmap_crosslink_is_reconstructed_without_copying_log_bytes() {
    let mut f = Fixture::new();
    let at = e::require(&f.records[6], ATTR_DATA, &[]).unwrap();
    e::remove(&mut f.records[6], at).unwrap();
    f.nonresident(6, ATTR_DATA, &[], 25, 1, 16);
    f.active(2);
    f.nonresident(2, ATTR_DATA, &[], 25, 1, 4096);
    f.image[25 * 4096..26 * 4096].fill(0xa5);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    crosslink_repairs(&f.path, f.boot, &mut plan, None).unwrap();
    let logical = f.logical(&plan, 6);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let bitmap = record.stream(ATTR_DATA, &[]).unwrap();
    let run = ntfs_rs::runlist::DataRuns::new(bitmap.data_runs().unwrap(), 0).next().unwrap().unwrap();
    assert_ne!(run.lcn, Some(25));
    let mut volume =
        Volume::new(PlannedImage { image: Image(File::open(&f.path).unwrap()), patches: &plan }, f.boot).unwrap();
    let mut bits = [0; 16];
    volume.read_attribute(bitmap, 0, &mut bits).unwrap();
    assert_ne!(bits[25 / 8] & (1 << (25 % 8)), 0);
    assert_eq!(bits[60 / 8] & (1 << (60 % 8)), 0);
    let mut source = vec![0; 4096];
    volume.read_physical(25 * 4096, &mut source).unwrap();
    assert_eq!(source, vec![0xa5; 4096]);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn quota_totals_count_file_charges_once_and_preserve_custom_limits() {
    let mut f = Fixture::new();
    f.metadata(24, "$Quota");
    f.active(26);
    f.active(27);
    for n in [0, 6, 11, 24, 26, 27] {
        let mut si = [0; 72];
        if n >= 26 {
            e::p32(&mut si, 48, 256).unwrap();
            e::p64(&mut si, 56, 100 * n as u64).unwrap();
        }
        f.resident(n, 0x10, &[], &si);
    }
    let mut defaults = vec![0; 48];
    e::p32(&mut defaults, 0, 2).unwrap();
    let mut control = vec![0; 64];
    e::p32(&mut control, 0, 2).unwrap();
    e::p64(&mut control, 8, 9999).unwrap();
    e::p64(&mut control, 32, 99999).unwrap();
    control[48..60].copy_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]);
    let rows = vec![
        semantic::view_entry(&1_u32.to_le_bytes(), &defaults).unwrap(),
        semantic::view_entry(&256_u32.to_le_bytes(), &control).unwrap(),
    ];
    f.root(24, b"$\0Q\0", 16, &rows);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    quota_repairs(&f.path, f.boot, &mut plan).unwrap();
    let rows = f.view(&plan, 24, b"$\0Q\0", 16);
    let at = ntfs_rs::bytes::u16_at(&rows[1], 0).unwrap() as usize;
    assert_eq!(u64_at(&rows[1], at + 8).unwrap(), 5300);
    assert_eq!(u64_at(&rows[1], at + 32).unwrap(), 99999);
}

#[test]
fn usn_external_max_is_reset_without_changing_history() {
    let mut f = Fixture::new();
    f.metadata(24, "$UsnJrnl");
    f.nonresident(24, ATTR_DATA, b"$\0J\0", 32, 1, 64);
    f.nonresident(25, ATTR_DATA, b"$\0M\0a\0x\0", 33, 1, 32);
    f.family(24, 25);
    e::p32(&mut f.image, 32 * 4096, 64).unwrap();
    e::p16(&mut f.image, 32 * 4096 + 4, 2).unwrap();
    e::p64(&mut f.image, 32 * 4096 + 24, 123).unwrap();
    e::p64(&mut f.image, 33 * 4096, 4096).unwrap();
    e::p64(&mut f.image, 33 * 4096 + 8, 4096).unwrap();
    e::p64(&mut f.image, 33 * 4096 + 16, 7).unwrap();
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    usn_repairs(&f.path, f.boot, &mut plan).unwrap();
    let logical = f.logical(&plan, 24);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let max = record.local_attribute(ATTR_DATA, b"$\0M\0a\0x\0").unwrap().unwrap().resident_value().unwrap();
    assert_eq!(u64_at(max, 16).unwrap(), 8);
    assert_eq!(u64_at(max, 24).unwrap(), 64);
    let mut old = f.image[32 * 4096..33 * 4096].to_vec();
    plan.overlay(32 * 4096, &mut old).unwrap();
    assert_eq!(old, f.image[32 * 4096..33 * 4096]);
    let count = plan.len();
    usn_repairs(&f.path, f.boot, &mut plan).unwrap();
    assert_eq!(plan.len(), count);
}

#[test]
fn overlapping_stages_preserve_original_bytes_and_check_preimages() {
    let mut plan = RepairPlan::new(4096).unwrap();
    plan.push(Patch::new(0, vec![1; 1024], vec![2; 1024])).unwrap();
    plan.compose(Patch::new(10, vec![2; 2], vec![3; 2])).unwrap();
    let saved = plan.get(0).unwrap();
    assert_eq!(saved.before, vec![1; 1024]);
    assert_eq!(&saved.after[10..12], &[3, 3]);
    assert!(plan.compose(Patch::new(9, vec![2; 4], vec![4; 4])).is_err());
    assert_eq!(plan.get(0).unwrap(), saved);
}

#[test]
fn growth_rebuilds_a_split_mft_bitmap_from_validated_extents() {
    let mut f = Fixture::new();
    let at = e::require(&f.records[0], ATTR_BITMAP, &[]).unwrap();
    e::set_sizes(&mut f.records[0], at, 8192, 8192, 8192).unwrap();
    f.nonresident(25, ATTR_BITMAP, &[], 26, 1, 0);
    let at = e::require(&f.records[25], ATTR_BITMAP, &[]).unwrap();
    e::p64(&mut f.records[25], at + 16, 1).unwrap();
    e::p64(&mut f.records[25], at + 24, 1).unwrap();
    f.family(0, 25);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    repair_mft_growth(&f.path, f.boot, &mut plan).unwrap();
    let raw = f.logical(&plan, 0);
    let record = MftRecord::from_decoded(&raw).unwrap();
    assert_eq!(record.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap(), 128 * 1024);
    assert_eq!(record.stream(ATTR_BITMAP, &[]).unwrap().data_size().unwrap(), 8192);
}

#[test]
fn growth_externalizes_a_resident_mft_bitmap() {
    let mut f = Fixture::new();
    let at = e::require(&f.records[0], ATTR_BITMAP, &[]).unwrap();
    e::remove(&mut f.records[0], at).unwrap();
    f.resident(0, ATTR_BITMAP, &[], &[0x41, 8, 0, 0, 0, 0, 0, 0]);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    repair_mft_growth(&f.path, f.boot, &mut plan).unwrap();
    let raw = f.logical(&plan, 0);
    let record = MftRecord::from_decoded(&raw).unwrap();
    assert!(record.stream(ATTR_BITMAP, &[]).unwrap().nonresident);
    assert_eq!(record.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap(), 128 * 1024);
}

#[test]
fn fragmented_mft_repack_uses_reachable_reserved_extent_slots() {
    let mut f = Fixture::new();
    f.boot.total_sectors = 8192;
    f.image.resize(4 * 1024 * 1024, 0);
    // The enlarged fixture needs one allocation bit for every cluster;
    // metadata growth must not allocate through a truncated volume bitmap.
    let at = e::require(&f.records[6], ATTR_DATA, &[]).unwrap();
    let mut allocation = [0_u8; 128];
    allocation[..4].fill(255);
    for lcn in (32..592).step_by(2) {
        allocation[lcn / 8] |= 1 << (lcn % 8);
    }
    e::set_resident_value(&mut f.records[6], at, &allocation).unwrap();
    let at = e::require(&f.records[0], ATTR_DATA, &[]).unwrap();
    e::set_sizes(&mut f.records[0], at, 296 * 4096, 65536, 65536).unwrap();
    let runs: Vec<_> = (0..280).map(|i| Extent { vcn: i, lcn: Some(32 + i * 2), len: 1 }).collect();
    let mut attribute = vec![0; 1024];
    let n = e::build_nonresident(ATTR_DATA, &[], &runs, 0, 0, 0, &mut attribute).unwrap();
    e::p64(&mut attribute, 16, 16).unwrap();
    e::p64(&mut attribute, 24, 295).unwrap();
    e::insert(&mut f.records[25], &attribute[..n]).unwrap();
    // Crowding forces the unrelated attribute into the old extension and a
    // DATA continuation into a reserved MFT expansion slot.
    f.resident(0, 0xe0, &[], &[0x5a; 608]);
    f.family(0, 25);
    f.save();
    f.image[24 * 4096 + 2] = 255;
    std::fs::write(&f.path, &f.image).unwrap();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    growth::repack(&f.path, f.boot, &mut plan).unwrap();
    let raw = f.logical(&plan, 0);
    let record = MftRecord::from_decoded(&raw).unwrap();
    assert_eq!(record.stream(ATTR_DATA, &[]).unwrap().initialized_size().unwrap(), 128 * 1024);
    assert_eq!(record.local_attribute(0xe0, &[]).unwrap().unwrap().resident_value().unwrap(), &[0x5a; 608]);
    let runs = ntfs_rs::runlist::DataRuns::new(record.stream(ATTR_DATA, &[]).unwrap().data_runs().unwrap(), 0)
        .collect::<ntfs_rs::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(runs.len(), 281);
    let mut volume =
        Volume::new(PlannedImage { image: Image(File::open(&f.path).unwrap()), patches: &plan }, f.boot).unwrap();
    let mut extension = vec![0; 1024];
    volume.read_mft_record(&record, 16, &mut extension).unwrap();
    let extension = MftRecord::parse(&mut extension, 512).unwrap();
    assert_eq!(extension.base_file_reference().unwrap(), 1_u64 << 48);
    assert!(extension.attributes().any(|a| a.is_ok_and(|a| a.kind == ATTR_DATA)));
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn log_size_query_resolves_split_stream_without_changing_source() {
    let mut f = Fixture::new();
    f.active(2);
    f.nonresident(2, ATTR_DATA, &[], 30, 1, 4096);
    let at = e::require(&f.records[2], ATTR_DATA, &[]).unwrap();
    e::set_sizes(&mut f.records[2], at, 8192, 8192, 6144).unwrap();
    f.nonresident(25, ATTR_DATA, &[], 34, 1, 0);
    let at = e::require(&f.records[25], ATTR_DATA, &[]).unwrap();
    e::p64(&mut f.records[25], at + 16, 1).unwrap();
    e::p64(&mut f.records[25], at + 24, 1).unwrap();
    e::set_sizes(&mut f.records[25], at, 0, 0, 0).unwrap();
    f.family(2, 25);
    f.save();
    let size = checker::inspect_logfile_size(checker::Image::open(&f.path).unwrap(), f.boot).unwrap();
    assert_eq!(
        size,
        checker::LogFileSize {
            data_bytes: 8192,
            allocated_bytes: 8192,
            initialized_bytes: 6144,
            default_bytes: 2 * 1024 * 1024,
        }
    );
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
    // The attribute-list sequence must match before stream sizes are trusted.
    e::p16(&mut f.records[25], 16, 2).unwrap();
    f.save();
    assert!(checker::inspect_logfile_size(checker::Image::open(&f.path).unwrap(), f.boot).is_err());
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn log_size_query_rejects_missing_and_inactive_streams() {
    let mut f = Fixture::new();
    f.active(2);
    f.save();
    assert!(checker::inspect_logfile_size(checker::Image::open(&f.path).unwrap(), f.boot).is_err());
    f.nonresident(2, ATTR_DATA, &[], 30, 1, 4096);
    e::p16(&mut f.records[2], 22, 0).unwrap();
    f.save();
    assert!(checker::inspect_logfile_size(checker::Image::open(&f.path).unwrap(), f.boot).is_err());
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn missing_parent_groups_count_objects_and_exclude_valid_or_unbounded_claims() {
    use checker::consistency::{inventory_next, DiskInventory};
    let live = (1_u64 << 48) | 11;
    let mut directories = DiskInventory::new();
    directories.push([live, 0, 0, 0]).unwrap();
    let mut directories = directories.finish().unwrap();
    let mut claims = DiskInventory::new();
    for (reference, owner, parent) in [
        (24, 24, (1_u64 << 48) | 63),
        (24, 25, (2_u64 << 48) | 63),
        (26, 26, (3_u64 << 48) | 63),
        (27, 27, (1_u64 << 48) | 62),
        (28, 28, (1_u64 << 48) | 62),
        (28, 28, live),
        (29, 29, (1_u64 << 48) | 61),
        (29, 29, (1_u64 << 48) | 61),
        (30, 30, (1_u64 << 48) | 64),
        (31, 31, (1_u64 << 48) | 64),
        (32, 32, (1_u64 << 48) | (1_u64 << 32) | 60),
        (33, 33, (1_u64 << 48) | (1_u64 << 32) | 60),
    ] {
        claims.push([reference, owner, parent, 0]).unwrap();
    }
    let mut claims = claims.finish().unwrap();
    let mut groups = missing_parent_groups(&mut claims, &mut directories, 64).unwrap();
    assert_eq!(inventory_next(&mut groups).unwrap(), Some([63, 24, 0, 0]));
    assert_eq!(inventory_next(&mut groups).unwrap(), Some([63, 26, 0, 0]));
    assert_eq!(inventory_next(&mut groups).unwrap(), None);
}

#[test]
fn overlapping_missing_parents_consume_the_first_group_before_recounting() {
    use checker::consistency::{inventory_next, DiskInventory};
    let mut directories = DiskInventory::new().finish().unwrap();
    let mut claims = DiskInventory::new();
    for (reference, parent) in [(24, 62), (24, 63), (25, 62), (26, 63)] {
        claims.push([reference, reference, (1_u64 << 48) | parent, 0]).unwrap();
    }
    let mut claims = claims.finish().unwrap();
    let mut groups = missing_parent_groups(&mut claims, &mut directories, 64).unwrap();
    assert_eq!(inventory_next(&mut groups).unwrap(), Some([62, 24, 0, 0]));
    assert_eq!(inventory_next(&mut groups).unwrap(), Some([62, 25, 0, 0]));
    assert_eq!(inventory_next(&mut groups).unwrap(), None);
}

#[test]
fn grouped_reconnection_preserves_aliases_and_other_family_attributes() {
    let mut f = Fixture::new();
    for (number, name, namespace, sequence) in [(24, "Long filename", 1, 1), (25, "LONGFI~1", 2, 2)] {
        f.metadata(number, name);
        let at = e::require(&f.records[number], 0x30, &[]).unwrap();
        let start = at + usize::from(ntfs_rs::bytes::u16_at(&f.records[number], at + 20).unwrap());
        e::p64(&mut f.records[number], start, (sequence << 48) | 63).unwrap();
        f.records[number][start + 65] = namespace;
    }
    f.resident(24, 0x10, &[], &[0x5a; 72]);
    f.resident(24, ATTR_DATA, &[], &[0x42; 32]);
    f.resident(25, 0x40, &[], &[0x39; 16]);
    f.family(24, 25);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    let mut directories = checker::consistency::DiskInventory::new().finish().unwrap();
    let parent = (1_u64 << 48) | 11;
    reconnect_orphan(
        &f.path,
        f.boot,
        &mut plan,
        (1_u64 << 48) | 24,
        &mut directories,
        None,
        Some((63, parent)),
        &mut None,
    )
    .unwrap();
    let logical = f.logical(&plan, 24);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let names = record
        .attributes()
        .filter_map(|attribute| {
            let attribute = attribute.unwrap();
            (attribute.kind == 0x30).then(|| attribute.resident_value().unwrap())
        })
        .collect::<Vec<_>>();
    assert_eq!(names.len(), 2);
    let mut namespaces = names.iter().map(|value| value[65]).collect::<Vec<_>>();
    namespaces.sort_unstable();
    assert_eq!(namespaces, [1, 2]);
    for value in names {
        assert_eq!(u64_at(value, 0).unwrap(), parent);
        let expected = if value[65] == 1 { "Long filename" } else { "LONGFI~1" };
        assert_eq!(value[66..], expected.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    }
    for (kind, expected) in [(0x10, vec![0x5a; 72]), (ATTR_DATA, vec![0x42; 32]), (0x40, vec![0x39; 16])] {
        assert_eq!(record.local_attribute(kind, &[]).unwrap().unwrap().resident_value().unwrap(), expected);
    }
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn colliding_extension_claim_removal_preserves_alias_and_family_metadata() {
    let mut f = Fixture::new();
    for (number, name, namespace) in [(24, "SURVIV~1", 2), (25, "colliding.txt", 1)] {
        f.metadata(number, name);
        let at = e::require(&f.records[number], 0x30, &[]).unwrap();
        let value_at = at + usize::from(ntfs_rs::bytes::u16_at(&f.records[number], at + 20).unwrap());
        f.records[number][value_at + 65] = namespace;
    }
    let removed = MftRecord::from_decoded(&f.records[25]).unwrap().local_attribute(0x30, &[]).unwrap().unwrap().id;
    f.resident(24, 0x10, &[], &[0x5a; 72]);
    f.resident(24, ATTR_DATA, &[], &[0x42; 32]);
    f.resident(25, 0x40, &[], &[0x39; 16]);
    f.family(24, 25);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    remove_colliding_filename(&f.path, f.boot, &mut plan, (1u64 << 48) | 24, (1u64 << 48) | 25, removed).unwrap();
    let logical = f.logical(&plan, 24);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let filename = record.local_attribute(0x30, &[]).unwrap().unwrap();
    let value = filename.resident_value().unwrap();
    assert_eq!(value[65], 0);
    assert_eq!(u64_at(value, 0).unwrap(), (1u64 << 48) | 11);
    assert_eq!(&value[66..], &"SURVIV~1".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    assert_eq!(record.attributes().filter(|attr| attr.as_ref().unwrap().kind == 0x30).count(), 1);
    for (kind, expected) in [(0x10, vec![0x5a; 72]), (ATTR_DATA, vec![0x42; 32]), (0x40, vec![0x39; 16])] {
        assert_eq!(record.local_attribute(kind, &[]).unwrap().unwrap().resident_value().unwrap(), expected);
    }
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn recovery_directory_ordinals_include_groups_and_fallback_names() {
    let mut f = Fixture::new();
    f.metadata(24, "dir0012.chk");
    f.metadata(25, "D0000000_dir.chk");
    f.metadata(26, "F0000000-payload");
    f.save();
    let mut volume = Volume::new(Image(File::open(&f.path).unwrap()), f.boot).unwrap();
    let logical = checker::consistency::mft_image(&mut volume).unwrap();
    let mft = MftRecord::from_decoded(&logical).unwrap();
    let parent = (1_u64 << 48) | 11;
    assert_eq!(metadata::next_recovery_ordinal(&mut volume, &mft, parent, true).unwrap(), 14);
    assert_eq!(metadata::next_recovery_ordinal(&mut volume, &mft, parent, false).unwrap(), 16);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn orphan_reconnection_normalizes_a_single_surviving_alias_across_a_family() {
    for namespace in [1, 2] {
        let mut f = Fixture::new();
        f.metadata(24, "surviving-name");
        let at = e::require(&f.records[24], 0x30, &[]).unwrap();
        let value_at = at + usize::from(ntfs_rs::bytes::u16_at(&f.records[24], at + 20).unwrap());
        f.records[24][value_at + 65] = namespace;
        f.metadata(25, "damaged-partner");
        let at = e::require(&f.records[25], 0x30, &[]).unwrap();
        let value_at = at + usize::from(ntfs_rs::bytes::u16_at(&f.records[25], at + 20).unwrap());
        e::p64(&mut f.records[25], value_at, (1_u64 << 48) | 63).unwrap();
        f.records[25][value_at + 65] = 3 - namespace;
        f.resident(24, 0x10, &[], &[0x5a; 72]);
        f.resident(24, ATTR_DATA, &[], &[0x42; 32]);
        f.resident(25, 0x40, &[], &[0x39; 16]);
        f.family(24, 25);
        f.save();
        let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
        let mut inventory = checker::consistency::DiskInventory::new();
        inventory.push([(1_u64 << 48) | 11, 0, 0, 0]).unwrap();
        let mut directories = inventory.finish().unwrap();
        reconnect_orphan(&f.path, f.boot, &mut plan, (1_u64 << 48) | 24, &mut directories, None, None, &mut None)
            .unwrap();
        let logical = f.logical(&plan, 24);
        let record = MftRecord::from_decoded(&logical).unwrap();
        let names = record
            .attributes()
            .filter_map(|a| {
                let a = a.unwrap();
                (a.kind == 0x30).then(|| a.resident_value().unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0][65], 0);
        assert_eq!(u64_at(names[0], 0).unwrap(), (1_u64 << 48) | 11);
        assert_eq!(names[0][66..], "surviving-name".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
        for (kind, expected) in [(0x10, vec![0x5a; 72]), (ATTR_DATA, vec![0x42; 32]), (0x40, vec![0x39; 16])] {
            assert_eq!(record.local_attribute(kind, &[]).unwrap().unwrap().resident_value().unwrap(), expected);
        }
        assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
    }
}

#[test]
fn directory_alias_reconnection_keeps_valid_parent_and_extension_metadata() {
    let mut f = Fixture::new();
    f.active(5);
    e::p16(&mut f.records[5], 22, 3).unwrap();
    f.metadata(24, "LongName");
    e::p16(&mut f.records[24], 22, 3).unwrap();
    f.metadata(25, "SHORT~1");
    let at = e::require(&f.records[25], 0x30, &[]).unwrap();
    let value_at = at + usize::from(ntfs_rs::bytes::u16_at(&f.records[25], at + 20).unwrap());
    e::p64(&mut f.records[25], value_at, (1u64 << 48) | 5).unwrap();
    f.records[25][value_at + 65] = 2;

    f.resident(24, 0x10, &[], &[0x5a; 72]);
    f.resident(25, 0x40, &[], &[0x39; 16]);
    f.family(24, 25);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    let reference = (1_u64 << 48) | 24;
    let parent = (1_u64 << 48) | 11;
    reconnect_directory(&f.path, f.boot, &mut plan, reference).unwrap();
    let logical = f.logical(&plan, 24);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let mut names = Vec::new();
    for attribute in record.attributes() {
        let attribute = attribute.unwrap();
        if attribute.kind != 0x30 {
            continue;
        }
        let value = attribute.resident_value().unwrap();
        assert_eq!(u64_at(value, 0).unwrap(), parent);
        assert_eq!(value[65], 0);
        names.push(value[66..].to_vec());
    }
    assert_eq!(names.len(), 1);
    assert!(names.contains(&"LongName".encode_utf16().flat_map(u16::to_le_bytes).collect()));
    assert_eq!(record.local_attribute(0x10, &[]).unwrap().unwrap().resident_value().unwrap(), &[0x5a; 72]);
    assert_eq!(record.local_attribute(0x40, &[]).unwrap().unwrap().resident_value().unwrap(), &[0x39; 16]);
    let count = plan.len();
    reconnect_directory(&f.path, f.boot, &mut plan, reference).unwrap();
    assert_eq!(plan.len(), count);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn directory_reconnection_rejects_truncated_alias_before_publishing_patches() {
    let mut f = Fixture::new();
    f.metadata(24, "valid");
    e::p16(&mut f.records[24], 22, 3).unwrap();
    f.active(25);
    f.resident(25, 0x30, &[], &[0; 16]);
    f.family(24, 25);
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    assert!(reconnect_directory(&f.path, f.boot, &mut plan, (1_u64 << 48) | 24,).is_err());
    assert_eq!(plan.len(), 0);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn directory_type_authority_requires_a_framed_named_root() {
    let mut fixture = Fixture::new();
    let i30 = ntfs_rs::index_tree::I30;
    e::p16(&mut fixture.records[36], 22, 3).unwrap();
    let record = MftRecord::from_decoded(&fixture.records[36]).unwrap();
    assert_eq!(metadata::filename_directory_type(&record).unwrap(), Some(false));

    fixture.root(36, i30, 1, &[]);
    e::p16(&mut fixture.records[36], 22, 1).unwrap();
    let record = MftRecord::from_decoded(&fixture.records[36]).unwrap();
    assert_eq!(metadata::filename_directory_type(&record).unwrap(), Some(true));

    let at = e::require(&fixture.records[36], 0x90, i30).unwrap();
    let value = at + usize::from(ntfs_rs::bytes::u16_at(&fixture.records[36], at + 20).unwrap());
    e::p32(&mut fixture.records[36], value, 0).unwrap();
    let record = MftRecord::from_decoded(&fixture.records[36]).unwrap();
    assert_eq!(metadata::filename_directory_type(&record).unwrap(), None);

    let at = e::require(&fixture.records[36], 0x90, i30).unwrap();
    e::remove(&mut fixture.records[36], at).unwrap();
    fixture.nonresident(36, 0x90, i30, 32, 1, 48);
    let record = MftRecord::from_decoded(&fixture.records[36]).unwrap();
    assert_eq!(metadata::filename_directory_type(&record).unwrap(), None);
}

#[test]
fn root_filename_repair_preserves_index_and_extension_metadata() {
    const I30: &[u8] = b"$\0I\x003\x000\0";
    let reference = (1u64 << 48) | 5;
    for (conventional, resident_flags) in [(false, 1), (true, 0), (true, 1), (true, 3)] {
        let mut f = Fixture::new();
        f.metadata(5, ".");
        e::p16(&mut f.records[5], 22, 3).unwrap();
        if conventional {
            let at = e::require(&f.records[5], 0x30, &[]).unwrap();
            let offset = at + usize::from(ntfs_rs::bytes::u16_at(&f.records[5], at + 20).unwrap());
            e::p64(&mut f.records[5], offset, reference).unwrap();
            f.records[5][offset + 65] = 3;
            f.records[5][at + 22] = resident_flags;
        }
        f.resident(5, 0x10, &[], &[0x5a; 72]);
        f.root(5, I30, 1, &[]);
        let index = MftRecord::from_decoded(&f.records[5])
            .unwrap()
            .local_attribute(0x90, I30)
            .unwrap()
            .unwrap()
            .resident_value()
            .unwrap()
            .to_vec();
        f.metadata(24, "external-root-claim");
        f.resident(24, 0x40, &[], &[0x39; 16]);
        f.family(5, 24);
        f.save();
        let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
        repair_system_filename(&f.path, f.boot, &mut plan, reference, ".", reference).unwrap();
        let logical = f.logical(&plan, 5);
        let record = MftRecord::from_decoded(&logical).unwrap();
        let names = record
            .attributes()
            .filter_map(|attribute| {
                let attribute = attribute.unwrap();
                (attribute.kind == 0x30).then(|| attribute.resident_value().unwrap())
            })
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 1);
        assert!(metadata::root_filename_valid(&record, reference).unwrap());
        let attribute = record.local_attribute(0x30, &[]).unwrap().unwrap();
        assert_eq!(
            attribute.resident_flags().unwrap(),
            if conventional && resident_flags & 1 != 0 { resident_flags } else { 1 },
        );
        assert_eq!(u64_at(names[0], 0).unwrap(), reference);
        assert_eq!(names[0][65], 3);
        assert_eq!(&names[0][66..], &[b'.', 0]);
        for (kind, name, expected) in
            [(0x10, &[][..], &[0x5a; 72][..]), (0x40, &[][..], &[0x39; 16][..]), (0x90, I30, &index[..])]
        {
            assert_eq!(record.local_attribute(kind, name).unwrap().unwrap().resident_value().unwrap(), expected,);
        }
        let count = plan.len();
        repair_system_filename(&f.path, f.boot, &mut plan, reference, ".", reference).unwrap();
        assert_eq!(plan.len(), count);
        assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
    }
}

#[test]
fn directory_parent_walk_accepts_dags_and_checks_every_parent_edge() {
    let reference = |number| (1u64 << 48) | number;
    for (sequence, cyclic) in [(1u64, false), (1, true), (2, false), (2, true)] {
        let reference = |number| {
            let sequence = if number == 24 { sequence } else { 1 };
            (sequence << 48) | number
        };
        let mut directories = checker::consistency::DiskInventory::new();
        for number in [5, 24, 25] {
            directories.push([reference(number), 0, 0, 0]).unwrap();
        }
        let mut parents = checker::consistency::DiskInventory::new();
        for (child, parent) in [(24, 5), (24, 25), (25, 5)] {
            parents.push([reference(child), reference(parent), 0, 0]).unwrap();
        }
        if cyclic {
            parents.push([reference(25), reference(24), 0, 0]).unwrap();
        }
        let mut changed = checker::consistency::scratch_file().unwrap();
        let cycle = directory_parent_cycle(
            &mut directories.finish().unwrap(),
            &mut parents.finish().unwrap(),
            64,
            &mut changed,
        )
        .unwrap();
        assert_eq!(cycle, cyclic.then_some((reference(24), reference(25))));
        for number in [24, 25] {
            assert_eq!(
                checker::consistency::audit_slot(&mut changed, number, None).unwrap(),
                cyclic.then_some(reference(number)),
            );
        }
        assert_eq!(checker::consistency::audit_slot(&mut changed, 5, None).unwrap(), None,);
    }
    let mut directories = checker::consistency::DiskInventory::new();
    directories.push([reference(24), 0, 0, 0]).unwrap();
    let mut parents = checker::consistency::DiskInventory::new();
    parents.push([reference(24), reference(64), 0, 0]).unwrap();
    assert!(directory_parent_cycle(
        &mut directories.finish().unwrap(),
        &mut parents.finish().unwrap(),
        64,
        &mut checker::consistency::scratch_file().unwrap(),
    )
    .is_err());
}

#[test]
fn directory_cycle_repair_reconnects_through_a_recovery_folder() {
    const I30: &[u8] = b"$\0I\x003\x000\0";
    let mut f = Fixture::new();
    f.active(5);
    e::p16(&mut f.records[5], 22, 3).unwrap();
    let mut standard = [0; 72];
    standard[52..56].copy_from_slice(&256u32.to_le_bytes());
    f.resident(5, 0x10, &[], &standard);
    f.root(5, I30, 1, &[]);
    f.root(11, I30, 1, &[]);
    f.active(10);
    f.nonresident(10, ATTR_DATA, &[], 40, 32, 131072);
    for unit in 0..=u16::MAX {
        let folded = if (97..=122).contains(&unit) { unit - 32 } else { unit };
        let offset = 40 * 4096 + usize::from(unit) * 2;
        f.image[offset..offset + 2].copy_from_slice(&folded.to_le_bytes());
    }
    for (number, parent, name) in [(24, 25, "A"), (25, 24, "B")] {
        f.metadata(number, name);
        f.resident(number, 0x10, &[], &standard);
        e::p16(&mut f.records[number], 22, 3).unwrap();
        let at = e::require(&f.records[number], 0x30, &[]).unwrap();
        let attr = MftRecord::from_decoded(&f.records[number]).unwrap().local_attribute(0x30, &[]).unwrap().unwrap();
        let mut value = attr.resident_value().unwrap().to_vec();
        e::p64(&mut value, 0, (1_u64 << 48) | parent).unwrap();
        e::set_resident_value(&mut f.records[number], at, &value).unwrap();
        f.root(number, I30, 1, &[]);
    }
    f.save();
    let mut plan = RepairPlan::new(f.image.len() as u64).unwrap();
    directory_repairs(&f.path, f.boot, &mut plan).unwrap();
    let mut repeated = RepairPlan::new(f.image.len() as u64).unwrap();
    repeated.recovery_created = plan.recovery_created;
    directory_repairs(&f.path, f.boot, &mut repeated).unwrap();
    assert!(plan.matches(&repeated).unwrap());
    let mut independently_created = RepairPlan::new(f.image.len() as u64).unwrap();
    independently_created.recovery_created = plan.recovery_created + 1;
    directory_repairs(&f.path, f.boot, &mut independently_created).unwrap();
    assert!(!plan.matches(&independently_created).unwrap());

    let logical = f.logical(&plan, 24);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let value = record.local_attribute(0x30, &[]).unwrap().unwrap().resident_value().unwrap();
    let folder_reference = u64_at(value, 0).unwrap();
    let folder_number = folder_reference & 0xffff_ffff_ffff;
    assert_eq!(&value[66..], &"00000000_dir.chk".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    assert_eq!(value[65], 0);
    let folder = f.logical(&plan, folder_number);
    let folder = MftRecord::from_decoded(&folder).unwrap();
    assert_eq!(folder.flags().unwrap(), 3);

    let created = folder.local_attribute(0x10, &[]).unwrap().unwrap().resident_value().unwrap();
    let timestamp = u64_at(created, 0).unwrap();
    assert!(timestamp > 0);
    for offset in [8, 16, 24] {
        assert_eq!(u64_at(created, offset).unwrap(), timestamp);
    }
    assert_eq!(u32_at(created, 32).unwrap(), 6);

    let name = folder.local_attribute(0x30, &[]).unwrap().unwrap().resident_value().unwrap();
    assert_eq!(u64_at(name, 0).unwrap(), (1u64 << 48) | 5);
    assert_eq!(&name[66..], &"found.000".encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    assert_eq!(name[65], 3);
    for (number, parent) in [(24, folder_reference), (25, (1u64 << 48) | 24)] {
        let logical = f.logical(&plan, number);
        let record = MftRecord::from_decoded(&logical).unwrap();
        let filename = record.local_attribute(0x30, &[]).unwrap().unwrap();
        assert_eq!(u64_at(filename.resident_value().unwrap(), 0).unwrap(), parent);
        assert_eq!(record.local_attribute(0x10, &[]).unwrap().unwrap().resident_value().unwrap(), &standard,);
    }
    // The repaired root contains its conventional self key and found folder.
    for (number, expected) in [(5, 2), (folder_number, 1), (24, 1), (25, 0)] {
        let logical = f.logical(&plan, number);
        let record = MftRecord::from_decoded(&logical).unwrap();
        let mut volume =
            Volume::new(PlannedImage { image: Image(File::open(&f.path).unwrap()), patches: &plan }, f.boot).unwrap();
        let mut buffer = vec![0; 65536];
        let mut count = 0;
        volume
            .visit_directory(&record, &mut buffer, |_| {
                count += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(count, expected);
    }
    let group = metadata::recovery_subdirectory(&f.path, f.boot, &mut plan, folder_reference, 1).unwrap();
    let logical = f.logical(&plan, group & 0xffff_ffff_ffff);
    let record = MftRecord::from_decoded(&logical).unwrap();
    let standard = record.local_attribute(0x10, &[]).unwrap().unwrap().resident_value().unwrap();
    for offset in [0, 8, 16, 24] {
        assert_eq!(u64_at(standard, offset).unwrap(), timestamp);
    }
    assert_eq!(u32_at(standard, 32).unwrap(), 0);
    assert_eq!(std::fs::read(&f.path).unwrap(), f.image);
}

#[test]
fn default_log_size_tracks_thresholds_rounding_and_cap() {
    let mut boot = Fixture::new().boot;
    for (bytes, expected) in [
        (64 * 1024 * 1024, 2 * 1024 * 1024),
        (200 * 1024 * 1024, 2 * 1024 * 1024),
        (400 * 1024 * 1024, 4 * 1024 * 1024),
        (400 * 1024 * 1024 + 800 * 512, 4 * 1024 * 1024 + 16384),
        (1200 * 1024 * 1024, 5 * 1024 * 1024),
        (50000 * 1024 * 1024, 64 * 1024 * 1024),
    ] {
        boot.total_sectors = bytes / 512;
        assert_eq!(checker::default_logfile_size(boot), expected);
    }
    boot.bytes_per_sector = 4096;
    boot.total_sectors = 400 * 1024 * 1024 / 4096;
    assert_eq!(checker::default_logfile_size(boot), 4 * 1024 * 1024);
    boot.total_sectors = u64::MAX;
    assert_eq!(checker::default_logfile_size(boot), 64 * 1024 * 1024);
}

#[test]
fn quick_object_index_preserves_stale_values_while_full_repairs_them() {
    let mut fixture = Fixture::new();
    fixture.metadata(24, "$ObjId");
    fixture.active(26);
    let identity = [26; 16];
    fixture.resident(26, 0x40, &[], &identity);
    let mut payload = ((1_u64 << 48) | 27).to_le_bytes().to_vec();
    payload.extend_from_slice(&[99; 48]);
    let row = semantic::view_entry(&identity[..16], &payload).unwrap();
    fixture.root(24, b"$\0O\0", 19, &[row]);
    fixture.save();
    let mut quick = RepairPlan::new(fixture.image.len() as u64).unwrap();
    semantic::object_id_repairs(&fixture.path, fixture.boot, &mut quick, checker::consistency::IndexCheck::Quick)
        .unwrap();
    assert!(quick.is_empty());
    let mut full = RepairPlan::new(fixture.image.len() as u64).unwrap();
    object_id_repairs(&fixture.path, fixture.boot, &mut full, checker::consistency::IndexCheck::Full).unwrap();
    assert!(!full.is_empty());
    let rows = fixture.view(&full, 24, b"$\0O\0", 19);
    assert_eq!(u64_at(&rows[0], 32).unwrap(), (1_u64 << 48) | 26);
    assert_eq!(&rows[0][40..88], &[99; 48]);
    assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.image);
}

#[test]
fn object_repair_preserves_invalid_primary_and_conflicting_birth_evidence() {
    for invalid_primary in [true, false] {
        let mut fixture = Fixture::new();
        fixture.metadata(24, "$ObjId");
        fixture.active(26);
        let identity = vec![26; if invalid_primary { 64 } else { 16 }];
        fixture.resident(26, 0x40, &[], &identity);
        let mut rows = Vec::new();
        for birth in [27, 28] {
            let mut payload = ((1_u64 << 48) | 26).to_le_bytes().to_vec();
            payload.extend_from_slice(&[birth; 48]);
            rows.push(semantic::view_entry(&identity[..16], &payload).unwrap());
        }
        fixture.root(24, b"$\0O\0", 19, &rows);
        fixture.save();
        let mut plan = RepairPlan::new(fixture.image.len() as u64).unwrap();
        let error = object_id_repairs(&fixture.path, fixture.boot, &mut plan, checker::consistency::IndexCheck::Full)
            .unwrap_err();
        assert!(error.to_string().contains(if invalid_primary {
            "no trustworthy identity"
        } else {
            "conflicting object-ID birth evidence"
        }));
        assert!(plan.is_empty());
        assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.image);
    }
}

#[test]
fn quick_object_index_reconstructs_malformed_or_missing_roots() {
    for missing in [false, true] {
        let mut fixture = Fixture::new();
        fixture.metadata(24, "$ObjId");
        fixture.active(26);
        let identity = [26; 16];
        fixture.resident(26, 0x40, &[], &identity);
        if !missing {
            let mut payload = ((1_u64 << 48) | 26).to_le_bytes().to_vec();
            payload.extend_from_slice(&[0; 48]);
            let mut row = semantic::view_entry(&identity[..16], &payload).unwrap();
            e::p16(&mut row, 10, 15).unwrap();
            fixture.root(24, b"$\0O\0", 19, &[row]);
        }
        fixture.save();
        let mut plan = RepairPlan::new(fixture.image.len() as u64).unwrap();
        semantic::object_id_repairs(&fixture.path, fixture.boot, &mut plan, checker::consistency::IndexCheck::Quick)
            .unwrap();
        assert!(!plan.is_empty());
        let rows = fixture.view(&plan, 24, b"$\0O\0", 19);
        assert_eq!(rows.len(), 1);
        assert_eq!(ntfs_rs::bytes::u16_at(&rows[0], 10).unwrap(), 16);
        assert_eq!(u64_at(&rows[0], 32).unwrap(), (1_u64 << 48) | 26);
        let count = plan.len();
        semantic::object_id_repairs(&fixture.path, fixture.boot, &mut plan, checker::consistency::IndexCheck::Quick)
            .unwrap();
        assert_eq!(plan.len(), count);
        assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.image);
    }
}
