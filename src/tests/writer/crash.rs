//! Module: tools::recovery_io::writer_crash
//! Purpose: Exercise real writer and recovery paths with volatile device writes.
//! Created: 2026-10-01
//! Architecture: Disposable image histories drive the shared writer; the tools
//! recovery adapter replays surviving, lost and torn metadata publications.
use ntfs_rs::{
    batch::BATCH_BYTES,
    boot::BootSector,
    mft::{MftRecord, ATTR_DATA},
    resident_writer::{WriteIo, Writer, METADATA_SCRATCH_BYTES},
    volume::{ReadAt, Volume},
    Error, Result,
};
use std::{
    collections::{hash_map::DefaultHasher, BTreeSet},
    fs::{self, OpenOptions},
    hash::{Hash, Hasher},
    io::{Seek, SeekFrom, Write},
    path::Path,
};

// PID namespaces may reuse identifiers across executions. Each matrix owns
// an exclusively created directory, so failed earlier runs cannot collide.
fn crash_directory(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("slate-{label}-{}-{nonce}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}

/// Exercise an interrupted clean-flag publication using a real writer checkpoint.
/// Either restart copy may survive; neither may authorize a clean classification.
#[test]
#[ignore = "requires SLATE_CRASH_SOURCE with a fresh disposable volume"]
fn clean_flag_publication_recovers_from_either_restart_copy() {
    use ntfs_rs::logfile::{classify_restart_pair, LogState, RestartPage};
    let source = std::env::var_os("SLATE_CRASH_SOURCE").unwrap();
    let dir = crash_directory("restart-flag");
    let mut image = Image { bytes: fs::read(source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..512]).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut sd = [0; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let reference =
        writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "restart-pair.bin", None, &sd, 0, &mut scratch).unwrap();
    let expected = vec![0x6b; 8192];
    writer.write(&mut image, reference, 0, &expected, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    let log_start = {
        let mut volume = Volume::new(&mut image, boot).unwrap();
        let mut zero = [0; 1024];
        let mut raw = [0; 1024];
        volume.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        volume.read_mft_record(&mft, 2, &mut raw).unwrap();
        let record = MftRecord::parse(&mut raw, 512).unwrap();
        let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        let run = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap();
        assert!(run.len * u64::from(boot.cluster_bytes) >= 8192);
        run.lcn.unwrap() as usize * boot.cluster_bytes as usize
    };
    for copy in 0..2 {
        let mut crashed = image.bytes.clone();
        let at = log_start + copy * 4096;
        let page = &mut crashed[at..at + 4096];
        let restart = RestartPage::parse(page, 512).unwrap();
        assert!(restart.clean_shutdown);
        let area = ntfs_rs::bytes::u16_at(page, 24).unwrap() as usize;
        page[area + 14..area + 16].copy_from_slice(&0u16.to_le_bytes());
        ntfs_rs::mft::protect_fixups(page).unwrap();
        let first = RestartPage::parse(&mut crashed[log_start..log_start + 4096].to_vec(), 512);
        let second = RestartPage::parse(&mut crashed[log_start + 4096..log_start + 8192].to_vec(), 512);
        assert_eq!(classify_restart_pair(first, second), LogState::ReplayRequired);
        let path = dir.join(format!("copy-{copy}.img"));
        fs::write(&path, crashed).unwrap();
        let plan = super::plan(&path).unwrap();
        assert!(plan.patches.is_empty(), "completed metadata needs no replay changes");
        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        super::recover_created_copy(&path, &mut file, &mut 0, None).unwrap();
        assert_eq!(content(&path, boot, reference), expected);
        let converged = super::plan(&path).unwrap();
        assert!(
            converged.preparation.is_empty() && converged.patches.is_empty() && converged.publication.is_empty(),
            "recovery must converge to a checkpoint"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

struct Image {
    bytes: Vec<u8>,
    held: Vec<(u64, Vec<u8>)>,
    trace: Vec<Option<(u64, Vec<u8>)>>,
}
impl ReadAt for Image {
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<()> {
        out.copy_from_slice(self.bytes.get(offset as usize..offset as usize + out.len()).ok_or(Error::Io)?);
        for (at, bytes) in &self.held {
            let lo = offset.max(*at);
            let hi = (offset + out.len() as u64).min(*at + bytes.len() as u64);
            if lo < hi {
                out[(lo - offset) as usize..(hi - offset) as usize]
                    .copy_from_slice(&bytes[(lo - at) as usize..(hi - at) as usize]);
            }
        }
        Ok(())
    }
}
impl WriteIo for Image {
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<()> {
        self.bytes[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        self.trace.push(Some((at, bytes.to_vec())));
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        self.trace.push(None);
        Ok(())
    }
    fn hold_at(&mut self, at: u64, bytes: &[u8], _: bool) -> Result<()> {
        self.held.retain(|(p, _)| *p != at);
        self.held.push((at, bytes.to_vec()));
        Ok(())
    }
    fn release_at(&mut self, at: u64, _: usize) {
        self.held.retain(|(p, _)| *p != at);
    }
}

#[test]
#[ignore = "requires SLATE_WINDOWS_SOURCE, a disposable clean Windows-return image"]
fn clean_windows_journal_handoff_crashes() {
    let source =
        std::env::var_os("SLATE_WINDOWS_SOURCE").expect("set SLATE_WINDOWS_SOURCE to run this fixture-backed test");
    let mut image = Image { bytes: fs::read(source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..512]).unwrap();
    let (log, length) = {
        let mut v = Volume::new(&mut image, boot).unwrap();
        let mut zero = [0; 1024];
        let mut raw = [0; 1024];
        v.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        v.read_mft_record(&mft, 2, &mut raw).unwrap();
        let record = MftRecord::parse(&mut raw, 512).unwrap();
        let data = record.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        let lcn = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap().lcn.unwrap();
        ((lcn * 4096) as usize, data.data_size().unwrap() as usize)
    };
    let original = image.bytes[log..log + length].to_vec();
    let baseline = image.bytes.clone();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    // A dirty, torn, or disagreeing pair must never authorize journal reset.
    for mode in 0..4 {
        image.bytes[log..log + length].copy_from_slice(&original);
        for copy in 0..2 {
            let at = log + copy * 4096;
            let area = u16::from_le_bytes(image.bytes[at + 24..at + 26].try_into().unwrap()) as usize;
            if mode == 0 || (mode == 1 && copy == 1) {
                image.bytes[at + area + 14] &= !2;
            }
            if mode == 2 && copy == 1 {
                image.bytes[at + 510] ^= 1;
            }
            if mode == 3 && copy == 1 {
                let client =
                    u16::from_le_bytes(image.bytes[at + area + 22..at + area + 24].try_into().unwrap()) as usize;
                image.bytes[at + area + client + 20] ^= 1;
            }
        }
        assert!(Writer::prepare(&mut image, boot, &mut scratch).is_err(), "unsafe admission mode {mode}");
        assert!(image.trace.is_empty());
    }
    image.bytes[log..log + length].copy_from_slice(&original);
    let mut writer = Writer::prepare_with_diagnostics(&mut image, boot, &mut scratch, |reason| {
        eprintln!("Windows handoff fixture rejected: {reason}");
    })
    .unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    let trace = std::mem::take(&mut image.trace);
    image.bytes = baseline;
    // Stop at the first new primary restart's flush. Until this point there
    // must be no metadata writes at all; subsequent ordinary WAL publication
    // is exercised by the existing initialize/finish crash matrices.
    let end = trace.iter().position(|e| e.as_ref().is_some_and(|(at, _)| *at == log as u64)).unwrap() + 2;
    let mut durable = original.clone();
    let mut pending: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut cases = 0;
    let mut refused = 0;
    for event in &trace[..end] {
        if let Some((at, bytes)) = event {
            assert!(*at >= log as u64 && *at + bytes.len() as u64 <= (log + length) as u64);
            pending.push((*at as usize - log, bytes.clone()));
        } else {
            for (at, bytes) in pending.drain(..) {
                durable[at..at + bytes.len()].copy_from_slice(&bytes);
            }
        }
        // Drop all, retain all, alternate survivors, latest only, drop latest,
        // and tear the latest write after sector one, at every write/flush.
        for mode in 0..7 {
            image.bytes[log..log + length].copy_from_slice(&durable);
            for (i, (at, bytes)) in pending.iter().enumerate() {
                let keep = match mode {
                    0 => false,
                    1 | 6 => true,
                    2 => i % 2 == 0,
                    3 => i % 2 == 1,
                    4 => i + 1 == pending.len(),
                    _ => i + 1 != pending.len(),
                };
                if keep {
                    let n = if mode == 6 && i + 1 == pending.len() { 512.min(bytes.len()) } else { bytes.len() };
                    image.bytes[log + at..log + at + n].copy_from_slice(&bytes[..n]);
                }
            }
            if Writer::prepare(&mut image, boot, &mut scratch).is_err() {
                refused += 1;
            }
            assert!(image.trace.is_empty());
            cases += 1;
        }
    }
    // Complete publication admits a normal session; all other file bytes were
    // held constant throughout the handoff, including torn/reset cases.
    image.bytes[log..log + length].copy_from_slice(&durable);
    Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    eprintln!("PASS Windows clean-journal handoff: {cases} crash states, {refused} fail-closed admissions; four dirty/torn/conflicting rejection cases");
}
fn content(path: &Path, boot: BootSector, reference: u64) -> Vec<u8> {
    let mut volume = Volume::new(super::Image(fs::File::open(path).unwrap()), boot).unwrap();
    let mut zero = [0; 1024];
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    let mut raw = [0; 1024];
    volume.read_mft_record(&mft, reference & 0xffff_ffff_ffff, &mut raw).unwrap();
    let file = MftRecord::parse(&mut raw, 512).unwrap();
    // Crash cases include split DATA streams; reading only the base segment
    // would miss corrupt or lost continuation mappings during verification.
    let number = reference & 0xffff_ffff_ffff;
    let mut scratch = vec![0; 2 * ntfs_rs::tx::RECORD_IMAGE + 1024];
    let size = volume.data_size_resolved(&mft, &file, number, &mut scratch).unwrap();
    let mut bytes = vec![0; size as usize];
    volume.read_data_resolved(&mft, &file, number, &mut scratch, 0, &mut bytes).unwrap();
    bytes
}

/// Build a fragmented stream that needs extension records, then interrupt
/// its next append at every I/O boundary. Existing bytes and acknowledged
/// growth must survive real replay, including each omitted and torn write.
#[test]
#[ignore = "requires SLATE_CRASH_SOURCE, a fresh disposable volume"]
fn fragmented_family_append_crashes() {
    let source =
        std::env::var_os("SLATE_CRASH_SOURCE").expect("set SLATE_CRASH_SOURCE to run this fixture-backed test");
    let dir = crash_directory("fragment-crash");
    let mut image = Image { bytes: fs::read(source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..512]).unwrap();
    mark_free(&mut image, boot);
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut descriptor = [0; 20];
    descriptor[0] = 1;
    descriptor[2..4].copy_from_slice(&0x8004_u16.to_le_bytes());
    let mut references = Vec::new();
    for name in ["fragment-a", "fragment-b"] {
        references.push(
            writer.file_lifecycle(&mut image, (5_u64 << 48) | 5, name, None, &descriptor, 0, &mut scratch).unwrap(),
        );
    }
    let block = vec![b'A'; 4096];
    for index in 0..320 {
        for &reference in &references {
            // Exact reservation defeats the append window so two files
            // receive interleaved one-cluster physical runs.
            writer.fallocate(&mut image, reference, index * 4096, 4096, 1, &mut scratch).unwrap();
            writer.write(&mut image, reference, index * 4096, &block, &mut scratch).unwrap();
        }
    }
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let baseline = image.bytes.clone();
    image.trace.clear();
    writer.write(&mut image, references[0], 320 * 4096, &vec![b'B'; 4096], &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    let cases =
        window_crashes(&image, &baseline, boot, references[0], 320 * 4096, 321 * 4096, "fragmented-append", &dir);
    eprintln!("PASS fragmented append: {cases} lost/reordered/torn crash states");
    fs::remove_dir_all(dir).unwrap();
}

// Fill every free cluster before exercising allocations: a missing exposure
// barrier must never let this previous-owner marker become visible.
fn mark_free(image: &mut Image, boot: BootSector) {
    let mut volume = Volume::new(&mut *image, boot).unwrap();
    let mut zero = [0; 1024];
    let mut raw = [0; 1024];
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    volume.read_mft_record(&mft, 6, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, 512).unwrap();
    let attr = record.attributes().map(|a| a.unwrap()).find(|a| a.kind == ATTR_DATA).unwrap();
    let mut bits = vec![0; attr.data_size().unwrap() as usize];
    volume.read_attribute(attr, 0, &mut bits).unwrap();
    drop(volume);
    for lcn in 0..(boot.total_sectors / u64::from(boot.sectors_per_cluster)) as usize {
        if bits[lcn / 8] & (1 << (lcn % 8)) == 0 {
            image.bytes[lcn * 4096..(lcn + 1) * 4096].fill(0xa5);
        }
    }
}

#[test]
#[ignore = "requires SLATE_CRASH_SOURCE, a fresh disposable volume"]
fn overwrites_reject_protected_spans_before_any_write() {
    let source =
        std::env::var_os("SLATE_CRASH_SOURCE").expect("set SLATE_CRASH_SOURCE to run this fixture-backed test");
    let mut image = Image { bytes: fs::read(&source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..512]).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut sd = [0; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let reference =
        writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "guards.bin", None, &sd, 0, &mut scratch).unwrap();
    writer.write(&mut image, reference, 0, &vec![7; 8192], &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let mut zero = [0; 1024];
    let mut raw = [0; 1024];
    let mut volume = Volume::new(&mut image, boot).unwrap();
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    let data = mft.attributes().map(|a| a.unwrap()).find(|a| a.kind == ATTR_DATA).unwrap();
    let mut physical = 0;
    ntfs_rs::write_plan::plan_nonresident_overwrite(data, boot, (reference & 0xffff_ffff_ffff) * 1024, 1024, |s| {
        physical = s.physical_offset as usize;
        Ok(())
    })
    .unwrap();
    volume.read_mft_record(&mft, 2, &mut raw).unwrap();
    let log = MftRecord::parse(&mut raw, 512).unwrap();
    let log = log.attributes().map(|a| a.unwrap()).find(|a| a.kind == ATTR_DATA).unwrap();
    let log_lcn = ntfs_rs::runlist::DataRuns::new(log.data_runs().unwrap(), 0).next().unwrap().unwrap().lcn.unwrap();
    drop(volume);
    let original = image.bytes[physical..physical + 1024].to_vec();
    for lcn in [0, boot.mft_lcn, boot.mft_lcn + 1, boot.mft_mirror_lcn, log_lcn] {
        let mut bad = original.clone();
        let rec = MftRecord::parse(&mut bad, 512).unwrap();
        let attr = rec.attributes().map(|a| a.unwrap()).find(|a| a.kind == ATTR_DATA).unwrap();
        let safe = ntfs_rs::runlist::DataRuns::new(attr.data_runs().unwrap(), 0).next().unwrap().unwrap().lcn.unwrap();
        let at = attr.record_offset();
        ntfs_rs::record_edit::set_runs(
            &mut bad,
            at,
            &[
                ntfs_rs::runlist::Extent { vcn: 0, len: 1, lcn: Some(safe) },
                ntfs_rs::runlist::Extent { vcn: 1, len: 1, lcn: Some(lcn) },
            ],
        )
        .unwrap();
        ntfs_rs::replay::protect_mft_record(&mut bad, 512).unwrap();
        image.bytes[physical..physical + 1024].copy_from_slice(&bad);
        image.trace.clear();
        assert_eq!(
            writer.write(&mut image, reference, 0, &vec![9; 8192], &mut scratch),
            Err(Error::InvalidRunlist),
            "protected lcn {lcn}"
        );
        assert!(image.trace.is_empty(), "wrote safe prefix before discovering protected suffix");
    }
}

#[test]
#[ignore = "requires SLATE_CRASH_SOURCE and SLATE_NAMESPACE_SOURCE, disposable volumes"]
fn lost_reordered_torn_writes_across_checkpoints_and_wrap() {
    let source =
        std::env::var_os("SLATE_CRASH_SOURCE").expect("set SLATE_CRASH_SOURCE to run this fixture-backed test");
    let namespace_source = std::env::var_os("SLATE_NAMESPACE_SOURCE")
        .expect("set SLATE_NAMESPACE_SOURCE to run the complete namespace crash matrix");
    let dir = crash_directory("real-crash");
    for (append, grouped, namespace) in
        [(false, false, true), (false, false, false), (false, true, false), (true, false, false)]
    {
        let source = if namespace { namespace_source.clone() } else { source.clone() };
        let mut image = Image { bytes: fs::read(&source).unwrap(), held: Vec::new(), trace: Vec::new() };
        let boot = BootSector::parse(&image.bytes[..512]).unwrap();
        mark_free(&mut image, boot);
        // Admit the clean source before replacing its disposable journal.
        // Retaining restart pages for the old size would create invalid log
        // geometry rather than exercise circular reuse of a valid journal.
        let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
        Writer::prepare(&mut image, boot, &mut scratch).unwrap();
        // Bound the fresh, empty fixture journal to 48 pages. Its allocation
        // stays intact; initialize publishes matching restart/checkpoint
        // geometry before any mutations enter the crash trace.
        let log_record = boot.mft_byte_offset().unwrap() as usize + 2 * 1024;
        let raw = &mut image.bytes[log_record..log_record + 1024];
        MftRecord::parse(raw, 512).unwrap();
        let at = ntfs_rs::record_edit::require(raw, ATTR_DATA, &[]).unwrap();
        let data = MftRecord::from_decoded(raw).unwrap().local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        let run = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap();
        assert!(run.len * 4096 >= 196608, "fixture journal must be contiguous");
        let log = run.lcn.unwrap() as usize * 4096;
        raw[at + 48..at + 56].copy_from_slice(&196608u64.to_le_bytes());
        raw[at + 56..at + 64].copy_from_slice(&196608u64.to_le_bytes());
        ntfs_rs::replay::protect_mft_record(raw, 512).unwrap();
        let mirror = boot.mft_mirror_lcn as usize * 4096 + 2 * 1024;
        let log_copy = image.bytes[log_record..log_record + 1024].to_vec();
        image.bytes[mirror..mirror + 1024].copy_from_slice(&log_copy);
        image.bytes[log..log + 196608].fill(0xff);
        let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
        writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
        writer.initialize(&mut image, &mut scratch).unwrap();
        let mut sd = [0; 20];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        let reference =
            writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "crash.bin", None, &sd, 0, &mut scratch).unwrap();
        let second = if grouped {
            Some(writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "second.bin", None, &sd, 0, &mut scratch).unwrap())
        } else {
            None
        };
        let initial = if append { vec![b'a'; 4096] } else { vec![b'a'; 16] };
        writer.write(&mut image, reference, 0, &initial, &mut scratch).unwrap();
        if let Some(second) = second {
            writer.write(&mut image, second, 0, &initial, &mut scratch).unwrap();
        }
        writer.checkpoint(&mut image, &mut scratch).unwrap();
        let mut durable = image.bytes.clone();
        image.trace.clear();
        let rounds = if append { 100 } else { 3 };
        let mut acknowledgments = Vec::new();
        for n in 0..rounds {
            let bytes = if append { vec![b'b' + (n % 23) as u8; 4096] } else { vec![b'b' + n as u8; 16] };
            let offset = if append { (n + 1) * 4096 } else { 0 };
            writer.write(&mut image, reference, offset as u64, &bytes, &mut scratch).unwrap();
            if namespace {
                let old = if n == 0 { "crash.bin".to_owned() } else { format!("crash-{}.bin", n - 1) };
                writer
                    .move_entry(
                        &mut image,
                        (5u64 << 48) | 5,
                        reference,
                        &old,
                        (5u64 << 48) | 5,
                        &format!("crash-{n}.bin"),
                        &mut scratch,
                    )
                    .unwrap();
            }
            if let Some(second) = second {
                writer.write(&mut image, second, 0, &bytes, &mut scratch).unwrap();
            }
            let before = image.trace.iter().filter(|e| e.is_none()).count();
            writer.drain(&mut image, &mut scratch).unwrap();
            let barriers = image.trace.iter().filter(|e| e.is_none()).count() - before;
            assert!(
                barriers
                    == if grouped || namespace || append {
                        // The file and parent index need a multipage WAL
                        // commit. Data-exposure barriers may already have
                        // occurred inside write before this drain is measured.
                        2
                    } else {
                        1
                    }
                    || (append && (5..=8).contains(&barriers)),
                "barriers {barriers}"
            );
            acknowledgments.push(image.trace.len());
            let idle = image.trace.len();
            writer.drain(&mut image, &mut scratch).unwrap();
            assert_eq!(idle, image.trace.len(), "idle fsync must not flush");
            if n == rounds / 2 {
                writer.checkpoint(&mut image, &mut scratch).unwrap();
            }
        }
        writer.finish(&mut image, &mut scratch).unwrap();
        let snapshot = dir.join("crash.img");
        if grouped {
            // Deliberately violate WAL: lose an update that was flushed but
            // retain its commit. Discovery must refuse, never truncate it.
            let mut invalid = durable.clone();
            let mut log_writes = 0;
            for event in &image.trace[..acknowledgments[0]] {
                if let Some((at, bytes)) = event {
                    if bytes.starts_with(b"RCRD") {
                        log_writes += 1;
                        if log_writes == 2 {
                            continue;
                        }
                    }
                    invalid[*at as usize..*at as usize + bytes.len()].copy_from_slice(bytes);
                }
            }
            fs::write(&snapshot, invalid).unwrap();
            assert!(super::plan(&snapshot).is_err(), "accepted a commit after a missing durable update");
        }
        let mut pending: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut seen = BTreeSet::new();
        let mut durable_epoch = 0;
        let mut cases = 0;
        for (point, event) in image.trace.iter().enumerate() {
            match event {
                Some(w) => pending.push(w.clone()),
                None => {
                    for (at, b) in pending.drain(..) {
                        durable[at as usize..at as usize + b.len()].copy_from_slice(&b);
                    }
                    durable_epoch += 1;
                }
            }
            // Crash after every write and flush; individual survivors/drops
            // model reorder, including commit-only survival; tears keep sector 0.
            let modes = 4 + pending.len() * 3;
            for mode in 0..modes {
                let mut writes = Vec::new();
                for (i, (at, bytes)) in pending.iter().enumerate() {
                    let survive = match mode {
                        0 => false,
                        1 => true,
                        2 => i % 2 == 0,
                        3 => i % 2 == 1,
                        m if m < 4 + pending.len() => i == m - 4,
                        m if m < 4 + 2 * pending.len() => i != m - 4 - pending.len(),
                        _ => true,
                    };
                    if survive {
                        let len = if mode >= 4 + 2 * pending.len() && i == mode - 4 - 2 * pending.len() {
                            512.min(bytes.len())
                        } else {
                            bytes.len()
                        };
                        writes.push((*at, bytes[..len].to_vec()));
                    }
                }
                let mut hash = DefaultHasher::new();
                durable_epoch.hash(&mut hash);
                writes.hash(&mut hash);
                if !seen.insert(hash.finish()) {
                    continue;
                }
                let mut file =
                    OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&snapshot).unwrap();
                file.write_all(&durable).unwrap();
                for (at, bytes) in writes {
                    file.seek(SeekFrom::Start(at)).unwrap();
                    file.write_all(&bytes).unwrap();
                }
                let mut flushes = 0;
                let plan = super::plan(&snapshot).unwrap_or_else(|e| {
                    panic!("initial plan append={append} grouped={grouped} point={point} mode={mode}: {e}")
                });
                if grouped && point == 2 && mode == 2 {
                    let saved = fs::read(&snapshot).unwrap();
                    let stops = plan
                        .preparation
                        .iter()
                        .chain(plan.patches.iter())
                        .chain(plan.publication.iter())
                        .filter(|p| !p.as_ref().unwrap().continuation)
                        .count();
                    for stop in 1..=stops {
                        fs::write(&snapshot, &saved).unwrap();
                        let mut n = 0;
                        assert!(super::recover_created_copy(&snapshot, &mut file, &mut n, Some(stop)).is_err());
                        super::recover_created_copy(&snapshot, &mut file, &mut n, None).unwrap();
                        assert_eq!(
                            content(&snapshot, boot, reference),
                            initial,
                            "interrupted recovery changed uncommitted data"
                        );
                    }
                    fs::write(&snapshot, &saved).unwrap();
                }
                if let Err(e) = super::recover_created_copy(&snapshot, &mut file, &mut flushes, None) {
                    panic!(
                        "append={append} point={point} mode={mode} pending={} snapshot={} recovery={e}",
                        pending.len(),
                        snapshot.display()
                    );
                }
                let got = content(&snapshot, boot, reference);
                if namespace {
                    let mut volume = Volume::new(super::Image(fs::File::open(&snapshot).unwrap()), boot).unwrap();
                    let mut zero = [0; 1024];
                    let mut root = [0; 1024];
                    let mut block = [0; 4096];
                    volume.read_mft_zero(&mut zero).unwrap();
                    let mft = MftRecord::parse(&mut zero, 512).unwrap();
                    volume.read_mft_record(&mft, 5, &mut root).unwrap();
                    let root = MftRecord::parse(&mut root, 512).unwrap();
                    let mut names = Vec::new();
                    volume
                        .visit_directory(&root, &mut block, |entry| {
                            if entry.file_reference == reference {
                                let units: Vec<u16> = entry
                                    .name
                                    .utf16le
                                    .chunks_exact(2)
                                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                    .collect();
                                names.push(String::from_utf16(&units).unwrap().to_lowercase());
                            }
                            Ok(())
                        })
                        .unwrap();
                    let expected =
                        if got[0] == b'a' { "crash.bin".to_owned() } else { format!("crash-{}.bin", got[0] - b'b') };
                    assert_eq!(names, vec![expected], "rename/data transaction split point={point} mode={mode}");
                }
                if let Some(second) = second {
                    assert_eq!(got, content(&snapshot, boot, second), "partial batch point={point} mode={mode}");
                }
                let ack = acknowledgments.iter().filter(|&&p| p <= point + 1).count();
                if append {
                    assert!(got.len() >= 4096 * (ack + 1) && got.len() <= 4096 * (rounds + 1));
                    assert_eq!(&got[..4096], &initial);
                    for (n, block) in got[4096..].chunks_exact(4096).enumerate() {
                        assert!(
                            block.iter().all(|&b| b == b'b' + (n % 23) as u8 || (n >= ack && b == 0)),
                            "stale or acknowledged data lost point={point} mode={mode} block={n}"
                        );
                    }
                } else {
                    assert_eq!(got.len(), 16);
                    assert!(got.iter().all(|&b| b == got[0]));
                    assert!(got[0] >= b'a' + ack as u8 && got[0] <= b'a' + rounds as u8);
                }
                cases += 1;
            }
            if point % 50 == 0 {
                eprintln!("append={append} point={point}/{} crash cases={cases}", image.trace.len());
            }
        }
        eprintln!("PASS append={append} grouped={grouped} namespace={namespace}: {} write/flush boundaries, {cases} distinct crashes",image.trace.len());
    }
    fs::remove_dir_all(dir).unwrap();
}
// Additional boundaries specific to the preallocation proof's lifetime.
fn window_crashes(
    image: &Image,
    baseline: &[u8],
    boot: BootSector,
    reference: u64,
    old_size: usize,
    new_size: usize,
    label: &str,
    dir: &Path,
) -> usize {
    let path = dir.join(format!("{label}.img"));
    let mut durable = baseline.to_vec();
    let mut pending: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut cases = 0;
    let mut checked = BTreeSet::new();
    let mut rejected_unlogged_bitmap = false;
    let bitmap_span = if label == "names-clean-shutdown" {
        let mut volume =
            Volume::new(Image { bytes: baseline.to_vec(), held: Vec::new(), trace: Vec::new() }, boot).unwrap();
        let mut zero = [0; 1024];
        let mut raw = [0; 1024];
        volume.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        volume.read_mft_record(&mft, 6, &mut raw).unwrap();
        let bitmap = MftRecord::parse(&mut raw, 512).unwrap();
        let data = bitmap.local_attribute(ATTR_DATA, &[]).unwrap().unwrap();
        let first = ntfs_rs::runlist::DataRuns::new(data.data_runs().unwrap(), 0).next().unwrap().unwrap();
        Some((first.lcn.unwrap() * 4096, data.data_size().unwrap()))
    } else {
        None
    };
    for (point, event) in image.trace.iter().enumerate() {
        if let Some(w) = event {
            pending.push(w.clone());
        } else {
            for (at, bytes) in pending.drain(..) {
                durable[at as usize..at as usize + bytes.len()].copy_from_slice(&bytes);
            }
        }
        for mode in 0..4 + pending.len() * 3 {
            let mut crashed = durable.clone();
            for (i, (at, bytes)) in pending.iter().enumerate() {
                let keep = match mode {
                    0 => false,
                    1 => true,
                    2 => i % 2 == 0,
                    3 => i % 2 == 1,
                    m if m < 4 + pending.len() => i == m - 4,
                    m if m < 4 + 2 * pending.len() => i != m - 4 - pending.len(),
                    _ => true,
                };
                if keep {
                    let n = if mode >= 4 + 2 * pending.len() && i == mode - 4 - 2 * pending.len() {
                        512.min(bytes.len())
                    } else {
                        bytes.len()
                    };
                    crashed[*at as usize..*at as usize + n].copy_from_slice(&bytes[..n]);
                }
            }
            // Several survivor masks yield identical disk bytes. Verify each
            // distinct image once, retaining every final acknowledgment check.
            let mut hash = DefaultHasher::new();
            crashed.hash(&mut hash);
            if !checked.insert(hash.finish()) && point + 1 != image.trace.len() {
                continue;
            }
            if !rejected_unlogged_bitmap && mode == 1 {
                if let (Some((bitmap, length)), Some((at, bytes))) = (bitmap_span, event) {
                    if bytes.len() == 512 && *at >= bitmap && *at + 512 <= bitmap + length {
                        // A newer logged image is valid recovery evidence; an
                        // unlogged change to even one byte must stay refused.
                        let mut corrupt = crashed.clone();
                        corrupt[*at as usize + 511] ^= 0x80;
                        let bad = dir.join("unlogged-bitmap.img");
                        fs::write(&bad, corrupt).unwrap();
                        let error = super::plan(&bad).err().expect("unlogged bitmap was accepted");
                        assert!(error.to_string().contains("raw replay preimage"), "{error}");
                        fs::remove_file(bad).unwrap();
                        rejected_unlogged_bitmap = true;
                    }
                }
            }
            fs::write(&path, crashed).unwrap();
            let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            super::recover_created_copy(&path, &mut file, &mut 0, None)
                .unwrap_or_else(|e| panic!("{label} point={point} mode={mode}: {e}"));
            if label.starts_with("names-") {
                let audit = crate::checker::consistency::audit(&path, boot, Default::default()).unwrap();
                assert!(audit.passed(), "{label} point={point} mode={mode}: {:?}", audit.findings);
            }
            let got = content(&path, boot, reference);
            assert!(got.len() == old_size || got.len() == new_size, "{label} unexpected length");
            let keep = old_size.min(new_size);
            assert!(got[..keep].iter().all(|&b| b == b'A'), "{label} lost existing data");
            if new_size > old_size && got.len() == new_size {
                assert!(
                    got[old_size..].iter().all(|&b| b == b'B' || b == 0),
                    "{label} stale exposed data point={point} mode={mode}"
                );
            }
            if point + 1 == image.trace.len() {
                assert_eq!(got.len(), new_size, "{label} lost acknowledged length");
                if new_size > old_size {
                    assert!(got[old_size..].iter().all(|&b| b == b'B'), "{label} lost acknowledged data");
                }
            }
            cases += 1;
        }
    }
    if bitmap_span.is_some() {
        assert!(rejected_unlogged_bitmap, "missing bitmap writeback corruption check");
    }
    cases
}

fn file_sizes(image: &mut Image, boot: BootSector, reference: u64) -> (u64, u64, u64, u64) {
    let mut volume = Volume::new(&mut *image, boot).unwrap();
    let mut zero = [0; 1024];
    let mut raw = [0; 1024];
    volume.read_mft_zero(&mut zero).unwrap();
    let mft = MftRecord::parse(&mut zero, 512).unwrap();
    let data = mft.attributes().map(|a| a.unwrap()).find(|a| a.kind == ATTR_DATA).unwrap();
    let mut physical = 0;
    ntfs_rs::write_plan::plan_nonresident_recovery(data, boot, (reference & 0xffff_ffff_ffff) * 1024, 1024, |s| {
        physical = s.physical_offset;
        Ok(())
    })
    .unwrap();
    volume.read_mft_record(&mft, reference & 0xffff_ffff_ffff, &mut raw).unwrap();
    let record = MftRecord::parse(&mut raw, 512).unwrap();
    let attr = record.attributes().map(|a| a.unwrap()).find(|a| a.kind == ATTR_DATA).unwrap();
    (attr.allocated_size().unwrap(), attr.data_size().unwrap(), attr.initialized_size().unwrap(), physical)
}

#[test]
#[ignore = "requires SLATE_CRASH_SOURCE, a fresh disposable volume"]
fn window_zeroing_truncate_trim_and_remount() {
    let source =
        std::env::var_os("SLATE_CRASH_SOURCE").expect("set SLATE_CRASH_SOURCE to run this fixture-backed test");
    let dir = crash_directory("window-crash");
    let mut image = Image { bytes: fs::read(&source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..512]).unwrap();
    mark_free(&mut image, boot);
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut sd = [0; 20];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let reference =
        writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "window.bin", None, &sd, 0, &mut scratch).unwrap();
    writer.write(&mut image, reference, 0, &vec![b'A'; 4096], &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    assert_eq!(file_sizes(&mut image, boot, reference).0, 16 * 4096);
    let baseline = image.bytes.clone();
    image.trace.clear();
    writer.write(&mut image, reference, 4096, &vec![b'B'; 4096], &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    // Filename and parent-index copies join this update. Their undo images
    // require a multipage WAL transaction and its two ordering barriers.
    assert_eq!(image.trace.iter().filter(|e| e.is_none()).count(), 2);
    let writes: Vec<_> = image.trace.iter().filter_map(|e| e.as_ref()).collect();
    assert_eq!(writes.iter().filter(|(_, b)| b.iter().all(|&v| v == b'B')).count(), 1);
    assert!(
        writes.iter().all(|(_, b)| b.iter().all(|&v| v == b'B') || b.starts_with(b"RCRD")),
        "steady state must write only data and log, retaining home metadata"
    );
    let mut cases = window_crashes(&image, &baseline, boot, reference, 4096, 8192, "inside-window", &dir);
    // Put a distinct old value in the soon-to-be-truncated range.
    writer.write(&mut image, reference, 4096, &vec![b'A'; 4096], &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let baseline = image.bytes.clone();
    image.trace.clear();
    writer.resize(&mut image, reference, 5000, &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    cases += window_crashes(&image, &baseline, boot, reference, 8192, 5000, "truncate", &dir);
    assert_eq!(file_sizes(&mut image, boot, reference).0, 8192);
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let baseline = image.bytes.clone();
    image.trace.clear();
    writer.write(&mut image, reference, 5000, &vec![b'B'; 1024], &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(image.trace.iter().filter(|e| e.is_none()).count(), 2, "truncate must invalidate zero proof");
    cases += window_crashes(&image, &baseline, boot, reference, 5000, 6024, "after-truncate", &dir);
    writer.write(&mut image, reference, 0, &vec![b'A'; 8192], &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    let baseline = image.bytes.clone();
    image.trace.clear();
    writer.write(&mut image, reference, 8192, &vec![b'B'; 4096], &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(image.trace.iter().filter(|e| e.is_none()).count(), 2, "new window needs exposure barrier");
    cases += window_crashes(&image, &baseline, boot, reference, 8192, 12288, "new-window-zeroing", &dir);
    assert!(file_sizes(&mut image, boot, reference).0 > 12288);
    writer.trim(&mut image, reference, &mut scratch).unwrap();
    writer.checkpoint(&mut image, &mut scratch).unwrap();
    assert_eq!(file_sizes(&mut image, boot, reference).0, 12288);
    // Create a valid clean image with preallocation owned by another session:
    // resize allocates but does not zero its uninitialized tail. After finish,
    // reduce only EOF in this disposable fixture before mounting it again.
    writer.write(&mut image, reference, 0, &vec![b'A'; 12288], &mut scratch).unwrap();
    writer.resize(&mut image, reference, 65536, &mut scratch).unwrap();
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    let (_, _, _, physical) = file_sizes(&mut image, boot, reference);
    let raw = &mut image.bytes[physical as usize..physical as usize + 1024];
    MftRecord::parse(raw, 512).unwrap();
    let at = ntfs_rs::record_edit::require(raw, ATTR_DATA, &[]).unwrap();
    ntfs_rs::record_edit::set_sizes(raw, at, 65536, 12288, 12288).unwrap();
    ntfs_rs::replay::protect_mft_record(raw, 512).unwrap();
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let baseline = image.bytes.clone();
    image.trace.clear();
    writer.write(&mut image, reference, 12288, &vec![b'B'; 4096], &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(image.trace.iter().filter(|e| e.is_none()).count(), 2, "remount must lose zero proof");
    cases += window_crashes(&image, &baseline, boot, reference, 12288, 16384, "remount", &dir);
    let owned = writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "finish.bin", None, &sd, 0, &mut scratch).unwrap();
    writer.write(&mut image, owned, 0, &vec![b'A'; 4096], &mut scratch).unwrap();
    writer.drain(&mut image, &mut scratch).unwrap();
    assert_eq!(file_sizes(&mut image, boot, owned).0, 65536);
    let full = writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "full.bin", None, &sd, 0, &mut scratch).unwrap();
    image.trace.clear();
    writer.write(&mut image, full, 0, &vec![b'A'; 65536], &mut scratch).unwrap();
    let data_bytes: usize =
        image.trace.iter().filter_map(|e| e.as_ref()).filter(|(_, b)| b.len() > 4096).map(|(_, b)| b.len()).sum();
    assert_eq!(data_bytes, 65536, "full-cluster appends must not zero the same clusters twice");
    writer.drain(&mut image, &mut scratch).unwrap();
    let clean_baseline = image.bytes.clone();
    image.trace.clear();
    writer.finish(&mut image, &mut scratch).unwrap();
    cases += window_crashes(&image, &clean_baseline, boot, owned, 4096, 4096, "names-clean-shutdown", &dir);
    assert_eq!(file_sizes(&mut image, boot, owned).0, 4096, "finish must return unused clusters");
    let resume_baseline = image.bytes.clone();
    image.trace.clear();
    let mut resumed = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    resumed.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    resumed.initialize(&mut image, &mut scratch).unwrap();
    cases += window_crashes(&image, &resume_baseline, boot, owned, 4096, 4096, "names-reopen-clean", &dir);
    resumed.finish(&mut image, &mut scratch).unwrap();
    let path = dir.join("audit.img");
    fs::write(&path, &image.bytes).unwrap();
    let audit = crate::checker::consistency::audit(&path, boot, Default::default()).unwrap();
    assert!(audit.passed(), "allocation audit failed: {:?}", audit.findings);
    eprintln!("PASS window zeroing/truncate/remount: {cases} crash cases; allocation audit passed");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "requires SLATE_NAMESPACE_SOURCE with at least forty namespace fixture objects"]
fn committed_hold_capacity_checkpoints_before_reuse() {
    let source =
        std::env::var_os("SLATE_NAMESPACE_SOURCE").expect("set SLATE_NAMESPACE_SOURCE to run this fixture-backed test");
    let dir = crash_directory("hold-capacity");
    let mut image = Image { bytes: fs::read(&source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..512]).unwrap();
    let baseline_audit = crate::checker::consistency::audit(Path::new(&source), boot, Default::default()).unwrap();
    let mut refs = BTreeSet::new();
    {
        let mut volume = Volume::new(&mut image, boot).unwrap();
        let mut zero = [0; 1024];
        let mut raw = [0; 1024];
        let mut block = [0; 4096];
        volume.read_mft_zero(&mut zero).unwrap();
        let mft = MftRecord::parse(&mut zero, 512).unwrap();
        volume.read_mft_record(&mft, 5, &mut raw).unwrap();
        let root = MftRecord::parse(&mut raw, 512).unwrap();
        volume
            .visit_directory(&root, &mut block, |entry| {
                if entry.name.utf16le.first() == Some(&b'z') {
                    refs.insert(entry.file_reference);
                }
                Ok(())
            })
            .unwrap();
    }
    assert!(refs.len() >= 40);
    let refs: Vec<_> = refs.into_iter().take(40).collect();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut cases = 0;
    for (n, &reference) in refs.iter().enumerate() {
        let baseline = if n == 32 { image.bytes.clone() } else { Vec::new() };
        image.trace.clear();
        writer.write(&mut image, reference, 0, &[b'B'; 16], &mut scratch).unwrap();
        writer.drain(&mut image, &mut scratch).unwrap();
        assert!(image.held.len() <= 36, "unbounded held images");
        let flushes = image.trace.iter().filter(|e| e.is_none()).count();
        // The file and its nonresident parent index exceed a single packed
        // page. Two WAL barriers are required without a capacity checkpoint.
        assert_eq!(flushes, 2, "hold capacity spill at {n}");
        if n == 32 {
            cases = window_crashes(&image, &baseline, boot, reference, 0, 16, "hold-capacity", &dir);
        }
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    assert!(image.held.is_empty());
    let path = dir.join("audit.img");
    fs::write(&path, &image.bytes).unwrap();
    for reference in refs {
        assert_eq!(content(&path, boot, reference), vec![b'B'; 16]);
    }
    let audit = crate::checker::consistency::audit(&path, boot, Default::default()).unwrap();
    // ntfs-3g's fixture has a pre-existing unsupported security descriptor on
    // MFT record zero. Require identical findings and exact allocation counts.
    let findings = |a: &crate::checker::consistency::Audit| {
        a.findings.iter().map(|f| (f.code, f.record, f.is_error, f.detail.clone())).collect::<Vec<_>>()
    };
    assert_eq!(findings(&audit), findings(&baseline_audit));
    assert_eq!(audit.referenced_clusters, audit.allocated_clusters);
    eprintln!(
        "PASS held capacity: {cases} crash cases; 40 contents intact; allocation balanced, audit findings unchanged"
    );
    fs::remove_dir_all(dir).unwrap();
}
#[test]
#[ignore = "requires SLATE_CRASH_SOURCE, a fresh disposable volume"]
fn extension_names_and_fresh_index_crashes() {
    let source =
        std::env::var_os("SLATE_CRASH_SOURCE").expect("set SLATE_CRASH_SOURCE to run this fixture-backed test");
    let dir = crash_directory("extension-crashes");
    let mut image = Image { bytes: fs::read(source).unwrap(), held: Vec::new(), trace: Vec::new() };
    let boot = BootSector::parse(&image.bytes[..512]).unwrap();
    let mut scratch = vec![0; METADATA_SCRATCH_BYTES];
    let mut writer = Writer::prepare(&mut image, boot, &mut scratch).unwrap();
    writer.attach_batch(Box::leak(vec![0; BATCH_BYTES].into_boxed_slice())).unwrap();
    writer.set_linux_compatibility(true).unwrap();
    writer.initialize(&mut image, &mut scratch).unwrap();
    let mut sd = [0; 256];
    sd[0] = 1;
    sd[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
    let reference = writer.file_lifecycle(&mut image, (5u64 << 48) | 5, "names", None, &sd, 0, &mut scratch).unwrap();
    writer.write(&mut image, reference, 0, &vec![b'A'; 4096], &mut scratch).unwrap();
    let mut cases = 0;
    for n in 0..10 {
        writer.checkpoint(&mut image, &mut scratch).unwrap();
        let baseline = image.bytes.clone();
        image.trace.clear();
        writer
            .hard_link(&mut image, reference, (5u64 << 48) | 5, &format!("link-{n}-{}", "x".repeat(100)), &mut scratch)
            .unwrap();
        writer.drain(&mut image, &mut scratch).unwrap();
        cases += window_crashes(&image, &baseline, boot, reference, 4096, 4096, &format!("names-{n}"), &dir);
    }
    writer.finish(&mut image, &mut scratch).unwrap();
    let path = dir.join("audit.img");
    fs::write(&path, &image.bytes).unwrap();
    let audit = crate::checker::consistency::audit(&path, boot, Default::default()).unwrap();
    assert!(audit.passed(), "{:?}", audit.findings);
    fs::remove_dir_all(dir).unwrap();
    eprintln!("PASS extension names/fresh index: {cases} crash cases; allocation audits passed");
}
