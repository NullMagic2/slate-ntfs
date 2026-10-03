//! Module: tests::checker::scan_resources
//! Purpose: Verify online-scan resource budgets, read-ahead and offline policy.
//! Created: 2026-10-03
//! Architecture: Included by slate_ntfs_tools::checker under cfg(test); the
//!     ignored fixture case needs SLATE_SCAN_RESOURCE_SOURCE.

use super::*;

#[test]
fn force_offline_policy_never_enters_mounted_repair_pass() {
    // Deliberately invalid paths: an attempted snapshot, freeze, namespace
    // walk or repair cannot succeed. Forced mode must touch none of them.
    let path = Path::new("/proc/self/slate-nonexistent-volume");
    let status =
        online_repairs(path, path, 0, OnlineScanOptions { force_offline_fix: true, ..Default::default() }).unwrap();
    assert!(status.online_repairs_bypassed);
    assert_eq!(status.ea_repairs + status.data_repairs + status.allocation_repairs, 0);
    assert!(online_repairs(path, path, 0, OnlineScanOptions::default()).is_err());
}

#[test]
fn pending_write_cache_bounds_share_the_scan_allowance() {
    assert_eq!(scan_write_cache_size("1280KiB"), Some(1310720));
    assert_eq!(scan_write_cache_size("128MiB"), Some(134217728));
    assert_eq!(scan_write_cache_size("1310721"), Some(1310721));
    for value in ["0", "1279KiB", "129MiB", "18446744073709551615MiB", "1.25MiB"] {
        assert_eq!(scan_write_cache_size(value), None);
    }
    for available in [0, 1024, 300 * 1024, 128 * 1024 * 1024, 8 * 1024 * 1024 * 1024] {
        for resources in [ScanResources::Balanced, ScanResources::High] {
            for request in [None, Some(1310720), Some(134217728)] {
                let memory = Some(ScanMemory { total: 8 * 1024 * 1024 * 1024, available });
                let budget = resources.budget(memory, Some(1), request);
                let total = budget.index_cache_bytes + budget.read_buffer_bytes as u64 + budget.write_view_cache_bytes;
                assert!(total <= available / 5 * 4);
                assert_eq!(budget.write_view_cache_bytes % (128 * 1024), 0);
                assert!(budget.write_view_cache_bytes <= request.unwrap_or(64 * 1024 * 1024));
            }
        }
    }
    assert_eq!(ScanResources::Balanced.budget(None, None, Some(1310720)).write_view_cache_bytes, 0);
    let path = Path::new("/proc/self/slate-nonexistent-scan");
    for bytes in [0, 1310719, 134217729, u64::MAX] {
        let error = online_scan(
            path,
            path,
            path,
            None,
            OnlineScanOptions { write_cache_bytes: Some(bytes), ..Default::default() },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

#[test]
fn explicit_percent_bypasses_floor_and_stays_within_available_headroom() {
    for available in [0, 10, 512 * 1024, 8 * 1024 * 1024 * 1024, u64::MAX] {
        for percent in [1, 25, 100] {
            let memory = Some(ScanMemory { total: u64::MAX, available });
            let budget = ScanResources::Balanced.budget(memory, Some(percent), None);
            let expected = (u128::from(available / 5 * 4) * u128::from(percent) / 100) as u64;
            assert_eq!(
                budget.index_cache_bytes + budget.read_buffer_bytes as u64 + budget.write_view_cache_bytes,
                expected
            );
            assert!(budget.read_buffer_bytes <= 64 * 1024);
            let high = ScanResources::High.budget(memory, Some(percent), None);
            assert_eq!(
                high.index_cache_bytes + high.read_buffer_bytes as u64 + high.write_view_cache_bytes,
                available / 5 * 4
            );
        }
    }
    let fallback = ScanResources::Balanced.budget(None, Some(1), None);
    assert_eq!(
        fallback.index_cache_bytes + fallback.read_buffer_bytes as u64 + fallback.write_view_cache_bytes,
        consistency::INDEX_CACHE_BYTES / 100
    );
    let path = Path::new("/proc/self/slate-nonexistent-scan");
    for percent in [0, 101, 255] {
        let error = online_scan(
            path,
            path,
            path,
            None,
            OnlineScanOptions { memory_percent: Some(percent), ..Default::default() },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
    let high = OnlineScanOptions {
        resources: ScanResources::High,
        memory_percent: Some(1),
        io_priority: Some(ScanIoPriority::Low),
        ..Default::default()
    };
    assert_eq!(high.memory_percent(), None);
    assert_eq!(high.io_priority(), None);
}

#[test]
fn io_priority_is_applied_to_this_thread_and_restored_on_success_error_and_panic() {
    let current = || {
        let value = unsafe { libc::syscall(libc::SYS_ioprio_get, 1, 0) };
        assert!(value >= 0, "{}", io::Error::last_os_error());
        value
    };
    let original = current();
    for priority in [ScanIoPriority::Low, ScanIoPriority::Normal, ScanIoPriority::High] {
        let mut guard = ScanPriorityGuard::enter(priority).unwrap();
        assert_eq!(current(), i64::from(priority.encoded()));
        guard.restore().unwrap();
        assert_eq!(current(), original);
    }
    let parent = original;
    std::thread::spawn(move || {
        let _guard = ScanPriorityGuard::enter(ScanIoPriority::Low).unwrap();
        assert_eq!(current(), i64::from(ScanIoPriority::Low.encoded()));
    })
    .join()
    .unwrap();
    assert_eq!(current(), parent);
    let path = Path::new("/proc/self/slate-nonexistent-scan");
    assert!(online_scan(
        path,
        path,
        path,
        None,
        OnlineScanOptions { io_priority: Some(ScanIoPriority::Low), ..Default::default() }
    )
    .is_err());
    assert_eq!(current(), original);
    let result = std::panic::catch_unwind(|| {
        let _guard = ScanPriorityGuard::enter(ScanIoPriority::Low).unwrap();
        panic!("scan priority unwind control");
    });
    assert!(result.is_err());
    assert_eq!(current(), original);
}

#[test]
fn memory_budgets_reserve_headroom_and_reduce_under_pressure() {
    let gib = 1024 * 1024 * 1024;
    let memory = Some(ScanMemory { total: 16 * gib, available: 10 * gib });
    let balanced = ScanResources::Balanced.budget(memory, None, None);
    let high = ScanResources::High.budget(memory, None, None);
    assert_eq!(
        balanced.index_cache_bytes + balanced.read_buffer_bytes as u64 + balanced.write_view_cache_bytes,
        2 * gib
    );
    assert_eq!(high.index_cache_bytes + high.read_buffer_bytes as u64 + high.write_view_cache_bytes, 8 * gib);
    for available in [0, 1000, 64 * 1024, 300 * 1024 * 1024, gib, u64::MAX] {
        for profile in [ScanResources::Balanced, ScanResources::High] {
            let budget = profile.budget(Some(ScanMemory { total: 16 * gib, available }), None, None);
            assert!(
                budget.index_cache_bytes + budget.read_buffer_bytes as u64 + budget.write_view_cache_bytes
                    <= available.min(16 * gib) / 5 * 4
            );
            assert!(budget.read_buffer_bytes <= profile.read_buffer_bytes());
        }
    }
    assert_eq!(
        ScanResources::Balanced.budget(None, None, None).index_cache_bytes
            + ScanResources::Balanced.budget(None, None, None).read_buffer_bytes as u64,
        64 * 1024 * 1024
    );
    assert_eq!(
        ScanResources::High.budget(None, None, None).index_cache_bytes
            + ScanResources::High.budget(None, None, None).read_buffer_bytes as u64,
        256 * 1024 * 1024
    );
    assert!(parse_scan_memory("MemTotal: 100 kB\nMemAvailable: 10 kB\n").is_some());
    assert!(parse_scan_memory("MemTotal: 100 kB\n").is_none());
    assert!(parse_scan_memory("MemTotal: 18446744073709551615 kB\nMemAvailable: 1 kB").is_none());
    assert!(parse_scan_memory("MemTotal: 10 bytes\nMemAvailable: 1 kB").is_none());
}

#[test]
fn cgroup_memory_honors_ancestor_limits_usage_and_pressure() {
    let root = std::env::temp_dir().join(format!("slate-cgroup-memory-{}", std::process::id()));
    let group = root.join("parent/child");
    std::fs::create_dir_all(&group).unwrap();
    let parent = group.parent().unwrap();
    for directory in [&root, parent, &group] {
        std::fs::write(directory.join("memory.max"), "max").unwrap();
        std::fs::write(directory.join("memory.high"), "max").unwrap();
    }
    std::fs::write(parent.join("memory.max"), "1000").unwrap();
    std::fs::write(parent.join("memory.current"), "950").unwrap();
    std::fs::write(group.join("memory.high"), "500").unwrap();
    std::fs::write(group.join("memory.current"), "100").unwrap();
    let host = ScanMemory { total: 10000, available: 5000 };
    let memory = cgroup_scan_memory(host, &root, &group, true).unwrap();
    assert_eq!((memory.total, memory.available), (500, 50));
    let mounts = format!("1 0 0:1 / {} rw - cgroup2 cgroup2 rw\n", root.display());
    let mapped = constrain_scan_memory(host, "0::/parent/child\n", &mounts).unwrap();
    assert_eq!((mapped.total, mapped.available), (500, 50));
    assert!(constrain_scan_memory(host, "0::/../outside\n", &mounts).is_none());
    let missing = constrain_scan_memory(host, "0::/missing\n", &mounts).unwrap();
    assert_eq!(ScanResources::High.budget(Some(missing), None, None).index_cache_bytes, 0);
    std::fs::write(parent.join("memory.current"), "1001").unwrap();
    assert_eq!(cgroup_scan_memory(host, &root, &group, true).unwrap().available, 0);
    std::fs::write(parent.join("memory.current"), "malformed").unwrap();
    let unknown_usage = cgroup_scan_memory(host, &root, &group, true).unwrap();
    assert_eq!((unknown_usage.total, unknown_usage.available), (500, 0));
    for profile in [ScanResources::Balanced, ScanResources::High] {
        let budget = profile.budget(Some(unknown_usage), None, None);
        assert_eq!(budget.index_cache_bytes, 0);
        assert_eq!(budget.read_buffer_bytes, 0);
    }
    let mapped = constrain_scan_memory(host, "0::/parent/child\n", &mounts).unwrap();
    assert_eq!(ScanResources::High.budget(Some(mapped), None, None).index_cache_bytes, 0);
    std::fs::write(parent.join("memory.max"), "invalid").unwrap();
    let mapped = constrain_scan_memory(host, "0::/parent/child\n", &mounts).unwrap();
    assert_eq!((mapped.total, mapped.available), (500, 0));
    std::fs::write(parent.join("memory.limit_in_bytes"), "1000").unwrap();
    std::fs::write(parent.join("memory.usage_in_bytes"), "900").unwrap();
    let memory = cgroup_scan_memory(host, &root, &group, false).unwrap();
    assert_eq!((memory.total, memory.available), (1000, 100));
    assert_eq!(memory_mount_path(r"/sys/cgroup\040memory").unwrap(), Path::new("/sys/cgroup memory"));
    assert!(memory_mount_path(r"/sys/cgroup\999").is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn exhausted_memory_reads_requested_bytes_without_prefetch() {
    let budget = ScanResources::High.budget(Some(ScanMemory { total: 1000, available: 0 }), None, None);
    let mut image = ScanImage::with_budget(CountedRead::new(65536), budget);
    let mut bytes = [0; 1024];
    image.read_exact_at(1024, &mut bytes).unwrap();
    assert_eq!(image.source.read_bytes, bytes.len());
    assert!(image.buffer.is_empty());
    assert_eq!(bytes[0], (1024 % 251) as u8);
}

struct CountedRead {
    bytes: std::io::Cursor<Vec<u8>>,
    calls: usize,
    read_bytes: usize,
    bad_start: Option<u64>,
    short_limit: usize,
    interrupt: bool,
}

impl CountedRead {
    fn new(length: usize) -> Self {
        Self {
            bytes: std::io::Cursor::new((0..length).map(|n| (n % 251) as u8).collect()),
            calls: 0,
            read_bytes: 0,
            bad_start: None,
            short_limit: usize::MAX,
            interrupt: false,
        }
    }
}

impl Read for CountedRead {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if std::mem::take(&mut self.interrupt) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let length = output.len().min(self.short_limit);
        if self.bad_start.is_some_and(|bad| self.bytes.position().saturating_add(length as u64) > bad) {
            return Err(io::ErrorKind::Other.into());
        }
        let count = self.bytes.read(&mut output[..length])?;
        self.read_bytes += count;
        Ok(count)
    }
}

impl Seek for CountedRead {
    fn seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(offset)
    }
}

#[test]
fn high_resources_reduce_sequential_reads_without_amplifying_random_reads() {
    let sequential = |resources: ScanResources| {
        let mut image = ScanImage::with_budget(CountedRead::new(8 * 1024 * 1024), resources.budget(None, None, None));
        for offset in (0..8 * 1024 * 1024).step_by(1024) {
            let mut output = [0; 1024];
            image.read_exact_at(offset, &mut output).unwrap();
            assert_eq!(output, image.source.bytes.get_ref()[offset as usize..offset as usize + 1024]);
            assert!(image.buffer.len() <= resources.read_buffer_bytes());
        }
        (image.source.calls, image.source.read_bytes)
    };
    let balanced = sequential(ScanResources::Balanced);
    let high = sequential(ScanResources::High);
    assert!(high.0 < balanced.0, "high={high:?} balanced={balanced:?}");
    assert_eq!(high.1, balanced.1);
    for resources in [ScanResources::Balanced, ScanResources::High] {
        let mut image = ScanImage::with_budget(CountedRead::new(8 * 1024 * 1024), resources.budget(None, None, None));
        for offset in [0, 4194304, 1048576, 6291456, 2097152] {
            let mut output = [0; 1024];
            image.read_exact_at(offset, &mut output).unwrap();
            assert_eq!(output, image.source.bytes.get_ref()[offset as usize..offset as usize + 1024]);
        }
        assert_eq!(image.source.read_bytes, 5 * 65536);
    }
}

#[test]
fn prefetch_errors_retry_only_the_requested_span_and_never_reuse_failed_bytes() {
    for resources in [ScanResources::Balanced, ScanResources::High] {
        let mut source = CountedRead::new(262144);
        source.bad_start = Some(2000);
        source.interrupt = true;
        let mut image = ScanImage::with_budget(source, resources.budget(None, None, None));
        let mut output = [0; 1024];
        image.read_exact_at(0, &mut output).unwrap();
        assert_eq!(output, image.source.bytes.get_ref()[..1024]);
        assert_eq!(image.valid, 0);
        assert!(image.read_exact_at(1800, &mut output).is_err());
        image.read_exact_at(0, &mut output).unwrap();
        assert_eq!(output, image.source.bytes.get_ref()[..1024]);
        image.source.bad_start = None;
        image.source.short_limit = 17;
        image.read_exact_at(8000, &mut output).unwrap();
        assert_eq!(output, image.source.bytes.get_ref()[8000..9024]);
    }
}

#[test]
fn scan_buffers_preserve_random_reads_and_recover_after_short_reads() {
    let mut source = consistency::scratch_file().unwrap();
    let bytes: Vec<u8> = (0..(5 * 1024 * 1024)).map(|n| (n % 251) as u8).collect();
    source.write_all(&bytes).unwrap();
    for resources in [ScanResources::Balanced, ScanResources::High] {
        source.seek(SeekFrom::Start(0)).unwrap();
        let mut image = ScanImage::with_budget(source.try_clone().unwrap(), resources.budget(None, None, None));
        for (offset, length) in
            [(0, 32), (100, 1024), (20, 70), (65500, 200), (4194200, 400), (0, 1024), (1048576, 65536)]
        {
            let mut actual = vec![0; length];
            image.read_exact_at(offset as u64, &mut actual).unwrap();
            assert_eq!(actual, bytes[offset..offset + length]);
        }
        assert!(image.read_exact_at(bytes.len() as u64 - 4, &mut [0; 8]).is_err());
        let mut actual = [0; 64];
        image.read_exact_at(24, &mut actual).unwrap();
        assert_eq!(actual, bytes[24..88]);
        assert!(image.read_exact_at(u64::MAX, &mut [0; 1]).is_err());
        image.read_exact_at(100, &mut actual).unwrap();
        assert_eq!(actual, bytes[100..164]);
    }
}

#[test]
fn a_new_scan_buffer_reads_metadata_changed_between_snapshots() {
    let mut source = consistency::scratch_file().unwrap();
    source.write_all(&[1; 8192]).unwrap();
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut image = ScanImage::with_budget(source.try_clone().unwrap(), ScanResources::High.budget(None, None, None));
    image.read_exact_at(0, &mut [0; 8]).unwrap();
    drop(image);
    source.seek(SeekFrom::Start(64)).unwrap();
    source.write_all(&[2; 8]).unwrap();
    source.seek(SeekFrom::Start(0)).unwrap();
    let mut fresh = ScanImage::with_budget(source.try_clone().unwrap(), ScanResources::High.budget(None, None, None));
    let mut actual = [0; 8];
    fresh.read_exact_at(64, &mut actual).unwrap();
    assert_eq!(actual, [2; 8]);
}

#[test]
#[ignore = "requires SLATE_SCAN_RESOURCE_SOURCE with an immutable NTFS image"]
fn resource_profiles_preserve_full_quick_findings_and_queue_bytes() {
    let path = std::path::PathBuf::from(std::env::var_os("SLATE_SCAN_RESOURCE_SOURCE").unwrap());
    let boot = probe(&path).unwrap().boot;
    let directory = std::env::temp_dir().join(format!("slate-resource-queue-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let parent = File::open(&directory).unwrap();
    for index_check in [consistency::IndexCheck::Full, consistency::IndexCheck::Quick] {
        for index_cache_passes in [
            consistency::IndexCachePasses::Auto,
            consistency::IndexCachePasses::Streaming,
            consistency::IndexCachePasses::Count(std::num::NonZeroU16::new(3).unwrap()),
        ] {
            let mut expected = None;
            for (resources, budget) in
                [ScanResources::Balanced, ScanResources::High].into_iter().flat_map(|resources| {
                    [
                        None,
                        Some(ScanMemory { total: 8 * 1024 * 1024 * 1024, available: 6 * 1024 * 1024 * 1024 }),
                        Some(ScanMemory { total: 1024 * 1024, available: 1024 }),
                        Some(ScanMemory { total: 1024 * 1024, available: 0 }),
                    ]
                    .into_iter()
                    .map(move |memory| (resources, resources.budget(memory, None, None)))
                })
            {
                let policy = consistency::AuditOptions { index_check, index_cache_passes, ..Default::default() };
                let started = std::time::Instant::now();
                let mut audit = consistency::audit_reader(
                    ScanImage::open(&path, budget).unwrap(),
                    boot,
                    |_, _, _| Ok(()),
                    |_| Ok(()),
                    policy,
                    budget.index_cache_bytes,
                )
                .unwrap();
                eprintln!(
                    "scan_resource={} index_check={:?} cache_policy={:?} read_budget={} cache_budget={} elapsed_us={}",
                    resources.name(),
                    index_check,
                    index_cache_passes,
                    budget.read_buffer_bytes,
                    budget.index_cache_bytes,
                    started.elapsed().as_micros()
                );
                let mut findings = Vec::new();
                audit
                    .for_each_finding(|code, record, error, detail| {
                        findings.push((code.to_owned(), record, error, detail.to_owned()));
                        Ok(())
                    })
                    .unwrap();
                assert!(!findings.is_empty(), "fixture must contain at least one defect");
                let digest = worklist_digest(audit.worklist_file().unwrap()).unwrap();
                let queue = directory.join(format!("{}-queue", resources.name()));
                let mut status = consistency::OnlineRepairStatus {
                    scan_resources: resources,
                    scan_budget: budget,
                    ..Default::default()
                };
                queue_scan_findings(
                    &queue,
                    &parent,
                    42,
                    boot,
                    &mut audit,
                    &mut status,
                    OnlineScanOptions { force_offline_fix: true, index_audit: policy, resources, ..Default::default() },
                )
                .unwrap();
                let queue_bytes = std::fs::read(&queue).unwrap();
                std::fs::remove_file(queue).unwrap();
                let result = (audit.complete, audit.errors, findings, digest, queue_bytes);
                if let Some(expected) = &expected {
                    assert_eq!(&result, expected);
                } else {
                    expected = Some(result);
                }
                let mut report = Vec::new();
                audit.online_repair = Some(status);
                audit.write_json(&mut report).unwrap();
                let report = String::from_utf8(report).unwrap();
                assert!(report.contains(&format!("\"scan_resources\":\"{}\"", resources.name())));
                assert!(report.contains(&format!("\"scan_index_cache_bytes\":{}", budget.index_cache_bytes)));
                assert!(report.contains(&format!("\"scan_read_buffer_bytes\":{}", budget.read_buffer_bytes)));
            }
        }
    }
    std::fs::remove_dir(directory).unwrap();
}
