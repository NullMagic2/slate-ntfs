//! Module: ntfs_chkdsk
//! Purpose: Parse Linux-style commands and report checking and recovery results.
//! Created: 2026-09-30
//! Architecture: Calls checker and recovery_io; those modules own validation,
//!     repair planning and durable disk writes.

use slate_ntfs_tools::checker::consistency::{self, Audit, AuditOptions, IndexCachePasses, IndexCheck};
use slate_ntfs_tools::recovery_io::CompletionMode;
use slate_ntfs_tools::{checker, offline_check, recovery_io, recovery_journal};

use ntfs_rs::hibernation::HibernationState;
use ntfs_rs::logfile::LogState;
use std::env;
use std::ffi::OsString;
use std::fmt::Display;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const EXIT_FINDINGS: i32 = 4;
const EXIT_FAILURE: i32 = 8;
const EXIT_USAGE: i32 = 16;
const KIB: u64 = 1024;
const MIB: u64 = KIB * KIB;
const GIB: u64 = MIB * KIB;
const MIN_LOG_BYTES: u64 = 2 * MIB;
const MAX_PERCENT: u8 = 100;
const SHA256_BYTES: usize = 32;
const HEX_DIGITS_PER_BYTE: usize = 2;
const HIBERNATION_SAMPLE_BYTES: usize = 4096;

const USAGE: &str = "\
usage: ntfs-chkdsk [--check|--audit|--status|--recovery-status|--log-inventory|--replay-plan|--validate-replay|--hibernation-page|--plan-hibernation-discard] <NTFS image or device>
       ntfs-chkdsk [--force] [--log PATH] --repair UNMOUNTED_DEVICE (complete check and repair; exit 0 clean, 1 repaired, 4 unresolved)
       ntfs-chkdsk --replay-to SOURCE_IMAGE NEW_IMAGE
       ntfs-chkdsk [--rescan-bad] [--security-cleanup] --repair-to SOURCE_IMAGE NEW_IMAGE (offline structural repair)
       ntfs-chkdsk --repair-plan SOURCE_IMAGE
       ntfs-chkdsk --log-size SOURCE_IMAGE
       ntfs-chkdsk [--progress] --resize-log SIZE SOURCE_IMAGE NEW_IMAGE (SIZE in bytes, K, M, or G)
       ntfs-chkdsk [--progress] --resize-log-in-place|--resume-log-resize SIZE UNMOUNTED_DEVICE EXTERNAL_JOURNAL
       ntfs-chkdsk [--json] [--skip-cycles] [--index-check=full|quick] [--index-cache-passes=auto|0|N] --check SOURCE_IMAGE
       ntfs-chkdsk [--progress] --surface-check SOURCE (allocated and free sectors)
       ntfs-chkdsk [--progress] --recover-for-mount UNMOUNTED_DEVICE (supported journal recovery only)
       ntfs-chkdsk [--progress] --replay-in-place|--resume-replay UNMOUNTED_DEVICE EXTERNAL_JOURNAL
       ntfs-chkdsk --validate-replay-completion SOURCE (read-only writable-candidate validation)
       ntfs-chkdsk --validate-runlist-widths SOURCE --record NUMBER --record-sha256 HASH [--volume-serial HEX] (read-only)
       ntfs-chkdsk [--progress] --repair-runlist-widths|--resume-runlist-widths UNMOUNTED_DEVICE --record NUMBER --record-sha256 HASH --journal EXTERNAL_JOURNAL [--volume-serial HEX]
       add --normalize-aliases to those commands for checked same-directory filename/index namespace corrections
       ntfs-chkdsk --repair-evidence SOURCE_IMAGE NEW_EVIDENCE_FILE
       ntfs-chkdsk [--progress] --rescue-to|--resume-rescue SOURCE EXTERNAL_ARCHIVE
       ntfs-chkdsk --extract-rescue EXTERNAL_ARCHIVE NEW_IMAGE (requires every sector)
       ntfs-chkdsk [--progress] --reintegrate-rescue SOURCE EXTERNAL_ARCHIVE NEW_IMAGE
       ntfs-chkdsk [--progress] --repair-rescue-to SOURCE ARCHIVE NEW_IMAGE
       ntfs-chkdsk [--progress] --recover-to|--resume-recovery SOURCE NEW_IMAGE --archive ARCHIVE --loss-map LOSS_MAP (explicit file loss possible)
       ntfs-chkdsk [--progress] --recover-in-place|--resume-device-recovery UNMOUNTED_DEVICE --archive ARCHIVE --loss-map LOSS_MAP --journal JOURNAL
       ntfs-chkdsk --repair-in-place|--resume-repair UNMOUNTED_DEVICE EXTERNAL_JOURNAL
       ntfs-chkdsk --online-check MOUNTPOINT DEVICE (pauses writes during audit)
       ntfs-chkdsk [--defer-repairs] [--scan-resources=balanced|high] [--scan-memory-percent=1..100] [--scan-io-priority=low|normal|high] [--scan-write-cache-size=SIZE] --online-scan MOUNTPOINT DEVICE EXTERNAL_QUEUE
       ntfs-chkdsk --spotfix UNMOUNTED_DEVICE EXTERNAL_QUEUE EXTERNAL_JOURNAL
       ntfs-chkdsk --online-repair-ea MOUNTED_PATH (Slate EA summary only)
       ntfs-chkdsk --online-repair-data MOUNTED_PATH (pauses writes; one DATA interval)
       ntfs-chkdsk --online-repair-allocation MOUNTPOINT BITMAP_BYTE_OFFSET (aligned to 512)
       ntfs-chkdsk --capabilities (JSON coverage and validation limits)
Prefixes: --json for a read-only full check; --progress for check and offline repair phase/sector progress;
       --log PATH before --check, --audit, --online-check, or --online-scan saves all findings.
";

const CAPABILITIES: &str = concat!(
    "{",
    "\"version\":\"0.7.0\"",
    ",\"check_json\":true",
    ",\"full_finding_report\":true",
    ",\"full_api_findings\":true",
    ",\"optional_report_log\":true",
    ",\"repair_progress\":\"phase-sector-coverage\"",
    ",\"copy_repair\":true",
    ",\"offline_in_place\":true",
    ",\"resume\":true",
    ",\"disk_backed_audit\":true",
    ",\"index_check_modes\":[\"full\",\"quick\"]",
    ",\"index_cache_passes\":true",
    ",\"disk_backed_structural_plan\":true",
    ",\"unrecoverable_evidence_export\":true",
    ",\"sector_rescue_archive\":true",
    ",\"rescue_extraction\":true",
    ",\"badclus_rescue_repair\":\"existing-and-new-extension-family-and-readable-owners\"",
    ",\"secure_root_repair\":\"base-record-and-index-allocation\"",
    ",\"raw_log_transfer\":\"changed-clusters-only\"",
    ",\"split_mft_mapping\":true",
    ",\"directory_index_allocation\":true",
    ",\"extension_family_repair\":true",
    ",\"physical_extent_relocation\":true",
    ",\"fragmented_log_publication\":true",
    ",\"unknown_log_operations\":\"refused\"",
    ",\"online_audit\":true",
    ",\"scan_resources\":[\"balanced\",\"high\"]",
    ",\"scan_memory_percent\":[1,100]",
    ",\"scan_write_cache_bytes\":[1310720,134217728]",
    ",\"scan_io_priority\":[\"low\",\"normal\",\"high\"]",
    ",\"force_offline_fix\":true",
    ",\"queued_spotfix\":true",
    ",\"spotfix_preflight\":true",
    ",\"online_repairs\":[\"ea-summary\",\"ea-orphan\",\"referenced-allocation\",\"bounded-data-crosslink\"]",
    ",\"system_metadata_audit\":[\"object-id\",\"quota\",\"usn\",\"reparse\",\"attribute-definitions\"]",
    ",\"filename_metadata_repair\":true",
    ",\"nameless_file_recovery\":true",
    ",\"reparse_index_repair\":true",
    ",\"quota_topology_recovery\":\"intact-allocated-control-pages\"",
    ",\"fragmented_system_index_repair\":true",
    ",\"security_cleanup\":\"copy-repair-option\"",
    ",\"bad_cluster_rescan\":\"complete-copy-read-required\"",
    ",\"surface_check\":true",
    ",\"log_size_query\":true",
    ",\"runtime_validated\":false",
    ",\"full_chkdsk_replacement\":false",
    ",\"copy_log_resize\":true",
    ",\"offline_log_resize\":true",
    ",\"log_resize_resume\":true",
    "}\n",
);

fn usage() -> ! {
    eprint!("{USAGE}");
    std::process::exit(EXIT_USAGE);
}

fn refuse(reason: &str) -> ! {
    eprintln!("{reason}");
    usage();
}

fn fail_code(code: i32, context: &str, error: impl Display) -> ! {
    eprintln!("ntfs-chkdsk: {context}: {error}");
    std::process::exit(code);
}

fn fail(context: &str, error: impl Display) -> ! {
    fail_code(EXIT_FAILURE, context, error);
}

// Unwrap a backend result; the context names the operation in the message.
fn finish<T>(result: io::Result<T>, context: &str) -> T {
    result.unwrap_or_else(|error| fail(context, error))
}

fn exit_unless(passed: bool) {
    if !passed {
        std::process::exit(EXIT_FINDINGS);
    }
}

struct Arguments(std::iter::Peekable<std::vec::IntoIter<OsString>>);

impl Arguments {
    fn value(&mut self) -> OsString {
        self.0.next().unwrap_or_else(|| usage())
    }

    fn path(&mut self) -> PathBuf {
        PathBuf::from(self.value())
    }

    fn text(&mut self) -> String {
        self.value().into_string().unwrap_or_else(|_| usage())
    }

    fn end(&mut self) {
        if self.0.next().is_some() {
            usage();
        }
    }
}

fn parse_option<T>(value: &str, prefix: &str, parse: impl FnOnce(&str) -> Option<T>) -> Option<T> {
    let value = value.strip_prefix(prefix)?;
    Some(parse(value).unwrap_or_else(|| usage()))
}

fn print_findings(audit: &Audit) {
    finish(audit.write_report(&mut io::stdout().lock()), "audit findings");
}

fn print_json(write: impl FnOnce(&mut io::StdoutLock<'static>) -> io::Result<()>) {
    let mut output = io::stdout().lock();
    finish(write(&mut output).and_then(|()| output.write_all(b"\n")), "JSON report");
}

fn print_audit(audit: &Audit, json: bool, summary: impl FnOnce(&Audit)) {
    if json {
        print_json(|output| audit.write_json(output));
    } else {
        print_findings(audit);
        summary(audit);
    }
    exit_unless(audit.passed());
}

fn main() {
    let all: Vec<_> = env::args_os().skip(1).collect();
    slate_ntfs_tools::bitlocker_cli::refuse_encrypted("ntfs-chkdsk", all.iter().map(|a| a.as_os_str()));
    let mut args = Arguments(all.into_iter().peekable());
    let mut check_options = AuditOptions::default();
    let mut index_options_set = false;
    let mut json = false;
    let mut show_progress = false;
    let mut force = false;
    let mut scan_options = checker::OnlineScanOptions::default();
    let mut scan_resources_set = false;
    let mut maintenance = recovery_io::RepairOptions::default();
    let mut log_path: Option<PathBuf> = None;
    while let Some(value) = args.0.peek().and_then(|a| a.to_str()).map(str::to_owned) {
        let value = value.as_str();
        if let Some(mode) = parse_option(value, "--index-check=", |mode| match mode {
            "full" => Some(IndexCheck::Full),
            "quick" => Some(IndexCheck::Quick),
            _ => None,
        }) {
            check_options.index_check = mode;
            index_options_set = true;
        } else if let Some(passes) = parse_option(value, "--index-cache-passes=", IndexCachePasses::parse) {
            check_options.index_cache_passes = passes;
            index_options_set = true;
        } else if let Some(resources) = parse_option(value, "--scan-resources=", checker::ScanResources::parse) {
            scan_options.resources = resources;
            scan_resources_set = true;
        } else if let Some(percent) = parse_option(value, "--scan-memory-percent=", |text| {
            text.parse::<u8>().ok().filter(|value| (1..=MAX_PERCENT).contains(value))
        }) {
            scan_options.memory_percent = Some(percent);
            scan_resources_set = true;
        } else if let Some(priority) = parse_option(value, "--scan-io-priority=", checker::ScanIoPriority::parse) {
            scan_options.io_priority = Some(priority);
            scan_resources_set = true;
        } else if let Some(bytes) = parse_option(value, "--scan-write-cache-size=", checker::scan_write_cache_size) {
            scan_options.write_cache_bytes = Some(bytes);
            scan_resources_set = true;
        } else {
            match value {
                "--skip-cycles" => check_options.skip_directory_cycles = true,
                "--json" => json = true,
                "--progress" => show_progress = true,
                "--force" => force = true,
                "--defer-repairs" => scan_options.force_offline_fix = true,
                "--rescan-bad" => maintenance.rescan_bad_clusters = true,
                "--security-cleanup" => maintenance.cleanup_security = true,
                "--log" if log_path.is_none() => {
                    args.0.next();
                    log_path = Some(args.path());
                    continue;
                }
                "--log" => usage(),
                _ => break,
            }
        }
        args.0.next();
    }
    let first = args.value();
    let command = first.to_str().unwrap_or("");
    let is_command = |allowed: &[&str]| !command.starts_with('-') || allowed.contains(&command);
    if check_options.skip_directory_cycles && !is_command(&["--check", "--audit", "--online-check"]) {
        refuse("--skip-cycles requires a read-only check or audit");
    }
    let index_commands = [
        "--check",
        "--audit",
        "--repair-to",
        "--repair-plan",
        "--repair-in-place",
        "--resume-repair",
        "--online-check",
        "--online-scan",
    ];
    if index_options_set && !is_command(&index_commands) {
        refuse("index checking options require a check, audit, scan or offline repair command");
    }
    maintenance.index_audit = check_options;
    scan_options.index_audit = check_options;
    if scan_resources_set && command != "--online-scan" {
        refuse("scan resource options require --online-scan MOUNTPOINT DEVICE EXTERNAL_QUEUE");
    }
    if scan_options.force_offline_fix && command != "--online-scan" {
        refuse("--defer-repairs requires --online-scan MOUNTPOINT DEVICE EXTERNAL_QUEUE");
    }
    if (maintenance.rescan_bad_clusters || maintenance.cleanup_security) && command != "--repair-to" {
        refuse("maintenance prefixes require --repair-to SOURCE NEW_IMAGE");
    }
    if json && !matches!(command, "--log-size" | "--capabilities" | "--online-scan" | "--online-check") {
        let path = match command {
            "--check" | "--audit" => args.path(),
            _ if command.starts_with('-') => usage(),
            _ => PathBuf::from(&first),
        };
        args.end();
        let report = finish(checker::check_device(&path, check_options, log_path.as_deref()), "check");
        print_json(|output| report.write_json(output));
        exit_unless(report.passed());
        return;
    }
    let mut progress = |value: recovery_io::RepairProgress| {
        if show_progress {
            eprintln!("{value}");
        }
    };
    let progress: &mut dyn FnMut(recovery_io::RepairProgress) = &mut progress;
    match command {
        "--log-size" => {
            let source = args.path();
            args.end();
            let size = finish(
                checker::probe(&source)
                    .and_then(|probe| checker::inspect_logfile_size(checker::Image::open(&source)?, probe.boot)),
                "log size",
            );
            if json {
                println!(
                    "{{\"log_size_bytes\":{},\"allocated_bytes\":{},\"initialized_bytes\":{},\"default_bytes\":{}}}",
                    size.data_bytes, size.allocated_bytes, size.initialized_bytes, size.default_bytes,
                );
            } else {
                println!(
                    "log_size_bytes={} log_size_kib={} allocated_bytes={} initialized_bytes={} default_bytes={} \
                     default_kib={} source_unchanged=1",
                    size.data_bytes,
                    size.data_bytes / KIB,
                    size.allocated_bytes,
                    size.initialized_bytes,
                    size.default_bytes,
                    size.default_bytes / KIB,
                );
            }
        }
        "--capabilities" => {
            args.end();
            print!("{CAPABILITIES}");
        }
        "--resize-log-in-place" | "--resume-log-resize" | "--resize-log" => {
            let bytes = parse_log_size(&args.text()).unwrap_or_else(|error| fail_code(EXIT_USAGE, "log size", error));
            let source = args.path();
            let target = args.path();
            args.end();
            if log_path.is_some() {
                usage();
            }
            if command == "--resize-log" {
                let stop = test_flush_boundary();
                let result = recovery_io::resize_log_to(&source, &target, bytes, stop, progress);
                finish(result, "resize log");
                println!("log_size_bytes={bytes} source_unchanged=1");
            } else {
                let resume = command == "--resume-log-resize";
                let result = recovery_io::resize_log_in_place(&source, &target, bytes, resume, progress);
                finish(result, "resize log in place");
                println!("log_size_bytes={bytes} resize_complete=1 preimages_retained=1");
            }
        }
        "--recover-for-mount" => {
            let source = args.path();
            args.end();
            if let Err(error) = recover_for_mount(source.clone(), progress) {
                // Journal recovery never repairs structures; name the command that does.
                let hint = if error.to_string().contains("structural repair is required") {
                    format!("; run: ntfs-chkdsk --repair {}", source.display())
                } else {
                    String::new()
                };
                fail("journal recovery", format!("{error}; writable admission remains required{hint}"));
            }
            println!("journal_recovery_complete=1 writable_candidate_validated=1");
        }
        "--replay-in-place" | "--resume-replay" => {
            let source = args.path();
            let journal = args.path();
            args.end();
            let resume = command == "--resume-replay";
            let result = std::fs::canonicalize(&source).and_then(|source| {
                recovery_io::replay_in_place(&source, &journal, resume, CompletionMode::Replay(None), progress)
            });
            if let Err(error) = result {
                fail("journal replay", format!("{error}; journal retained when present"));
            }
            println!("journal_recovery_complete=1 writable_candidate_validated=1");
        }
        "--validate-runlist-widths" | "--repair-runlist-widths" | "--resume-runlist-widths" => {
            if log_path.is_some() || json {
                usage();
            }
            runlist_widths(command, &mut args, progress);
        }
        "--validate-replay-completion" => {
            let source = args.path();
            args.end();
            finish(recovery_io::validate_replay(&source, CompletionMode::Replay(None)), "replay completion validation");
        }
        "--surface-check" => {
            let source = args.path();
            args.end();
            let report = finish(
                recovery_io::surface_check(&source, progress, &mut |offset, length| {
                    println!("unreadable_range offset={offset} length={length}");
                }),
                "surface check",
            );
            println!(
                "surface_check_complete=1 total_bytes={} unreadable_bytes={} source_unchanged=1 io_error_count={}",
                report.total_bytes, report.unreadable_bytes, report.io_error_count,
            );
            exit_unless(report.unreadable_bytes == 0);
        }
        "--rescue-to" | "--resume-rescue" => {
            let source = args.path();
            let archive = args.path();
            args.end();
            let resume = command == "--resume-rescue";
            let unresolved = recovery_io::rescue_to_with_progress(&source, &archive, resume, progress)
                .unwrap_or_else(|error| fail("rescue", format!("{error}; archive retained")));
            println!("rescue_scan_complete=1 unresolved_sectors={unresolved} sector_bytes=512 archive_is_volume=0");
            exit_unless(unresolved == 0);
        }
        "--extract-rescue" => {
            let archive = args.path();
            let destination = args.path();
            args.end();
            let sectors = finish(recovery_io::extract_rescue_to(&archive, &destination), "rescue extract");
            println!("rescue_extract_complete=1 sectors={sectors} sector_bytes=512");
        }
        "--reintegrate-rescue" | "--repair-rescue-to" => {
            let source = args.path();
            let archive = args.path();
            let destination = args.path();
            args.end();
            if command == "--reintegrate-rescue" {
                let sectors = recovery_io::reintegrate_rescue_to(&source, &archive, &destination, progress)
                    .unwrap_or_else(|error| fail("rescue reintegration", format!("{error}; archive retained")));
                println!("rescue_reintegration_complete=1 sectors={sectors} sector_bytes=512");
            } else {
                let sectors =
                    recovery_io::repair_rescue_to(&source, &archive, &destination, progress).unwrap_or_else(|error| {
                        fail("rescue repair", format!("{error}; archive and private image retained"))
                    });
                println!("rescue_repair_complete=1 sectors={sectors} sector_bytes=512");
            }
        }
        "--recover-in-place" | "--resume-device-recovery" => {
            let source = args.path();
            let [archive, loss_map, journal] = named_paths(&mut args, &["--archive", "--loss-map", "--journal"]);
            let resume = command == "--resume-device-recovery";
            let report =
                recover_in_place(source, archive, loss_map, journal, resume, progress).unwrap_or_else(|error| {
                    fail("device recovery", format!("{error}; archive, loss map and journal retained when present"))
                });
            print_file_recovery("device_recovery_complete=1 ", &report);
        }
        "--recover-to" | "--resume-recovery" => {
            let source = args.path();
            let destination = args.path();
            let [archive, loss_map] = named_paths(&mut args, &["--archive", "--loss-map"]);
            let resume = command == "--resume-recovery";
            let report = recovery_io::recover_rescue_to(&source, &archive, &loss_map, &destination, resume, progress)
                .unwrap_or_else(|error| {
                    fail("file recovery", format!("{error}; archive and private evidence retained"))
                });
            print_file_recovery("", &report);
        }
        "--online-repair-allocation" => {
            let mount = args.path();
            let logical = args.text().parse::<u64>().unwrap_or_else(|_| usage());
            args.end();
            let changed = finish(checker::online_repair_allocation_sector(&mount, logical), "online allocation repair");
            println!("online_repair_complete=1 changes={} operation=allocation", u8::from(changed));
        }
        "--online-repair-ea" | "--online-repair-data" => {
            let path = args.path();
            args.end();
            let operation = u8::from(command == "--online-repair-data");
            let flags = finish(checker::online_repair(&path, operation), "online repair");
            println!("online_repair_complete=1 changes={flags} operation={operation}");
        }
        "--online-scan" => {
            let mount = args.path();
            let device = args.path();
            let queue = args.path();
            args.end();
            let audit =
                finish(checker::online_scan(&mount, &device, &queue, log_path.as_deref(), scan_options), "online scan");
            print_audit(&audit, json, |audit| {
                let queued = audit.online_repair.as_ref().is_some_and(|status| status.queue_written);
                println!(
                    "online_scan_complete={} errors={} queued={} findings={} omitted_findings=0",
                    u8::from(audit.complete),
                    audit.errors,
                    u8::from(queued),
                    audit.finding_count
                );
            });
        }
        "--spotfix" => {
            let device = args.path();
            let queue = args.path();
            let journal = args.path();
            args.end();
            finish(recovery_io::spotfix_in_place(&device, &queue, &journal, progress), "spotfix");
            println!("spotfix_complete=1 preimages_retained=1");
        }
        "--freeze-guard" => {
            let mount = args.path();
            let expected = args.text().parse::<u64>().unwrap_or_else(|_| usage());
            args.end();
            finish(checker::freeze_guard(&mount, expected), "online audit");
        }
        "--online-check" => {
            let mount = args.path();
            let device = args.path();
            args.end();
            let audit =
                finish(checker::online_audit(&mount, &device, check_options, log_path.as_deref()), "online audit");
            print_audit(&audit, json, |audit| {
                println!("online_audit_complete={} errors={} writes_resumed=1", u8::from(audit.complete), audit.errors);
            });
        }
        "--repair-in-place" | "--resume-repair" => {
            let source = args.path();
            let journal = args.path();
            args.end();
            let resume = command == "--resume-repair";
            finish(recovery_io::repair_in_place(&source, &journal, resume, progress, maintenance), "repair");
            println!("repair_complete=1 preimages_retained=1");
        }
        "--repair-evidence" => {
            let source = args.path();
            let destination = args.path();
            args.end();
            finish(recovery_io::export_repair_evidence(&source, &destination), "repair evidence");
            println!("evidence_exported=1 repair_complete=0 source_unchanged=1");
        }
        "--replay-to" => {
            let source = args.path();
            let destination = args.path();
            args.end();
            if let Err(error) = recovery_io::replay_to(&source, &destination, test_flush_boundary()) {
                fail("replay-to", format!("{error}; any partial output remains dirty"));
            }
        }
        "--repair-to" => {
            let source = args.path();
            let destination = args.path();
            args.end();
            let stop = test_flush_boundary();
            if let Err(error) = recovery_io::repair_to(&source, &destination, stop, progress, maintenance) {
                fail("repair-to", format!("{error}; inspect any NEW_IMAGE.repair-incomplete before use"));
            }
            println!("repair_supported=1 repair_complete=1");
        }
        "--help" => print!("{USAGE}"),
        _ => {
            let (mode, path) = match command {
                _ if !command.starts_with('-') => ("--check", PathBuf::from(&first)),
                "--check"
                | "--audit"
                | "--validate-replay"
                | "--status"
                | "--recovery-status"
                | "--log-inventory"
                | "--replay-plan"
                | "--hibernation-page"
                | "--plan-hibernation-discard"
                | "--repair"
                | "--repair-plan" => (command, args.path()),
                _ => usage(),
            };
            args.end();
            if mode == "--repair" {
                repair(path, log_path, force);
            }
            if force {
                refuse("--force requires --repair UNMOUNTED_DEVICE");
            }
            inspect(mode, &path, log_path, check_options, maintenance, progress);
        }
    }
}

fn recover_for_mount(source: PathBuf, progress: &mut dyn FnMut(recovery_io::RepairProgress)) -> io::Result<()> {
    // Resolve aliases once; the backend claims the resulting block
    // device exclusively before planning or replaying retained work.

    let source = std::fs::canonicalize(&source)?;
    let pending = recovery_journal::pending(&source, recovery_journal::JournalKind::Replay)?;
    let mut expected_serial = None;
    if pending.is_none() {
        let probe = checker::probe(&source)?;
        expected_serial = Some(probe.boot.serial_number);
        let recovery = checker::inspect_recovery(checker::Image::open(&source)?, probe.boot)?;
        if !probe.info.needs_check() && recovery.log != LogState::ReplayRequired {
            return Err(io::Error::other("no pending journal recovery; writable admission failed for another reason"));
        }
    }
    let resume = pending.is_some();
    let journal = match pending {
        Some(journal) => journal,
        None => recovery_journal::new(&source, recovery_journal::JournalKind::Replay)?,
    };
    eprintln!("ntfs-chkdsk: supported journal recovery; journal={}", journal.display());
    let result = recovery_io::replay_in_place(&source, &journal, resume, CompletionMode::Replay(expected_serial), progress);
    // A device someone else holds was never read; there is nothing to save.
    let busy = result.as_ref().is_err_and(|error| error.raw_os_error() == Some(libc::EBUSY));
    if let (Err(error), false, false) = (&result, resume, busy) {
        // A refusal writes nothing to the volume, and the journal it would
        // replay may later be replayed elsewhere. Keep a copy so the refusal
        // can be reproduced and fixed offline.
        let mut capture = journal.clone().into_os_string();
        capture.push(".refused");
        match recovery_io::capture_refused_log(&source, Path::new(&capture), &error.to_string()) {
            Ok(()) => eprintln!("ntfs-chkdsk: refused journal saved to {}", Path::new(&capture).display()),
            Err(capture_error) => eprintln!("ntfs-chkdsk: could not save the refused journal: {capture_error}"),
        }
    }
    result
}

fn recover_in_place(
    source: PathBuf,
    archive: PathBuf,
    loss_map: PathBuf,
    journal: PathBuf,
    resume: bool,
    progress: &mut dyn FnMut(recovery_io::RepairProgress),
) -> io::Result<recovery_io::FileRecoveryReport> {
    use std::os::unix::fs::FileTypeExt;

    let source = std::fs::canonicalize(&source)?;
    if !std::fs::metadata(&source)?.file_type().is_block_device() {
        return Err(io::Error::other("in-place recovery requires an unmounted block/loop device"));
    }
    if !resume {
        // Retained capture is resumed only after its original identity
        // and every durable good payload agree with the current source.

        recovery_io::rescue_to_with_progress(&source, &archive, recovery_journal::exists(&archive)?, progress)?;
    }
    recovery_io::recover_archive_in_place(&source, &archive, &loss_map, &journal, resume, progress)
}

fn print_file_recovery(prefix: &str, report: &recovery_io::FileRecoveryReport) {
    println!(
        "{prefix}metadata_consistent=1 recovered_bytes={} unreadable_bytes={} lost_file_bytes={} \
         encoded_storage_loss_bytes={} affected_compressed_bytes={} surface_clean=0 loss_map_required=1",
        report.recovered_bytes,
        report.unreadable_bytes,
        report.lost_file_bytes,
        report.encoded_storage_loss_bytes,
        report.affected_compressed_bytes,
    );
    exit_unless(!report.has_data_loss());
}

// Collect each named path option exactly once; every name is required.
fn named_paths<const N: usize>(args: &mut Arguments, names: &[&str; N]) -> [PathBuf; N] {
    let mut values: [Option<PathBuf>; N] = std::array::from_fn(|_| None);
    while let Some(option) = args.0.next() {
        let slot = names
            .iter()
            .position(|name| option == **name)
            .filter(|&slot| values[slot].is_none())
            .unwrap_or_else(|| usage());
        values[slot] = Some(args.path());
    }
    values.map(|value| value.unwrap_or_else(|| usage()))
}

fn runlist_widths(command: &str, args: &mut Arguments, progress: &mut dyn FnMut(recovery_io::RepairProgress)) {
    let source = args.path();
    let mut record = None;
    let mut raw_sha256 = None;
    let mut expected_serial = None;
    let mut journal = None;
    let mut normalize_aliases = false;
    while let Some(option) = args.0.next() {
        match option.to_str() {
            Some("--normalize-aliases") if !normalize_aliases => normalize_aliases = true,
            Some("--record") if record.is_none() => {
                record = Some(args.text().parse::<u64>().unwrap_or_else(|_| usage()));
            }
            Some("--record-sha256") if raw_sha256.is_none() => raw_sha256 = Some(parse_sha256(&args.text())),
            Some("--volume-serial") if expected_serial.is_none() => {
                let text = args.text();
                let serial = u64::from_str_radix(text.trim_start_matches("0x"), 16);
                expected_serial = Some(serial.unwrap_or_else(|_| usage()));
            }
            Some("--journal") if journal.is_none() => journal = Some(args.path()),
            _ => usage(),
        }
    }
    let target = recovery_io::WidthRepairTarget {
        record: record.unwrap_or_else(|| usage()),
        raw_sha256: raw_sha256.unwrap_or_else(|| usage()),
        expected_serial,
    };
    let mode =
        if normalize_aliases { CompletionMode::WidthsAndAliases(target) } else { CompletionMode::Widths(target) };
    let result = if command == "--validate-runlist-widths" {
        if journal.is_some() {
            usage();
        }
        recovery_io::validate_replay(&source, mode)
    } else {
        let journal = journal.unwrap_or_else(|| usage());
        recovery_io::replay_in_place(&source, &journal, command == "--resume-runlist-widths", mode, progress)
    };
    finish(result, "mapping-width recovery");
    if command != "--validate-runlist-widths" {
        println!("mapping_width_recovery_complete=1 writable_candidate_validated=1 preimages_retained=1");
    }
}

fn parse_sha256(text: &str) -> [u8; SHA256_BYTES] {
    if text.len() != SHA256_BYTES * HEX_DIGITS_PER_BYTE || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        usage();
    }
    std::array::from_fn(|index| {
        let start = index * HEX_DIGITS_PER_BYTE;
        u8::from_str_radix(&text[start..start + HEX_DIGITS_PER_BYTE], 16).unwrap_or_else(|_| usage())
    })
}

/// The complete check and repair of one unmounted device, as fsck.ntfsrs
/// --repair runs it; each step is this same command run as a child.
fn repair(device: PathBuf, log: Option<PathBuf>, force: bool) -> ! {
    let request = offline_check::Request {
        device,
        journal: None,
        log,
        force,
        checker: finish(std::env::current_exe(), "cannot locate this command"),
        program: "ntfs-chkdsk",
    };
    std::process::exit(finish(offline_check::run(request, Some(&mut |_, _| true)), "repair"))
}

// Read-only inspection commands share one probe and recovery assessment.
fn inspect(
    mode: &str,
    path: &std::path::Path,
    log_path: Option<PathBuf>,
    check_options: AuditOptions,
    maintenance: recovery_io::RepairOptions,
    progress: &mut dyn FnMut(recovery_io::RepairProgress),
) {
    match mode {
        "--repair-plan" => {
            if let Err(error) = recovery_io::describe_repair(path, maintenance) {
                eprintln!("repair_supported=0\nreason={error}");
                std::process::exit(EXIT_FINDINGS);
            }
            return;
        }
        "--validate-replay" => {
            if let Err(error) = recovery_io::describe_plan(path) {
                eprintln!("replay_supported=0\nreason={error}");
                std::process::exit(EXIT_FINDINGS);
            }
            return;
        }
        "--hibernation-page" => {
            let mut bytes = [0_u8; HIBERNATION_SAMPLE_BYTES];
            let mut file = finish(std::fs::File::open(path), "cannot read hibernation sample");
            if !file.metadata().is_ok_and(|meta| meta.is_file() && meta.len() == HIBERNATION_SAMPLE_BYTES as u64) {
                eprintln!("ntfs-chkdsk: hibernation sample must be exactly 4096 bytes");
                std::process::exit(EXIT_FAILURE);
            }
            finish(file.read_exact(&mut bytes), "cannot read hibernation sample");
            let state = ntfs_rs::hibernation::classify_header(&bytes);
            println!("hibernation_state={}", hibernation_label(state));
            return;
        }
        _ => {}
    }
    let probe = finish(checker::probe(path), "cannot inspect volume");
    let dirty = u8::from(probe.info.is_dirty());
    if mode == "--status" {
        println!("dirty={dirty}");
        return;
    }
    let mut audit = || {
        let result = consistency::audit_with_progress(path, probe.boot, check_options, progress);
        // The scans are over either way; the report that follows is not progress.
        progress(recovery_io::RepairProgress::new(recovery_io::Phase::Complete, 0, 0));
        finish(
            result.and_then(|audit| {
                if let Some(log) = &log_path {
                    audit.save_report(log)?;
                }
                Ok(audit)
            }),
            if mode == "--audit" { "audit incomplete" } else { "consistency audit incomplete" },
        )
    };
    if mode == "--audit" {
        let report = audit();
        println!("audit_complete={}", u8::from(report.complete));
        println!(
            "allocated_records={} directories={} directory_entries={} descriptors={}",
            report.allocated_records, report.directories, report.directory_entries, report.descriptors
        );
        println!("referenced_clusters={} allocated_clusters={}", report.referenced_clusters, report.allocated_clusters);
        print_findings(&report);
        println!("findings={} omitted_findings=0 errors={}", report.finding_count, report.errors);
        println!("dirty={dirty}");
        exit_unless(report.passed());
        println!("ntfs-chkdsk: cross-checks passed; this is not authorization to write or clear the dirty flag");
        return;
    }
    let recovery = checker::Image::open(path)
        .and_then(|image| checker::inspect_recovery(image, probe.boot))
        .unwrap_or_else(|error| fail_code(EXIT_FINDINGS, "recovery inspection failed", error));
    let log_status = match recovery.log {
        LogState::Uninitialized => "uninitialized",
        LogState::NoActiveClients => "no-active-clients",
        LogState::CheckedVolume => "checked-volume",
        LogState::CleanShutdown => "clean-shutdown",
        LogState::ReplayRequired => "replay-required",
        LogState::NeedsReview => "needs-review",
    };
    println!("log_state={log_status}");
    println!("hibernation_file_present={}", u8::from(recovery.hibernation != HibernationState::Absent));
    println!("hibernation_state={}", hibernation_label(recovery.hibernation));
    match mode {
        "--recovery-status" => {
            println!("dirty={dirty}");
            return;
        }
        "--plan-hibernation-discard" => {
            if recovery.hibernation != HibernationState::ActiveImage {
                eprintln!("ntfs-chkdsk: a recognized active hibernation image is required");
                std::process::exit(EXIT_FINDINGS);
            }
            let plan = checker::inspect_hiber_delete_plan(path, probe.boot)
                .unwrap_or_else(|error| fail_code(EXIT_FINDINGS, "cannot plan hibernation discard", error));
            println!("hiber_mft_number={}", plan.mft_number);
            println!("hiber_sequence={}", plan.sequence);
            println!("hiber_data_bytes={}", plan.data_bytes);
            println!("hiber_clusters={}", plan.clusters);
            println!("hiber_runs={}", plan.runs);
            println!("discard_ready=0");
            return;
        }
        "--log-inventory" | "--replay-plan" => {
            print_log_inventory(path, probe.boot, recovery.log, mode == "--replay-plan");
            return;
        }
        _ => {}
    }
    let report = audit();
    println!(
        "audit_complete={} findings={} omitted_findings=0 errors={}",
        u8::from(report.complete),
        report.finding_count,
        report.errors
    );
    print_findings(&report);
    exit_unless(report.passed());
    let records = checker::audit_mft_records(path, probe.boot)
        .unwrap_or_else(|error| fail_code(EXIT_FINDINGS, "MFT audit failed", error));
    println!(
        "MFT: {} allocated records, {} attributes, {} security IDs, {} slots",
        records.allocated_records, records.attributes, records.security_references, records.record_slots
    );
    let count = checker::check_known_structures(path, probe.boot)
        .unwrap_or_else(|error| fail_code(EXIT_FINDINGS, "root index check failed", error));
    println!("Root index: {count} reachable entries checked");
    // The same judgement the one-command repair uses: our own empty
    // checkpoint keeps an active journal client and still needs nothing.
    if finish(offline_check::requests_attention(path), "cannot inspect recovery state") {
        println!("write_ready=0 recovery_prerequisites_unresolved=1");
    }
    println!("ntfs-chkdsk: checked structures passed; full consistency is not yet established");
}

fn print_log_inventory(path: &std::path::Path, boot: ntfs_rs::boot::BootSector, log: LogState, plan: bool) {
    if log == LogState::Uninitialized {
        println!("log_inventory=uninitialized");
        return;
    }
    let inventory = checker::inspect_log_inventory(path, boot)
        .unwrap_or_else(|error| fail_code(EXIT_FINDINGS, "log inventory failed", error));
    println!("log_pages_scanned={}", inventory.scanned_pages);
    println!("record_pages={}", inventory.record_pages);
    println!("records={}", inventory.records);
    println!("metadata_intents={}", inventory.metadata_intents);
    println!("control_records={}", inventory.control_records);
    println!("unresolved_pages={}", inventory.unresolved_pages);
    println!("invalid_pages={}", inventory.invalid_pages);
    if plan {
        println!("client_restart_lsn={}", inventory.restart_lsn);
        println!("client_oldest_lsn={}", inventory.client_oldest_lsn);
        println!("client_sequence={}", inventory.client_sequence);
        println!("restart_page_count={}", inventory.restart_page_count);
        println!("restart_page_position={}", inventory.restart_page_position);
        println!("restart_record_valid={}", u8::from(inventory.restart_record_valid));
        println!("multi_page_sets={}", inventory.multi_page_sets);
        println!("continuation_pages={}", inventory.continuation_pages);
        println!("checkpoint_found={}", u8::from(inventory.checkpoint.is_some()));
        println!("checkpoint_tables_referenced={}", inventory.checkpoint_tables_referenced);
        println!("checkpoint_tables_validated={}", inventory.checkpoint_tables_validated);
        println!("checkpoint_table_mask={}", inventory.checkpoint_table_mask);
        if let Some(checkpoint) = inventory.checkpoint {
            println!("checkpoint_start_lsn={}", checkpoint.start_lsn);
            println!("open_attributes_bytes={}", checkpoint.open_attributes_bytes);
            println!("attribute_names_bytes={}", checkpoint.attribute_names_bytes);
            println!("dirty_pages_bytes={}", checkpoint.dirty_pages_bytes);
            println!("transactions_bytes={}", checkpoint.transactions_bytes);
        }
    }
    println!("replay_ready=0");
}

fn hibernation_label(state: HibernationState) -> &'static str {
    match state {
        HibernationState::Absent => "absent",
        HibernationState::ActiveImage => "active-image",
        HibernationState::InterruptedResume => "interrupted-resume",
        HibernationState::InvalidatedImage => "invalidated-image",
        HibernationState::ZeroedHeader => "zeroed-header",
        HibernationState::Unknown => "unknown",
    }
}

fn test_flush_boundary() -> Option<usize> {
    let value = env::var_os("SLATE_NTFS_TEST_STOP_AFTER_FLUSH")?;
    let boundary = value.to_str().and_then(|text| text.parse::<usize>().ok()).filter(|&value| value > 0);
    Some(boundary.unwrap_or_else(|| {
        eprintln!("invalid test flush boundary");
        std::process::exit(EXIT_USAGE);
    }))
}

fn parse_log_size(value: &str) -> Result<u64, &'static str> {
    let split = value.find(|c: char| !c.is_ascii_digit()).unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let scale = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kib" => KIB,
        "m" | "mib" => MIB,
        "g" | "gib" => GIB,
        _ => return Err("use bytes or a K, M, G, KiB, MiB, or GiB suffix"),
    };
    let bytes =
        number.parse::<u64>().ok().and_then(|n| n.checked_mul(scale)).ok_or("invalid or overflowing log size")?;
    if !(MIN_LOG_BYTES..=u64::from(u32::MAX)).contains(&bytes) || bytes % KIB != 0 {
        return Err("log size must be a multiple of 1 KiB, at least 2 MiB, and below 4 GiB");
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "../../tests/checker/log_size_arguments.rs"]
mod log_size_arguments;
