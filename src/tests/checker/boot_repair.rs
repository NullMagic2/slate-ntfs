//! Module: checker.tests.boot_repair
//! Purpose: Reject malformed persistent scheduling identities and unsafe paths.
//! Created: 2026-11-24
//! Architecture: Exercises the shared boot-job decoder; disposable boot guests
//! separately validate device claims, ordering and interruption recovery.

use super::*;

const REQUESTED_LOG_BYTES: u64 = 8 * 1024 * 1024;

fn job() -> Job {
    Job {
        uuid: "0123456789ABCDEF".to_owned(),
        bytes: 64 * 1024 * 1024,
        storage_uuid: "12345678-1234-1234-1234-123456789abc".to_owned(),
        storage_type: "ext4".to_owned(),
        storage_mount: PathBuf::from("/boot"),
        storage_relative: PathBuf::from("slate ntfs/repair"),
        storage_directory: PathBuf::from("/boot/slate ntfs/repair"),
        job_id: "0123456789abcdef0123456789abcdef".to_owned(),
        intent: Intent::default(),
        legacy: false,
    }
}

#[test]
fn persistent_job_round_trip_preserves_stable_volume_and_storage() {
    let job = job();
    let encoded = job.encode().unwrap();
    assert_eq!(Job::decode(&encoded).unwrap(), job);
    assert_eq!(job.device(), Path::new("/dev/disk/by-uuid/0123456789ABCDEF"));
    assert_eq!(
        job.directory(Some(Path::new("/run/store"))),
        Path::new("/run/store/slate ntfs/repair/0123456789ABCDEF/0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn malformed_or_ambiguous_persistent_records_are_refused() {
    let encoded = job().encode().unwrap();
    for replacement in ["", "short", "0123456789ABCDEG", "../0123456789ABCDEF", "0123456789ABCDEF\nextra"] {
        assert!(Job::decode(&encoded.replace("0123456789ABCDEF", replacement)).is_err());
    }
    for broken in
        [encoded.replace(RECORD_VERSION, "UNKNOWN"), format!("{encoded}extra\n"), encoded.replace("ext4", "tmpfs")]
    {
        assert!(Job::decode(&broken).is_err());
    }
    let mut invalid = job();
    invalid.storage_relative = PathBuf::from("../escape");
    assert!(Job::decode(&invalid.encode().unwrap()).is_err());
    invalid.storage_relative = PathBuf::from("/absolute");
    assert!(Job::decode(&invalid.encode().unwrap()).is_err());
    invalid = job();
    invalid.job_id = "../old-request".to_owned();
    assert!(Job::decode(&invalid.encode().unwrap()).is_err());
    invalid = job();
    invalid.storage_directory = PathBuf::from("/another/volume");
    assert!(Job::decode(&invalid.encode().unwrap()).is_err());
}

#[test]
fn systemd_arguments_preserve_spaces_and_escape_expansions() {
    assert_eq!(quote_unit(Path::new("/repair store/100%/a\"b")).unwrap(), "\"/repair store/100%%/a\\\"b\"");
    assert!(quote_unit(Path::new("/repair\nExecStart=/bad")).is_err());
    assert!(unhex("0").is_err());
    assert!(unhex("zz").is_err());
}

#[test]
fn versioned_intent_preserves_index_cache_and_log_size() {
    let mut job = job();
    job.intent.audit.index_check = IndexCheck::Quick;
    job.intent.audit.index_cache_passes = IndexCachePasses::parse("7").unwrap();
    job.intent.log_bytes = Some(REQUESTED_LOG_BYTES);
    assert_eq!(Job::decode(&job.encode().unwrap()).unwrap(), job);
    assert!(operation_matches(
        job.intent,
        "repair",
        Operation::Repair { audit: job.intent.audit, cleanup_security: false }
    ));
    assert!(!operation_matches(
        job.intent,
        "repair",
        Operation::Repair { audit: AuditOptions::default(), cleanup_security: false }
    ));
    assert!(operation_matches(job.intent, "resize", Operation::Resize(REQUESTED_LOG_BYTES)));
    assert!(!operation_matches(job.intent, "resize", Operation::Resize(REQUESTED_LOG_BYTES * 2)));
    assert!(!operation_matches(job.intent, "surface", Operation::Surface(false)));
    assert!(!operation_matches(
        job.intent,
        "verify",
        Operation::Repair { audit: job.intent.audit, cleanup_security: false }
    ));
}

#[test]
fn surface_commands_retain_recovery_mode_and_private_artifact_names() {
    let directory = Path::new("/uncreated-scheduled-test-store");
    for surface in [SurfaceIntent::Recover, SurfaceIntent::Reassess] {
        let mut job = job();
        job.intent.surface = surface;
        assert_eq!(Job::decode(&job.encode().unwrap()).unwrap(), job);
        let command = step_command(&job, directory, "surface").unwrap();
        let arguments: Vec<_> = command.get_args().map(|value| value.to_str().unwrap()).collect();
        assert_eq!(arguments.contains(&"--rescan-bad"), surface == SurfaceIntent::Reassess);
        assert!(arguments.contains(&"--recover-in-place"));
        assert!(arguments.contains(&"/uncreated-scheduled-test-store/surface.archive"));
        assert!(arguments.contains(&"/uncreated-scheduled-test-store/surface.loss-map"));
        assert!(arguments.contains(&"/uncreated-scheduled-test-store/surface.journal"));
        assert!(operation_matches(job.intent, "surface", Operation::Surface(surface == SurfaceIntent::Reassess)));
        assert!(!operation_matches(job.intent, "surface", Operation::Surface(surface != SurfaceIntent::Reassess)));
        assert!(!operation_matches(job.intent, "surface", Operation::Resize(REQUESTED_LOG_BYTES)));
    }
}

#[test]
fn legacy_jobs_mean_only_ordinary_repair() {
    let mut legacy = job();
    legacy.legacy = true;
    let encoded = legacy.encode().unwrap();
    assert!(encoded.starts_with(LEGACY_RECORD_VERSION));
    assert_eq!(Job::decode(&encoded).unwrap(), legacy);
    assert!(Job::decode(&format!("{encoded}reassess\n0\n0\n")).is_err());
    legacy.intent.surface = SurfaceIntent::Reassess;
    assert!(legacy.encode().is_err());
}

#[test]
fn unsupported_maintenance_combinations_are_refused_before_scheduling() {
    let skipped =
        Intent { audit: AuditOptions { skip_directory_cycles: true, ..Default::default() }, ..Default::default() };
    assert!(skipped.validate().unwrap_err().to_string().contains("read-only"));
    let reduced_surface = Intent {
        surface: SurfaceIntent::Recover,
        audit: AuditOptions { index_check: IndexCheck::Quick, ..Default::default() },
        ..Default::default()
    };
    assert!(reduced_surface.validate().is_err());
    assert!(Intent { log_bytes: Some(1), ..Default::default() }.validate().is_err());
    let encoded = job().encode().unwrap();
    assert!(Job::decode(&encoded.replace("\nnone\n", "\nunknown\n")).is_err());
    assert!(Job::decode(
        &encoded.replace(&format!("\n{}\n", AuditOptions::default().index_policy_word()), &format!("\n{}\n", u64::MAX))
    )
    .is_err());
}

#[test]
fn unfinished_publication_cannot_be_skipped_by_changing_the_stage() {
    let directory = std::env::temp_dir().join(format!("slate-scheduled-stage-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    fs::create_dir(directory.join("fsck")).unwrap();
    fs::write(directory.join("fsck/repair.journal"), b"retained").unwrap();
    assert!(validate_pending_stage(&directory, "repair").is_ok());
    for step in ["surface", "resize", "verify", "complete"] {
        assert!(validate_pending_stage(&directory, step).is_err());
    }
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn cleanup_intent_preserves_older_jobs_and_binds_the_repair_stage() {
    let plain = job();
    let old = plain.encode().unwrap();
    assert!(old.starts_with(RECORD_VERSION));
    assert_eq!(Job::decode(&old).unwrap().encode().unwrap(), old);
    let mut requested = job();
    requested.intent.cleanup_security = true;
    let encoded = requested.encode().unwrap();
    assert!(encoded.starts_with(CLEANUP_RECORD_VERSION));
    assert_eq!(Job::decode(&encoded).unwrap(), requested);
    assert!(Job::decode(&encoded.replace(CLEANUP_RECORD_VERSION, RECORD_VERSION)).is_err());
    assert!(Job::decode(encoded.strip_suffix("1\n").unwrap()).is_err());
    let directory = Path::new("/uncreated-cleanup-test-store");
    let repair = step_command(&requested, directory, "repair").unwrap();
    assert!(repair.get_args().any(|arg| arg == "--security-cleanup"));
    let verify = step_command(&requested, directory, "verify").unwrap();
    assert!(!verify.get_args().any(|arg| arg == "--security-cleanup"));
    for cleanup_security in [false, true] {
        let operation = Operation::Repair { audit: requested.intent.audit, cleanup_security };
        assert_eq!(operation_matches(requested.intent, "repair", operation), cleanup_security);
        assert_eq!(operation_matches(plain.intent, "repair", operation), !cleanup_security);
    }
}
