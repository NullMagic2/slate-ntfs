// Module: slate_ntfs_tools::recovery_io::coordinator_support
// Purpose: Provide test-only accessors and adapters for recovery regressions.
// Created: 2026-10-02
// Architecture: Included only under cfg(test) in the original owning scope;
// production module files contain no test-only helper implementations.

fn directory_repairs(source: &Path, boot: ntfs_rs::boot::BootSector, patches: &mut RepairPlan) -> io::Result<()> {
    directory_repairs_with_options(
        source,
        boot,
        patches,
        checker::consistency::AuditOptions::default(),
        checker::consistency::scratch_file()?,
        &mut |_| {},
    )
}
