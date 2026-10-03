// Module: slate_ntfs_tools::recovery_io::plan_support
// Purpose: Provide test-only accessors and adapters for recovery regressions.
// Created: 2026-10-02
// Architecture: Included only under cfg(test) in the original owning scope;
// production module files contain no test-only helper implementations.

impl RepairPlan {
    pub(crate) fn payload_len(&self) -> u64 {
        self.storage.borrow().payload.length
    }
}
