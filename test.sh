#!/usr/bin/env bash
# Module: tests.selector
# Purpose: run one explicitly selected implementation or integration suite.
# Created: 2026-10-01
# Architecture: dispatches to Rust crate tests and kernel test scripts; each
# suite retains its own host requirements and device isolation checks.

set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

usage() {
    cat <<'USAGE'
Usage: bash test.sh SELECTOR [test arguments]
No selector (or --list) lists choices without running tests. No implicit all.

  unit:MODULE          Shared Rust module, e.g. unit:logfile or unit:security
  utils:lib            ntfs_utils device/discovery unit tests
                       Rust selectors accept an optional test-name filter.
  core:robustness       Malformed parser input
  recovery:metadata    MFT/attribute/runlist/index replay primitives
  recovery:unit DOMAIN [TEST_NAME] [--offline]
                       One recovery namespace; no DOMAIN lists choices only
  recovery:native      Native resident replay images
  recovery:bitmap      Bitmap replay images
  recovery:advanced    LFS 1.1/2.0, spanning/tail/checkpoint/rollback images
  checker:consistency  Allocation/graph/security/mirror diagnostics
  checker:broader      Attribute-list ownership, collation and security inventory
  checker:repair       Copy-only allocation repair and interrupted publication
  checker:filename-cache Cached filename preservation and genuine bitmap repair
  checker:semantic     Quota/object-ID repair and reserved bitmap reconstruction
  checker:repair-expansion IMAGE [--stage EMPTY_DIR] [--in-place]
                       Rescue/$Secure interruption matrix on copies of IMAGE
  checker:status       Dirty status and checker CLI
  checker:capture      Read-only recovery-case capture
  boot:prompt          Optional fsck boot prompt unit tests
  writer:native        Native journaled resident writer
  writer:data          Copy-only data overwrite lab
  writer:lifecycle     Core creation/deletion on SLATE_LIFECYCLE_SOURCE copy
  writer:metadata [DIR] B-tree rename/move, native ACLs, $MFT growth, crash matrix (root)
  writer:namespace-safety DIR Direct-engine descendant-move refusal
  hibernation:corpus   Synthetic corpus verifier
  utils:bindings       Rust/C/Python device bindings (loop tests need root)
  utils:security       Descriptor resolution through C/Python
  format:admin         Formatter/permission APIs (root, disposable images)
  format:geometry      Formatter geometry matrix
  kernel:probe         FFI tests; set NTFS_RS_TEST_IMAGE for image checks
  kernel:images        Disposable parser/FFI read images
  kernel:mount         Live read-only module test (root, matching kernel)
  kernel:permissions   Live permission test (root)
  kernel:permission-callback Real C callback regressions (no root)
  kernel:desktop-permissions Live GIO/Files permissions on a disposable image (root)
  kernel:file-deletion  GIO Trash and deletion, optional Windows fixture (root)
  automount:unit       Mount request identity and credential regressions
  permissions:unit     Permissions manager backend unit tests
  kernel:read-errors   Live device-error test (root, dmsetup)
  kernel:writes DIR    Live write/crash test (root, new output directory)
  kernel:streams DIR   Live allocation/growth/truncation test (root, new directory)
  kernel:namespace DIR Live rename and multi-page transaction interruption tests
  kernel:lifecycle DIR Live file creation/deletion and allocation reuse tests
  kernel:lifecycle-crashes DIR Creation/MFT-growth/deletion interruption recovery
  kernel:acl DIR       Live system.ntfs_security, chown and rename test (root, new directory)
  kernel:volume-flags DIR Journaled mount/unmount flag interruption and mirror recovery
  kernel:compatibility DIR Linux/native policies, modes, names and tree lifecycle
  kernel:application-views DIR Shared writable views and per-application launcher
  kernel:vfs           Full mounted VFS regression (root, disposable image)
  kernel:shutdown      write_inode/freeze/remount-ro/full-sync shutdown lifecycle
  kernel:privileges DIR Explicit SACL/restore grants and default refusal
  kernel:benchmark DIR NTFS-3G comparison (root, new output directory)
  style                Rust formatting check only

Build binaries first with bash build.sh. Tests do not run during a build.
Integration tests use disposable images; live kernel tests need matching KDIR.
USAGE
}

recovery_units() {
    cat <<'DOMAINS'
Recovery unit domains:
  storage plan log transactions dirty replay family growth log_resize
  relocation reserved semantic metadata completion summaries widths
  planner mirror_reconstruction_checks semantic_view_checks
  mft_list_growth_checks split_mft_growth_checks unrecoverable_evidence_checks

Usage: bash test.sh recovery:unit DOMAIN [TEST_NAME] [Cargo options]
       bash test.sh recovery:unit recovery_io::QUALIFIED_FILTER [Cargo options]
The optional test name narrows the selected domain. --offline reaches Cargo.
No domain, --list or --help lists choices without running tests.
DOMAINS
}

selector=${1:---list}
[[ $# == 0 ]] || shift
case "$selector" in
    --list|--help|-h) usage ;;
    unit:*|utils:*)
        # Named integration suites are handled below, rather than as modules.
        case "$selector" in utils:bindings|utils:security) ;;
        *)
            module=${selector#*:}
            [[ "$module" =~ ^[a-z][a-z0-9_]*$ ]] || { echo 'Invalid module name' >&2; exit 2; }
            if [[ "$selector" == unit:* ]]; then
                # Filename views and cache refresh share one physical module.
                [[ "$module" != filename ]] || module=filename_metadata
                source=''
                for group in ondisk engine ops; do
                    if [[ -f "src/$group/$module.rs" ]]; then
                        source="src/$group/$module.rs"
                        break
                    fi
                done
                [[ -n "$source" ]] || { echo "No core module: $module" >&2; exit 2; }
                manifest=Cargo.toml
                filter="format::$module::tests::"
            else
                [[ -f "ntfs_utils/src/$module.rs" ]] || { echo "No utils module: $module" >&2; exit 2; }
                manifest=ntfs_utils/Cargo.toml
                filter="$module::tests::"
                source="ntfs_utils/src/$module.rs"
                [[ "$module" != lib ]] || filter='tests::'
            fi
            grep -Eq '^[[:space:]]*mod tests[[:space:]]*(\{|;)' "$source" || { echo "No unit-test module in $source; use its integration selector from --list" >&2; exit 2; }
            if [[ $# -gt 0 && "$1" != -* ]]; then filter+=$1; shift; fi
            exec cargo test --manifest-path "$manifest" --lib --locked "$filter" "$@"
        esac ;;
esac
case "$selector" in
    --list|--help|-h) exit 0 ;;
    recovery:unit)
        domain=${1:---list}
        [[ $# == 0 ]] || shift
        case "$domain" in
            --list|--help|-h|--offline)
                recovery_units
                exit 0
                ;;
            storage|plan|log|transactions|dirty|replay|family|growth|log_resize|relocation|reserved|semantic|metadata|completion|summaries|widths)
                filter="recovery_io::models::$domain::"
                ;;
            mirror_reconstruction_checks|semantic_view_checks|mft_list_growth_checks|split_mft_growth_checks|unrecoverable_evidence_checks)
                filter="recovery_io::$domain::"
                ;;
            planner) filter='recovery_io::recovery_semantic_checks::' ;;
            recovery_io::*) filter="$domain" ;;
            *)
                echo "Unknown recovery domain: $domain (use recovery:unit --list)" >&2
                exit 2
                ;;
        esac
        if [[ $# -gt 0 && "$1" != -* ]]; then
            test_name=$1
            shift
            # Resolve names inside this domain before running exact matches;
            # nested external test modules need not share one tests namespace.
            cargo_options=()
            for argument in "$@"; do
                [[ "$argument" != -- ]] || break
                cargo_options+=("$argument")
            done
            test_list=$(cargo test --manifest-path src/tools/Cargo.toml \
                --lib --locked "$filter" "${cargo_options[@]}" -- --list)
            matches=()
            while IFS= read -r entry; do
                [[ "$entry" == "$filter"* && "$entry" == *': test' ]] || continue
                name=${entry%: test}
                [[ "$name" != *"$test_name"* ]] || matches+=("$name")
            done <<< "$test_list"
            [[ ${#matches[@]} -gt 0 ]] || {
                echo "No recovery tests match $domain / $test_name" >&2
                exit 2
            }
            test_options=("$@")
            if [[ " ${test_options[*]} " == *' -- '* ]]; then
                test_options+=(--exact)
            else
                test_options+=(-- --exact)
            fi
            for name in "${matches[@]}"; do
                cargo test --manifest-path src/tools/Cargo.toml \
                    --lib --locked "$name" "${test_options[@]}"
            done
            exit 0
        fi
        exec cargo test --manifest-path src/tools/Cargo.toml --lib --locked "$filter" "$@"
        ;;
    core:robustness) exec cargo test --test robustness --locked "$@" ;;
    recovery:metadata) exec cargo test --manifest-path src/tools/Cargo.toml --test metadata_replay --locked "$@" ;;
    recovery:native) exec python3 src/tests/recovery/test_native_replay.py "$@" ;;
    recovery:bitmap) exec python3 src/tests/recovery/test_bitmap_replay.py "$@" ;;
    recovery:advanced) exec python3 src/tests/recovery/test_advanced_replay.py "$@" ;;
    checker:consistency) exec python3 src/tests/checker/test_consistency.py "$@" ;;
    checker:repair) exec python3 src/tests/checker/test_repair.py "$@" ;;
    checker:filename-cache) exec python3 src/tests/checker/test_filename_cache.py "$@" ;;
    checker:semantic) exec python3 src/tests/checker/test_semantic_repair.py "$@" ;;
    checker:repair-expansion) exec python3 src/tests/checker/test_repair_expansion.py "$@" ;;
    checker:broader) exec python3 src/tests/checker/test_broader_consistency.py "$@" ;;
    checker:status) exec bash src/tests/checker/test_checkfs.sh "$@" ;;
    checker:capture) exec bash src/tests/checker/test_recovery_case.sh "$@" ;;
    boot:prompt) exec cargo test --manifest-path src/tools/Cargo.toml --bin fsck_ntfsrs --locked 'tests::' "$@" ;;
    writer:native) exec python3 src/tests/writer/test_native_writer.py "$@" ;;
    writer:data) exec bash src/tests/writer/test_write_lab.sh "$@" ;;
    writer:lifecycle) exec cargo test --test writer_lifecycle --locked "$@" ;;
    writer:metadata) exec python3 src/tests/writer/test_metadata_writer.py "$@" ;;
    writer:namespace-safety) exec python3 src/tests/writer/test_namespace_safety.py "$@" ;;
    hibernation:corpus) exec python3 src/tests/hibernation/test_hibernation_corpus_tool.py "$@" ;;
    utils:bindings) exec bash ntfs_utils/tests/test_bindings.sh "$@" ;;
    utils:security) exec python3 ntfs_utils/tests/test_security_store.py "$@" ;;
    format:admin) exec python3 ntfs_utils/tests/test_format_admin.py "$@" ;;
    format:geometry) exec python3 ntfs_utils/tests/test_format_geometries.py "$@" ;;
    kernel:probe) exec cargo test --test kernel_probe --locked "$@" ;;
    kernel:images) exec bash kernel/tests/test_image_reads.sh "$@" ;;
    kernel:mount) exec bash kernel/tests/test_wsl_module.sh "$@" ;;
    kernel:permissions) exec bash kernel/tests/test_kernel_permissions.sh "$@" ;;
    kernel:permission-callback) exec python3 kernel/tests/test_permission_callback.py "$@" ;;
    kernel:desktop-permissions) exec python3 kernel/tests/test_desktop_permissions.py "$@" ;;
    kernel:file-deletion) exec python3 kernel/tests/test_file_deletion.py "$@" ;;
    automount:unit) exec cargo test --manifest-path ntfs_utils/Cargo.toml --bin ntfs-automount --locked "$@" ;;
    permissions:unit) exec cargo test --manifest-path permissions/rust/Cargo.toml --lib --no-default-features --locked "$@" ;;
    kernel:read-errors) exec bash kernel/tests/test_kernel_read_errors.sh "$@" ;;
    kernel:writes) exec python3 kernel/tests/test_kernel_writes.py "$@" ;;
    kernel:streams) exec python3 kernel/tests/test_kernel_streams.py "$@" ;;
    kernel:namespace) exec python3 kernel/tests/test_kernel_namespace.py "$@" ;;
    kernel:lifecycle) exec python3 kernel/tests/test_kernel_lifecycle.py "$@" ;;
    kernel:lifecycle-crashes) exec python3 kernel/tests/test_kernel_lifecycle_crashes.py "$@" ;;
    kernel:acl) exec python3 kernel/tests/test_kernel_acl.py "$@" ;;
    kernel:volume-flags) exec python3 kernel/tests/test_kernel_volume_flags.py "$@" ;;
    kernel:compatibility) exec python3 kernel/tests/test_linux_compatibility.py "$@" ;;
    kernel:application-views) exec python3 kernel/tests/test_application_views.py "$@" ;;
    kernel:vfs) exec python3 kernel/tests/test_kernel_vfs.py "$@" ;;
    kernel:shutdown) exec python3 kernel/tests/test_kernel_shutdown.py "$@" ;;
    kernel:privileges) exec python3 kernel/tests/test_security_privileges.py "$@" ;;
    kernel:benchmark) exec bash kernel/tests/benchmark_reads.sh "$@" ;;
    style)
        cargo fmt --all -- --check
        cargo fmt --manifest-path src/tools/Cargo.toml -- --check
        cargo fmt --manifest-path ntfs_utils/Cargo.toml -- --check
        cargo fmt --manifest-path kernel/rust/Cargo.toml -- --check
        cargo fmt --manifest-path permissions/rust/Cargo.toml -- --check
        # Cargo only discovers registered targets and their modules. Also check
        # standalone fixtures and adapter sources, retaining vendor formatting.
        mapfile -d '' -t rust_sources < <(
            find src kernel ntfs_utils permissions examples \
                -type d \( -name target -o -name vendor \) -prune -o \
                -type f -name '*.rs' -print0
        )
        rustfmt --edition 2021 --config skip_children=true --check "${rust_sources[@]}" ;;
    *) echo "Unknown selector: $selector (use --list)" >&2; exit 2 ;;
esac
