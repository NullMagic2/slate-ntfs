#!/usr/bin/env bash
# Module: clean_build
# Purpose: Remove compiler outputs and Python bytecode caches.
# Created: 2026-10-02
# Architecture: Coordinates cleanup for each independent crate without changing handwritten sources.

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if ! command -v cargo >/dev/null 2>&1; then
    echo 'error: cargo is required' >&2
    exit 1
fi

cargo clean
cargo clean --manifest-path ntfs_utils/Cargo.toml
cargo clean --manifest-path kernel/rust/Cargo.toml
# Tests now live with their implementations; remove only Python bytecode caches.
find src/tests kernel/tests ntfs_utils/tests tests -type f -path '*/__pycache__/*.pyc' -delete
find src/tests kernel/tests ntfs_utils/tests tests -depth -type d -name __pycache__ -empty -delete
rm -f -- ntfs_utils/python/ntfs_utils/libntfs_utils.so
if [[ -d ntfs_utils/python/ntfs_utils/__pycache__ ]]; then
    rm -f -- ntfs_utils/python/ntfs_utils/__pycache__/*.pyc
    rmdir -- ntfs_utils/python/ntfs_utils/__pycache__
fi

# Kbuild cleanup is confined to this repository and an explicitly selected
# kernel tree. Do not glob or delete outside this tree.
if [[ -f kernel/Makefile && -n "${KDIR:-}" ]]; then
    if [[ ! -f "$KDIR/Makefile" ]]; then
        echo "error: KDIR is not a kernel build tree: $KDIR" >&2
        exit 1
    fi
    make -C "$KDIR" M="$PWD/kernel" clean
fi
rm -f -- kernel/*.o kernel/.*.o kernel/*.ko kernel/*.mod \
    kernel/*.mod.c kernel/Module.symvers kernel/modules.order kernel/.*.cmd
if [[ -d kernel/.tmp_versions ]]; then
    rm -rf -- kernel/.tmp_versions
fi
