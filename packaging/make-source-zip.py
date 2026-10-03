#!/usr/bin/env python3
"""
Module: packaging.make_source_zip
Purpose: Archive the complete working source without local build products.
Created: 2026-09-30
Architecture: Reads the package version from Cargo.toml and preserves source
paths and file modes for standalone source snapshots.
"""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
import os
import sys
import tomllib


root = Path(__file__).resolve().parents[1]
with (root / "Cargo.toml").open("rb") as manifest:
    version = tomllib.load(manifest)["package"]["version"]
archive_root = f"slate-ntfs-{version}"
destination = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) > 1
    else root.parent.parent / "outputs" / f"{archive_root}-source.zip"
)
destination.parent.mkdir(parents=True, exist_ok=True)
skip_dirs = {".git", "target", "__pycache__", ".pytest_cache", ".tmp_versions"}
skip_names = {"Module.symvers", "modules.order", "core_fingerprint.h"}
skip_suffixes = {
    ".ko", ".o", ".cmd", ".pyc", ".so", ".exe", ".dll", ".pdb",
    ".zip", ".img", ".qcow2", ".deb", ".mod",
}
count = 0
with ZipFile(destination, "w", ZIP_DEFLATED, compresslevel=6) as archive:
    for directory, children, files in os.walk(root):
        parent = Path(directory)
        children[:] = sorted(child for child in children if child not in skip_dirs)
        if parent == root / "tests":
            children[:] = [child for child in children if child not in {"results", "benchmarks"}]
        for filename in sorted(files):
            source = parent / filename
            if (
                filename in skip_names
                or source.suffix in skip_suffixes
                or filename.endswith(".mod.c")
            ):
                continue
            relative = source.relative_to(root)
            archive.write(source, Path(archive_root) / relative)
            count += 1
print(f"{destination}: {count} files, {destination.stat().st_size} bytes")
