#!/usr/bin/env python3
"""Module: checker_fsck_policy_tests
Purpose: Verify that read-only assessment and recovery status select fsck repair correctly.
Created: 2026-10-01
Architecture: Mutates private fixture copies and invokes both production binaries;
    device-claim and journal interruption tests require a separate Linux device host.
"""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from test_readonly_assessment import Image, digest, integer, put


def run(binary, arguments, expected):
    result = subprocess.run(
        [str(binary), *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == expected, (
        arguments, result.returncode, result.stdout, result.stderr
    )
    return {
        "arguments": list(map(str, arguments)),
        "exit": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def verify(source, binary, directory):
    original = digest(source)
    clean = directory / "clean.img"
    dirty = directory / "dirty.img"
    shutil.copyfile(source, clean)
    shutil.copyfile(source, dirty)
    image = Image(dirty)
    try:
        volume = image.get(3)
        value = image.value(volume, image.attribute(volume, 0x70))
        put(volume, value + 10, integer(volume, value + 10, 2) | 1, 2)
        image.save(3, volume)
    finally:
        image.file.close()
    before = digest(dirty)
    checker = binary.with_name("ntfs-chkdsk")
    rows = [run(binary, ["--check", clean], 0)]
    # Structural success cannot suppress the dirty-only recovery requirement.
    rows.append(run(checker, ["--check", dirty], 0))
    for flag in ["--check", "-n", "-fn"]:
        rows.append(run(binary, [flag, dirty], 4))
        assert digest(dirty) == before
    pending = directory / "pending.journal"
    pending.write_bytes(b"retained journal evidence")
    rows.append(run(binary, ["--check", "--journal", pending, dirty], 4))
    assert pending.read_bytes() == b"retained journal evidence"
    rows.append(run(binary, ["--check", "--repair", dirty], 16))
    rows.append(run(binary, ["-ny", dirty], 16))
    # A regular image cannot establish the exclusive device claim for repair.
    fresh = directory / "must-not-create.journal"
    rows.append(run(binary, ["--repair", "--journal", fresh, dirty], 8))
    assert not fresh.exists()
    assert digest(dirty) == before
    rows.append(run(binary, ["--repair", clean], 0))
    assert digest(clean) == original
    assert digest(source) == original
    (directory / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(f"fsck policy: {len(rows)} CLI controls passed; all inputs unchanged")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fsck", type=Path, required=True)
    parser.add_argument("--work", type=Path)
    options = parser.parse_args()
    if options.work is not None:
        options.work.mkdir(parents=True, exist_ok=False)
        verify(options.source.resolve(), options.fsck.resolve(), options.work)
    else:
        with tempfile.TemporaryDirectory(prefix="slate-fsck-policy-") as directory:
            verify(options.source.resolve(), options.fsck.resolve(), Path(directory))


if __name__ == "__main__":
    main()
