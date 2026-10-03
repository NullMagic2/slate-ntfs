#!/usr/bin/env python3
"""
Module: src.tests.checker.test_badclus_extension
Purpose: Force $BadClus mapping pairs beyond one MFT record on a disposable image.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Force $BadClus mapping pairs beyond one MFT record on a disposable image.
"""
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import ROOT, CHECKER, u, attr, first_extent, decode, digest
from test_repair_expansion import entry


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError((result.returncode, result.stdout, result.stderr))
    return result


def main():
    with tempfile.TemporaryDirectory(prefix="slate-many-bad-") as td:
        source, archive, output = (pathlib.Path(td) / name for name in
                                   ("source.img", "many.rescue", "repaired.img"))
        with source.open("wb") as file:
            file.truncate(64 << 20)
        run(ROOT / "ntfs_utils/target/release/ntfs-format", source, "--yes", "--quick")
        before = digest(source)
        run(CHECKER, "--rescue-to", source, archive)
        with source.open("rb") as file:
            boot = file.read(512)
            cluster_bytes = u(boot, 11, 2) * boot[13]
            mft = u(boot, 48, 8) * cluster_bytes
            record_bytes = 1 << -int.from_bytes(boot[64:65], "little", signed=True)
            file.seek(mft + 6 * record_bytes)
            bitmap = decode(file.read(record_bytes))
            lcn, _ = first_extent(bitmap, attr(bitmap, 0x80))
            file.seek(lcn * cluster_bytes)
            bits = file.read((64 << 20) // cluster_bytes // 8)
        free = [number for number in range(16, len(bits) * 8)
                if number % 3 == 0 and not bits[number // 8] & (1 << (number % 8))][:300]
        assert len(free) == 300
        with archive.open("ab") as file:
            for number in free:
                file.write(entry(number * cluster_bytes, cluster_bytes, 5))
        run(CHECKER, "--repair-rescue-to", source, archive, output)
        run(CHECKER, "--audit", output)
        assert digest(source) == before, "source changed"
    print("PASS: 300 scattered $BadClus entries repaired through extension records")


if __name__ == "__main__":
    main()
