#!/usr/bin/env python3
"""
Module: src.tests.checker.test_repair
Purpose: Copy-only repair on fresh images; independent corruptions and persisted subsets.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Copy-only repair on fresh images; independent corruptions and persisted subsets.
"""
import itertools
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import ROOT, CHECKER, run, u, put, attr, decode, protect, first_extent, digest
from test_consistency import damage


def main():
    count = 0
    with tempfile.TemporaryDirectory(prefix="slate-repair-") as tmp:
        root = Path(tmp)
        for formatter in ("slate", "mkntfs"):
            base = root / (formatter + ".img")
            with base.open("xb") as f:
                f.truncate(128 << 20)
            if formatter == "slate":
                run(ROOT / "ntfs_utils/target/release/ntfs-format", "--yes", "--quick", base)
            else:
                run("mkfs.ntfs", "-F", "-Q", "-L", "SLREPAIR", base)
            run(CHECKER, "--audit", base)
            original = digest(base)
            with base.open("rb") as f:
                boot = f.read(512)
                cluster = u(boot, 11, 2) * boot[13]
                mft = u(boot, 48, 8) * cluster
                record_size = 1 << -int.from_bytes(boot[64:65], "little", signed=True)
                f.seek(mft + 6 * record_size)
                bitmap = decode(f.read(record_size))
                lcn, _ = first_extent(bitmap, attr(bitmap, 0x80))
                physical = lcn * cluster
                f.seek(physical)
                bits = f.read((u(boot, 40, 8) * u(boot, 11, 2) // cluster) // 8)
            occupied = [i for i, b in enumerate(bits) if b]
            offsets = sorted(set([occupied[0], occupied[len(occupied)//2], occupied[-1]]))
            damaged = root / "damaged.img"
            target = root / "repaired.img"

            def repair(image, expected=original):
                nonlocal count
                before = digest(image)
                result = root / "resumed.img" if image.name.endswith(".repair-incomplete") else target
                run(CHECKER, "--repair-to", image, result)
                assert digest(image) == before, "source changed"
                assert digest(result) == expected, "unexpected changed bytes"
                run(CHECKER, "--audit", result)
                assert not Path(str(result) + ".repair-incomplete").exists()
                result.unlink()
                count += 1

            repair(base)  # no-op must be byte-identical
            # Every persisted subset of three separate bitmap writes, including
            # all lost and all durable. A surviving write only reserves ownership.
            for surviving in itertools.product((False, True), repeat=len(offsets)):
                shutil.copyfile(base, damaged)
                with damaged.open("r+b") as f:
                    for offset, persisted in zip(offsets, surviving):
                        if not persisted:
                            f.seek(physical + offset)
                            f.write(b"\0")
                repair(damaged)
            # Partial-byte persistence and a range torn at its first sector.
            for mask in (0x55, 0xaa, 0x01):
                shutil.copyfile(base, damaged)
                with damaged.open("r+b") as f:
                    for offset in occupied:
                        f.seek(physical + offset)
                        f.write(bytes([bits[offset] & mask]))
                repair(damaged)
            shutil.copyfile(base, damaged)
            with damaged.open("r+b") as f:
                f.seek(physical + 512)
                f.write(bytes(len(bits) - 512))
            repair(damaged)

            shutil.copyfile(base, damaged)
            with damaged.open("r+b") as f:
                for offset in offsets:
                    f.seek(physical + offset)
                    f.write(b"\0")
            damaged_hash = digest(damaged)
            ranges = 1 + sum(b != a + 1 for a, b in zip(offsets, offsets[1:]))
            for stop in range(1, ranges + 2):
                env = dict(os.environ, SLATE_NTFS_TEST_STOP_AFTER_FLUSH=str(stop))
                p = run(CHECKER, "--repair-to", damaged, target, env=env, ok=False)
                assert p.returncode == 8 and not target.exists()
                partial = Path(str(target) + ".repair-incomplete")
                assert partial.exists() and digest(damaged) == damaged_hash
                # Interruption is resumed by repairing another new copy.
                repair(partial)
                partial.unlink()

            # Existing names, aliases and dangling symlinks are never replaced.
            for kind in ("file", "hardlink", "symlink"):
                if kind == "file":
                    target.write_bytes(b"keep me")
                elif kind == "hardlink":
                    os.link(damaged, target)
                else:
                    target.symlink_to(root / "absent")
                run(CHECKER, "--repair-to", damaged, target, ok=False)
                if kind == "file":
                    assert target.read_bytes() == b"keep me"
                assert digest(damaged) == damaged_hash
                target.unlink()
                count += 1
            run(CHECKER, "--repair-to", damaged, target,
                env=dict(os.environ, SLATE_NTFS_TEST_STOP_AFTER_FLUSH="999"), ok=False)
            assert not target.exists() and not Path(str(target) + ".repair-incomplete").exists()

            if formatter == "slate":
                # Added after the first 58-case run; pending the combined run.
                for corruption in ("unreferenced-clusters", "mft-bitmap-free"):
                    shutil.copyfile(base, damaged)
                    damage(damaged, corruption)
                    repair(damaged)
                for corruption in ("cross-linked-clusters", "invalid-parent-reference", "missing-directory-link",
                    "stale-index-reference", "security-invalid", "mft-invalid",
                    "boot-mirror-mismatch", "runlist-invalid", "unreachable-record"):
                    shutil.copyfile(base, damaged)
                    damage(damaged, "cluster-marked-free")
                    damage(damaged, corruption)
                    before = digest(damaged)
                    try:
                        run(CHECKER, "--repair-to", damaged, target, ok=False)
                    except AssertionError as error:
                        raise AssertionError(f"{formatter} {corruption}: {error}") from error
                    assert digest(damaged) == before
                    assert not target.exists() and not Path(str(target) + ".repair-incomplete").exists()
                    count += 1
            for state in ("dirty", "unknown-log", "hibernation"):
                shutil.copyfile(base, damaged)
                if state == "hibernation":
                    hiber = root / "hiber"
                    hiber.write_bytes(b"hibr" + bytes(4092))
                    run("ntfscp", "-f", damaged, hiber, "/hiberfil.sys")
                else:
                    with damaged.open("r+b") as f:
                        number = 3 if state == "dirty" else 2
                        f.seek(mft + number * record_size)
                        b = decode(f.read(record_size))
                        if state == "dirty":
                            a = attr(b, 0x70)
                            at = a + u(b, a + 20, 2) + 10
                            put(b, at, u(b, at, 2) | 1, 2)
                            for physical_record in (mft, u(boot, 56, 8) * cluster):
                                f.seek(physical_record + number * record_size)
                                f.write(protect(b))
                        else:
                            log_lcn, _ = first_extent(b, attr(b, 0x80))
                            f.seek(log_lcn * cluster)
                            f.write(b"BAD!")
                before = digest(damaged)
                run(CHECKER, "--repair-to", damaged, target, ok=False)
                assert digest(damaged) == before and not target.exists()
                count += 1
            assert digest(base) == original
    print(f"PASS: {count} repair, persistence-subset, interruption/resume and refusal cases; two formatters; sources unchanged")


if __name__ == "__main__":
    main()
