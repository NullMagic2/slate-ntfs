#!/usr/bin/env python3
"""
Module: src.tests.checker.test_repair_expansion
Purpose: Disposable rescue/$Secure crash matrix. Run explicitly, never during a build.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Disposable rescue/$Secure crash matrix. Run explicitly, never during a build.
"""

import argparse
import os
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import ROOT, CHECKER, digest, run, u, attrs, attr, first_extent
from test_broader_consistency import Image, rewrite, damage

POLY = 0x42F0E1EBA9EA3693


def crc64(data, value=0):
    for byte in data:
        value ^= byte << 56
        for _ in range(8):
            value = ((value << 1) ^ (POLY if value >> 63 else 0)) & ((1 << 64) - 1)
    return value


def entry(offset, size, status, payload=b""):
    header = b"".join(word.to_bytes(8, "little") for word in (offset, size, status))
    return header + crc64(payload, crc64(header)).to_bytes(8, "little") + payload


def first_entry(archive):
    with archive.open("rb") as f:
        f.seek(72)
        header = f.read(32)
        assert len(header) == 32 and u(header, 16, 8) == 0
        payload = f.read(u(header, 8, 8))
        assert len(payload) == u(header, 8, 8)
    return header, payload


def refuse_extract(archive, output):
    result = run(CHECKER, "--extract-rescue", archive, output, ok=False)
    assert result.returncode == 8, result.stderr
    assert not output.exists(), "incomplete or conflicting image was published"


def rescue_matrix(source, directory):
    original = digest(source)
    archive = directory / "complete.rescue"
    captured = run(CHECKER, "--rescue-to", source, archive)
    assert b"unresolved_sectors=0" in captured.stdout
    archive_hash = digest(archive)
    header, payload = first_entry(archive)
    assert u(header, 8, 8) >= 512

    extracted = directory / "extracted.img"
    assert b"rescue_extract_complete=1" in run(
        CHECKER, "--extract-rescue", archive, extracted).stdout
    assert digest(extracted) == original
    run(CHECKER, "--audit", extracted)
    extracted.unlink()

    for phase in range(1, 6):
        output = directory / f"stopped-{phase}.img"
        env = dict(os.environ, SLATE_NTFS_TEST_RESCUE_STOP_AFTER=str(phase))
        result = run(CHECKER, "--extract-rescue", archive, output, env=env, ok=False)
        assert result.returncode == 8 and b"injected rescue" in result.stderr
        assert output.exists() == (phase >= 4)
        if output.exists():
            assert digest(output) == original, "published output differs from source"
            run(CHECKER, "--audit", output)
            output.unlink()
        for private in directory.glob(output.name + ".rescue-incomplete-*"):
            if phase >= 3:
                assert digest(private) == original
            private.unlink()
        assert digest(archive) == archive_hash

    # Truncated append header and payload: extraction refuses, resume trims
    # only that incomplete tail, and the earlier durable good copy survives.
    for suffix in (b"\x01", bytes(31), entry(0, 512, 0, payload[:7])):
        damaged = directory / "short.rescue"
        shutil.copy2(archive, damaged)
        with damaged.open("ab") as f:
            f.write(suffix)
        refuse_extract(damaged, extracted)
        run(CHECKER, "--resume-rescue", source, damaged)
        run(CHECKER, "--extract-rescue", damaged, extracted)
        assert digest(extracted) == original
        extracted.unlink()
        damaged.unlink()

    # A complete bad checksum and divergent duplicate are evidence, not
    # incomplete tails. Both extraction and resume must refuse them.
    bad = directory / "checksum.rescue"
    shutil.copy2(archive, bad)
    with bad.open("r+b") as f:
        f.seek(72 + 32)
        byte = f.read(1)
        f.seek(-1, 1)
        f.write(bytes([byte[0] ^ 1]))
    refuse_extract(bad, extracted)
    assert run(CHECKER, "--resume-rescue", source, bad, ok=False).returncode == 8
    bad.unlink()

    bad = directory / "duplicate.rescue"
    shutil.copy2(archive, bad)
    changed = bytes([payload[0] ^ 1]) + payload[1:512]
    with bad.open("ab") as f:
        f.write(entry(u(header, 0, 8), 512, 0, changed))
    refuse_extract(bad, extracted)
    assert run(CHECKER, "--resume-rescue", source, bad, ok=False).returncode == 8
    bad.unlink()

    # An EIO record replaces one good record in an otherwise complete archive.
    # The source is unchanged; resume must fetch the missing range, preserving
    # all other previously captured data.
    missing = directory / "missing.rescue"
    with archive.open("rb") as inp, missing.open("xb") as out:
        out.write(inp.read(72))
        inp.seek(72 + 32 + len(payload))
        out.write(entry(u(header, 0, 8), u(header, 8, 8), 5))
        shutil.copyfileobj(inp, out)
    missing.chmod(0o600)
    refuse_extract(missing, extracted)
    assert run(CHECKER, "--resume-rescue", source, missing).returncode == 0
    run(CHECKER, "--extract-rescue", missing, extracted)
    assert digest(extracted) == original
    extracted.unlink()

    reintegrated = directory / "reintegrated.img"
    run(CHECKER, "--reintegrate-rescue", source, missing, reintegrated)
    assert digest(reintegrated) == original
    run(CHECKER, "--audit", reintegrated)
    assert digest(source) == original and digest(archive) == archive_hash
    return reintegrated, archive


def free_cluster(source):
    image = Image(source)
    try:
        record = image.get(6)
        bitmap_lcn, _ = first_extent(record, attr(record, 0x80))
        total = u(image.boot, 40, 8) * u(image.boot, 11, 2) // image.cluster
        image.f.seek(bitmap_lcn * image.cluster)
        for base in range(0, (total + 7) // 8, 4096):
            for index, value in enumerate(image.f.read(min(4096, (total + 7) // 8 - base))):
                for bit in range(8):
                    cluster = (base + index) * 8 + bit
                    if 16 <= cluster < total and not value & (1 << bit):
                        return cluster, image.cluster
    finally:
        image.close()
    raise AssertionError("fixture has no free cluster")


def badclus_matrix(source, archive, directory):
    original = digest(source)
    cluster, cluster_bytes = free_cluster(source)
    assert cluster_bytes <= 65536
    marked = directory / "marked-bad.rescue"
    shutil.copy2(archive, marked)
    with marked.open("ab") as saved:
        saved.write(entry(cluster * cluster_bytes, cluster_bytes, 5))
    output = directory / "retired-bad-cluster.img"
    run(CHECKER, "--repair-rescue-to", source, marked, output)
    run(CHECKER, "--audit", output)
    image = Image(output)
    try:
        found = False
        base = image.get(8)
        base_ref = 8 | (u(base, 16, 2) << 48)
        for number in range(8, 64):
            try:
                record = image.get(number)
            except AssertionError:
                continue  # uninitialized MFT slot
            if number != 8 and u(record, 32, 8) != base_ref:
                continue
            for bad, kind in attrs(record):
                name = bytes(record[bad + u(record, bad + 10, 2):
                                    bad + u(record, bad + 10, 2) + record[bad + 9] * 2])
                if kind != 0x80 or name != "$Bad".encode("utf-16le"):
                    continue
                cursor = bad + u(record, bad + 32, 2)
                vcn, lcn = u(record, bad + 16, 8), 0
                while record[cursor]:
                    header = record[cursor]
                    width, displacement = header & 15, header >> 4
                    length = u(record, cursor + 1, width)
                    if displacement:
                        lcn += int.from_bytes(record[cursor + 1 + width:cursor + 1 + width + displacement],
                                               "little", signed=True)
                    if vcn <= cluster < vcn + length:
                        assert displacement and lcn + cluster - vcn == cluster
                        found = True
                    vcn += length
                    cursor += 1 + width + displacement
        assert found, "recorded EIO cluster was not retired"
        bitmap = image.get(6)
        bitmap_lcn, _ = first_extent(bitmap, attr(bitmap, 0x80))
        image.f.seek(bitmap_lcn * image.cluster + cluster // 8)
        assert image.f.read(1)[0] & (1 << (cluster % 8))
    finally:
        image.close()
    assert digest(source) == original
    return output


def damage_secure_root(image, name):
    state = Image(image)
    try:
        record = state.get(9)
        kept = []
        removed = 0
        for offset, kind in attrs(record):
            value = bytearray(record[offset:offset + u(record, offset + 4, 4)])
            start = u(value, 10, 2)
            attr_name = bytes(value[start:start + value[9] * 2])
            if kind == 0x90 and attr_name == name.encode("utf-16le"):
                removed += 1
            else:
                kept.append(value)
        assert removed == 1, f"fixture needs one resident {name} root"
        state.save(9, rewrite(record, kept))
    finally:
        state.close()


def secure_matrix(source, directory):
    original = digest(source)
    results = []
    for names in (("$SII",), ("$SDH",), ("$SII", "$SDH")):
        label = "-".join(name[1:] for name in names)
        damaged = directory / f"missing-{label}.img"
        shutil.copyfile(source, damaged)
        for name in names:
            damage_secure_root(damaged, name)
        before = digest(damaged)
        plan = run(CHECKER, "--repair-plan", damaged).stdout.decode()
        assert "repair_supported=1" in plan, plan
        count = int(next(word.split("=")[1] for word in plan.split() if word.startswith("ranges=")))
        assert count > 0
        repaired = directory / f"secure-{label}.img"
        run(CHECKER, "--repair-to", damaged, repaired)
        run(CHECKER, "--audit", repaired)
        assert digest(damaged) == before and digest(source) == original
        assert "ranges=0" in run(CHECKER, "--repair-plan", repaired).stdout.decode()
        results.append(repaired)

        # Boundary 1 is the durable copy; later boundaries follow every
        # preimage-checked patch. Each partial copy must be resumable.
        for boundary in range(1, count + 2):
            stopped = directory / f"stopped-{label}-{boundary}.img"
            env = dict(os.environ, SLATE_NTFS_TEST_STOP_AFTER_FLUSH=str(boundary))
            result = run(CHECKER, "--repair-to", damaged, stopped, env=env, ok=False)
            assert result.returncode == 8 and not stopped.exists(), result.stderr
            partial = Path(str(stopped) + ".repair-incomplete")
            assert partial.exists() and digest(damaged) == before
            resumed = directory / f"resumed-{label}-{boundary}.img"
            run(CHECKER, "--repair-to", partial, resumed)
            run(CHECKER, "--audit", resumed)
            assert "ranges=0" in run(CHECKER, "--repair-plan", resumed).stdout.decode()
            partial.unlink()
            resumed.unlink()
    for case in ("security-order", "security-header"):
        damaged = directory / f"damaged-{case}.img"
        shutil.copyfile(source, damaged)
        image = Image(damaged)
        try:
            damage(image, case)
        finally:
            image.close()
        before = digest(damaged)
        repaired = directory / f"repaired-{case}.img"
        run(CHECKER, "--repair-to", damaged, repaired)
        run(CHECKER, "--audit", repaired)
        assert "ranges=0" in run(CHECKER, "--repair-plan", repaired).stdout.decode()
        assert digest(damaged) == before and digest(source) == original
        results.append(repaired)
    return results


def in_place_matrix(source, directory):
    assert os.geteuid() == 0, "--in-place requires root and disposable loop devices"
    damaged = directory / "in-place-damaged.img"
    shutil.copyfile(source, damaged)
    damage_secure_root(damaged, "$SII")
    before = digest(damaged)
    plan = run(CHECKER, "--repair-plan", damaged).stdout.decode()
    count = int(next(word.split("=")[1] for word in plan.split() if word.startswith("ranges=")))
    assert count > 0
    # Journal fsync; two dirty guards, every redo and two clean finalizers;
    # completion journal fsync; completed-name fsync; journal unlink fsync.
    for boundary in range(1, count + 9):
        candidate = directory / f"in-place-{boundary}.img"
        journal = directory / f"in-place-{boundary}.journal"
        shutil.copyfile(damaged, candidate)
        device = run("losetup", "-f", "--show", candidate).stdout.decode().strip()
        assert device.startswith("/dev/loop"), device
        try:
            env = dict(os.environ, SLATE_NTFS_TEST_REPAIR_STOP_AFTER_SYNC=str(boundary))
            result = run(CHECKER, "--repair-in-place", device, journal, env=env, ok=False)
            assert result.returncode == 8 and b"injected in-place" in result.stderr
            if journal.exists():
                with journal.open("rb") as saved:
                    assert saved.read(8) == b"SLTRPR01"
                run(CHECKER, "--resume-repair", device, journal)
            assert Path(str(journal) + ".completed").exists()
        finally:
            run("losetup", "-d", device)
        run(CHECKER, "--audit", candidate)
        assert "ranges=0" in run(CHECKER, "--repair-plan", candidate).stdout.decode()
        assert digest(damaged) == before


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="existing clean disposable NTFS image; never modified")
    parser.add_argument("--stage", type=Path, help="existing empty directory for later Windows/ntfs-3g checks")
    parser.add_argument("--in-place", action="store_true", help="also run every durable journal/redo boundary on disposable loop copies (root)")
    args = parser.parse_args()
    assert args.source.is_file() and args.source.stat().st_size % 512 == 0
    with tempfile.TemporaryDirectory(prefix="slate-repair-expansion-") as tmp:
        work = Path(tmp)
        source = work / "source.img"
        shutil.copyfile(args.source, source)
        run(CHECKER, "--audit", source)
        original = digest(source)
        rescue, archive = rescue_matrix(source, work)
        badclus = badclus_matrix(source, archive, work)
        repaired = secure_matrix(source, work)
        if args.in_place:
            in_place_matrix(source, work)
        if args.stage:
            assert args.stage.is_dir() and not any(args.stage.iterdir()), "stage must be empty"
            for image in (rescue, badclus, *repaired):
                shutil.copyfile(image, args.stage / image.name)
                run("python3", ROOT / "tests/windows/wrap_ntfs_image_vhd.py",
                    args.stage / image.name, args.stage / (image.stem + ".vhd"))
            manifest = [f"{digest(path).hex()}  {path.name}" for path in args.stage.iterdir()]
            (args.stage / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
        assert digest(source) == original
    print("PASS rescue publication, BadClus retirement, corrupt/torn archives, resume and $Secure repair boundaries")


if __name__ == "__main__":
    main()
