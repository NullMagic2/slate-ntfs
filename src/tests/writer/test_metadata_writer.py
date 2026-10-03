#!/usr/bin/env python3
"""
Module: src.tests.writer.test_metadata_writer
Purpose: Directory B-tree restructuring, native ACL replacement and $MFT growth.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Directory B-tree restructuring, native ACL replacement and $MFT growth.

Drives the shared Rust metadata engine (the code linked into the kernel
module) on disposable image copies through ntfs-write-lab --metadata.
Every result is checked independently: ntfs-chkdsk --audit cross-checks
allocation, directory graph and $Secure agreement; NTFS-3G tools look up
every name through the on-disk B-trees and read file contents and raw
descriptors. Each operation type is interrupted at every durable flush and
recovered with ntfs-chkdsk --replay-to; the recovered image must hold
either the complete old or the complete new state.

Requires root, mkntfs and the NTFS-3G tools; FUSE is used to populate images.
Usage: python3 src/tests/writer/test_metadata_writer.py [NEW_OUTPUT_DIRECTORY]
"""
import os
import ctypes
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import run, u, decode  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "target/release/ntfs-write-lab"
CHKDSK = ROOT / "target/release/ntfs-chkdsk"
ADMIN = "S-1-5-32-544"
MAP = f"u:0:{ADMIN};g:0:S-1-5-18;u:1000:S-1-5-21-7-8-9-1000;g:1000:S-1-5-21-7-8-9-513;u:1002:S-1-5-21-7-8-9-1002;g:1002:S-1-5-21-7-8-9-514"
EVERYONE = (1, [0])  # S-1-1-0 authority 1


def sid(authority, *subs):
    return bytes([1, len(subs)]) + authority.to_bytes(6, "big") + b"".join(struct.pack("<I", s) for s in subs)


def sid_text(text):
    parts = text.split("-")
    return sid(int(parts[2]), *[int(p) for p in parts[3:]])


def ace(kind, principal, mask, flags=0):
    body = struct.pack("<I", mask) + principal
    return bytes([kind, flags]) + struct.pack("<H", 4 + len(body)) + body


def acl(aces):
    body = b"".join(aces)
    return bytes([2, 0]) + struct.pack("<HHH", 8 + len(body), len(aces), 0) + body


def descriptor(owner, group, dacl_aces, sacl_aces=None):
    """Self-relative descriptor: header, SACL, DACL, owner, group."""
    control = 0x8004 | (0x10 if sacl_aces is not None else 0)
    parts = []
    offset = 20
    sacl_off = dacl_off = 0
    if sacl_aces is not None:
        s = acl(sacl_aces); sacl_off = offset; parts.append(s); offset += len(s)
    d = acl(dacl_aces); dacl_off = offset; parts.append(d); offset += len(d)
    owner_off = offset; parts.append(owner); offset += len(owner)
    group_off = offset; parts.append(group); offset += len(group)
    header = bytes([1, 0]) + struct.pack("<HIIII", control, owner_off, group_off, sacl_off, dacl_off)
    return header + b"".join(parts)


EVERYONE_SID = sid(1, 0)
OWNER = sid_text("S-1-5-21-7-8-9-1000")
GROUP = sid_text("S-1-5-21-7-8-9-513")
OTHER = sid_text("S-1-5-21-7-8-9-1002")
ADMIN_SID = sid_text(ADMIN)


def mkimage(path, megabytes=24):
    with open(path, "xb") as f:
        f.truncate(megabytes * 1024 * 1024)
    run("mkntfs", "-F", "-Q", "-q", "-c", "4096", "-s", "512", path)


class Mounted:
    """Populate or inspect an image through NTFS-3G (FUSE)."""

    def __init__(self, image, mountpoint, readonly=False):
        self.image, self.mountpoint, self.readonly = image, mountpoint, readonly

    def __enter__(self):
        self.mountpoint.mkdir(exist_ok=True)
        opts = ["-o", "ro"] if self.readonly else []
        run("ntfs-3g", *opts, self.image, self.mountpoint)
        return self.mountpoint

    def __exit__(self, *exc):
        subprocess.run(["umount", str(self.mountpoint)], check=True)


def lab(source, destination, *ops, stop=None, leave_dirty=False, ok=True):
    env = dict(os.environ)
    env.pop("SLATE_NTFS_TEST_STOP_AFTER_FLUSH", None)
    if stop is not None:
        env["SLATE_NTFS_TEST_STOP_AFTER_FLUSH"] = str(stop)
    args = [LAB, "--metadata", source, destination, "--compatibility=ntfs"]
    if leave_dirty:
        args.append("--leave-dirty")
    for i, op in enumerate(ops):
        if i:
            args.append("::")
        args.extend(op)
    p = subprocess.run([str(a) for a in args], capture_output=True, env=env)
    if ok and p.returncode:
        raise AssertionError(("lab failed", [str(a)[:60] for a in args[:8]], p.returncode, p.stderr.decode(errors="replace")))
    if not ok and not p.returncode:
        raise AssertionError(("lab unexpectedly succeeded", [str(a)[:60] for a in args[:8]]))
    return p


# Findings already reported for a freshly formatted image (for example the
# mkntfs $MFT record without a security ID); every write must add none.
BASELINE = set()


def audit(image, allow_dirty=False, tolerate=()):
    p = subprocess.run([str(CHKDSK), "--audit", str(image)], capture_output=True)
    out = p.stdout.decode()
    findings = {l for l in out.splitlines() if l.startswith("finding=") and " severity=info " not in l}
    findings = {f for f in findings if not any(f.startswith(t) for t in tolerate)}
    assert findings <= BASELINE, sorted(findings - BASELINE)
    # Coverage may be incomplete only because of the baseline's unsupported
    # system-record findings; every other cross-check still ran.
    baseline_unsupported = any("finding=unsupported" in l for l in BASELINE)
    assert "audit_complete=1" in out or (baseline_unsupported and "audit_complete=0" in out), out + p.stderr.decode()
    assert "omitted_findings=0" in out, out
    if not allow_dirty:
        assert "dirty=0" in out, out
    assert p.returncode in (0, 4), (p.returncode, out)
    return out


def names(image, directory):
    p = run("ntfsls", "-f", "-p", directory, image)
    return sorted(l for l in p.stdout.decode().splitlines() if l and l not in (".", ".."))


def content(image, path):
    return run("ntfscat", "-f", image, path).stdout


def replay(image, recovered):
    run(CHKDSK, "--replay-to", image, recovered)


def secure_sds_size(image):
    data = Path(image).read_bytes()
    cluster = u(data, 11, 2) * data[13]
    mft = u(data, 48, 8) * cluster
    record = decode(data[mft + 9 * 1024:mft + 10 * 1024])
    off = u(record, 0x14, 2)
    while u(record, off, 4) != 0xFFFFFFFF:
        size = u(record, off + 4, 4)
        name_len, name_off = record[off + 9], u(record, off + 10, 2)
        name = bytes(record[off + name_off:off + name_off + 2 * name_len]).decode("utf-16-le")
        if u(record, off, 4) == 0x80 and name == "$SDS":
            return u(record, off + 48, 8)
        off += size
    raise AssertionError("no $SDS")


def mft_records(image):
    data = Path(image).read_bytes()
    cluster = u(data, 11, 2) * data[13]
    mft = u(data, 48, 8) * cluster
    record = decode(data[mft:mft + 1024])
    off = u(record, 0x14, 2)
    while u(record, off, 4) != 0xFFFFFFFF:
        if u(record, off, 4) == 0x80 and record[off + 9] == 0:
            return u(record, off + 48, 8) // 1024
        off += u(record, off + 4, 4)
    raise AssertionError("no $MFT data")


def raw_descriptor(image, path, work):
    with Mounted(image, work / "ro-mount", readonly=True) as m:
        # NTFS-3G 2022.10.3 can send an oversized FUSE reply instead of ERANGE
        # for Python's initial 128-byte buffer. Query the exact size first,
        # as getfattr does, then use the ordinary Linux getxattr syscall.
        libc = ctypes.CDLL(None, use_errno=True)
        get = libc.getxattr
        get.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t]
        get.restype = ctypes.c_ssize_t
        name = os.fsencode(m / path.lstrip('/'))
        size = get(name, b'system.ntfs_acl', None, 0)
        if size < 0: raise OSError(ctypes.get_errno(), 'getxattr size')
        buffer = ctypes.create_string_buffer(size)
        count = get(name, b'system.ntfs_acl', buffer, size)
        if count < 0: raise OSError(ctypes.get_errno(), 'getxattr value')
        assert count <= size
        return buffer.raw[:count]


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def is_dirty(image):
    return "dirty=1" in subprocess.run([str(CHKDSK), "--status", str(image)], capture_output=True).stdout.decode()


def crash_matrix(label, source, ops, old_check, new_check, work):
    """Interrupt at every flush; recovery must yield the old or new state."""
    complete = work / f"{label}-complete.img"
    p = lab(source, complete, *ops, leave_dirty=True)
    fields = dict(l.split("=", 1) for l in p.stdout.decode().splitlines() if "=" in l)
    total = int(fields["flushes"])
    recovered = work / f"{label}-complete-recovered.img"
    replay(complete, recovered)
    new_check(recovered)
    audit(recovered, allow_dirty=True)
    seen_new = False
    outcomes = {"old": 0, "new": 0}
    for boundary in range(1, total + 1):
        dirty = work / f"{label}-stop{boundary}.img"
        lab(source, dirty, *ops, stop=boundary, leave_dirty=True, ok=False)
        recovered = work / f"{label}-stop{boundary}-recovered.img"
        # Flush counting starts after the journal is initialized and the
        # volume is marked dirty, so every interrupted image needs replay.
        assert is_dirty(dirty), (label, boundary)
        replay(dirty, recovered)
        audit(recovered, allow_dirty=True)
        try:
            new_check(recovered)
            seen_new = True
            outcomes["new"] += 1
        except AssertionError:
            expect(not seen_new, (label, boundary, "state regressed to old after a durable commit"))
            old_check(recovered)
            outcomes["old"] += 1
        if is_dirty(recovered):
            # Recovery is idempotent: replaying the recovered image changes nothing.
            again = work / f"{label}-stop{boundary}-again.img"
            replay(recovered, again)
            expect(again.read_bytes() == recovered.read_bytes(), (label, boundary, "replay not idempotent"))
            again.unlink()
        dirty.unlink()
        recovered.unlink()
    # Both rollback (before commit) and roll-forward (after) must occur.
    expect(outcomes["old"] and outcomes["new"], (label, outcomes))
    print(f"PASS crash matrix {label}: {total} flush boundaries {outcomes}", flush=True)


def sequence_matrix(label, source, ops, states, observe, work, stride=1):
    """Interrupt a multi-transaction sequence; recovery must land exactly on
    an operation boundary, never going backwards as boundaries advance."""
    complete = work / f"{label}-complete.img"
    p = lab(source, complete, *ops, leave_dirty=True)
    total = int(dict(l.split("=", 1) for l in p.stdout.decode().splitlines() if "=" in l)["flushes"])
    last = -1
    checked = 0
    tail = total - 40
    for boundary in range(1, total + 1):
        if boundary % stride and boundary < tail:
            continue
        dirty = work / f"{label}-stop{boundary}.img"
        lab(source, dirty, *ops, stop=boundary, leave_dirty=True, ok=False)
        recovered = work / f"{label}-stop{boundary}-recovered.img"
        replay(dirty, recovered)
        audit(recovered, allow_dirty=True)
        state = observe(recovered)
        expect(state in states, (label, boundary, "recovered state is not an operation boundary"))
        index = states.index(state)
        expect(index >= last, (label, boundary, "recovered state went backwards"))
        last = index
        checked += 1
        dirty.unlink()
        recovered.unlink()
    expect(last == len(states) - 1 or last == len(states) - 2, (label, last, len(states)))
    print(f"PASS sequence matrix {label}: {checked}/{total} flush boundaries across {len(ops)} operations", flush=True)


def main():
    assert os.geteuid() == 0, "root is required for FUSE population"
    for tool in ("mkntfs", "ntfs-3g", "ntfsls", "ntfscat"):
        assert shutil.which(tool), f"missing {tool}"
    assert LAB.exists() and CHKDSK.exists(), "build first: bash build.sh"
    if len(sys.argv) > 1:
        work = Path(sys.argv[1]).resolve()
        work.mkdir(parents=True, exist_ok=False)
    else:
        work = Path(tempfile.mkdtemp(prefix="slate-metadata-"))
    rng = random.Random(20260928)

    # ---- Fixture: nested directories, a multi-level index and small ones.
    base = work / "base.img"
    mkimage(base)
    with Mounted(base, work / "mnt") as m:
        (m / "big").mkdir()
        (m / "small").mkdir()
        (m / "empty").mkdir()
        (m / "small" / "sub").mkdir()
        (m / "small" / "sub" / "inner.txt").write_bytes(b"inner")
        for i in range(420):
            (m / "big" / f"file-{i:04d}-{'x' * (i % 23)}.dat").write_bytes(f"payload {i}\n".encode())
        for i in range(3):
            (m / "small" / f"s{i}.txt").write_bytes(f"small {i}".encode())
        (m / "root.txt").write_bytes(b"root file")
        for i in range(320):
            (m / "small" / "sub" / f"acl-{i:03d}").write_bytes(b"a")
    # NTFS-3G population can leave pre-existing, system-record findings (for
    # example $MFT without a security ID). They define the baseline.
    probe = subprocess.run([str(CHKDSK), "--audit", str(base)], capture_output=True)
    BASELINE.update(l for l in probe.stdout.decode().splitlines() if l.startswith("finding="))
    assert all("record=0 " in l or "record=1 " in l for l in BASELINE), BASELINE
    audit(base)
    big = names(base, "/big")
    assert len(big) == 420

    # ---- 1. Cross-directory moves out of a multi-level tree into a resident root.
    moved = work / "moved.img"
    picks = rng.sample(big, 150)
    ops = [("move", f"/big/{n}", f"/empty/m-{n}") for n in picks]
    lab(base, moved, *ops)
    audit(moved)
    assert names(moved, "/empty") == sorted(f"m-{n}" for n in picks)
    assert names(moved, "/big") == sorted(set(big) - set(picks))
    for n in picks[:40]:
        i = int(n.split("-")[1])
        assert content(moved, f"/empty/m-{n}") == f"payload {i}\n".encode()
    print("PASS cross-directory moves with root push-down and splits", flush=True)

    # ---- 2. Long renames force block splits in both directions.
    split = work / "split.img"
    rest = names(moved, "/big")
    longs = {n: ("L" * 180) + f"-{k:03d}-" + n for k, n in enumerate(rng.sample(rest, 80))}
    lab(moved, split, *[("move", f"/big/{a}", f"/big/{b}") for a, b in longs.items()])
    audit(split)
    expected = sorted((set(rest) - set(longs)) | set(longs.values()))
    assert names(split, "/big") == expected
    for b in list(longs.values())[:20]:
        assert content(split, f"/big/{b}").startswith(b"payload")
    print("PASS in-directory renames with block splits", flush=True)

    # ---- 3. Empty /big entirely: branch removal and collapse to a resident root.
    drained = work / "drained.img"
    remaining = names(split, "/big")
    lab(split, drained, *[("move", f"/big/{n}", f"/small/d{k:04d}") for k, n in enumerate(remaining)])
    audit(drained)
    assert names(drained, "/big") == []
    assert len(names(drained, "/small")) == 3 + 1 + len(remaining)
    info = run("ntfsinfo", "-f", "-F", "/big", drained).stdout.decode()
    assert "$INDEX_ALLOCATION" not in info, "emptied index was not collapsed"
    print("PASS deletion rebalancing and collapse to resident root", flush=True)

    # ---- 4. Directory move, case-only rename, collision refusal.
    shuffled = work / "shuffled.img"
    lab(drained, shuffled, ("move", "/small/sub", "/big/sub-moved"), ("move", "/root.txt", "/ROOT.TXT"))
    audit(shuffled)
    assert "sub-moved" in names(shuffled, "/big")
    assert content(shuffled, "/big/sub-moved/inner.txt") == b"inner"
    assert "ROOT.TXT" in names(shuffled, "/")
    refused = work / "refused.img"
    p = lab(shuffled, refused, ("move", "/big/sub-moved/inner.txt", "/root.TXT"), ok=False)
    assert b"Exists" in p.stderr, p.stderr
    recovered = work / "refused-recovered.img"
    replay(refused, recovered)
    audit(recovered, allow_dirty=True)
    assert names(recovered, "/") == names(shuffled, "/")
    print("PASS directory move, case-only rename and collision refusal", flush=True)

    # ---- 5. Native ACL replacement: new entries, dedupe, $SII/$SDH growth.
    # NTFS-3G made Administrators (uid 0 here) the owner of every file.
    d1 = descriptor(ADMIN_SID, GROUP, [ace(0, EVERYONE_SID, 0x1F01FF)])
    acl1 = work / "acl1.img"
    sds_before = secure_sds_size(shuffled)
    lab(shuffled, acl1, ("set-security", "/ROOT.TXT", d1.hex(), "0", "0", MAP))
    audit(acl1)
    assert raw_descriptor(acl1, "/ROOT.TXT", work) == d1
    sds_after = secure_sds_size(acl1)
    acl2 = work / "acl2.img"
    lab(acl1, acl2, ("set-security", "/big/sub-moved/inner.txt", d1.hex(), "0", "0", MAP))
    assert secure_sds_size(acl2) == sds_after, "identical descriptor was not reused"
    assert raw_descriptor(acl2, "/big/sub-moved/inner.txt", work) == d1
    many = work / "acl-many.img"
    files = names(acl2, "/big/sub-moved")
    unique = {}
    for k, n in enumerate(f for f in files if f.startswith("acl-")):
        unique[n] = descriptor(ADMIN_SID, GROUP, [ace(0, EVERYONE_SID, 0x1F01FF), ace(0, sid(5, 21, 7, 8, 9, 5000 + k), 0x120089)])
    lab(acl2, many, *[("set-security", f"/big/sub-moved/{n}", d.hex(), "0", "0", MAP) for n, d in unique.items()])
    audit(many)
    for n in rng.sample(sorted(unique), 25):
        assert raw_descriptor(many, f"/big/sub-moved/{n}", work) == unique[n]
    assert secure_sds_size(many) > sds_before
    print(f"PASS {len(unique)} distinct descriptors: $SDS append, $SII/$SDH splits, dedupe", flush=True)

    # ---- 6. Authorization: taking ownership, owner implicit WRITE_DAC,
    # denial without privilege bypass, SACL and owner-assignment rules.
    taken = work / "taken.img"
    owned = descriptor(OWNER, GROUP, [ace(0, EVERYONE_SID, 0x1F01FF)])
    lab(many, taken, ("set-security", "/ROOT.TXT", owned.hex(), "1000", "1000", MAP))
    assert raw_descriptor(taken, "/ROOT.TXT", work) == owned
    restrictive = descriptor(OWNER, GROUP, [ace(0, EVERYONE_SID, 0x120089)])
    locked = work / "locked.img"
    lab(taken, locked, ("set-security", "/ROOT.TXT", restrictive.hex(), "1000", "1000", MAP))
    for uid in ("1002", "0"):
        p = lab(locked, work / f"denied-{uid}.img", ("set-security", "/ROOT.TXT", owned.hex(), uid, uid, MAP), ok=False)
        assert b"AccessDenied" in p.stderr, (uid, p.stderr)
    owner_ok = work / "owner-ok.img"
    lab(locked, owner_ok, ("set-security", "/ROOT.TXT", owned.hex(), "1000", "1000", MAP))
    assert raw_descriptor(owner_ok, "/ROOT.TXT", work) == owned
    sacl = descriptor(OWNER, GROUP, [ace(0, EVERYONE_SID, 0x1F01FF)], sacl_aces=[ace(2, EVERYONE_SID, 0x10000, 0xC0)])
    p = lab(owner_ok, work / "sacl.img", ("set-security", "/ROOT.TXT", sacl.hex(), "1000", "1000", MAP), ok=False)
    assert b"NotPermitted" in p.stderr, p.stderr
    stolen = descriptor(OTHER, GROUP, [ace(0, EVERYONE_SID, 0x1F01FF)])
    p = lab(owner_ok, work / "stolen.img", ("set-security", "/ROOT.TXT", stolen.hex(), "1000", "1000", MAP), ok=False)
    assert b"NotPermitted" in p.stderr, p.stderr
    chowned = work / "chowned.img"
    lab(owner_ok, chowned, ("chown", "/ROOT.TXT", "-", "1002", "1000", "1000", MAP))
    audit(chowned)
    got = raw_descriptor(chowned, "/ROOT.TXT", work)
    assert sid_text("S-1-5-21-7-8-9-514") in got and acl([ace(0, EVERYONE_SID, 0x1F01FF)]) in got
    assert got.find(OWNER) >= 0
    p = lab(chowned, work / "chown-other.img", ("chown", "/ROOT.TXT", "1002", "-", "1000", "1000", MAP), ok=False)
    assert b"NotPermitted" in p.stderr, p.stderr
    print("PASS ownership, WRITE_DAC/WRITE_OWNER, no admin bypass, SACL refusal, chown", flush=True)

    # ---- 7. $MFT growth, then independent use of the new records.
    grown = work / "grown.img"
    before = mft_records(chowned)
    lab(chowned, grown, ("grow-mft", "1000"))
    audit(grown)
    after = mft_records(grown)
    assert after >= before + 1000 and after % 64 == 0, (before, after)
    with Mounted(grown, work / "mnt") as m:
        for i in range(40):
            (m / "empty" / f"new-{i}").write_bytes(b"n")
    audit(grown)
    assert len([n for n in names(grown, "/empty") if n.startswith("new-")]) == 40
    print(f"PASS $MFT growth {before} -> {after} records", flush=True)

    # ---- 8. Crash matrices: every durable flush of each operation type.
    base_names = names(base, "/big")
    pick = sorted(base_names)[200]
    crash_matrix(
        "move-split", base, [("move", f"/big/{pick}", "/empty/" + "Z" * 200)],
        old_check=lambda img: expect(names(img, "/big") == base_names and names(img, "/empty") == [], "not old"),
        new_check=lambda img: expect(pick not in names(img, "/big") and names(img, "/empty") == ["Z" * 200], "not new"),
        work=work,
    )
    fresh = descriptor(ADMIN_SID, GROUP, [ace(0, EVERYONE_SID, 0x1F01FF), ace(0, sid(5, 21, 1, 2, 3), 0x1200A9)])
    crash_matrix(
        "security", base, [("set-security", "/root.txt", fresh.hex(), "0", "0", MAP)],
        old_check=lambda img: expect(raw_descriptor(img, "/root.txt", work) != fresh, "not old"),
        new_check=lambda img: expect(raw_descriptor(img, "/root.txt", work) == fresh, "not new"),
        work=work,
    )
    base_records = mft_records(base)
    crash_matrix(
        "grow-mft", base, [("grow-mft", "300")],
        old_check=lambda img: expect(mft_records(img) == base_records, "not old"),
        new_check=lambda img: expect(mft_records(img) > base_records, "not new"),
        work=work,
    )
    # Push-down and splits in a destination tree, then a full collapse of a
    # multi-level source tree, interrupted across whole sequences.
    seq = work / "seq-base.img"
    mkimage(seq)
    with Mounted(seq, work / "mnt") as m:
        (m / "src").mkdir()
        (m / "dst").mkdir()
        for i in range(150):
            (m / "src" / (f"{i:03d}-" + "n" * (i % 29))).write_bytes(b"s")
    # Attribute-list directories are refused by design; keep the fixture's
    # index root in its base record.
    for d in ("/src", "/dst"):
        assert "$ATTRIBUTE_LIST" not in run("ntfsinfo", "-f", "-F", d, seq).stdout.decode(), d
    assert "$INDEX_ALLOCATION" in run("ntfsinfo", "-f", "-F", "/src", seq).stdout.decode()
    src_names = names(seq, "/src")
    moves = [("move", f"/src/{n}", f"/dst/{n}") for n in src_names]
    states = [(tuple(src_names[k:]), tuple(sorted(src_names[:k]))) for k in range(len(src_names) + 1)]
    observe = lambda img: (tuple(names(img, "/src")), tuple(names(img, "/dst")))
    sequence_matrix("drain-and-fill", seq, moves, states, observe, work, stride=5)
    drained_seq = work / "seq-drained.img"
    lab(seq, drained_seq, *moves)
    info = run("ntfsinfo", "-f", "-F", "/src", drained_seq).stdout.decode()
    assert "$INDEX_ALLOCATION" not in info
    info = run("ntfsinfo", "-f", "-F", "/dst", drained_seq).stdout.decode()
    assert "$INDEX_ALLOCATION" in info
    print("PASS all metadata writer cases", flush=True)


if __name__ == "__main__":
    main()
