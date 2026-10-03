#!/usr/bin/env python3
"""Module: test_log_resize
Purpose: Verify log resizing, allocation ownership and interruption boundaries.
Created: 2026-10-01
Architecture: Runs the offline checker on disposable images and independently parses
    their metadata through tests/support/ntfs_image.py.
"""

import json
import os
import pathlib
import shutil
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import (
    ROOT,
    CHECKER,
    run,
    u,
    put,
    attr,
    attrs,
    decode,
    protect,
    restart,
    digest,
)

FORMATTER = pathlib.Path(
    os.environ.get(
        "SLATE_NTFS_FORMATTER", ROOT / "ntfs_utils/target/release/ntfs-format"
    )
)
MIB = 1024 * 1024


def mapping(record, at):
    cursor = at + u(record, at + 32, 2)
    lcn = 0
    result = []
    while record[cursor]:
        tag = record[cursor]
        n, m = tag & 15, tag >> 4
        assert n
        length = u(record, cursor + 1, n)
        if m:
            lcn += int.from_bytes(
                record[cursor + 1 + n : cursor + 1 + n + m], "little", signed=True
            )
        result.append((lcn if m else None, length))
        cursor += 1 + n + m
    return result


def encode_mapping(runs):
    result = bytearray()
    previous = 0
    for lcn, length in runs:
        n = max(1, (length.bit_length() + 7) // 8)
        delta = lcn - previous
        m = next(
            m for m in range(1, 9) if -(1 << (m * 8 - 1)) <= delta < (1 << (m * 8 - 1))
        )
        result.append(n | (m << 4))
        result.extend(length.to_bytes(n, "little"))
        result.extend(delta.to_bytes(m, "little", signed=True))
        previous = lcn
    result.append(0)
    return result


class Volume:
    def __init__(self, path):
        self.file = path.open("r+b")
        self.boot = self.file.read(512)
        self.cluster = u(self.boot, 11, 2) * self.boot[13]
        record_units = int.from_bytes(self.boot[64:65], "little", signed=True)
        self.record_bytes = (
            (1 << -record_units) if record_units < 0 else self.cluster * record_units
        )
        self.mft = u(self.boot, 48, 8) * self.cluster

    def close(self):
        self.file.close()

    def record(self, number):
        self.file.seek(self.mft + number * self.record_bytes)
        return decode(self.file.read(self.record_bytes))

    def save(self, number, record):
        raw = protect(record)
        self.file.seek(self.mft + number * self.record_bytes)
        self.file.write(raw)
        if number < 4:
            self.file.seek(
                u(self.boot, 56, 8) * self.cluster + number * self.record_bytes
            )
            self.file.write(raw)

    def stream(self, record, at):
        result = bytearray()
        for lcn, length in mapping(record, at):
            self.file.seek(lcn * self.cluster)
            result.extend(self.file.read(length * self.cluster))
        return result[: u(record, at + 48, 8)]

    def bitmap(self):
        record = self.record(6)
        at = attr(record, 0x80)
        runs = mapping(record, at)
        assert len(runs) == 1
        return runs[0][0] * self.cluster, self.stream(record, at)


def check(image):
    report = json.loads(run(CHECKER, "--json", "--check", image).stdout)
    assert report["complete"] and report["errors"] == 0 and report["passed"], report
    return report


def initialize(image):
    v = Volume(image)
    try:
        record = v.record(2)
        at = attr(record, 0x80)
        lcn, _ = mapping(record, at)[0]
        size = u(record, at + 48, 8)
        # Retain a nonzero historical LSN while keeping both client lists inactive.

        page = decode(restart(size, 0, 0x24000, 0))
        put(page, 48 + 10, 0, 2)
        put(page, 48 + 12, 0xFFFF, 2)
        page = protect(page)
        v.file.seek(lcn * v.cluster)
        v.file.write(page)
        v.file.write(page)
        for offset in (65536, size - 4096):
            v.file.seek(lcn * v.cluster + offset)
            v.file.write(bytes(range(256)) * 16)
    finally:
        v.close()
    check(image)


def fragment(image):
    v = Volume(image)
    try:
        record = v.record(2)
        at = attr(record, 0x80)
        lcn, length = mapping(record, at)[0]
        half = length // 2
        target = 10000
        bitmap_at, bitmap = v.bitmap()
        assert all(
            not (bitmap[c // 8] & (1 << (c % 8)))
            for c in range(target, target + length - half)
        )
        v.file.seek((lcn + half) * v.cluster)
        tail = v.file.read((length - half) * v.cluster)
        v.file.seek(target * v.cluster)
        v.file.write(tail)
        for c in range(lcn + half, lcn + length):
            bitmap[c // 8] &= ~(1 << (c % 8))
        for c in range(target, target + length - half):
            bitmap[c // 8] |= 1 << (c % 8)
        v.file.seek(bitmap_at)
        v.file.write(bitmap)
        encoded = encode_mapping([(lcn, half), (target, length - half)])
        old_length = u(record, at + 4, 4)
        run_offset = u(record, at + 32, 2)
        new_length = (run_offset + len(encoded) + 7) & ~7
        replacement = bytearray(new_length)
        replacement[:run_offset] = record[at : at + run_offset]
        replacement[run_offset : run_offset + len(encoded)] = encoded
        put(replacement, 4, new_length, 4)
        used = u(record, 24, 4)
        remainder = record[at + old_length : used]
        assert at + new_length + len(remainder) <= len(record)
        record[at : at + new_length] = replacement
        record[at + new_length : at + new_length + len(remainder)] = remainder
        put(record, 24, at + new_length + len(remainder), 4)
        v.save(2, record)
    finally:
        v.close()
    check(image)


def fill_volume(image):
    v = Volume(image)
    try:
        bitmap_at, bitmap = v.bitmap()
        clusters = u(v.boot, 40, 8) // v.boot[13]
        runs = []
        cursor = 0
        while cursor < clusters:
            if bitmap[cursor // 8] & (1 << (cursor % 8)):
                cursor += 1
                continue
            start = cursor
            while cursor < clusters and not bitmap[cursor // 8] & (1 << (cursor % 8)):
                bitmap[cursor // 8] |= 1 << (cursor % 8)
                cursor += 1
            runs.append((start, cursor - start))
        count = sum(length for _, length in runs)
        assert count
        encoded = encode_mapping(runs)
        name = "fill".encode("utf-16le")
        extra = bytearray((72 + len(encoded) + 7) & ~7)
        put(extra, 0, 0x80, 4)
        put(extra, 4, len(extra), 4)
        extra[8] = 1
        extra[9] = len(name) // 2
        put(extra, 10, 64, 2)
        put(extra, 24, count - 1, 8)
        put(extra, 32, 72, 2)
        put(extra, 40, count * v.cluster, 8)
        put(extra, 48, count * v.cluster, 8)
        extra[64:72] = name
        extra[72 : 72 + len(encoded)] = encoded
        record = v.record(24)
        assert u(record, 22, 2) & 3 == 1
        put(extra, 14, u(record, 40, 2), 2)
        put(record, 40, u(record, 40, 2) + 1, 2)
        used = u(record, 24, 4)
        at = next((a for a, kind in attrs(record) if kind > 0x80), used - 8)
        remainder = record[at:used]
        assert used + len(extra) <= len(record)
        record[at : at + len(extra)] = extra
        record[at + len(extra) : at + len(extra) + len(remainder)] = remainder
        put(record, 24, used + len(extra), 4)
        v.save(24, record)
        v.file.seek(bitmap_at)
        v.file.write(bitmap)
    finally:
        v.close()
    check(image)


def verify_resize(source, result, size):
    original = digest(source)
    run(CHECKER, "--resize-log", str(size), source, result)
    assert digest(source) == original
    check(result)
    a, b = Volume(source), Volume(result)
    try:
        ra, rb = a.record(2), b.record(2)
        aa, ab = attr(ra, 0x80), attr(rb, 0x80)
        before, after = a.stream(ra, aa), b.stream(rb, ab)
        assert len(after) == size and u(rb, ab + 56, 8) == size
        assert u(rb, ab + 40, 8) == ((size + b.cluster - 1) // b.cluster) * b.cluster
        for offset in (0, 4096):
            assert after[offset : offset + 16] == b"CHKD" + bytes(4) + (
                0x24000
            ).to_bytes(8, "little")
            assert (
                after[offset + 16 : offset + 4096]
                == before[offset + 16 : offset + 4096]
            )
        assert (
            after[8192 : min(size, len(before))]
            == before[8192 : min(size, len(before))]
        )
        if size > len(before):
            assert after[len(before) :] == bytes([255]) * (size - len(before))
        prefix_a = [
            c for lcn, length in mapping(ra, aa) for c in range(lcn, lcn + length)
        ]
        prefix_b = [
            c for lcn, length in mapping(rb, ab) for c in range(lcn, lcn + length)
        ]
        common = min(len(prefix_a), len(prefix_b))
        assert prefix_a[:common] == prefix_b[:common]
        _, bitmap = b.bitmap()
        assert all(bitmap[c // 8] & (1 << (c % 8)) for c in prefix_b)
        # Metadata publication may reuse newly released log clusters, including
        # index attributes stored in extension records. Verify their ownership.

        zero = b.record(0)
        slots = u(zero, attr(zero, 0x80) + 56, 8) // b.record_bytes
        metadata = set()
        for number in range(slots):
            if number == 2:
                continue
            record = b.record(number)
            if not u(record, 22, 2) & 1:
                continue
            for at, _ in attrs(record):
                if record[at + 8]:
                    for lcn, length in mapping(record, at):
                        if lcn is not None:
                            metadata.update(range(lcn, lcn + length))
        for c in prefix_a[common:]:
            assert bool(bitmap[c // 8] & (1 << (c % 8))) == (c in metadata)
    finally:
        a.close()
        b.close()
    assert not pathlib.Path(str(result) + ".log-resize-incomplete").exists()


def main():
    with tempfile.TemporaryDirectory(prefix="slate-log-resize-") as scratch:
        d = pathlib.Path(scratch)
        base = d / "base.img"
        template = os.environ.get("SLATE_NTFS_TEST_BASE_IMAGE")
        if template:
            shutil.copyfile(template, base)
        else:
            with base.open("wb") as f:
                f.truncate(64 * MIB)
            run(FORMATTER, "--yes", "--quick", base)
        blank = d / "uninitialized.img"
        shutil.copyfile(base, blank)
        v = Volume(blank)
        record = v.record(2)
        at = attr(record, 0x80)
        for lcn, length in mapping(record, at):
            v.file.seek(lcn * v.cluster)
            v.file.write(bytes([255]) * (length * v.cluster))
        v.close()
        initialize(base)
        verify_resize(base, d / "grown.img", 4 * MIB)
        verify_resize(d / "grown.img", d / "shrunk.img", 2 * MIB)
        verify_resize(base, d / "unaligned-cluster.img", 2 * MIB + 1024)
        verify_resize(
            d / "unaligned-cluster.img", d / "tail-regrown.img", 2 * MIB + 4096
        )
        original = digest(base)
        run(CHECKER, "--resize-log", "2M", base, d / "same.img")
        assert digest(d / "same.img") == original and digest(base) == original
        split = d / "fragmented.img"
        shutil.copyfile(base, split)
        fragment(split)
        verify_resize(split, d / "fragmented-grown.img", 5 * MIB)
        verify_resize(d / "fragmented-grown.img", d / "fragmented-shrunk.img", 2 * MIB)
        full = d / "full.img"
        shutil.copyfile(d / "grown.img", full)
        fill_volume(full)
        verify_resize(full, d / "full-shrunk.img", 2 * MIB)
        run(CHECKER, "--resize-log", "5M", full, d / "full-grown.img", ok=False)
        assert not (d / "full-grown.img").exists()
        run(CHECKER, "--resize-log", "4M", blank, d / "blank-result.img", ok=False)
        assert not (d / "blank-result.img").exists()
        torn = d / "torn.img"
        shutil.copyfile(base, torn)
        v = Volume(torn)
        record = v.record(2)
        lcn, _ = mapping(record, attr(record, 0x80))[0]
        v.file.seek(lcn * v.cluster)
        v.file.write(b"CHKD" + bytes(4) + (0x24000).to_bytes(8, "little"))
        v.close()
        run(CHECKER, "--resize-log", "4M", torn, d / "torn-result.img", ok=False)
        assert not (d / "torn-result.img").exists()
        existing = d / "existing.img"
        existing.write_bytes(b"keep this destination")
        run(CHECKER, "--resize-log", "4M", base, existing, ok=False)
        assert existing.read_bytes() == b"keep this destination"
        # Exercise every durable boundary until one beyond the plan is rejected.

        boundaries = 0
        for boundary in range(1, 200):
            target = d / ("interrupted-%d.img" % boundary)
            env = dict(os.environ, SLATE_NTFS_TEST_STOP_AFTER_FLUSH=str(boundary))
            result = run(CHECKER, "--resize-log", "4M", base, target, ok=False, env=env)
            assert not target.exists() and digest(base) == original
            partial = pathlib.Path(str(target) + ".log-resize-incomplete")
            if b"outside this resize plan" in result.stderr:
                assert not partial.exists()
                break
            assert b"injected" in result.stderr and partial.exists(), (
                boundary,
                result.stderr,
            )
            if boundary == 1:
                assert digest(partial) == original
            partial.unlink()
            boundaries += 1
        else:
            raise AssertionError("resize plan did not terminate within 199 boundaries")
    print(
        "Log resize: growth, shrink, cluster-tail reuse, fragmented mappings, full-volume shrink, markers, history, allocation, source preservation, refusals and %d durable interruption boundaries passed."
        % boundaries
    )


if __name__ == "__main__":
    main()
