#!/usr/bin/env python3
"""
Module: kernel.tests.benchmark_reads
Purpose: Identical deterministic workloads; correctness assertions are outside timing.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Identical deterministic workloads; correctness assertions are outside timing.
"""
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import sys
import time

BLOCK = bytes(range(256)) * 256
LARGE_BYTES = 32 * 1024 * 1024
FILES = 128


def prepare(root):
    for n in range(4):
        (root / f"dir{n}").mkdir()
    with (root / "large.bin").open("wb") as stream:
        for _ in range(LARGE_BYTES // len(BLOCK)):
            stream.write(BLOCK)
    for n in range(FILES):
        (root / f"dir{n % 4}" / f"file{n:04}.bin").write_bytes(BLOCK[:4096])


def run(root, driver, round_number):
    paths = [root / f"dir{n % 4}" / f"file{n:04}.bin" for n in range(FILES)]
    rng = random.Random(1729)
    offsets = [rng.randrange(LARGE_BYTES // 4096) * 4096 for _ in range(512)]

    def sequential():
        total = 0
        with (root / "large.bin").open("rb", buffering=0) as stream:
            while data := stream.read(65536):
                total += len(data)
        return total

    def random_reads():
        with (root / "large.bin").open("rb", buffering=0) as stream:
            return sum(len(os.pread(stream.fileno(), 4096, offset)) for offset in offsets)

    def metadata():
        return sum(path.stat().st_size for path in paths)

    def small_reads():
        return sum(len(path.read_bytes()) for path in paths)

    def directories():
        return sum(len(os.listdir(root / f"dir{n}")) for n in range(4))

    # First read after a fresh mount: filesystem page cache is empty, but
    # backing-device/host caches are uncontrolled. This is NOT cold storage.
    start = time.perf_counter_ns()
    initial_size = sequential()
    elapsed = (time.perf_counter_ns() - start) / 1e6
    assert initial_size == LARGE_BYTES
    print(json.dumps({"driver": driver, "round": round_number,
                      "workload": "initial_sequential_32m_64k",
                      "samples_ms": [elapsed], "median_ms": elapsed}), flush=True)
    # Validate bytes and listings independently of the measured read lengths.
    expected = hashlib.sha256(BLOCK * (LARGE_BYTES // len(BLOCK))).digest()
    assert hashlib.sha256((root / "large.bin").read_bytes()).digest() == expected
    assert all(path.read_bytes() == BLOCK[:4096] for path in paths)
    workloads = [
        ("sequential_32m_64k", sequential, LARGE_BYTES),
        ("random_512x4k", random_reads, 512 * 4096),
        ("stat_128", metadata, FILES * 4096),
        ("open_read_close_128x4k", small_reads, FILES * 4096),
        ("list_four_directories", directories, FILES),
    ]
    for name, operation, expected_result in workloads:
        assert operation() == expected_result  # Explicit warmup, no cache dropping.
        samples = []
        for _ in range(7):
            start = time.perf_counter_ns()
            result = operation()
            samples.append((time.perf_counter_ns() - start) / 1e6)
            assert result == expected_result
        print(json.dumps({"driver": driver, "round": round_number,
                          "workload": name, "samples_ms": samples,
                          "median_ms": statistics.median(samples)}), flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "prepare":
        prepare(Path(sys.argv[2]))
    else:
        run(Path(sys.argv[2]), sys.argv[1], int(sys.argv[3]))
