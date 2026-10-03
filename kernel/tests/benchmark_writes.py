#!/usr/bin/env python3
"""
Module: kernel.tests.benchmark_writes
Purpose: Compare mounted slate-ntfs and NTFS-3G write latency on disposable files.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Compare mounted slate-ntfs and NTFS-3G write latency on disposable files.

Usage: benchmark_writes.py /mnt/slate /mnt/ntfs3g [--rounds 3]
Each round creates and removes only its own temporary directory.
"""

import argparse
import json
import os
import statistics
import time
from pathlib import Path


def timed(action):
    start = time.perf_counter_ns()
    action()
    return (time.perf_counter_ns() - start) / 1e9


def overwrite(directory):
    path = directory / "overwrite.bin"
    with path.open("wb", buffering=0) as file:
        for _ in range(64):
            file.write(bytes(65536))
        os.fsync(file.fileno())
    with path.open("r+b", buffering=0) as file:
        def run():
            for i in range(512):
                file.seek(((i * 7919) % 1024) * 4096)
                file.write(b"x" * 4096)
            os.fsync(file.fileno())
        duration = timed(run)
    expected = bytearray(4 << 20)
    for i in range(512):
        offset = ((i * 7919) % 1024) * 4096
        expected[offset:offset + 4096] = b"x" * 4096
    assert path.read_bytes() == expected
    return duration


def append(directory):
    path = directory / "append.bin"
    with path.open("wb", buffering=0) as file:
        block = b"a" * 65536
        def run():
            for _ in range(128):
                file.write(block)
            os.fsync(file.fileno())
        duration = timed(run)
    assert path.read_bytes() == b"a" * (8 << 20)
    return duration


def names(directory):
    def run():
        for i in range(20):
            (directory / f"entry-{i:04d}").touch()
        for i in range(20):
            (directory / f"entry-{i:04d}").unlink()
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    duration = timed(run)
    assert all(not (directory / f"entry-{i:04d}").exists() for i in range(20))
    return duration


def sync_each(directory):
    path = directory / "sync.bin"
    with path.open("wb", buffering=0) as file:
        block = b"s" * 4096
        def run():
            for _ in range(100):
                file.write(block)
                os.fsync(file.fileno())
        duration = timed(run)
    assert path.read_bytes() == b"s" * (100 * 4096)
    return duration


def measure_round(mount):
    values = {}
    for name, action in (("overwrite_4k_512", overwrite),
                         ("append_64k_128", append),
                         ("create_unlink_20", names),
                         ("append_fsync_4k_100", sync_each)):
        values[name] = action(mount)
    for name in ("overwrite.bin", "append.bin", "sync.bin"):
        (mount / name).unlink()
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slate_mount", type=Path)
    parser.add_argument("ntfs3g_mount", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    if args.rounds < 1 or not args.slate_mount.is_dir() or not args.ntfs3g_mount.is_dir():
        parser.error("both mounts must exist and rounds must be positive")
    samples = {"slate": {}, "ntfs3g": {}}
    mounts = {"slate": args.slate_mount, "ntfs3g": args.ntfs3g_mount}
    for round_number in range(args.rounds):
        order = ("slate", "ntfs3g") if round_number % 2 == 0 else ("ntfs3g", "slate")
        for label in order:
            for name, value in measure_round(mounts[label]).items():
                samples[label].setdefault(name, []).append(value)
    results = {label: {name: {"median_seconds": statistics.median(values),
                              "rounds": values} for name, values in workloads.items()}
               for label, workloads in samples.items()}
    for name in results["slate"]:
        slate = results["slate"][name]["median_seconds"]
        ntfs3g = results["ntfs3g"][name]["median_seconds"]
        print(f"{name:22s} slate={slate:8.3f}s ntfs3g={ntfs3g:8.3f}s "
              f"ratio={slate / ntfs3g:6.2f}x")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
