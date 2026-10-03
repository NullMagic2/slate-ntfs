#!/usr/bin/env python3
"""Module: examples.benchmark_ntfs3g
Purpose: Measure the matching workload on a disposable ntfs-3g mount.
Created: 2026-10-02
Architecture: run_wsl_comparison.sh supplies the mount; benchmark_writer.rs measures the
corresponding core workload.

Matching mounted ntfs-3g workload for benchmark_writer.rs, on a disposable image."""
import os
import sys
import time
from pathlib import Path


def timed(action):
    start = time.perf_counter()
    action()
    return time.perf_counter() - start


def main(root: Path):
    overwrite = root / "overwrite.bin"
    with overwrite.open("wb", buffering=0) as out:
        for _ in range(64):
            out.write(bytes(65536))
        os.fsync(out.fileno())
    block = b"x" * 4096
    with overwrite.open("r+b", buffering=0) as out:
        def do_overwrite():
            for i in range(512):
                out.seek(((i * 7919) % 1024) * 4096)
                out.write(block)
            os.fsync(out.fileno())
        print(f"overwrite_4k_512={timed(do_overwrite):.6f}", flush=True)

    with (root / "append.bin").open("wb", buffering=0) as out:
        def do_append():
            for _ in range(128):
                out.write(b"a" * 65536)
            os.fsync(out.fileno())
        print(f"append_64k_128={timed(do_append):.6f}", flush=True)

    def do_names():
        for i in range(20):
            (root / f"entry-{i:04d}").touch()
        for i in range(20):
            (root / f"entry-{i:04d}").unlink()
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    print(f"create_unlink_20={timed(do_names):.6f}", flush=True)

    with (root / "sync.bin").open("wb", buffering=0) as out:
        def do_sync_each():
            for _ in range(100):
                out.write(block)
                os.fsync(out.fileno())
        print(f"append_fsync_4k_100={timed(do_sync_each):.6f}", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]))
