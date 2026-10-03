#!/usr/bin/env python3
"""
Module: kernel.tests.run_wsl_fresh_benchmark
Purpose: Compare mounted filesystems on a new disposable NTFS image each round.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Compare mounted filesystems on a new disposable NTFS image each round.
"""
import argparse
import json
import os
import shutil
import statistics
import subprocess
import tempfile
from pathlib import Path

from benchmark_writes import measure_round


def run(*args, **options):
    return subprocess.run(args, check=True, **options)


def mounted(path, image, kind):
    if kind == "slate":
        loop = run("losetup", "--find", "--show", str(image),
                   capture_output=True, text=True).stdout.strip()
        try:
            run("mount", "-t", "ntfsrs", "-o",
                "rw,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18", loop, str(path))
            return loop
        except BaseException:
            run("losetup", "-d", loop)
            raise
    run("ntfs-3g", str(image), str(path))
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=7)
    parser.add_argument("--module", type=Path, required=True)
    args = parser.parse_args()
    if args.rounds < 1 or os.geteuid() != 0:
        parser.error("run as root with at least one round")
    loaded_here = b"ntfs_rs " not in run("lsmod", capture_output=True).stdout
    if loaded_here:
        run("insmod", str(args.module))
    samples = {"slate": {}, "ntfs3g": {}}
    try:
        with tempfile.TemporaryDirectory(prefix="slate-fresh-", dir="/var/tmp") as raw:
            base = Path(raw)
            for round_number in range(args.rounds):
                source = base / "source.img"
                run("truncate", "-s", "128M", str(source))
                run("mkfs.ntfs", "-F", "-Q", "-c", "4096", str(source),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                order = ("slate", "ntfs3g") if round_number % 2 == 0 else ("ntfs3g", "slate")
                for label in order:
                    image = base / f"{label}.img"
                    directory = base / label
                    shutil.copyfile(source, image)
                    directory.mkdir(exist_ok=True)
                    loop = None
                    try:
                        loop = mounted(directory, image, label)
                        for name, value in measure_round(directory).items():
                            samples[label].setdefault(name, []).append(value)
                    finally:
                        if os.path.ismount(directory):
                            run("umount", str(directory))
                        if loop:
                            run("losetup", "-d", loop)
                        image.unlink(missing_ok=True)
                source.unlink()
    finally:
        if loaded_here:
            run("rmmod", "ntfs_rs")
    results = {label: {name: {"median_seconds": statistics.median(values),
                              "rounds": values} for name, values in workloads.items()}
               for label, workloads in samples.items()}
    for name in results["slate"]:
        slate = results["slate"][name]["median_seconds"]
        ntfs3g = results["ntfs3g"][name]["median_seconds"]
        print(f"{name:22s} slate={slate:8.3f}s ntfs3g={ntfs3g:8.3f}s "
              f"slate/ntfs3g={slate / ntfs3g:6.2f}x")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
