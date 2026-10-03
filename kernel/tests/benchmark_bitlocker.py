#!/usr/bin/env python3
"""
Module: kernel.tests.benchmark_bitlocker
Purpose: Retained synthetic BitLocker fixtures and mounted crypto comparison (root).
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Retained synthetic BitLocker fixtures and mounted crypto comparison (root).

All keys are public test constants. A source image is copied once and retained;
the originals are never modified. Stock dm-crypt generates the ciphertext.
FVE metadata lives beyond the NTFS address space, so allocation cannot reuse it.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import mmap
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src/tests/bitlocker"))
from test_image import metadata_block, put

MIB = 1 << 20
FILE_BYTES = 32 * MIB
FILE_NAME = "slate-crypto-benchmark.bin"
SIDMAP = "u:0:S-1-5-32-544;g:0:S-1-5-18"
TOOLS = ROOT / "target/release"
MOUNT = ROOT / "ntfs_utils/target/release/ntfs-mount"


def run(*args, **kwargs):
    result = subprocess.run([str(a) for a in args], capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args}: {result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hash_stream(source)


def hash_stream(source):
    value = hashlib.sha256()
    for block in iter(lambda: source.read(MIB), b""):
        value.update(block)
    return value.hexdigest()


@contextmanager
def loop_device(image):
    device = run("losetup", "--find", "--show", image)
    try:
        yield device
    finally:
        run("losetup", "-d", device)


@contextmanager
def crypt_device(device, method, length):
    name = f"slate-crypto-{os.getpid()}"
    key = bytes(range(32)) if method == "xts" else bytes(range(16)) + bytes(range(32, 48))
    cipher = "aes-xts-plain64" if method == "xts" else "aes-cbc-elephant"
    # This is a known fixture key, never a user's volume key.
    table = f"0 {length // 512} crypt {cipher} {key.hex()} 0 {device} 0"
    run("dmsetup", "create", name, input=table)
    try:
        yield Path("/dev/mapper") / name
    finally:
        run("dmsetup", "remove", "--retry", name)


@contextmanager
def logical_device(raw, info):
    name = f"slate-logical-{os.getpid()}"
    sectors = info["plain_bytes"] // 512
    table = f"0 16 linear {raw} {info['header_offset'] // 512}\n16 {sectors - 16} linear {raw} 16"
    run("dmsetup", "create", name, input=table)
    try:
        yield Path("/dev/mapper") / name
    finally:
        run("dmsetup", "remove", "--retry", name)


@contextmanager
def mounted(device, directory, encrypted=False, ntfs3g=False):
    directory.mkdir(exist_ok=True)
    if ntfs3g:
        run("ntfs-3g", device, directory)
    elif encrypted:
        run(MOUNT, device, directory, f"--sidmap={SIDMAP}", "--bitlocker=clear")
    else:
        run("mount", "-t", "ntfsrs", "-o", f"rw,sidmap={SIDMAP}", device, directory)
    try:
        yield directory
    finally:
        run("umount", directory)


def fill(path, value):
    with path.open("wb") as output:
        for _ in range(FILE_BYTES // MIB):
            output.write(bytes([value]) * MIB)
        output.flush()
        os.fsync(output.fileno())


def prepare(directory, source):
    directory.mkdir(parents=True, exist_ok=True)
    manifest = directory / "fixture.json"
    if manifest.exists():
        info = json.loads(manifest.read_text())
        for name in ("plain", "xts", "diffuser"):
            assert (directory / f"{name}.img").is_file()
        return info
    pending = directory / "preparation.json"
    if any(directory.glob("*.img")) and not pending.exists():
        raise RuntimeError("Incomplete retained fixture exists; inspect it before resuming")
    run(TOOLS / "ntfs-chkdsk", "--audit", source)
    before = digest(source)
    if pending.exists():
        assert json.loads(pending.read_text())["source_sha256"] == before
    else:
        pending.write_text(json.dumps({"source_sha256": before}) + "\n")
    plain = directory / "plain.img"
    if not plain.exists():
        shutil.copyfile(source, plain)
        with loop_device(plain) as device, mounted(device, directory / "seed-mount") as mount:
            assert not (mount / FILE_NAME).exists()
            fill(mount / FILE_NAME, 0x5a)
    run(TOOLS / "ntfs-chkdsk", "--audit", plain)
    size = plain.stat().st_size
    info = {"source": str(source), "source_sha256": before, "plain_bytes": size,
            "device_bytes": size + 4 * MIB, "offsets": [size, size + MIB, size + 2 * MIB],
            "header_offset": size + 3 * MIB, "file_bytes": FILE_BYTES,
            "keys": "Public test constants from src/tests/bitlocker/test_image.py; no security value",
            "generator": "Stock Linux dm-crypt; synthetic FVE metadata outside the NTFS namespace"}
    with plain.open("rb") as source_file:
        header = source_file.read(8192)
    assert header[3:11] == b"NTFS    "
    for method, code in [("xts", 0x8004), ("diffuser", 0x8000)]:
        print(f"Generating retained {method} fixture", flush=True)
        image = directory / f"{method}.img"
        with image.open("r+b" if image.exists() else "xb") as output:
            output.truncate(info["device_bytes"])
        with loop_device(image) as device, crypt_device(device, method, info["device_bytes"]) as crypt:
            with plain.open("rb") as source_file, crypt.open("r+b", buffering=0) as output:
                shutil.copyfileobj(source_file, output, MIB)
                output.seek(info["header_offset"])
                assert output.write(header) == len(header)
                os.fsync(output.fileno())
        boot = bytearray(header[:512])
        boot[3:11] = b"-FVE-FS-"
        for index, offset in enumerate(info["offsets"]):
            put(boot, 176 + 8 * index, offset, 8)
        key = bytes(range(32 if method == "xts" else 64))
        block = metadata_block(code, key, info["device_bytes"], info["offsets"], info["header_offset"])
        with image.open("r+b") as output:
            output.write(boot)
            for offset in info["offsets"]:
                output.seek(offset)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        print(run(TOOLS / "ntfs-bitlocker", "verify", image, "--bitlocker=clear"), flush=True)
    assert digest(source) == before
    info["initial_sha256"] = {name: digest(directory / f"{name}.img") for name in ("plain", "xts", "diffuser")}
    manifest.write_text(json.dumps(info, indent=2) + "\n")
    return info


def read_file(path, expected, direct):
    flags = os.O_RDONLY | (os.O_DIRECT if direct else 0)
    fd = os.open(path, flags)
    try:
        with mmap.mmap(-1, FILE_BYTES) as data:
            view = memoryview(data)
            try:
                start = time.perf_counter()
                at = 0
                while at < FILE_BYTES:
                    part = view[at:min(at + MIB, FILE_BYTES)]
                    try:
                        count = os.preadv(fd, [part], at)
                    finally:
                        part.release()
                    assert count > 0, f"unexpected EOF at {at}"
                    at += count
                elapsed = time.perf_counter() - start
                actual = hashlib.sha256(data).digest()
            finally:
                view.release()
            assert actual == hashlib.sha256(expected).digest(), "mounted read differs from expected bytes"
            return elapsed
    finally:
        os.close(fd)


def write_file(path, value, direct):
    fd = os.open(path, os.O_RDWR | (os.O_DIRECT if direct else 0))
    try:
        with mmap.mmap(-1, MIB) as data:
            data[:] = bytes([value]) * MIB
            start = time.perf_counter()
            for at in range(0, FILE_BYTES, MIB):
                done = 0
                while done < MIB:
                    part = memoryview(data)[done:]
                    try:
                        count = os.pwrite(fd, part, at + done)
                    finally:
                        part.release()
                    assert count > 0, "zero-length write"
                    done += count
            os.fsync(fd)
            return time.perf_counter() - start
    finally:
        os.close(fd)


def measure(mount):
    path = mount / FILE_NAME
    expected = bytearray([0x5a]) * FILE_BYTES
    result = {"first_read_seconds": read_file(path, expected, False),
              "direct_read_seconds": read_file(path, expected, True)}
    result["buffered_write_fsync_seconds"] = write_file(path, 0x6d, False)
    expected[:] = bytes([0x6d]) * FILE_BYTES
    read_file(path, expected, True)
    result["direct_write_fsync_seconds"] = write_file(path, 0x38, True)
    expected[:] = bytes([0x38]) * FILE_BYTES
    read_file(path, expected, False)
    fd = os.open(path, os.O_RDWR)
    try:
        start = time.perf_counter()
        for index in range(100):
            at = ((index * 53) % (FILE_BYTES // 4096)) * 4096
            data = bytes([index]) * 4096
            assert os.pwrite(fd, data, at) == 4096
            os.fsync(fd)
        result["overwrite_100_fsync_seconds"] = time.perf_counter() - start
    finally:
        os.close(fd)
    for index in range(100):
        at = ((index * 53) % (FILE_BYTES // 4096)) * 4096
        expected[at:at + 4096] = bytes([index]) * 4096
    read_file(path, expected, True)
    write_file(path, 0x5a, False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--source", type=Path, default=Path("/var/tmp/slate-test-source.img"))
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    assert os.geteuid() == 0 and args.rounds > 0
    info = prepare(args.directory, args.source)
    if args.prepare_only:
        print(args.directory / "fixture.json")
        return
    cases = ["plain", "slate-xts", "dmcrypt-xts", "slate-diffuser", "dmcrypt-diffuser"]
    samples = {name: [] for name in cases}
    output = args.output or args.directory / "mounted-results.json"
    for round_number in range(args.rounds):
        order = cases[round_number:] + cases[:round_number]
        for name in order:
            kind = "plain" if name == "plain" else name.split("-", 1)[1]
            with loop_device(args.directory / f"{kind}.img") as device:
                mount = args.directory / "mount"
                if name.startswith("dmcrypt-"):
                    with crypt_device(device, kind, info["device_bytes"]) as crypt, logical_device(crypt, info) as logical:
                        with mounted(logical, mount):
                            sample = measure(mount)
                else:
                    with mounted(device, mount, encrypted=kind != "plain"):
                        sample = measure(mount)
            samples[name].append(sample)
            print(name, round_number + 1, json.dumps(sample), flush=True)
            output.write_text(json.dumps({"fixture": info, "samples": samples}, indent=2) + "\n")
    medians = {name: {metric: statistics.median(row[metric] for row in rows)
                     for metric in rows[0]} for name, rows in samples.items()}
    result = {"fixture": info, "samples": samples, "median_seconds": medians,
              "kernel": run("uname", "-r"), "module_sha256": digest(ROOT / "kernel/ntfs_rs.ko"),
              "scope": "Same Slate filesystem, ntfs-mount mapping versus direct dm-crypt mapping, reused images; fresh mount per case. Host caches remain warm. Writes include fsync. All payloads checked."}
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(medians, indent=2))


if __name__ == "__main__":
    main()
