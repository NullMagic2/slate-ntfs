#!/usr/bin/env python3
"""
Module: src.tests.bitlocker.test_image
Purpose: Independent clear-key BitLocker fixture over one disposable NTFS image.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Independent clear-key BitLocker fixture over one disposable NTFS image.
"""
import pathlib
import struct
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

ROOT = pathlib.Path(__file__).resolve().parents[3]
TOOLS = ROOT / "target" / "release"
SIZE = 32 * 1024 * 1024
SECTOR = 512
OFFSETS = (28 * 1024 * 1024, 29 * 1024 * 1024, 30 * 1024 * 1024)
HEADER_OFFSET = 31 * 1024 * 1024
GUID = bytes(range(16))
FVEK = bytes(range(32))
VMK = bytes(range(32, 64))
CLEAR = bytes(range(64, 96))


def put(buffer, at, number, width):
    buffer[at:at + width] = number.to_bytes(width, "little")


def datum(entry, value, body):
    return struct.pack("<HHHH", 8 + len(body), entry, value, 1) + body


def wrapped(key, plain, nonce):
    sealed = AESCCM(key, tag_length=16).encrypt(nonce, plain, None)
    return nonce + sealed[-16:] + sealed[:-16]


def key_datum(method, key):
    return struct.pack("<HHHHI", 12 + len(key), 0, 1, 1, method) + key


def metadata_block(method=0x8004, key=FVEK, volume_bytes=SIZE,
                   offsets=OFFSETS, header_offset=HEADER_OFFSET):
    clear_datum = datum(0, 1, bytes(4) + CLEAR)
    vmk_datum = datum(0, 5, wrapped(CLEAR, key_datum(0, VMK), bytes(range(12))))
    protector = bytearray(28)
    protector[:16] = GUID
    # Protection type at byte 26 is zero (clear key).
    entries = datum(2, 8, protector + clear_datum + vmk_datum)
    entries += datum(3, 5, wrapped(VMK, key_datum(method, key), bytes(range(12, 24))))
    size = 48 + len(entries)
    block = bytearray(65536)
    block[:8] = b"-FVE-FS-"
    put(block, 10, 2, 2)
    put(block, 12, 4, 2)
    put(block, 14, 4, 2)
    put(block, 16, volume_bytes, 8)
    put(block, 28, 16, 4)
    for index, offset in enumerate(offsets):
        put(block, 32 + 8 * index, offset, 8)
    put(block, 56, header_offset, 8)
    put(block, 64, size, 4)
    put(block, 68, 1, 4)
    put(block, 72, 48, 4)
    put(block, 76, size, 4)
    block[80:96] = GUID
    put(block, 100, method, 2)
    block[112:112 + len(entries)] = entries
    return block


def encrypt_sector(plain, sector_number):
    tweak = sector_number.to_bytes(16, "little")
    return Cipher(algorithms.AES(FVEK), modes.XTS(tweak)).encryptor().update(plain)


def run(*command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{command}: stdout={result.stdout} stderr={result.stderr}")
    return result.stdout


def main():
    with tempfile.TemporaryDirectory(prefix="slate-bitlocker-") as directory:
        baseline = pathlib.Path(directory) / "plain.img"
        encrypted = pathlib.Path(directory) / "encrypted.img"
        with baseline.open("wb") as output:
            output.truncate(SIZE)
        run("mkntfs", "-F", "-Q", "-s", "512", "-c", "4096", "-L", "SLATECRYPT", str(baseline))
        plain = baseline.read_bytes()
        assert plain[3:11] == b"NTFS    "
        image = bytearray(plain)
        for at in range(0, SIZE, SECTOR):
            if at == 0 or any(start <= at < start + 65536 for start in OFFSETS):
                continue
            image[at:at + SECTOR] = encrypt_sector(plain[at:at + SECTOR], at // SECTOR)
        for at in range(0, 16 * SECTOR, SECTOR):
            physical = HEADER_OFFSET + at
            image[physical:physical + SECTOR] = encrypt_sector(
                plain[at:at + SECTOR], physical // SECTOR)
        boot = bytearray(plain[:SECTOR])
        boot[3:11] = b"-FVE-FS-"
        for index, offset in enumerate(OFFSETS):
            put(boot, 176 + 8 * index, offset, 8)
        image[:SECTOR] = boot
        block = metadata_block()
        for at in OFFSETS:
            image[at:at + len(block)] = block
        encrypted.write_bytes(image)
        info = run(str(TOOLS / "ntfs-bitlocker"), "info", str(encrypted))
        assert "XTS-AES-128" in info, info
        verified = run(str(TOOLS / "ntfs-bitlocker"), "verify", str(encrypted),
                       "--bitlocker=clear")
        assert "unlocked=1" in verified, verified
        # Damage the first metadata copy; the second copy must still unlock.
        image[OFFSETS[0]:OFFSETS[0] + 8] = b"bad-copy"
        encrypted.write_bytes(image)
        verified = run(str(TOOLS / "ntfs-bitlocker"), "verify", str(encrypted),
                       "--bitlocker=clear")
        assert "unlocked=1" in verified, verified
        print("BitLocker clear-key unlock, relocated NTFS boot, metadata-copy fallback: passed")


if __name__ == "__main__":
    main()
