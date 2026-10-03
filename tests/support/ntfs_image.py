"""Module: tests.support.ntfs_image
Purpose: Encode independent disposable NTFS image fixtures.
Created: 2026-10-02
Architecture: Test suites reuse these encoders and process helpers; the checker binary validates
the resulting images.

Independent disposable-image fixture encoders; no tests execute on import."""
import hashlib
import os
import pathlib
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = pathlib.Path(os.environ.get("SLATE_NTFS_CHECKER", ROOT / "target/release/ntfs-chkdsk"))

def run(*args, ok=True, env=None):
    p = subprocess.run([str(x) for x in args], capture_output=True, env=env)
    if ok and p.returncode:
        raise AssertionError((args, p.returncode, p.stdout.decode(errors='replace'), p.stderr.decode(errors='replace')))
    if not ok and not p.returncode:
        raise AssertionError(('unexpected success', args, p.stdout))
    return p

def u(b, off, size):
    return int.from_bytes(b[off:off + size], 'little')


def put(b, off, value, size):
    b[off:off + size] = value.to_bytes(size, 'little')

def decode(raw, sector=512):
    b = bytearray(raw)
    usa, count = u(b, 4, 2), u(b, 6, 2)
    assert count == len(b) // sector + 1
    for i in range(count - 1):
        tail = (i + 1) * sector - 2
        assert b[tail:tail+2] == b[usa:usa+2]
        b[tail:tail+2] = b[usa+2+i*2:usa+4+i*2]
    return b

def protect(b, sector=512):
    b = bytearray(b)
    usa, count = u(b, 4, 2), u(b, 6, 2)
    seq = ((u(b, usa, 2) + 1) % 65536) or 1
    put(b, usa, seq, 2)
    for i in range(count - 1):
        tail = (i + 1) * sector - 2
        b[usa+2+i*2:usa+4+i*2] = b[tail:tail+2]
        put(b, tail, seq, 2)
    return b

def attrs(b):
    off = u(b, 0x14, 2)
    while u(b, off, 4) != 0xffffffff:
        size = u(b, off+4, 4)
        assert size >= 24
        yield off, u(b, off, 4)
        off += size

def attr(b, kind):
    return next(off for off, k in attrs(b) if k == kind and b[off+9] == 0)

def first_extent(b, off):
    cursor = off + u(b, off+0x20, 2)
    tag = b[cursor]; n, m = tag & 15, tag >> 4
    length = u(b, cursor+1, n)
    lcn = int.from_bytes(b[cursor+1+n:cursor+1+n+m], 'little', signed=True)
    assert b[cursor+1+n+m] == 0, 'fixture expects one physical extent'
    return lcn, length

def operation(code, target=0, redo=b'', undo=b'', record_off=0, attr_off=0, vcn=0, cluster_off=0, lcn=None):
    start = 40
    undo_start = (start + len(redo) + 7) & ~7
    b = bytearray((undo_start + len(undo) + 7) & ~7)
    struct.pack_into('<8H', b, 0, code, 7 if code == 7 else 0,
                     start, len(redo), undo_start, len(undo), target, int(lcn is not None))
    struct.pack_into('<3H', b, 16, record_off, attr_off, cluster_off)
    put(b, 24, vcn, 8)
    if lcn is not None: put(b, 32, lcn, 8)
    b[start:start+len(redo)] = redo
    b[undo_start:undo_start+len(undo)] = undo
    return b

def record(lsn, payload, tid=0, prev=0, kind=1):
    b = bytearray(48 + len(payload))
    struct.pack_into('<QQQIHHIIH', b, 0, lsn, prev, prev, len(payload), 0, 0, kind, tid, 0)
    b[48:] = payload
    return b

def page(lsn, raw, position):
    b = bytearray(4096)
    b[:4] = b'RCRD'
    struct.pack_into('<HHQ', b, 4, 40, 9, lsn)
    struct.pack_into('<IHHH', b, 16, 1, 1, 1, (64 + len(raw) + 7) & ~7)
    put(b, 32, lsn, 8); put(b, 60, position, 4)
    b[64:64+len(raw)] = raw
    return protect(b)

def restart(length, oldest, current, last_payload):
    b = bytearray(4096); b[:4] = b'RSTR'
    struct.pack_into('<HH', b, 4, 30, 9)
    struct.pack_into('<IIHHH', b, 16, 4096, 4096, 48, 1, 1)
    ra = 48; client = ra + 64
    put(b, ra, current, 8)
    struct.pack_into('<4H', b, ra+8, 1, 0xffff, 0, 0)
    struct.pack_into('<IHHQIHHI', b, ra+16, 67-length.bit_length(), 224, 64,
                     length, last_payload, 48, 64, 1)
    struct.pack_into('<QQHHH', b, client, oldest, oldest, 0xffff, 0xffff, 0)
    put(b, client+28, 8, 4); b[client+32:client+40] = 'NTFS'.encode('utf-16le')
    return protect(b)

def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''): result.update(block)
    return result.digest()
