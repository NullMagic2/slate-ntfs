#!/usr/bin/env python3
"""
Module: src.tests.recovery.test_bitmap_replay
Purpose: Independent allocation-log fixtures. Only creates disposable regular files.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Independent allocation-log fixtures. Only creates disposable regular files.

These establish operation semantics and crash retry, not general Windows-log
compatibility. No fixture uses slate's Rust journal encoder.
"""
import os
import pathlib
import shutil
import struct
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import (ROOT, CHECKER, run, u, put, attr, decode,
                               protect, first_extent, operation, record,
                               page, restart, digest)


def fixture(path, code, committed, persisted, mft_bits=False, bad=None):
    with path.open('r+b') as f:
        boot = f.read(512)
        cluster = u(boot, 11, 2) * boot[13]
        size = 1 << -int.from_bytes(boot[64:65], 'little', signed=True)
        mft = u(boot, 48, 8) * cluster
        def get(n):
            f.seek(mft + n * size)
            return decode(f.read(size))
        owner = get(0 if mft_bits else 6)
        kind = 0xb0 if mft_bits else 0x80
        a = attr(owner, kind)
        bitmap_lcn, _ = first_extent(owner, a)
        bitmap = bitmap_lcn * cluster
        data_size = u(owner, a+48, 8)
        f.seek(bitmap)
        before = f.read(data_size)
        # Unaligned range crossing bytes; keep every unrelated bit unchanged.
        first = 29 if mft_bits else 8001
        count = 3 if mft_bits else 14
        for bit in range(first, first+count):
            assert not before[bit//8] & (1 << (bit % 8))
        clear = code == 0x16
        initial = bytearray(before)
        if clear:
            for bit in range(first, first+count): initial[bit//8] |= 1 << (bit%8)
        final = bytearray(initial)
        for bit in range(first, first+count):
            if clear: final[bit//8] &= ~(1 << (bit%8))
            else: final[bit//8] |= 1 << (bit%8)
        lo, hi = first//8, (first+count+7)//8
        if code == 8:
            payload = operation(8, 64, final[lo:hi], initial[lo:hi], attr_off=lo, lcn=bitmap_lcn)
            put(payload, 2, 8, 2)
        else:
            interval = struct.pack('<II', first, count)
            payload = operation(code, 64, interval, interval, lcn=bitmap_lcn)
            put(payload, 2, 0x15 if clear else 0x16, 2)
        if bad == 'lcn': put(payload, 32, bitmap_lcn+1, 8)
        if bad == 'range': put(payload, 40, 0xffffffff, 4)
        if bad == 'undo': payload[u(payload, 8, 2)] ^= 1
        if bad == 'target': put(payload, 12, 104, 2)
        if bad == 'padding':
            payload=operation(8,64,bytes([before[-1]^0x80]),before[-1:],attr_off=data_size-1,lcn=bitmap_lcn)
            put(payload,2,8,2)
        if bad == 'alias':
            at=a+u(owner,a+32,2); n,m=owner[at]&15,owner[at]>>4
            owner[at+1+n:at+1+n+m]=(mft//cluster).to_bytes(m,'little',signed=True)
            f.seek(mft+6*size); f.write(protect(owner))
            put(payload,32,mft//cluster,8)
        log = get(2); a = attr(log, 0x80)
        log_lcn, _ = first_extent(log, a)
        log_size = u(log, a+48, 8)
        bits = log_size.bit_length() - 3
        positions = [4096 * (i+4) for i in range(4 if committed else 3)]
        lsns = [(1 << bits) | ((p+64)//8) for p in positions]
        cp = bytearray(64); put(cp, 0, 1, 4); put(cp, 8, lsns[0], 8)
        opened = bytearray(40)
        put(opened, 0, 0xffffffff, 4); put(opened, 8, kind, 4)
        put(opened, 16, (0 if mft_bits else 6) | (u(owner, 16, 2)<<48), 8)
        put(opened, 24, lsns[1], 8)
        if bad == 'sequence': opened[22] ^= 1
        payloads = [cp, operation(0x1c, 64, opened), payload]
        if committed: payloads.append(operation(0x1a))
        raw = [record(lsns[0], cp, kind=2)]
        raw.extend(record(lsns[i], payloads[i], 24, 0 if i==1 else lsns[i-1]) for i in range(1, len(lsns)))
        data = bytearray(b'\xff' * log_size)
        for p, lsn, r in zip(positions, lsns, raw): data[p:p+4096] = page(lsn, r, p)
        rp = restart(log_size, lsns[0], lsns[-1], len(payloads[-1]))
        data[:4096] = rp; data[4096:8192] = rp
        f.seek(log_lcn*cluster); f.write(data)
        observed = final if persisted else initial
        if bad == 'preimage':
            observed = bytearray(observed); observed[lo] ^= 1  # unrelated bit inside byte patch
        f.seek(bitmap); f.write(observed)
        vol = get(3); a = attr(vol, 0x70); value = a + u(vol, a+20, 2)
        put(vol, value+10, 1, 2)
        for where in (mft+3*size, u(boot, 56, 8)*cluster+3*size):
            f.seek(where); f.write(protect(vol))
    return bitmap, bytes(final if committed else initial), (log_lcn*cluster, log_size), (lo, hi)


def main():
    cases = 0
    with tempfile.TemporaryDirectory(prefix='slate-bitmap-replay-') as tmp:
        d = pathlib.Path(tmp); base = d/'base.img'
        with base.open('wb') as f: f.truncate(64*1024*1024)
        run(ROOT/'ntfs_utils/target/release/ntfs-format', '--yes', '--quick', base)
        for mft_bits in (False, True):
            for code in (8, 0x15, 0x16):
                for committed in (False, True):
                    for persisted in (False, True):
                        source = d/'source.img'; shutil.copyfile(base, source)
                        at, expected, log, interval = fixture(source, code, committed, persisted, mft_bits)
                        original = digest(source)
                        plan = run(CHECKER, '--validate-replay', source)
                        assert b'replay_supported=1' in plan.stdout
                        for boundary in (None, 1, 2, 3, 4, 5):
                            output = d/'output.img'; output.unlink(missing_ok=True)
                            env = dict(os.environ)
                            if boundary: env['SLATE_NTFS_TEST_STOP_AFTER_FLUSH'] = str(boundary)
                            run(CHECKER, '--replay-to', source, output, ok=not boundary, env=env)
                            resumed = d/'resumed.img'; resumed.unlink(missing_ok=True)
                            run(CHECKER, '--replay-to', output, resumed)
                            with resumed.open('rb') as f: f.seek(at); assert f.read(len(expected)) == expected
                            # No modifications outside bitmap bytes and $LogFile.
                            a, b = source.read_bytes(), resumed.read_bytes()
                            allowed = [(at+interval[0], at+interval[1]), (log[0], log[0]+log[1])]
                            for start in range(0, len(a), 4096):
                                if a[start:start+4096] != b[start:start+4096]:
                                    assert all(x==y or any(lo<=start+i<hi for lo,hi in allowed)
                                               for i,(x,y) in enumerate(zip(a[start:start+4096],b[start:start+4096])))
                            assert digest(source) == original
                            cases += 1
        for code, bad in ((8,'lcn'), (8,'preimage'), (8,'target'), (8,'sequence'),
                          (0x15,'range'), (0x15,'undo'), (0x16,'undo'),
                          (8,'padding'), (0x15,'alias')):
            source=d/'bad.img'; shutil.copyfile(base, source)
            fixture(source, code, True, False, bad=bad)
            original=digest(source); output=d/'refused.img'
            run(CHECKER, '--replay-to', source, output, ok=False)
            assert not output.exists() and digest(source)==original
            cases+=1
    print(f'Bitmap replay: {cases} redo/undo, durable interruption, preservation and refusal cases passed.')

if __name__ == '__main__': main()
