#!/usr/bin/env python3
"""
Module: src.tests.recovery.test_native_replay
Purpose: Independent native LFS fixture encoder + disposable NTFS integration tests.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Independent native LFS fixture encoder + disposable NTFS integration tests.

Does not use slate's log encoders. Never accepts a user disk path. Windows
compatibility is not established by these synthetic histories.
"""
import hashlib
import pathlib
import shutil
import struct
import subprocess
import tempfile
import os

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import ROOT, CHECKER, run, u, put, decode, protect, attrs, attr, first_extent, operation, record, page, restart, digest

def fixture(path, wrap=False):
    """Two independent resident records: committed redo and unfinished undo."""
    with path.open('r+b') as f:
        boot = f.read(512); cluster = u(boot, 11, 2) * boot[13]
        rs = 1 << -int.from_bytes(boot[64:65], 'little', signed=True)
        mft_start = u(boot, 48, 8) * cluster
        def get(number):
            f.seek(mft_start + number * rs); return decode(f.read(rs))
        zero = get(0); mft_off = attr(zero, 0x80)
        mft_lcn, _ = first_extent(zero, mft_off)
        assert mft_lcn * cluster == mft_start
        targets = []
        for number in range(16, u(zero, mft_off+48, 8) // rs):
            b = get(number)
            if u(b, 22, 2) != 1: continue
            for off, kind in attrs(b):
                if kind != 0x30: continue
                val = off + u(b, off+20, 2)
                name = bytes(b[val+66:val+66+b[val+64]*2]).decode('utf-16le')
                if name in ('winner.bin', 'loser.bin'):
                    targets.append((name, number, b))
        targets.sort(reverse=True)
        assert [x[0] for x in targets] == ['winner.bin', 'loser.bin']
        log_record = get(2); log_attr = attr(log_record, 0x80)
        log_lcn, _ = first_extent(log_record, log_attr)
        length = u(log_record, log_attr+48, 8)
        log_start = log_lcn * cluster
        count = 5
        positions = []; generation = 1
        position = length - 3 * 4096 if wrap else 4 * 4096
        bits = length.bit_length() - 3
        for _ in range(count):
            positions.append((position, (generation << bits) | ((position+64)//8)))
            position += 4096
            if position == length: position = 4*4096; generation += 1
        lsns = [lsn for _, lsn in positions]
        cp = bytearray(64); put(cp, 0, 1, 4); put(cp, 8, lsns[0], 8)
        opened = bytearray(40); put(opened, 0, 0xffffffff, 4); put(opened, 8, 0x80, 4)
        put(opened, 16, u(zero, 16, 2) << 48, 8); put(opened, 24, lsns[1], 8)
        payloads = [cp, operation(0x1c, 24, opened)]
        metadata = []
        for index, (name, number, b) in enumerate(targets):
            off = attr(b, 0x80); assert b[off+8] == 0
            value = u(b, off+20, 2); vbo = number * rs
            before, after = (b'AAA', b'111') if index == 0 else (b'BBB', b'222')
            assert b[off+value+1:off+value+4] == before
            op = operation(7, 24, after, before, off, value+1, vbo//cluster,
                           (vbo % cluster)//512, mft_lcn + vbo//cluster)
            if index == 0:
                payloads.extend([op, operation(0x1a)])
            else:
                payloads.append(op)
                # Simulate an uncommitted dirty metadata page reaching disk.
                b[off+value+1:off+value+4] = after
                put(b, 8, lsns[4], 8)
                f.seek(mft_start + number * rs); f.write(protect(b))
            metadata.append((number, off+value+1))
        raw_records = [record(lsns[0], payloads[0], kind=2),
                       record(lsns[1], payloads[1], 24),
                       record(lsns[2], payloads[2], 24, lsns[1]),
                       record(lsns[3], payloads[3], 24, lsns[2]),
                       record(lsns[4], payloads[4], 64)]
        log = bytearray(b'\xff' * length)
        for (pos, lsn), raw in zip(positions, raw_records):
            log[pos:pos+4096] = page(lsn, raw, pos)
        rp = restart(length, lsns[0], lsns[-1], len(payloads[-1]))
        log[:4096] = rp; log[4096:8192] = rp
        f.seek(log_start); f.write(log)
        volume = get(3); off = attr(volume, 0x70); val = off + u(volume, off+20, 2)
        put(volume, val+10, u(volume, val+10, 2) | 1, 2)
        for pos in (mft_start+3*rs, u(boot, 56, 8)*cluster+3*rs):
            f.seek(pos); f.write(protect(volume))
    return dict(log_start=log_start, positions=positions, metadata=metadata,
                mft_start=mft_start, record_size=rs, log_length=length)

def assert_data(path):
    assert run('ntfscat', '-f', path, '/winner.bin').stdout == b'A111'
    assert run('ntfscat', '-f', path, '/loser.bin').stdout == b'BBBB'

def main():
    for tool in ('mkfs.ntfs', 'ntfscp', 'ntfscat'): assert shutil.which(tool), tool
    cases = 0
    with tempfile.TemporaryDirectory(prefix='slate-native-replay-') as tmp:
        d = pathlib.Path(tmp); base = d/'base.img'
        with base.open('wb') as f: f.truncate(64*1024*1024)
        run('mkfs.ntfs', '-F', '-Q', base)
        for name, payload in [('winner.bin', b'AAAA'), ('loser.bin', b'BBBB')]:
            p = d/name; p.write_bytes(payload); run('ntfscp', '-f', base, p, '/'+name)
        for wrap in (False, True):
            source = d/f'source-{wrap}.img'; shutil.copyfile(base, source)
            info = fixture(source, wrap); original = digest(source)
            output = d/f'recovered-{wrap}.img'
            result = run(CHECKER, '--replay-to', source, output)
            assert b'redo_records=1' in result.stdout and b'undo_records=1' in result.stdout
            assert b'checkpoint_published=1' in result.stdout
            assert_data(output); assert digest(source) == original
            assert run(CHECKER, '--status', output).stdout == b'dirty=1\n'
            checkpoint_pos = info['positions'][-1][0] + 4096
            if checkpoint_pos == info['log_length']: checkpoint_pos = 4*4096
            final_checkpoint_pos = checkpoint_pos + 4096
            if final_checkpoint_pos == info['log_length']: final_checkpoint_pos = 4*4096
            allowed_ranges = [(info['log_start'], info['log_start']+8192),
                              (info['log_start']+checkpoint_pos, info['log_start']+checkpoint_pos+4096),
                              (info['log_start']+final_checkpoint_pos, info['log_start']+final_checkpoint_pos+4096)]
            allowed_ranges += [(info['mft_start']+n*info['record_size'],
                                info['mft_start']+(n+1)*info['record_size']) for n, _ in info['metadata']]
            # The entire image, including $Secure and all directory indexes,
            # must be identical outside the explicitly planned record/pages.
            with source.open('rb') as before, output.open('rb') as after:
                offset = 0
                while True:
                    a, b = before.read(1024*1024), after.read(1024*1024)
                    if not a: assert not b; break
                    assert len(a) == len(b)
                    if a != b:
                        outside = [offset+i for i, (x, y) in enumerate(zip(a, b))
                                   if x != y and not any(lo <= offset+i < hi for lo, hi in allowed_ranges)]
                        assert not outside, (outside[0], outside[-1], len(outside),
                                             checkpoint_pos, info['positions'], allowed_ranges)
                    offset += len(a)
            # Preserve all MFT bytes outside data, LSN and USA fields, including
            # security IDs, names, timestamps and any other attributes.
            with source.open('rb') as before, output.open('rb') as after:
                for number, data_off in info['metadata']:
                    pos = info['mft_start'] + number*info['record_size']
                    before.seek(pos); after.seek(pos)
                    a = decode(before.read(info['record_size'])); b = decode(after.read(info['record_size']))
                    usa, usa_bytes = u(a, 4, 2), u(a, 6, 2)*2
                    allowed = set(range(8, 16)) | set(range(usa, usa+usa_bytes)) | set(range(data_off, data_off+3))
                    assert all(x == y or i in allowed for i, (x, y) in enumerate(zip(a, b)))
            again = d/f'again-{wrap}.img'; run(CHECKER, '--replay-to', output, again)
            assert digest(again) == digest(output), 'checkpoint retry must be byte-identical'
            run(CHECKER, '--replay-to', source, output, ok=False) # Never overwrite.
            # Copy, two metadata writes, checkpoint, secondary restart, primary.
            for boundary in range(1, 7):
                crash = d/f'crash-{wrap}-{boundary}.img'
                env = dict(os.environ, SLATE_NTFS_TEST_STOP_AFTER_FLUSH=str(boundary))
                run(CHECKER, '--replay-to', source, crash, env=env, ok=False)
                resumed = d/f'resumed-{wrap}-{boundary}.img'
                run(CHECKER, '--replay-to', crash, resumed)
                assert_data(resumed); cases += 1
            # Simulate a torn new restart copy; old restart must survive.
            crash = d/f'crash-{wrap}-5.img'
            with crash.open('r+b') as f:
                f.seek(info['log_start']+4096+510); f.write(b'\0\0')
            resumed = d/f'torn-restart-{wrap}.img'
            run(CHECKER, '--replay-to', crash, resumed); assert_data(resumed); cases += 1
            # An unpublished torn checkpoint is safely overwritten; a torn
            # primary restart is repaired using the durable secondary copy.
            for boundary, relative in ((4, None), (6, 0)):
                crash = d/f'crash-{wrap}-{boundary}.img'
                if relative is None:
                    relative = info['positions'][-1][0] + 4096
                    if relative == info['log_length']: relative = 4*4096
                with crash.open('r+b') as f:
                    f.seek(info['log_start']+relative+510); f.write(b'\0\0')
                resumed = d/f'torn-publication-{wrap}-{boundary}.img'
                run(CHECKER, '--replay-to', crash, resumed); assert_data(resumed); cases += 1
            # Corrupt current metadata fixups: do not attempt reconstruction.
            bad = d/f'torn-mft-{wrap}.img'; shutil.copyfile(source, bad)
            with bad.open('r+b') as f:
                f.seek(info['mft_start']+info['metadata'][0][0]*info['record_size']+510); f.write(b'\0\0')
            rejected = d/f'torn-mft-output-{wrap}.img'
            run(CHECKER, '--replay-to', bad, rejected, ok=False); assert not rejected.exists(); cases += 1
            # Individually corrupt a record while keeping valid page fixups.
            for kind in ('operation', 'lcn', 'chain', 'client', 'stale', 'attribute-boundary'):
                bad = d/f'bad-{wrap}-{kind}.img'; shutil.copyfile(source, bad)
                pos = info['log_start'] + info['positions'][2][0]
                with bad.open('r+b') as f:
                    f.seek(pos); b = decode(f.read(4096))
                    at = {'operation':112, 'lcn':144, 'chain':72, 'client':92, 'stale':64,
                          'attribute-boundary':128}[kind]
                    if kind == 'operation':
                        # 7 XOR 0x10 is HotFix (23), now a supported control.
                        # Use an unknown opcode for this refusal fixture.
                        put(b, at, 0xffff, 2)
                    else:
                        b[at] ^= 0x10
                    f.seek(pos); f.write(protect(b))
                rejected = d/f'bad-output-{wrap}-{kind}.img'
                run(CHECKER, '--replay-to', bad, rejected, ok=False); assert not rejected.exists(); cases += 1
            # A restart area's current LSN can lag durable log appends.
            # Discover the later commit, so the former loser keeps its redo.
            bad = d/f'later-commit-{wrap}.img'; shutil.copyfile(source, bad)
            pos, previous_lsn = info['positions'][-1]
            next_pos = pos + 4096
            bits = info['log_length'].bit_length() - 3
            generation = previous_lsn >> bits
            if next_pos == info['log_length']: next_pos = 4*4096; generation += 1
            lsn = (generation << bits) | ((next_pos+64)//8)
            with bad.open('r+b') as f:
                f.seek(info['log_start']+next_pos)
                f.write(page(lsn, record(lsn, operation(0x1a), 64, previous_lsn), next_pos))
            recovered = d/f'later-commit-output-{wrap}.img'
            run(CHECKER, '--replay-to', bad, recovered)
            assert run('ntfscat', '-f', recovered, '/winner.bin').stdout == b'A111'
            assert run('ntfscat', '-f', recovered, '/loser.bin').stdout == b'B222'
            cases += 1
    print(f'Native replay: redo/undo, circular wrap, metadata preservation, checkpoint idempotence; {cases} interruption/refusal cases passed.')

if __name__ == '__main__': main()
