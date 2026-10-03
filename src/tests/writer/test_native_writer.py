#!/usr/bin/env python3
"""
Module: src.tests.writer.test_native_writer
Purpose: Native writer -> actual image -> reopened recovery -> independent readback.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Native writer -> actual image -> reopened recovery -> independent readback.
"""
import os
import pathlib
import shutil
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests/support"))
from ntfs_image import run, digest, decode, u, ROOT, CHECKER

WRITER = ROOT/'target/release/ntfs-write-lab'

def main():
    with tempfile.TemporaryDirectory(prefix='slate-native-writer-') as tmp:
        d = pathlib.Path(tmp)
        source = d/'source.img'
        with source.open('wb') as f: f.truncate(64*1024*1024)
        run('mkfs.ntfs', '-F', '-Q', source)
        payload = d/'payload'; payload.write_bytes(b'AAAA')
        run('ntfscp', '-f', source, payload, '/write.bin')
        source_hash = digest(source)
        def write(out, **kwargs):
            return run(WRITER, '--journaled', source, out, 'write.bin', 1, '414141', '313131', **kwargs)
        output = d/'completed.img'
        result = write(output)
        assert b'native_transaction_committed=1' in result.stdout
        assert b'checkpoint_published=1' in result.stdout
        assert run('ntfscat', '-f', output, '/write.bin').stdout == b'A111'
        assert run(CHECKER, '--status', output).stdout == b'dirty=1\n'
        repeat = d/'repeated.img'; run(CHECKER, '--replay-to', output, repeat)
        assert digest(output) == digest(repeat)
        assert source_hash == digest(source)
        write(output, ok=False); assert run('ntfscat', '-f', output, '/write.bin').stdout == b'A111'
        for boundary in range(1, 12):
            interrupted = d/f'interrupted-{boundary}.img'
            env = dict(os.environ, SLATE_NTFS_TEST_STOP_AFTER_FLUSH=str(boundary))
            write(interrupted, env=env, ok=False)
            if boundary == 7:
                # Inspect durable bytes independently of our Rust decoder.
                # Windows rejects the transaction if these LFS flags are zero.
                log = run('ntfscat', '-f', interrupted, '/$LogFile').stdout
                for page_number, opcode, flags in ((5, 0x1c, 4), (6, 7, 0), (7, 0x1a, 6)):
                    page = decode(log[page_number*4096:(page_number+1)*4096])
                    assert u(page, 64+48, 2) == opcode
                    assert u(page, 64+0x28, 2) == flags
            recovered = d/f'recovered-{boundary}.img'
            run(CHECKER, '--replay-to', interrupted, recovered)
            expected = b'AAAA' if boundary < 5 else b'A111'
            assert run('ntfscat', '-f', recovered, '/write.bin').stdout == expected, boundary
            again = d/f'repeat-{boundary}.img'; run(CHECKER, '--replay-to', recovered, again)
            assert digest(again) == digest(recovered), boundary
        # Refusals must precede output creation.
        wrong = d/'wrong.img'
        run(WRITER, '--journaled', source, wrong, 'write.bin', 1, '424242', '313131', ok=False)
        assert not wrong.exists()
        initialized = d/'initialized.img'
        run(WRITER, '--journaled', output, initialized, 'write.bin', 1, '313131', '323232', ok=False)
        assert not initialized.exists()
        assert source_hash == digest(source)
        assert not list(d.glob('*.initializing-*'))
    print('Native writer passed: actual redo/undo+commit creation, 11 durable interruption boundaries, old/new commit outcomes, repeat recovery, NTFS-3G readback and source immutability.')

if __name__ == '__main__': main()
