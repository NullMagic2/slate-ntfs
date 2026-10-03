#!/usr/bin/env python3
"""Module: tests.windows.prepare_native_recovery
Purpose: Create disposable disks for native Windows recovery checks.
Created: 2026-10-02
Architecture: Produces guest disks and case manifests; native_recovery_guest.ps1 records the
Windows evidence.

Create disposable MBR disks for Windows recovery; never accepts an input device."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'source.img'
    with source.open('xb') as stream:
        stream.truncate(64 * 1024 * 1024)
    subprocess.run(['mkfs.ntfs', '-F', '-Q', str(source)], check=True, capture_output=True)
    payload = out / 'payload'
    payload.write_bytes(b'AAAA')
    subprocess.run(['ntfscp', '-f', str(source), str(payload), '/write.bin'], check=True)
    source_hash = digest(source)
    run_id = uuid.uuid4().hex
    template = Path(__file__).with_name('native_recovery_guest.ps1').read_text()
    writer = ROOT / 'target/release/ntfs-write-lab'
    for batch, phases in enumerate((range(0, 5), range(5, 10), (10, 11, 12))):
        directory = out / f'recovery-{run_id}-{batch}'
        directory.mkdir()
        cases = []
        for phase in phases:
            image = directory / f'phase{phase:02}.img'
            if phase == 0:
                image.write_bytes(source.read_bytes())
            else:
                env = dict(os.environ)
                env.pop('SLATE_NTFS_TEST_STOP_AFTER_FLUSH', None)
                if phase != 12:
                    env['SLATE_NTFS_TEST_STOP_AFTER_FLUSH'] = str(phase)
                result = subprocess.run([str(writer), '--journaled', str(source), str(image),
                                         'write.bin', '1', '414141', '313131'],
                                        env=env, capture_output=True)
                assert (result.returncode == 0) == (phase == 12), result
                assert image.is_file(), result
                (directory / f'phase{phase:02}.writer.txt').write_bytes(result.stdout + result.stderr)
            data = image.read_bytes()
            signature = 0x53600000 + phase
            mbr = bytearray(1048576)
            struct.pack_into('<I', mbr, 440, signature)
            mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff', 7,
                                      b'\xfe\xff\xff', 2048, len(data)//512)
            mbr[510:512] = b'\x55\xaa'
            disk = image.with_suffix('.disk')
            disk.write_bytes(mbr + data)
            cases.append(dict(phase=phase, signature=signature, disk=disk.name,
                              image_sha256=digest(image), disk_sha256=digest(disk),
                              expected='AAAA' if phase < 5 else 'A111'))
        manifest = dict(run_id=directory.name, source_sha256=source_hash, cases=cases)
        (directory / 'cases.json').write_text(json.dumps(manifest, indent=2)+'\n')
        script = template.replace('@RUN_ID@', directory.name).replace('@CASES_JSON@', json.dumps(cases))
        (directory / 'guest.ps1').write_text(script)
        print(directory)
    assert digest(source) == source_hash

if __name__ == '__main__':
    main()
