#!/usr/bin/env python3
"""Module: tests.windows.prepare_kernel_recovery
Purpose: Stage actual kernel write fixtures for Windows recovery checks.
Created: 2026-10-02
Architecture: Consumes test_kernel_writes.py results and creates disposable guest disks and case
manifests.

Wrap actual test_kernel_writes.py outputs for a disposable Windows VM."""
from pathlib import Path
import hashlib
import json
import struct
import sys

source, out = (Path(arg).resolve() for arg in sys.argv[1:])
results = json.loads((source/'results.json').read_text())
assert len(results) == 11 and all(case['passed'] for case in results)
out.mkdir(parents=True, exist_ok=False)
cases = []
for phase in (0, 3, 4, 8, 10):
    image = source/f'phase{phase:02}.img'
    data = image.read_bytes()
    assert len(data) == 64*1024*1024
    signature = 0x53700000+phase
    mbr = bytearray(1048576)
    struct.pack_into('<I', mbr, 440, signature)
    mbr[446:462] = struct.pack('<B3sB3sII', 0, b'\xfe\xff\xff', 7,
                              b'\xfe\xff\xff', 2048, len(data)//512)
    mbr[510:512] = b'\x55\xaa'
    disk = out/image.with_suffix('.disk').name
    disk.write_bytes(mbr+data)
    cases.append(dict(phase=phase, signature=signature, disk=disk.name,
                      image_sha256=hashlib.sha256(data).hexdigest(),
                      expected='A222' if phase == 0 else ('AAAA' if phase < 4 else 'A111')))
(out/'cases.json').write_text(json.dumps(dict(run_id=out.name, cases=cases), indent=2)+'\n')
template = Path(__file__).with_name('native_recovery_guest.ps1').read_text()
(out/'guest.ps1').write_text(template.replace('@RUN_ID@', out.name).replace('@CASES_JSON@', json.dumps(cases)))
print(out)
