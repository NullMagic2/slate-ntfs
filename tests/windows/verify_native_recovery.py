#!/usr/bin/env python3
"""Module: tests.windows.verify_native_recovery
Purpose: Validate guest recovery evidence against the generated case manifest.
Created: 2026-10-02
Architecture: Parses native_recovery_guest.ps1 transcripts; host test runners consume its
verification result.

Validate a fresh guest transcript against the exact generated case manifest."""
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

def verify(manifest, transcript):
    run_id = manifest['run_id']
    assert re.findall(r'^RUN_ID=(.*)$', transcript, re.M) == [run_id]
    assert re.findall(r'^RUN_COMPLETE=(.*)$', transcript, re.M) == [run_id]
    assert 'RUN_ERROR=' not in transcript
    blocks = re.findall(r'^CASE_SIGNATURE=(\d+);DRIVE=([A-Z]:)\n(.*?)(?=^CASE_SIGNATURE=|^NTFS_EVENT=|^RUN_COMPLETE=)',
                        transcript, re.M | re.S)
    assert len(blocks) == len(manifest['cases'])
    results = []
    for case, (signature, drive, body) in zip(manifest['cases'], blocks):
        assert int(signature) == case['signature']
        assert re.findall(r'^CONTENT=(.*)$', body, re.M) == [case['expected']], (case, body)
        assert re.findall(r'^CHKDSK_EXIT=(.*)$', body, re.M) == ['0'], (case, body)
        results.append(dict(phase=case['phase'], signature=int(signature), drive=drive,
                            content=case['expected'], chkdsk_exit=0))
    ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    drives = {row['drive'] for row in results}
    for xml in re.findall(r'^NTFS_EVENT=(.*?)(?=^NTFS_EVENT=|^RUN_COMPLETE=)', transcript, re.M | re.S):
        event = ET.fromstring(xml)
        event_id = int(event.find('e:System/e:EventID', ns).text)
        level = int(event.find('e:System/e:Level', ns).text)
        fields = {entry.get('Name'): entry.text for entry in event.findall('e:EventData/e:Data', ns)}
        # Also reject any reported repair on a tested volume, not just event 55.
        if any(value in drives for value in fields.values()):
            assert event_id not in (55, 98, 130, 131, 140) and level > 3, (event_id, fields)
    return dict(run_id=run_id, cases=results, passed=True)

if __name__ == '__main__':
    directory = Path(sys.argv[1])
    transcript = (directory/'windows.txt').read_text(encoding='utf-8-sig')
    result = verify(json.loads((directory/'cases.json').read_text()), transcript)
    (directory/'verified.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))
