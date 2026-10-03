#!/usr/bin/env python3
"""Module: tests.windows.test_native_recovery_verifier
Purpose: Reject stale, incomplete or failed native recovery evidence.
Created: 2026-10-02
Architecture: Exercises verify_native_recovery.py with captured and corrupted transcripts
without attaching any disk.

Ensure captured Windows evidence cannot pass with stale or failed results."""
import json
from pathlib import Path
from verify_native_recovery import verify

root = Path(__file__).with_name('results')/'2026-09-28-native-recovery'
for batch in sorted(root.glob('recovery-*')):
    manifest = json.loads((batch/'cases.json').read_text())
    transcript = (batch/'windows.txt').read_text(encoding='utf-8-sig')
    assert verify(manifest, transcript)['passed']
    # A stale run, incomplete run, wrong data and chkdsk failure must fail.
    corrupt = [transcript.replace('RUN_ID=', 'STALE_RUN_ID=', 1),
               transcript.replace('RUN_COMPLETE=', 'INCOMPLETE=', 1),
               transcript.replace('CONTENT=', 'CONTENT=wrong', 1),
               transcript.replace('CHKDSK_EXIT=0', 'CHKDSK_EXIT=3', 1)]
    # chkdsk can report success after Windows has discarded a bad transaction.
    # Reject an explicit NTFS event even if all content/check outputs still pass.
    event = """NTFS_EVENT=<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>55</EventID><Level>2</Level></System><EventData><Data Name='DriveName'>D:</Data></EventData></Event>
"""
    corrupt.append(transcript.replace('RUN_COMPLETE=', event+'RUN_COMPLETE=', 1))
    for bad in corrupt:
        try:
            verify(manifest, bad)
        except AssertionError:
            pass
        else:
            raise AssertionError('Invalid Windows recovery evidence was accepted')
print('Windows transcript verifier: 3 recorded passes and 15 injected evidence failures passed.')
