#!/usr/bin/env python3
"""Module: kernel.tests.reclaim_vm
Purpose: Verify foreground progress during real mounted background reclamation.
Created: 2026-10-21
Architecture: Reuses the private shutdown guest runner; kprobe entry/return and
userspace markers establish overlap without adding production instrumentation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

import test_shutdown_vm as guest

TRACE_BUFFER_KIB = 8192
MINIMUM_RECLAIM_STEPS = 2
MINIMUM_OVERLAPPING_LOOKUPS = 10
NANOSECONDS_PER_SECOND = 1_000_000_000

CONTROLLER = r'''#!/bin/sh
# Module: kernel.tests.reclaim_controller
# Purpose: Mount a private fixture and trace concurrent reclaim work.
# Created: 2026-10-21
# Architecture: Only the isolated RAM-root guest registers these probes.
set -eu
export PATH=/bin:/usr/bin:/usr/sbin
root='/media/x/Novo volume'
trace=/sys/kernel/tracing
fail()
{
    echo D26_FAILED
    echo D27_FAILED
    dmesg
    trap - EXIT
    systemctl poweroff
    exit 1
}
trap fail EXIT
mkdir -p "$root" "$trace"
mount -t tracefs tracefs "$trace"
printf 'p:d27/reclaim_start slate_ntfs:ntfs_rs_reclaim reference=$arg2:u64\n' > "$trace/kprobe_events"
printf 'r:d27/reclaim_end slate_ntfs:ntfs_rs_reclaim\n' >> "$trace/kprobe_events"
# This C gate runs once per step; the Rust entry has no ftrace call site.
printf 'p:d27/reclaim_step slate_ntfs:ntfs_rs_make_room\n' >> "$trace/kprobe_events"
printf '@TRACE_BUFFER_KIB@' > "$trace/buffer_size_kb"
printf mono > "$trace/trace_clock"
printf 1 > "$trace/events/d27/enable"
printf 1 > "$trace/tracing_on"
view=$(cat /etc/d26-view)
mount -t ntfsrs -o "rw,compatibility=$view,permissions=desktop,uid=1000,gid=1000,sidmap=@SID_MAP@" /dev/vda "$root"
test-reclaim-guest "$root"
sync
mount -i -o remount,ro -- "$root"
umount "$root"
printf 0 > "$trace/tracing_on"
echo D27_TRACE_BEGIN
cat "$trace/trace"
echo D27_TRACE_END
ntfs-chkdsk --recovery-status /dev/vda
echo D27_PASS
trap - EXIT
systemctl poweroff
'''


def validate_trace(text, reference):
    intervals = []
    active = {}
    lookups = []
    fsyncs = []
    event = re.compile(r'-(\d+)\s+\[\d+\].*?\s(\d+\.\d+):\s+(\w+):\s+(.*)')
    for line in text.splitlines():
        match = event.search(line)
        if not match:
            continue
        pid, timestamp, kind, detail = match.groups()
        at = float(timestamp)
        if kind == 'reclaim_start':
            value = re.search(r'reference=(0x[\da-fA-F]+|\d+)', detail)
            if value and int(value[1], 0) == reference:
                active[pid] = {'start': at, 'steps': 0}
        elif kind == 'reclaim_step' and pid in active:
            active[pid]['steps'] += 1
        elif kind == 'reclaim_end' and pid in active:
            intervals.append({**active.pop(pid), 'end': at})
        elif kind == 'tracing_mark_write':
            value = re.search(r'D27_LOOKUP value=(\d+)', detail)
            if value:
                lookups.append((at, int(value[1])))
            elif 'D27_CREATOR_FSYNC' in detail or 'D27_LEDGER_FSYNC' in detail:
                fsyncs.append(at)
    if len(intervals) != 1:
        raise AssertionError(f'expected one complete target reclamation, got {intervals}')
    interval = intervals[0]
    overlapping = [(at, delay) for at, delay in lookups if interval['start'] < at < interval['end']]
    concurrent_fsyncs = [at for at in fsyncs if interval['start'] < at < interval['end']]
    assert interval['steps'] >= MINIMUM_RECLAIM_STEPS, interval
    assert len(overlapping) >= MINIMUM_OVERLAPPING_LOOKUPS, (interval, len(overlapping))
    assert concurrent_fsyncs, 'no durable foreground progress during target reclamation'
    elapsed_ns = (interval['end'] - interval['start']) * NANOSECONDS_PER_SECOND
    assert max(delay for _, delay in overlapping) < elapsed_ns, 'lookup waited for the entire reclaim'
    return {
        **interval,
        'duration_seconds': elapsed_ns / NANOSECONDS_PER_SECOND,
        'overlapping_lookups': len(overlapping),
        'overlapping_fsync_markers': len(concurrent_fsyncs),
        'overlapping_lookup_max_ns': max(delay for _, delay in overlapping),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['module', 'kernel', 'checker', 'fixture', 'output', 'reference-file']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--view', choices=['ntfs', 'linux'], required=True)
    args = parser.parse_args()
    for name in ['module', 'kernel', 'checker', 'fixture', 'output', 'reference_file']:
        setattr(args, name, getattr(args, name).resolve())
    if not args.fixture.is_file():
        parser.error('--fixture must be a regular disposable image')
    args.case = 'reclaim'
    args.kernel_version = subprocess.check_output(
        ['modinfo', '-F', 'vermagic', str(args.module)], text=True
    ).split()[0]
    reference = int(args.reference_file.read_text().strip())
    with args.fixture.open('rb') as source:
        source_hash = hashlib.file_digest(source, 'sha256').hexdigest()
    args.output.mkdir(parents=True, exist_ok=False)
    image = args.output / 'volume.img'
    shutil.copyfile(args.fixture, image)
    controller = CONTROLLER.replace('@TRACE_BUFFER_KIB@', str(TRACE_BUFFER_KIB))
    initrd = guest.stage(
        args, helper_source=Path(__file__).with_name('test_reclaim_guest.c'),
        helper_name='test-reclaim-guest', controller=controller,
    )
    text = guest.boot(args, initrd, image, 1)
    assert 'D27_PASS' in text and 'D27_WORKLOAD_PASS' in text
    assert not re.search(r'\b(BUG:|Oops:|Kernel panic|WARNING:)', text), 'kernel diagnostics require investigation'
    match = re.search(r'D27_METRICS (\{[^\r\n]+\})', text)
    assert match, 'missing workload metrics'
    metrics = json.loads(match[1])
    metrics['target_reclaim'] = validate_trace(text, reference)
    metrics['final_status'] = guest.check_image(args, image, 0)
    checked = subprocess.run([str(args.checker), '--check', str(image)], capture_output=True, text=True)
    (args.output / 'check.log').write_text(checked.stdout + checked.stderr)
    assert checked.returncode == 0, checked.stdout + checked.stderr
    with args.fixture.open('rb') as source:
        assert hashlib.file_digest(source, 'sha256').hexdigest() == source_hash, 'source fixture changed'
    metrics['source_sha256'] = source_hash
    with args.module.open('rb') as source:
        metrics['module_sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
    (args.output / 'results.json').write_text(json.dumps(metrics, indent=2) + '\n')
    print(json.dumps(metrics, indent=2))
    print(f'PASS D27 {args.view}: {image}')


if __name__ == '__main__':
    main()
