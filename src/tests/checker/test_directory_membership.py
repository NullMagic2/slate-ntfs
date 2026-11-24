#!/usr/bin/env python3
"""Module: tests.checker.directory_membership
Purpose: Check reconstruction of derived indexes without losing family payloads.
Created: 2026-11-24
Architecture: Independent image edits exercise the public checker and copy repair;
    shared fixture encoders retain original generations, attributes and hashes.
"""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT / 'tests/support'))
from ntfs_image import CHECKER
from test_directory_repair import Image, attributes, data_hash, digest, u, put, values
from test_broader_consistency import listed, resident, rewrite
from test_semantic_repair import named

CASES = (
    'rootless-local', 'rootless-mixed', 'rootless-foreign-critical',
    'duplicate-roots', 'duplicate-foreign-owner',
    'middle-zero', 'middle-short', 'middle-overlong',
    'middle-unqualified-suffix', 'framed-padding',
)
REFUSALS = {'rootless-foreign-critical', 'duplicate-foreign-owner', 'middle-unqualified-suffix'}
MARKER = b'independent mixed-member payload'


def mutate(path, case):
    image = Image(path)
    try:
        record = image.get(5)
        items = values(record)
        index = next(attribute for attribute in items if u(attribute, 0, 4) == 0x90)
        if not case.startswith('duplicate-'):
            items.remove(index)
        if case == 'rootless-local':
            image.save(5, rewrite(record, items))
            return
        member = image.get(38)
        assert not u(member, 22, 2) & 1
        reference = 5 | (u(record, 16, 2) << 48)
        member_reference = 38 | (1 << 48)
        put(member, 16, 1, 2)
        put(member, 22, 1, 2)
        put(member, 32, reference, 8)
        put(member, 18, 0, 2)
        put(member, 40, 10, 2)
        marker = named(0x80, 'retained', MARKER, 9)
        if case.startswith('rootless-'):
            index[u(index, 20, 2) + 16] = 9
        if case == 'duplicate-foreign-owner':
            put(member, 32, 37 | (u(image.get(37), 16, 2) << 48), 8)
        image.save(38, rewrite(member, [index, marker]))
        image.bit(Image.runs(image.zero, Image.attribute(image.zero, 0xb0)), 38, True)
        entries = [listed(attribute, reference) for attribute in items]
        entries.extend([listed(index, member_reference), listed(marker, member_reference)])
        entries.sort(key=lambda row: (u(row, 0, 4), bytes(row[26:]), u(row, 8, 8)))
        target = next(row for row in entries if u(row, 0, 4) == 0x90)
        if case.startswith('middle-'):
            length = {
                'middle-zero': 0, 'middle-short': 32, 'middle-overlong': 48,
                'middle-unqualified-suffix': 0,
            }[case]
            put(target, 4, length, 2)
            if case == 'middle-unqualified-suffix':
                put(entries[entries.index(target) + 1], 24, 65535, 2)
        elif case == 'framed-padding':
            target[34:40] = bytes.fromhex('aa bb cc dd ee ff')
        elif case == 'rootless-foreign-critical':
            foreign = next(row for row in entries if u(row, 0, 4) == 0x80)
            put(foreign, 16, 37 | (u(image.get(37), 16, 2) << 48), 8)
        identifier = u(record, 40, 2)
        items.append(resident(0x20, b''.join(entries), identifier))
        put(record, 40, identifier + 1, 2)
        image.save(5, rewrite(record, items))
    finally:
        image.file.close()


def retained_attributes(image):
    return {
        u(attribute, 14, 2): bytes(attribute)
        for attribute in values(image.get(5))
        if u(attribute, 0, 4) not in (0x20, 0x30, 0x90, 0xa0, 0xb0)
    }


def check_case(base, output, case, quick):
    label = case + ('-quick' if quick else '')
    source = output / (label + '.img')
    repaired = output / (label + '-host.img')
    shutil.copyfile(base, source)
    mutate(source, case)
    image = Image(source)
    try:
        retained = retained_attributes(image)
        payloads = {number: data_hash(image, number) for number in (35, 37)}
        unchanged_parent = None
        if quick and case != 'framed-padding':
            record = image.get(24)
            at = Image.value(record, Image.attribute(record, 0x10))
            put(record, at, u(record, at, 8) + 123, 8)
            image.save(24, record)
            unchanged_parent = image.get(11)
    finally:
        image.file.close()
    original = digest(source)
    options = ['--index-check=quick'] if quick else []
    assessment = subprocess.run(
        [str(CHECKER), '--json', '--check', str(source)], capture_output=True, text=True,
    )
    if case == 'framed-padding':
        assert assessment.returncode == 0, (label, assessment.stdout, assessment.stderr)
    else:
        assert assessment.returncode != 0, label
    repair = subprocess.run(
        [str(CHECKER), *options, '--repair-to', str(source), str(repaired)],
        capture_output=True, text=True,
    )
    assert digest(source) == original
    if case in REFUSALS:
        assert repair.returncode != 0 and not repaired.exists(), (label, repair.stdout, repair.stderr)
        return {'case': label, 'refused': True, 'source_unchanged': True}
    assert repair.returncode == 0, (label, repair.stdout, repair.stderr)
    audit = subprocess.run(
        [str(CHECKER), '--json', '--check', str(repaired)], capture_output=True, text=True,
    )
    assert audit.returncode == 0, (label, audit.stdout, audit.stderr)
    image = Image(repaired)
    try:
        assert retained_attributes(image) == retained, label
        assert {number: data_hash(image, number) for number in payloads} == payloads, label
        if unchanged_parent is not None:
            assert image.get(11) == unchanged_parent, label
        if case != 'rootless-local':
            member = image.get(38)
            marker = next(attribute for attribute in values(member) if u(attribute, 0, 4) == 0x80)
            offset = u(marker, 20, 2)
            assert marker[offset:offset + u(marker, 16, 4)] == MARKER
            assert u(marker, 14, 2) == 9
            assert u(member, 32, 8) == 5 | (u(image.get(5), 16, 2) << 48)
    finally:
        image.file.close()
    repeated = output / (label + '-repeat.img')
    repeat = subprocess.run(
        [str(CHECKER), *options, '--repair-to', str(repaired), str(repeated)],
        capture_output=True, text=True,
    )
    assert repeat.returncode == 0, (label, repeat.stdout, repeat.stderr)
    assert digest(repeated) == digest(repaired), label
    return {
        'case': label, 'path': str(repaired.resolve()), 'sha256': digest(repaired),
        'source_unchanged': True, 'retained_attributes': True, 'idempotent': True,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('base', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cases', nargs='+', choices=CASES)
    parser.add_argument('--all', action='store_true')
    args = parser.parse_args()
    if not args.all and not args.cases:
        print('\n'.join(CASES))
        return
    args.output.mkdir(exist_ok=False)
    original = digest(args.base)
    results = []
    for case in CASES if args.all else args.cases:
        for quick in (False, True):
            results.append(check_case(args.base, args.output, case, quick))
            (args.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            jobs = [result for result in results if not result.get('refused')]
            (args.output / 'postchecks.json').write_text(json.dumps({'jobs': jobs}, indent=2) + '\n')
            print('PASS', results[-1]['case'], flush=True)
    assert digest(args.base) == original


if __name__ == '__main__':
    main()
