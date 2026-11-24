#!/usr/bin/env python3
"""Module: tests.checker.reserved_collisions
Purpose: Verify canonical system-name recovery without losing ordinary file data.
Created: 2026-11-24
Architecture: Independent directory keys and complete families exercise copy
    repair; resulting audits, payloads, hard links and source hashes are checked.
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
from test_directory_repair import (
    Image, data_hash, decode, digest, family_filenames, index_name_keys, protect, put, u, values,
)
from test_broader_consistency import listed, resident, rewrite
from test_semantic_repair import named, root, rows

CASES = (
    'ordinary-key', 'reserved-key', 'no-key', 'stale-key',
    'noncanonical', 'noncanonical-posix', 'alternative-link', 'extension-key',
)


def claim(record, label, parent, namespace, identifier):
    old = next(attribute for attribute in values(record) if u(attribute, 0, 4) == 0x30)
    offset = u(old, 20, 2)
    body = bytearray(old[offset:offset + 66]) + label.encode('utf-16le')
    put(body, 0, parent, 8)
    body[64] = len(label)
    body[65] = namespace
    attribute = resident(0x30, body, identifier)
    attribute[22] = 1
    return attribute, body


def entry(reference, body):
    result = bytearray((16 + len(body) + 7) & ~7)
    put(result, 0, reference, 8)
    put(result, 8, len(result), 2)
    put(result, 10, len(body), 2)
    result[16:16 + len(body)] = body
    return result


def mutate(path, case):
    image = Image(path)
    try:
        parent = 5 | (u(image.get(5), 16, 2) << 48)
        ordinary = image.get(37)
        reserved = image.get(10)
        ordinary_reference = 37 | (u(ordinary, 16, 2) << 48)
        reserved_reference = 10 | (u(reserved, 16, 2) << 48)
        label = 'WPSettings.dat' if case.startswith('noncanonical') else '$UpCase'
        namespace = 0 if case in ('noncanonical-posix', 'alternative-link') else 3
        attribute, body = claim(ordinary, label, parent, namespace, 2)
        contents = [attribute for attribute in values(ordinary) if u(attribute, 0, 4) != 0x30]
        contents.append(attribute)
        alternative = None
        if case == 'alternative-link':
            attribute, alternative = claim(ordinary, 'ordinary-survivor', parent, 0, 3)
            contents.append(attribute)
        put(ordinary, 18, 2 if alternative is not None else 1, 2)
        image.save(37, rewrite(ordinary, contents))
        if case.startswith('noncanonical'):
            attribute, _ = claim(reserved, label, parent, 3, 1)
            reserved = rewrite(reserved, [
                attribute if u(item, 0, 4) == 0x30 else item for item in values(reserved)
            ])
            image.save(10, reserved)
        if case == 'extension-key':
            member = image.get(38)
            assert not u(member, 22, 2) & 1
            put(member, 16, 1, 2)
            put(member, 22, 1, 2)
            put(member, 32, reserved_reference, 8)
            put(member, 18, 0, 2)
            contents = values(reserved)
            attribute = next(item for item in contents if u(item, 0, 4) == 0x30)
            contents.remove(attribute)
            image.save(38, rewrite(member, [attribute]))
            image.bit(Image.runs(image.zero, Image.attribute(image.zero, 0xb0)), 38, True)
            entries = [listed(item, reserved_reference) for item in contents]
            entries.append(listed(attribute, 38 | (1 << 48)))
            entries.sort(key=lambda row: (u(row, 0, 4), bytes(row[26:]), u(row, 8, 8)))
            identifier = u(reserved, 40, 2)
            contents.append(resident(0x20, b''.join(entries), identifier))
            put(reserved, 40, identifier + 1, 2)
            image.save(10, rewrite(reserved, contents))
        nested = image.get(36)
        value, entries = rows(nested, '$I30')
        entries = [item for item in entries if u(item, 0, 8) != ordinary_reference]
        image.save(36, rewrite(nested, [
            named(0x90, '$I30', root(value, entries), u(item, 14, 2))
            if u(item, 0, 4) == 0x90 else item for item in values(nested)
        ]))
        allocation = next(item for item in values(image.get(5)) if u(item, 0, 4) == 0xa0)
        physical = image.physical(Image.runs(allocation, 0), 0)
        image.file.seek(physical)
        block = decode(image.file.read(4096), image.sector)
        assert not block[36] & 1
        start = 24 + u(block, 24, 4)
        cursor = start
        entries = []
        while not u(block, cursor + 12, 2) & 2:
            length = u(block, cursor + 8, 2)
            if u(block, cursor, 8) != reserved_reference:
                entries.append(bytearray(block[cursor:cursor + length]))
            cursor += length
        terminal = block[cursor:cursor + u(block, cursor + 8, 2)]
        if case == 'reserved-key':
            attribute = next(item for item in values(reserved) if u(item, 0, 4) == 0x30)
            offset = u(attribute, 20, 2)
            entries.append(entry(reserved_reference, attribute[offset:offset + u(attribute, 16, 4)]))
        elif case != 'no-key':
            reference = ordinary_reference + (1 << 48) if case == 'stale-key' else ordinary_reference
            entries.append(entry(reference, body))
        if alternative is not None:
            entries.append(entry(ordinary_reference, alternative))
        entries.sort(key=lambda item: bytes(item[82:82 + item[80] * 2]).decode('utf-16le').upper())
        packed = b''.join(entries) + terminal
        assert start + len(packed) <= len(block)
        block[start:] = packed + bytes(len(block) - start - len(packed))
        put(block, 28, start + len(packed) - 24, 4)
        image.file.seek(physical)
        image.file.write(protect(block, image.sector))
    finally:
        image.file.close()


def fingerprints(path):
    image = Image(path)
    try:
        result = {}
        for number in (10, 37):
            record = image.get(number)
            offset = Image.value(record, Image.attribute(record, 0x10))
            result[number] = (data_hash(image, number), bytes(record[offset:offset + 32]))
        return result
    finally:
        image.file.close()


def check_case(base, output, case, quick):
    label = case + ('-quick' if quick else '')
    source = output / (label + '.img')
    target = output / (label + '-host.img')
    shutil.copyfile(base, source)
    mutate(source, case)
    original = digest(source)
    before = fingerprints(source)
    options = ['--index-check=quick'] if quick else []
    assessment = subprocess.run([str(CHECKER), '--json', '--check', str(source)], capture_output=True, text=True)
    assert assessment.returncode == 4, (label, assessment.stdout, assessment.stderr)
    repair = subprocess.run(
        [str(CHECKER), *options, '--repair-to', str(source), str(target)], capture_output=True, text=True,
    )
    assert repair.returncode == 0, (label, repair.stdout, repair.stderr)
    audit = subprocess.run([str(CHECKER), '--json', '--check', str(target)], capture_output=True, text=True)
    assert audit.returncode == 0, (label, audit.stdout, audit.stderr)
    assert fingerprints(target) == before
    image = Image(target)
    try:
        parent = 5 | (u(image.get(5), 16, 2) << 48)
        assert [(name['parent'], name['namespace'], name['name']) for name in family_filenames(image, 10)] == [
            (parent, 3, '$UpCase'),
        ]
        assert index_name_keys(image, 5, 10) == [(3, '$UpCase')]
        claims = family_filenames(image, 37)
        if case in ('alternative-link', 'noncanonical-posix'):
            name = 'ordinary-survivor' if case == 'alternative-link' else 'WPSettings.dat'
            assert [(item['parent'], item['namespace'], item['name']) for item in claims] == [(parent, 0, name)]
        else:
            name = '00000000file.chk' if case == 'noncanonical' else '00000000-$UpCase'
            assert [(item['namespace'], item['name']) for item in claims] == [(0, name)]
            assert claims[0]['parent'] != parent
    finally:
        image.file.close()
    repeated = output / (label + '-repeat.img')
    repeat = subprocess.run(
        [str(CHECKER), *options, '--repair-to', str(target), str(repeated)], capture_output=True, text=True,
    )
    assert repeat.returncode == 0, (label, repeat.stdout, repeat.stderr)
    assert digest(repeated) == digest(target)
    assert digest(source) == original
    return {'case': label, 'path': str(target.resolve()), 'sha256': digest(target)}


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
            (args.output / 'postchecks.json').write_text(json.dumps({'jobs': results}, indent=2) + '\n')
            print('PASS', results[-1]['case'], flush=True)
    assert digest(args.base) == original


if __name__ == '__main__':
    main()
