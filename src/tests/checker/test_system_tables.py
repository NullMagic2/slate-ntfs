#!/usr/bin/env python3
"""Module: tests.checker.system_tables
Purpose: Verify system-table recovery, trusted mappings and private definitions.
Created: 2026-11-25
Architecture: Private image mutations call the real checker; independent bytes
verify collation, definition retention, DATA, ACLs and repeat repair.
"""
import argparse
import json
from pathlib import Path
import tempfile

import test_usn_repair as fixture
from test_object_reparse_repair import (
    Image, names, attributes, name, u, put, named, rewrite, family_values,
    value_of, digest, DATA_ATTRIBUTE, SECURITY_ATTRIBUTE, ATTRIBUTE_KIND,
    ATTRIBUTE_ID, RECORD_NEXT_ATTRIBUTE, RESIDENT_OFFSET,
)
from ntfs_image import CHECKER, run

UPCASE_RECORD = 10
ATTRDEF_RECORD = 4
TABLE_BYTES = 65536 * 2
INFO_BYTES = 32
CHECKSUM_OFFSET = 8
VERSION_OFFSET = 16
WORD_BYTES = 2
DWORD_BYTES = 4
QWORD_BYTES = 8
ROW_BYTES = 160
TYPE_OFFSET = 128
MINIMUM_OFFSET = 144
MAXIMUM_OFFSET = 152
PRIVATE_TYPE = 0x110
PRIVATE_LIMIT = 0x1000
PRIVATE_NAME = '$Private'
CUSTOM_UNIT = 0x0378
CUSTOM_FOLDED = 0x0379
SURROGATE = 0xd800
CRC_POLYNOMIAL = 0x9a6c9329ac4bc9b5
CRC_MASK = (1 << 64) - 1
ENCRYPTED_ATTRIBUTE = 0x4000
CASES = (
    'intact', 'trusted-custom', 'trusted-version', 'extended-info', 'external-info',
    'missing-info', 'short-info', 'bad-info-size', 'bad-checksum', 'nonascii-cycle',
    'surrogate-map', 'short-map', 'odd-map', 'missing-map', 'zero-map',
    'extension-map', 'extension-info', 'private-definition', 'private-with-missing-standard',
    'unordered-definitions', 'duplicate-private', 'conflicting-unused-private',
    'invalid-unused-private', 'partial-definitions', 'missing-definitions',
    'used-private', 'used-private-extension', 'undefined-private', 'conflicting-used-private', 'invalid-used-private',
    'unsupported-map-flags', 'unsupported-definition-flags',
    'uninitialized-map', 'uninitialized-info', 'uninitialized-definitions', 'missing-definition-stream',
)
REFUSED = {'unsupported-map-flags', 'unsupported-definition-flags'}
LIVE_PRIVATE_CASES = {
    'used-private', 'used-private-extension', 'undefined-private',
    'conflicting-used-private', 'invalid-used-private',
}
TRUSTED = {'intact', 'trusted-custom', 'trusted-version', 'extended-info', 'external-info',
           'extension-map', 'extension-info'}
PRIVATE_RETAINED = {'private-definition', 'private-with-missing-standard', 'unordered-definitions',
                    'duplicate-private', 'partial-definitions', 'used-private', 'used-private-extension'}


def crc(data):
    value = CRC_MASK
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (CRC_POLYNOMIAL if value & 1 else 0)
    return value ^ CRC_MASK


def cat(path, number, label=''):
    image = Image(path)
    try:
        attribute = next(a for a in family_values(image, number)
                         if u(a, ATTRIBUTE_KIND, DWORD_BYTES) == DATA_ATTRIBUTE and name(a) == label)
        if not attribute[fixture.ATTRIBUTE_NONRESIDENT]:
            at = u(attribute, RESIDENT_OFFSET, WORD_BYTES)
            return bytes(attribute[at:at + u(attribute, fixture.RESIDENT_LENGTH, DWORD_BYTES)])
        value = bytearray()
        for physical, clusters in fixture.extents(attribute):
            length = clusters * image.cluster
            if physical is None:
                value.extend(bytes(length))
            else:
                image.f.seek(physical * image.cluster)
                block = image.f.read(length)
                assert len(block) == length
                value.extend(block)
        return bytes(value[:u(attribute, fixture.DATA_OFFSET, QWORD_BYTES)])
    finally:
        image.close()


def replace_stream(image, number, label, value):
    fixture.stream(image, number, label, value)
    raw = image.get(number)
    ordered = sorted(attributes(raw), key=lambda a: (u(a, ATTRIBUTE_KIND, DWORD_BYTES), name(a).upper()))
    image.save(number, rewrite(raw, ordered))


def private_row():
    value = bytearray(ROW_BYTES)
    text = PRIVATE_NAME.encode('utf-16le')
    value[:len(text)] = text
    put(value, TYPE_OFFSET, PRIVATE_TYPE, DWORD_BYTES)
    put(value, MAXIMUM_OFFSET, CRC_MASK, QWORD_BYTES)
    return value


def mutate(path, case):
    image = Image(path)
    mapping = bytearray(cat(path, UPCASE_RECORD))
    information = bytearray(cat(path, UPCASE_RECORD, '$Info'))
    if case == 'trusted-custom':
        put(mapping, CUSTOM_UNIT * WORD_BYTES, CUSTOM_FOLDED, WORD_BYTES)
        put(information, CHECKSUM_OFFSET, crc(mapping), QWORD_BYTES)
    elif case == 'nonascii-cycle':
        put(mapping, CUSTOM_UNIT * WORD_BYTES, CUSTOM_FOLDED, WORD_BYTES)
        put(mapping, CUSTOM_FOLDED * WORD_BYTES, CUSTOM_UNIT, WORD_BYTES)
    elif case == 'surrogate-map':
        put(mapping, SURROGATE * WORD_BYTES, CUSTOM_UNIT, WORD_BYTES)
    elif case == 'zero-map':
        mapping[:] = bytes(TABLE_BYTES)
    elif case in {'short-map', 'odd-map'}:
        mapping = mapping[:TABLE_BYTES // 2 + (1 if case == 'odd-map' else 0)]
    elif case == 'trusted-version':
        information[VERSION_OFFSET:] = bytes(range(VERSION_OFFSET, INFO_BYTES))
    elif case == 'extended-info':
        information.extend(b'preserved-profile-tail')
        put(information, 0, len(information), DWORD_BYTES)
    elif case == 'bad-checksum':
        information[CHECKSUM_OFFSET] ^= 1
    elif case == 'short-info':
        information = information[:VERSION_OFFSET]
    elif case == 'bad-info-size':
        put(information, 0, INFO_BYTES + QWORD_BYTES, DWORD_BYTES)
    if case in {'trusted-custom', 'nonascii-cycle', 'surrogate-map', 'zero-map', 'short-map', 'odd-map'}:
        replace_stream(image, UPCASE_RECORD, '', mapping)
    if case in {'trusted-custom', 'trusted-version', 'extended-info', 'bad-checksum', 'short-info',
                'bad-info-size', 'external-info'}:
        replace_stream(image, UPCASE_RECORD, '$Info', information)
    if case in {'missing-map', 'missing-info'}:
        raw = image.get(UPCASE_RECORD)
        label = '' if case == 'missing-map' else '$Info'
        image.save(UPCASE_RECORD, rewrite(raw, [a for a in attributes(raw)
                   if not (u(a, ATTRIBUTE_KIND, DWORD_BYTES) == DATA_ATTRIBUTE and name(a) == label)]))
    if case in {'uninitialized-map', 'uninitialized-info', 'uninitialized-definitions'}:
        owner = ATTRDEF_RECORD if case == 'uninitialized-definitions' else UPCASE_RECORD
        label = '$Info' if case == 'uninitialized-info' else ''
        if label:
            replace_stream(image, owner, label, information)
        raw = image.get(owner)
        values = attributes(raw)
        data = next(a for a in values if u(a, ATTRIBUTE_KIND, DWORD_BYTES) == DATA_ATTRIBUTE and name(a) == label)
        put(data, fixture.INITIALIZED_OFFSET, u(data, fixture.DATA_OFFSET, QWORD_BYTES) // 2, QWORD_BYTES)
        image.save(owner, rewrite(raw, values))
    if case == 'missing-definition-stream':
        raw = image.get(ATTRDEF_RECORD)
        image.save(ATTRDEF_RECORD, rewrite(raw, [a for a in attributes(raw)
                   if not (u(a, ATTRIBUTE_KIND, DWORD_BYTES) == DATA_ATTRIBUTE and not name(a))]))
    if case in REFUSED:
        owner = UPCASE_RECORD if case == 'unsupported-map-flags' else ATTRDEF_RECORD
        raw = image.get(owner)
        values = attributes(raw)
        data = next(a for a in values if u(a, ATTRIBUTE_KIND, DWORD_BYTES) == DATA_ATTRIBUTE and not name(a))
        put(data, fixture.FLAGS_OFFSET, ENCRYPTED_ATTRIBUTE, WORD_BYTES)
        image.save(owner, rewrite(raw, values))
    if case in {'extension-map', 'extension-info'}:
        fixture.move(image, UPCASE_RECORD, DATA_ATTRIBUTE, '' if case == 'extension-map' else '$Info')
    if 'private' in case or case in {'unordered-definitions', 'partial-definitions', 'missing-definitions'}:
        table = cat(path, ATTRDEF_RECORD)
        rows = [bytearray(table[at:at + ROW_BYTES]) for at in range(0, len(table), ROW_BYTES)
                if any(table[at:at + ROW_BYTES])]
        private = private_row()
        if case != 'missing-definitions':
            rows.append(private)
        if case == 'private-with-missing-standard':
            rows.pop(0)
        elif case == 'unordered-definitions':
            rows.reverse()
        elif case == 'duplicate-private':
            rows.append(private.copy())
        elif case in {'conflicting-unused-private', 'conflicting-used-private'}:
            conflicting = private.copy()
            put(conflicting, MINIMUM_OFFSET, 1, QWORD_BYTES)
            rows.append(conflicting)
        elif case in {'invalid-unused-private', 'invalid-used-private'}:
            put(private, TYPE_OFFSET, PRIVATE_LIMIT, DWORD_BYTES)
        elif case == 'undefined-private':
            rows.pop()
        if case == 'missing-definitions':
            rows = []
        table = b''.join(rows) + bytes(ROW_BYTES)
        if case == 'partial-definitions':
            table += b'partial'
        replace_stream(image, ATTRDEF_RECORD, '', table)
        if case in LIVE_PRIVATE_CASES:
            number = names(image)['payload.bin']
            raw = image.get(number)
            values = attributes(raw)
            identifier = u(raw, RECORD_NEXT_ATTRIBUTE, WORD_BYTES)
            values.append(named(PRIVATE_TYPE, '', b'private-payload', identifier))
            put(raw, RECORD_NEXT_ATTRIBUTE, identifier + 1, WORD_BYTES)
            image.save(number, rewrite(raw, values))
            if case == 'used-private-extension':
                fixture.move(image, number, PRIVATE_TYPE)
    image.close()


def verify(source, target, case, canonical):
    table = cat(target, UPCASE_RECORD)
    expected = cat(source, UPCASE_RECORD) if case in TRUSTED else canonical
    assert table == expected, case
    information = cat(target, UPCASE_RECORD, '$Info')
    assert u(information, 0, DWORD_BYTES) == len(information)
    assert u(information, CHECKSUM_OFFSET, QWORD_BYTES) == crc(table)
    if case in {'trusted-version', 'extended-info', 'external-info', 'trusted-custom'}:
        assert information == cat(source, UPCASE_RECORD, '$Info'), case
    definitions = cat(target, ATTRDEF_RECORD)
    rows = [definitions[at:at + ROW_BYTES] for at in range(0, len(definitions), ROW_BYTES)]
    private = [row for row in rows if u(row, TYPE_OFFSET, DWORD_BYTES) == PRIVATE_TYPE]
    assert private == ([private_row()] if case in PRIVATE_RETAINED else []), case
    before, after = Image(source), Image(target)
    old, new = names(before), names(after)
    for label in ['payload.bin', 'other.bin']:
        assert cat(source, old[label]) == cat(target, new[label]), case
        assert value_of(family_values(before, old[label]), SECURITY_ATTRIBUTE) == value_of(
            family_values(after, new[label]), SECURITY_ATTRIBUTE), case
    if case in LIVE_PRIVATE_CASES:
        assert value_of(family_values(after, new['payload.bin']), PRIVATE_TYPE) is None
    before.close()
    after.close()


def execute(directory, seed, cases):
    canonical = cat(seed, UPCASE_RECORD)
    results = []
    for case in cases:
        source, target = directory / (case + '.img'), directory / (case + '-fixed.img')
        run('cp', '--reflink=auto', '--sparse=always', seed, source)
        mutate(source, case)
        before = digest(source)
        repaired = run(CHECKER, '--repair-to', source, target, ok=False) if case in REFUSED else run(
            CHECKER, '--repair-to', source, target)
        if case in REFUSED:
            assert repaired.returncode != 0, case
            assert not target.exists(), case
        else:
            run(CHECKER, '--audit', target)
            verify(source, target, case, canonical)
            repeat = directory / (case + '-again.img')
            run(CHECKER, '--repair-to', target, repeat)
            assert digest(repeat) == digest(target), case
            repeat.unlink()
        assert digest(source) == before, case
        results.append({'case': case, 'source': str(source), 'source_sha256': before,
                        'path': str(target), 'sha256': digest(target) if target.exists() else None,
                        'refused': case in REFUSED, 'passed': True})
        print('PASS', case,
              'refusal' if case in REFUSED else 'mapping definitions DATA ACLs and repeat repair', flush=True)
    (directory / 'results.json').write_text(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--cases', help='Comma-separated case names')
    parser.add_argument('--image', type=Path)
    parser.add_argument('--keep', type=Path)
    args = parser.parse_args()
    if not args.all and not args.cases:
        print('\n'.join(CASES))
        return
    cases = args.cases.split(',') if args.cases else CASES
    if args.image is None or any(case not in CASES for case in cases):
        parser.error('A Windows-formatted --image and valid case selectors are required')
    if args.keep:
        args.keep.mkdir(parents=True, exist_ok=False)
        execute(args.keep, args.image, cases)
    else:
        with tempfile.TemporaryDirectory(prefix='slate-tables-') as directory:
            execute(Path(directory), args.image, cases)


if __name__ == '__main__':
    main()
