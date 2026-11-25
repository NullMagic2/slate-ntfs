#!/usr/bin/env python3
"""Module: tests.checker.object_reparse_repair
Purpose: Exercise optional identity and reparse repair on disposable NTFS images.
Created: 2026-11-25
Architecture: Independent byte fixtures call the real checker and verify data,
permission, identifier and repeat-repair results without mounting host volumes.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import tempfile

from test_semantic_repair import (
    Image, attributes, attrs, attr, u, put, rewrite, name, resident, named,
    rows, root, row, names, listed, mapped, first_extent,
)
from test_broader_consistency import decode, protect
from ntfs_image import CHECKER, run

MIB = 1024 * 1024
IMAGE_BYTES = 64 * MIB
ATTRIBUTE_LIST = 0x20
STANDARD_ATTRIBUTE = 0x10
OBJECT_ATTRIBUTE = 0x40
SECURITY_ATTRIBUTE = 0x50
DATA_ATTRIBUTE = 0x80
INDEX_ROOT = 0x90
REPARSE_ATTRIBUTE = 0xc0
OBJECT_BYTES = 16
OBJECT_ID = bytes(range(1, OBJECT_BYTES + 1))
OTHER_ID = bytes(range(OBJECT_BYTES + 1, OBJECT_BYTES * 2 + 1))
STALE_ID = bytes(range(81, 97))
BIRTH_FIELDS = bytes(range(33, 81))
REFERENCE_BYTES = 8
REFERENCE_SEQUENCE_SHIFT = 48
BITS_PER_BYTE = 8
RECORD_SEQUENCE = 16
RECORD_LINK_COUNT = 18
RECORD_FLAGS = 22
RECORD_BASE_REFERENCE = 32
RECORD_NEXT_ATTRIBUTE = 40
ATTRIBUTE_KIND = 0
ATTRIBUTE_NONRESIDENT = 8
ATTRIBUTE_NAME_LENGTH = 9
ATTRIBUTE_ID = 14
RESIDENT_LENGTH = 16
RESIDENT_OFFSET = 20
RESIDENT_FLAGS = 22
ALLOCATED_LENGTH = 40
DATA_LENGTH = 48
INITIALIZED_LENGTH = 56
LIST_NAME_OFFSET = 26
LIST_FIRST_VCN = 8
BITMAP_RECORD = 6
FIRST_FIXTURE_CLUSTER = 256
STANDARD_FLAGS = 32
INDEX_HEADER_BYTES = 16
INDEX_DATA_OFFSET = 0
MALFORMED_NODE_OFFSET = 0xfffffff0
MALFORMED_PATH_OFFSET = 0xfff0
REPARSE_LENGTH_OFFSET = 4
SYMLINK_HEADER_BYTES = 20
SUBSTITUTE_LENGTH = 10
PRINT_OFFSET = 12
PRINT_LENGTH = 14
LINK_FLAGS = 16
LX_HEADER_BYTES = 12
TAG_LX_SYMLINK = 0xa000001d
TAG_LX_FIFO = 0x80000024
OPAQUE_PAYLOAD = b'opaque'
HEADER_BYTES = 8
GUID_HEADER_BYTES = HEADER_BYTES + OBJECT_BYTES
TAG_SYMLINK = 0xa000000c
MICROSOFT_TAG = 0x80000000
TAG_VENDOR = 0x42
REPARSE_FLAG = 0x400
EXTENSION_SLOT = 27
CASES = (
    'object-missing-index', 'object-short-value', 'object-zero-value', 'object-long-value',
    'object-duplicate-empty', 'object-duplicate-index-later', 'object-conflicting-primary',
    'object-index-only', 'object-stale-sequence', 'object-stale-slot', 'object-wrong-owner',
    'object-birth-fields', 'object-short-lookup', 'object-duplicate-index',
    'object-conflicting-birth', 'object-missing-root', 'object-broken-root',
    'object-extension', 'object-index-extension', 'object-nonresident',
    'reparse-relative', 'reparse-nonresident', 'reparse-unc', 'reparse-volume-guid', 'reparse-opaque-guid',
    'reparse-opaque-microsoft', 'reparse-zero-guid', 'reparse-reserved-tag',
    'reparse-short', 'reparse-wrong-length', 'reparse-bad-offset',
    'reparse-lx-version', 'reparse-special-body', 'reparse-extension',
    'reparse-index-extension', 'paired-missing-roots', 'paired-stale-indexes',
    'paired-quick', 'object-resident-flags', 'object-duplicate-stale-owner',
    'object-conflicting-birth-reversed', 'object-index-only-multiple',
    'object-wrong-first-owner', 'object-short-before-full',
    'object-duplicate-index-owners', 'object-duplicate-stale-first-reference',
    'object-duplicate-extension', 'object-conflicting-birth-index-extension',
)
INVALID_OBJECTS = {'object-short-value', 'object-zero-value', 'object-long-value', 'object-nonresident',
                   'object-resident-flags'}
INVALID_REPARSE = {'reparse-zero-guid', 'reparse-reserved-tag', 'reparse-short',
                   'reparse-bad-offset', 'reparse-lx-version', 'reparse-special-body'}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def replace_value(image, number, kind, value):
    record = image.get(number)
    values = [a for a in attributes(record) if u(a, ATTRIBUTE_KIND, 4) != kind]
    if value is not None:
        values.append(resident(kind, value, u(record, RECORD_NEXT_ATTRIBUTE, 2)))
        put(record, RECORD_NEXT_ATTRIBUTE, u(record, RECORD_NEXT_ATTRIBUTE, 2) + 1, 2)
    image.save(number, rewrite(record, values))


def reference(image, number):
    return number | (u(image.get(number), RECORD_SEQUENCE, 2) << REFERENCE_SEQUENCE_SHIFT)


def set_index(image, owner, label, entries):
    record = image.get(owner)
    values = attributes(record)
    old = next(a for a in values if u(a, ATTRIBUTE_KIND, 4) == INDEX_ROOT and name(a) == label)
    value_at = u(old, RESIDENT_OFFSET, 2)
    value = root(old[value_at:value_at + u(old, RESIDENT_LENGTH, 4)], entries)
    values[values.index(old)] = named(INDEX_ROOT, label, value, u(old, ATTRIBUTE_ID, 2))
    image.save(owner, rewrite(record, values))


def drop_root(image, owner, label, broken=False):
    record = image.get(owner)
    values = attributes(record)
    old = next(a for a in values if u(a, ATTRIBUTE_KIND, 4) == INDEX_ROOT and name(a) == label)
    if broken:
        put(old, u(old, RESIDENT_OFFSET, 2) + INDEX_HEADER_BYTES, MALFORMED_NODE_OFFSET, 4)
    else:
        values.remove(old)
    image.save(owner, rewrite(record, values))


def move_attribute(image, number, kind, label='', slot=EXTENSION_SLOT):
    record = image.get(number)
    values = attributes(record)
    selected = next(a for a in values if u(a, ATTRIBUTE_KIND, 4) == kind and name(a) == label)
    values.remove(selected)
    base = reference(image, number)
    extension = image.get(slot)
    assert not u(extension, RECORD_FLAGS, 2) & 1
    put(extension, RECORD_SEQUENCE, 1, 2)
    put(extension, RECORD_FLAGS, 1, 2)
    put(extension, RECORD_BASE_REFERENCE, base, 8)
    put(extension, RECORD_LINK_COUNT, 0, 2)
    put(extension, RECORD_NEXT_ATTRIBUTE, u(selected, ATTRIBUTE_ID, 2) + 1, 2)
    image.save(slot, rewrite(extension, [selected]))
    image.bitmap(slot)
    items = [listed(a, base) for a in values] + [listed(selected, slot | (1 << REFERENCE_SEQUENCE_SHIFT))]
    items.sort(key=lambda item: (
        u(item, ATTRIBUTE_KIND, 4), bytes(item[LIST_NAME_OFFSET:]), u(item, LIST_FIRST_VCN, REFERENCE_BYTES),
    ))
    values.append(resident(ATTRIBUTE_LIST, b''.join(items), u(record, RECORD_NEXT_ATTRIBUTE, 2)))
    put(record, RECORD_NEXT_ATTRIBUTE, u(record, RECORD_NEXT_ATTRIBUTE, 2) + 1, 2)
    image.save(number, rewrite(record, values))


def make_nonresident(image, number, kind, content):
    record = image.get(number)
    values = attributes(record)
    old = next(a for a in values if u(a, ATTRIBUTE_KIND, 4) == kind)
    template = next(a for a in values if u(a, ATTRIBUTE_KIND, 4) == DATA_ATTRIBUTE and not a[ATTRIBUTE_NAME_LENGTH])
    bitmap_record = image.get(BITMAP_RECORD)
    map_at = attr(bitmap_record, DATA_ATTRIBUTE)
    lcn, _ = first_extent(bitmap_record, map_at)
    image.f.seek(lcn * image.cluster)
    bits = bytearray(image.f.read(u(bitmap_record, map_at + DATA_LENGTH, 8)))
    spare = next(
        n for n in range(FIRST_FIXTURE_CLUSTER, len(bits) * BITS_PER_BYTE)
        if not bits[n // BITS_PER_BYTE] & (1 << (n % BITS_PER_BYTE))
    )
    bits[spare // BITS_PER_BYTE] |= 1 << (spare % BITS_PER_BYTE)
    image.f.seek(lcn * image.cluster)
    image.f.write(bits)
    replacement = mapped(template, [(spare, 1)])
    put(replacement, ATTRIBUTE_KIND, kind, 4)
    put(replacement, ATTRIBUTE_ID, u(old, ATTRIBUTE_ID, 2), 2)
    lengths = [(ALLOCATED_LENGTH, image.cluster), (DATA_LENGTH, len(content)), (INITIALIZED_LENGTH, len(content))]
    for offset, size in lengths:
        put(replacement, offset, size, 8)
    values[values.index(old)] = replacement
    image.save(number, rewrite(record, values))
    image.f.seek(spare * image.cluster)
    image.f.write(content)


def symlink(path, relative=True):
    path = path.encode('utf-16le')
    value = bytearray(SYMLINK_HEADER_BYTES + len(path) * 2)
    put(value, 0, TAG_SYMLINK, 4)
    put(value, REPARSE_LENGTH_OFFSET, len(value) - HEADER_BYTES, 2)
    put(value, SUBSTITUTE_LENGTH, len(path), 2)
    put(value, PRINT_OFFSET, len(path), 2)
    put(value, PRINT_LENGTH, len(path), 2)
    put(value, LINK_FLAGS, int(relative), 4)
    value[SYMLINK_HEADER_BYTES:SYMLINK_HEADER_BYTES + len(path)] = path
    value[SYMLINK_HEADER_BYTES + len(path):] = path
    return value


def add_reparse(image, number, value):
    replace_value(image, number, REPARSE_ATTRIBUTE, value)
    record = image.get(number)
    standard = attr(record, STANDARD_ATTRIBUTE)
    at = standard + u(record, standard + 20, 2)
    put(record, at + STANDARD_FLAGS, u(record, at + STANDARD_FLAGS, 4) | REPARSE_FLAG, 4)
    image.save(number, record)


def family_values(image, number):
    base = reference(image, number)
    count = u(image.get(0), attr(image.get(0), DATA_ATTRIBUTE) + DATA_LENGTH, REFERENCE_BYTES) // image.size
    result = attributes(image.get(number))
    for slot in range(count):
        record = image.get(slot)
        if u(record, RECORD_FLAGS, 2) & 1 and u(record, RECORD_BASE_REFERENCE, 8) == base:
            result.extend(attributes(record))
    return result


def value_of(values, kind, image=None):
    matching = [a for a in values if u(a, ATTRIBUTE_KIND, 4) == kind]
    if not matching:
        return None
    assert len(matching) == 1
    value = matching[0]
    if value[ATTRIBUTE_NONRESIDENT]:
        assert image is not None
        lcn, _ = first_extent(value, 0)
        image.f.seek(lcn * image.cluster)
        return image.f.read(u(value, DATA_LENGTH, 8))
    return bytes(value[u(value, RESIDENT_OFFSET, 2):u(value, RESIDENT_OFFSET, 2) + u(value, RESIDENT_LENGTH, 4)])


def make_case(source, case):
    image = Image(source)
    files = names(image)
    first, second = files['payload.bin'], files['other.bin']
    object_owner, reparse_owner = files['$ObjId'], files['$Reparse']
    first_ref, second_ref = reference(image, first), reference(image, second)
    expected_ids = {first: None, second: None}
    expected_birth = None
    expected_reparse = None
    if case.startswith('object-') or case.startswith('paired-'):
        replace_value(image, first, OBJECT_ATTRIBUTE, OBJECT_ID)
        expected_ids[first] = OBJECT_ID
        if case in INVALID_OBJECTS:
            wrong = {'object-short-value': OBJECT_ID[:-1], 'object-zero-value': bytes(OBJECT_BYTES),
                     'object-long-value': OBJECT_ID + BIRTH_FIELDS}.get(case, OBJECT_ID)
            replace_value(image, first, OBJECT_ATTRIBUTE, wrong)
            expected_ids[first] = None
        if case.startswith('object-duplicate-') and case != 'object-duplicate-index':
            replace_value(image, second, OBJECT_ATTRIBUTE, OBJECT_ID)
            if case.endswith('index-later'):
                set_index(image, object_owner, '$O', [
                    row(OBJECT_ID, second_ref.to_bytes(REFERENCE_BYTES, 'little') + BIRTH_FIELDS),
                ])
                expected_ids[first], expected_ids[second] = None, OBJECT_ID
                expected_birth = BIRTH_FIELDS
        elif case == 'object-conflicting-primary':
            replace_value(image, second, OBJECT_ATTRIBUTE, OTHER_ID)
            expected_ids[second] = OTHER_ID
            set_index(image, object_owner, '$O', [
                row(STALE_ID, first_ref.to_bytes(REFERENCE_BYTES, 'little') + BIRTH_FIELDS),
            ])
        elif case == 'object-index-only':
            replace_value(image, first, OBJECT_ATTRIBUTE, None)
            expected_ids[first] = None
            set_index(image, object_owner, '$O', [
                row(OBJECT_ID, first_ref.to_bytes(REFERENCE_BYTES, 'little') + BIRTH_FIELDS),
            ])
        elif case in {'object-stale-sequence', 'object-stale-slot', 'object-wrong-owner',
                      'object-birth-fields', 'object-short-lookup', 'object-duplicate-index',
                      'object-conflicting-birth'}:
            owner = first_ref
            if case == 'object-stale-sequence':
                owner += 1 << REFERENCE_SEQUENCE_SHIFT
            elif case == 'object-stale-slot':
                owner = EXTENSION_SLOT | (1 << REFERENCE_SEQUENCE_SHIFT)
            elif case == 'object-wrong-owner':
                owner = second_ref
            payload = owner.to_bytes(REFERENCE_BYTES, 'little')
            if case != 'object-short-lookup':
                payload += BIRTH_FIELDS
                expected_birth = bytes(len(BIRTH_FIELDS)) if case in {
                    'object-stale-slot', 'object-wrong-owner',
                } else BIRTH_FIELDS
            entries = [row(OBJECT_ID, payload)]
            if case in {'object-duplicate-index', 'object-conflicting-birth'}:
                duplicate = bytearray(entries[0])
                if case == 'object-conflicting-birth':
                    duplicate[-1] ^= 1
                entries.append(duplicate)
            set_index(image, object_owner, '$O', entries)
        elif case == 'object-missing-root':
            drop_root(image, object_owner, '$O')
        elif case == 'object-broken-root':
            drop_root(image, object_owner, '$O', broken=True)
        elif case == 'object-extension':
            move_attribute(image, first, OBJECT_ATTRIBUTE)
        elif case == 'object-index-extension':
            move_attribute(image, object_owner, INDEX_ROOT, '$O')
        elif case == 'object-nonresident':
            make_nonresident(image, first, OBJECT_ATTRIBUTE, OBJECT_ID)
    if case.startswith('reparse-') or case.startswith('paired-'):
        value = symlink('other.bin')
        if case == 'reparse-unc':
            value = symlink(r'\??\UNC\server\share\file', False)
        elif case == 'reparse-volume-guid':
            value = symlink(r'\??\Volume{11111111-1111-1111-1111-111111111111}\file', False)
        elif case in {'reparse-opaque-guid', 'reparse-zero-guid'}:
            value = bytearray(GUID_HEADER_BYTES + len(OPAQUE_PAYLOAD))
            put(value, 0, TAG_VENDOR, 4)
            put(value, REPARSE_LENGTH_OFFSET, len(OPAQUE_PAYLOAD), 2)
            value[HEADER_BYTES:GUID_HEADER_BYTES] = OBJECT_ID if case != 'reparse-zero-guid' else bytes(OBJECT_BYTES)
            value[GUID_HEADER_BYTES:] = OPAQUE_PAYLOAD
        elif case == 'reparse-opaque-microsoft':
            value = bytearray(HEADER_BYTES + len(OPAQUE_PAYLOAD))
            put(value, 0, (MICROSOFT_TAG | TAG_VENDOR), 4)
            put(value, REPARSE_LENGTH_OFFSET, len(OPAQUE_PAYLOAD), 2)
            value[HEADER_BYTES:] = OPAQUE_PAYLOAD
        elif case == 'reparse-reserved-tag':
            put(value, 0, 1, 4)
        elif case == 'reparse-short':
            value = bytes(4)
        elif case == 'reparse-wrong-length':
            put(value, REPARSE_LENGTH_OFFSET, 0, 2)
        elif case == 'reparse-bad-offset':
            put(value, HEADER_BYTES, MALFORMED_PATH_OFFSET, 2)
        elif case == 'reparse-lx-version':
            value = bytearray(LX_HEADER_BYTES + 1)
            put(value, 0, TAG_LX_SYMLINK, 4)
            put(value, REPARSE_LENGTH_OFFSET, len(value) - HEADER_BYTES, 2)
            value[LX_HEADER_BYTES:] = b'x'
        elif case == 'reparse-special-body':
            value = bytearray(LX_HEADER_BYTES)
            put(value, 0, TAG_LX_FIFO, 4)
            put(value, REPARSE_LENGTH_OFFSET, len(value) - HEADER_BYTES, 2)
        add_reparse(image, first, value)
        if case not in INVALID_REPARSE:
            expected_reparse = bytearray(value)
            if case == 'reparse-wrong-length':
                put(expected_reparse, REPARSE_LENGTH_OFFSET, len(value) - HEADER_BYTES, 2)
        if case == 'reparse-nonresident':
            make_nonresident(image, first, REPARSE_ATTRIBUTE, value)
        elif case == 'reparse-extension':
            move_attribute(image, first, REPARSE_ATTRIBUTE)
        elif case == 'reparse-index-extension':
            move_attribute(image, reparse_owner, INDEX_ROOT, '$R')
        elif case in ('paired-missing-roots', 'paired-quick'):
            drop_root(image, object_owner, '$O')
            drop_root(image, reparse_owner, '$R')
        elif case == 'paired-stale-indexes':
            stale_reference = (second_ref + (1 << REFERENCE_SEQUENCE_SHIFT)).to_bytes(REFERENCE_BYTES, 'little')
            set_index(image, object_owner, '$O', [row(STALE_ID, stale_reference + BIRTH_FIELDS)])
            key = TAG_SYMLINK.to_bytes(4, 'little') + second_ref.to_bytes(REFERENCE_BYTES, 'little')
            entry = row(key, b'')
            put(entry, 0, 0, 2)
            set_index(image, reparse_owner, '$R', [entry])
    if case == 'object-resident-flags':
        record = image.get(first)
        record[attr(record, OBJECT_ATTRIBUTE) + RESIDENT_FLAGS] = 1
        image.save(first, record)
    elif case in {'object-duplicate-stale-owner', 'object-duplicate-index-owners',
                  'object-duplicate-stale-first-reference'}:
        indexed_ref = second_ref
        if case != 'object-duplicate-index-owners':
            indexed_ref += 1 << REFERENCE_SEQUENCE_SHIFT
        entries = [row(OBJECT_ID, indexed_ref.to_bytes(REFERENCE_BYTES, 'little') + BIRTH_FIELDS)]
        if case != 'object-duplicate-stale-owner':
            entries.append(row(OBJECT_ID, first_ref.to_bytes(REFERENCE_BYTES, 'little') + bytes(len(BIRTH_FIELDS))))
        set_index(image, object_owner, '$O', entries)
        expected_ids[first], expected_ids[second] = None, OBJECT_ID
        expected_birth = BIRTH_FIELDS
    elif case in {'object-conflicting-birth-reversed', 'object-conflicting-birth-index-extension'}:
        changed_birth = bytearray(BIRTH_FIELDS)
        changed_birth[-1] ^= 1
        payload = first_ref.to_bytes(REFERENCE_BYTES, 'little')
        set_index(image, object_owner, '$O', [
            row(OBJECT_ID, payload + changed_birth), row(OBJECT_ID, payload + BIRTH_FIELDS),
        ])
        expected_birth = changed_birth
        if case == 'object-conflicting-birth-index-extension':
            move_attribute(image, object_owner, INDEX_ROOT, '$O')
    elif case == 'object-index-only-multiple':
        replace_value(image, first, OBJECT_ATTRIBUTE, None)
        expected_ids[first] = None
        payload = first_ref.to_bytes(REFERENCE_BYTES, 'little') + BIRTH_FIELDS
        set_index(image, object_owner, '$O', [row(OBJECT_ID, payload), row(OTHER_ID, payload)])
    elif case == 'object-wrong-first-owner':
        payload = first_ref.to_bytes(REFERENCE_BYTES, 'little') + BIRTH_FIELDS
        set_index(image, object_owner, '$O', [row(bytes(range(OBJECT_BYTES)), payload), row(OBJECT_ID, payload)])
        expected_birth = bytes(len(BIRTH_FIELDS))
    elif case == 'object-short-before-full':
        payload = first_ref.to_bytes(REFERENCE_BYTES, 'little')
        set_index(image, object_owner, '$O', [row(OBJECT_ID, payload), row(OBJECT_ID, payload + BIRTH_FIELDS)])
        expected_birth = bytes(len(BIRTH_FIELDS))
    elif case == 'object-duplicate-extension':
        move_attribute(image, first, OBJECT_ATTRIBUTE)
    image.close()
    return files, expected_ids, expected_birth, expected_reparse


def check_case(source, target, case, expected):
    files, identities, birth, reparse = expected
    image = Image(target)
    for number, identity in identities.items():
        assert value_of(family_values(image, number), OBJECT_ATTRIBUTE) == identity, (case, number)
    assert value_of(family_values(image, files['payload.bin']), REPARSE_ATTRIBUTE, image) == reparse, case
    for label in ['payload.bin', 'other.bin']:
        expected_data = run('ntfscat', '-f', source.parent / 'base.img', '/' + label).stdout
        assert run('ntfscat', '-f', target, '/' + label).stdout == expected_data
        before = Image(source)
        expected_acl = value_of(family_values(before, files[label]), SECURITY_ATTRIBUTE)
        assert value_of(family_values(image, files[label]), SECURITY_ATTRIBUTE) == expected_acl
        before.close()
    if birth is not None:
        # These controls keep a resident index; family controls check attributes separately.
        owner = files['$ObjId']
        index_root = next(a for a in family_values(image, owner) if
                          u(a, ATTRIBUTE_KIND, 4) == INDEX_ROOT and name(a) == '$O')
        _, lookup = rows(rewrite(image.get(owner), [index_root]), '$O')
        found = [r for r in lookup if r[INDEX_HEADER_BYTES:INDEX_HEADER_BYTES + OBJECT_BYTES] == OBJECT_ID]
        assert len(found) == 1, case
        birth_at = u(found[0], INDEX_DATA_OFFSET, 2) + REFERENCE_BYTES
        assert found[0][birth_at:birth_at + len(BIRTH_FIELDS)] == birth, case
    image.close()


def execute(directory, selected):
    base = directory / 'base.img'
    with base.open('xb') as stream:
        stream.truncate(IMAGE_BYTES)
    run('mkfs.ntfs', '-F', '-Q', base)
    content = directory / 'payload'
    content.write_bytes(b'preserved object and reparse data' * 4096)
    for filename in ['payload.bin', 'other.bin']:
        run('ntfscp', '-f', base, content, '/' + filename)
    run(CHECKER, '--audit', base)
    results = []
    for case in selected:
        source, target = directory / (case + '.img'), directory / (case + '-fixed.img')
        run('cp', '--reflink=auto', '--sparse=always', base, source)
        expected = make_case(source, case)
        before = digest(source)
        flags = ['--index-check=quick'] if case == 'paired-quick' else []
        run(CHECKER, *flags, '--repair-to', source, target)
        run(CHECKER, '--audit', target)
        assert digest(source) == before
        check_case(source, target, case, expected)
        repeat = directory / (case + '-again.img')
        run(CHECKER, *flags, '--repair-to', target, repeat)
        assert digest(repeat) == digest(target), case
        repeat.unlink()
        results.append({'case': case, 'source': str(source), 'source_sha256': before,
                        'path': str(target), 'sha256': digest(target), 'passed': True})
        print('PASS', case, 'audit, data, permissions and repeat repair', flush=True)
    (directory / 'results.json').write_text(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--cases', help='Comma-separated case names')
    parser.add_argument('--keep', type=Path, help='Retain fixtures in a new directory')
    options = parser.parse_args()
    if not options.all and not options.cases:
        print('\n'.join(CASES))
        return
    selected = options.cases.split(',') if options.cases else CASES
    if any(case not in CASES for case in selected):
        parser.error('Unknown case name')
    if options.keep:
        options.keep.mkdir(parents=True, exist_ok=False)
        execute(options.keep, selected)
    else:
        with tempfile.TemporaryDirectory(prefix='slate-objects-') as directory:
            execute(Path(directory), selected)


if __name__ == '__main__':
    main()
