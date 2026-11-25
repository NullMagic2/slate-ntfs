#!/usr/bin/env python3
"""Module: tests.checker.usn_repair
Purpose: Exercise sparse change-journal records, recovery and deletion on private images.
Created: 2026-11-25
Architecture: A Windows-created seed supplies native metadata; independent byte
fixtures verify history, generation, DATA, ACLs and repeat repair without mounts.
"""
import argparse
import json
from pathlib import Path
import tempfile

import test_object_reparse_repair as family_fixture
from test_object_reparse_repair import (
    Image, names, attributes, name, u, put, named, rewrite, family_values,
    value_of, digest, DATA_ATTRIBUTE, SECURITY_ATTRIBUTE, STANDARD_ATTRIBUTE,
    RECORD_FLAGS, RECORD_NEXT_ATTRIBUTE, ATTRIBUTE_KIND, ATTRIBUTE_NONRESIDENT, ATTRIBUTE_NAME_LENGTH,
    RESIDENT_OFFSET, RESIDENT_LENGTH, ATTRIBUTE_ID, BITS_PER_BYTE,
)
from test_semantic_repair import mapped, first_extent
from ntfs_image import CHECKER, run

FILENAME_ATTRIBUTE = 0x30
FILENAME_TEXT = 66
RECORD_IN_USE = 1
MAPPING_LENGTH_MASK = 0x0f
MAPPING_WIDTH_SHIFT = 4
UTF16_BYTES = 2
CONFIG_MAXIMUM_SIZE = 1024 * 1024
CONFIG_ALLOCATION_DELTA = 256 * 1024
CONFIG_BYTES = 32
ID_OFFSET = 16
LOW_OFFSET = 24
ALIGNMENT = 8
PAGE_BYTES = 4096
ADVANCE_BYTES = 65536
SPARSE = 0x8000
MODERN_SI_BYTES = 72
SI_USN = 64
MAPPING_OFFSET = 32
NAME_OFFSET = 10
FLAGS_OFFSET = 12
ALLOCATION_OFFSET = 40
DATA_OFFSET = 48
INITIALIZED_OFFSET = 56
PHYSICAL_OFFSET = 64
EXTENDED_HEADER = 72
RECORD_LENGTH = 0
MAJOR_OFFSET = 4
MINOR_OFFSET = 6
V2_BYTES = 60
V3_BYTES = 76
V4_BYTES = 64
V2_USN = 24
WIDE_USN = 40
V2_NAME_LENGTH = 56
V2_NAME_OFFSET = 58
V3_NAME_LENGTH = 72
V3_NAME_OFFSET = 74
EXTENT_COUNT = 60
EXTENT_WIDTH = 62
EXTENT_BYTES = 16
BITMAP_RECORD = 6
FIRST_TEST_CLUSTER = 1024
FIRST_EXTENSION_SLOT = 27
DELETE_UNDERWAY = 0x10
VOLUME_RECORD = 3
VOLUME_ATTRIBUTE = 0x70
VOLUME_FLAGS_OFFSET = 10
TEST_FILE_USN = 8192
JOURNAL_ID = 7
EXTRA_PARAMETERS = b'preserved-private-parameter-tail'
CASES = (
    'native-intact', 'v2', 'v3', 'v4', 'future-version', 'minor-version',
    'maximum-record', 'oversized-record', 'cross-page-record', 'page-padding',
    'zero-history', 'sparse-prefix', 'trimmed-prefix', 'sparse-interior',
    'fragmented-history', 'preallocated-sparse-tail', 'empty-sparse', 'missing-sparse-flag', 'missing-max',
    'short-max', 'extended-max', 'external-max', 'missing-j', 'resident-j',
    'zero-generation', 'low-beyond-end', 'unaligned-low', 'bad-record-usn',
    'bad-name-offset', 'wide-extent', 'invalid-extent', 'deletion-pending',
    'orphan-file-usns', 'extension-max', 'extension-j', 'extension-si-deletion', 'maximum-file-usn',
)
RESET = {
    'oversized-record', 'cross-page-record', 'sparse-interior', 'missing-max',
    'short-max', 'missing-j', 'resident-j', 'zero-generation', 'low-beyond-end',
    'unaligned-low', 'bad-record-usn', 'bad-name-offset', 'invalid-extent', 'maximum-file-usn',
}
DELETED = {'deletion-pending', 'extension-si-deletion'}


def record(major=2, offset=0, length=None, width=EXTENT_BYTES):
    minimum = {2: V2_BYTES, 3: V3_BYTES, 4: V4_BYTES + width}.get(major, ALIGNMENT)
    length = length or ((minimum + 2 + ALIGNMENT - 1) & ~(ALIGNMENT - 1))
    value = bytearray(length)
    put(value, RECORD_LENGTH, length, 4)
    put(value, MAJOR_OFFSET, major, 2)
    if major in (2, 3, 4):
        put(value, V2_USN if major == 2 else WIDE_USN, offset, ALIGNMENT)
    if major in (2, 3):
        length_at, name_at = (V2_NAME_LENGTH, V2_NAME_OFFSET) if major == 2 else (V3_NAME_LENGTH, V3_NAME_OFFSET)
        put(value, length_at, 2, 2)
        put(value, name_at, minimum, 2)
        value[minimum:minimum + 2] = b'x\0'
    elif major == 4:
        put(value, EXTENT_COUNT, 1, 2)
        put(value, EXTENT_WIDTH, width, 2)
        put(value, V4_BYTES + ALIGNMENT, PAGE_BYTES, ALIGNMENT)
    return value


def extents(attribute):
    at = u(attribute, MAPPING_OFFSET, 2)
    lcn = 0
    while attribute[at]:
        tag = attribute[at]
        count, width = tag & MAPPING_LENGTH_MASK, tag >> MAPPING_WIDTH_SHIFT
        size = u(attribute, at + 1, count)
        at += 1 + count
        if width:
            lcn += int.from_bytes(attribute[at:at + width], 'little', signed=True)
        yield lcn if width else None, size
        at += width


def stream(image, number, label, payload, holes=0, fragmented=False):
    raw = image.get(number)
    values = attributes(raw)
    old = next((a for a in values if u(a, ATTRIBUTE_KIND, 4) == DATA_ATTRIBUTE and name(a) == label), None)
    bitmap = image.get(BITMAP_RECORD)
    lcn, _ = first_extent(bitmap, next_index(bitmap, DATA_ATTRIBUTE))
    image.f.seek(lcn * image.cluster)
    bits = bytearray(image.f.read(u(bitmap, next_index(bitmap, DATA_ATTRIBUTE) + DATA_OFFSET, ALIGNMENT)))
    if old is not None and old[ATTRIBUTE_NONRESIDENT]:
        for physical, count in extents(old):
            if physical is not None:
                for cluster in range(physical, physical + count):
                    bits[cluster // BITS_PER_BYTE] &= ~(1 << (cluster % BITS_PER_BYTE))
    count = (len(payload) + image.cluster - 1) // image.cluster
    free = [n for n in range(FIRST_TEST_CLUSTER, len(bits) * BITS_PER_BYTE)
            if not bits[n // BITS_PER_BYTE] & (1 << (n % BITS_PER_BYTE))]
    selected = free[::2][:count] if fragmented else free[:count]
    assert len(selected) == count
    runs = [(None, holes)] if holes else []
    for index, physical in enumerate(selected):
        bits[physical // BITS_PER_BYTE] |= 1 << (physical % BITS_PER_BYTE)
        runs.append((physical, 1))
        image.f.seek(physical * image.cluster)
        block = payload[index * image.cluster:(index + 1) * image.cluster]
        image.f.write(block + bytes(image.cluster - len(block)))
    image.f.seek(lcn * image.cluster)
    image.f.write(bits)
    encoded = label.encode('utf-16le')
    mapping = EXTENDED_HEADER + ((len(encoded) + ALIGNMENT - 1) & ~(ALIGNMENT - 1))
    template = bytearray(mapping)
    put(template, 0, DATA_ATTRIBUTE, 4)
    template[ATTRIBUTE_NONRESIDENT] = 1
    template[ATTRIBUTE_NAME_LENGTH] = len(encoded) // UTF16_BYTES
    put(template, NAME_OFFSET, EXTENDED_HEADER, 2)
    put(template, MAPPING_OFFSET, mapping, 2)
    template[EXTENDED_HEADER:EXTENDED_HEADER + len(encoded)] = encoded
    replacement = mapped(template, runs)
    put(replacement, FLAGS_OFFSET, SPARSE if label == '$J' else 0, 2)
    logical = holes * image.cluster + len(payload)
    for at, size in [(ALLOCATION_OFFSET, (holes + count) * image.cluster),
                     (DATA_OFFSET, logical), (INITIALIZED_OFFSET, logical), (PHYSICAL_OFFSET, count * image.cluster)]:
        put(replacement, at, size, ALIGNMENT)
    identifier = u(old, ATTRIBUTE_ID, 2) if old is not None else u(raw, RECORD_NEXT_ATTRIBUTE, 2)
    put(replacement, ATTRIBUTE_ID, identifier, 2)
    values = [a for a in values if a is not old]
    values.append(replacement)
    put(raw, RECORD_NEXT_ATTRIBUTE, max(u(raw, RECORD_NEXT_ATTRIBUTE, 2), identifier + 1), 2)
    image.save(number, rewrite(raw, values))


def next_index(raw, kind):
    from test_semantic_repair import attr
    return attr(raw, kind)


def replace_max(image, number, value):
    raw = image.get(number)
    values = attributes(raw)
    old = next((a for a in values if name(a) == '$Max'), None)
    identifier = u(old, ATTRIBUTE_ID, 2) if old is not None else u(raw, RECORD_NEXT_ATTRIBUTE, 2)
    values = [a for a in values if a is not old]
    if value is not None:
        values.append(named(DATA_ATTRIBUTE, '$Max', value, identifier))
    put(raw, RECORD_NEXT_ATTRIBUTE, max(u(raw, RECORD_NEXT_ATTRIBUTE, 2), identifier + 1), 2)
    image.save(number, rewrite(raw, values))


def change_file_usns(image, value=0):
    zero = image.get(0)
    slots = u(zero, next_index(zero, DATA_ATTRIBUTE) + INITIALIZED_OFFSET, ALIGNMENT) // image.size
    for number in range(slots):
        raw = image.get(number)
        if not u(raw, RECORD_FLAGS, 2) & RECORD_IN_USE:
            continue
        for attribute in attributes(raw):
            modern = u(attribute, RESIDENT_LENGTH, 4) == MODERN_SI_BYTES
            if u(attribute, ATTRIBUTE_KIND, 4) == STANDARD_ATTRIBUTE and modern:
                at = next_index(raw, STANDARD_ATTRIBUTE) + u(attribute, RESIDENT_OFFSET, 2)
                put(raw, at + SI_USN, value, ALIGNMENT)
                image.save(number, raw)
                break


def move(image, number, kind, label=''):
    zero = image.get(0)
    slots = u(zero, next_index(zero, DATA_ATTRIBUTE) + INITIALIZED_OFFSET, ALIGNMENT) // image.size
    spare = next(n for n in range(FIRST_EXTENSION_SLOT, slots)
                 if not u(image.get(n), RECORD_FLAGS, 2) & RECORD_IN_USE)
    family_fixture.move_attribute(image, number, kind, label, slot=spare)


def make_case(path, case):
    image = Image(path)
    files = names(image)
    number = files['$UsnJrnl']
    if case == 'native-intact':
        image.close()
        return files
    change_file_usns(image)
    payload = record()
    holes = 0
    if case in ('v3', 'v4', 'future-version'):
        payload = record({'v3': 3, 'v4': 4, 'future-version': 5}[case])
    elif case == 'minor-version':
        put(payload, MINOR_OFFSET, 1, 2)
    elif case == 'maximum-record':
        payload = record(length=PAGE_BYTES)
    elif case == 'oversized-record':
        payload = record(length=PAGE_BYTES + ALIGNMENT)
    elif case == 'cross-page-record':
        first = PAGE_BYTES - ALIGNMENT * 2
        payload = record(length=first) + record(offset=first, length=ALIGNMENT * 10)
    elif case in ('page-padding', 'fragmented-history'):
        payload += bytes(PAGE_BYTES - len(payload)) + record(offset=PAGE_BYTES)
    elif case == 'zero-history':
        payload = bytes(PAGE_BYTES * 2)
    elif case in ('sparse-prefix', 'trimmed-prefix'):
        holes = ADVANCE_BYTES // image.cluster
        payload = record(offset=ADVANCE_BYTES)
    elif case == 'empty-sparse':
        holes, payload = ADVANCE_BYTES // image.cluster, b''
    elif case == 'bad-record-usn':
        put(payload, V2_USN, JOURNAL_ID, ALIGNMENT)
    elif case == 'bad-name-offset':
        put(payload, V2_NAME_OFFSET, PAGE_BYTES, 2)
    elif case == 'wide-extent':
        payload = record(major=4, width=EXTENT_BYTES + ALIGNMENT)
    elif case == 'invalid-extent':
        payload = record(major=4)
        put(payload, V4_BYTES + ALIGNMENT, 0, ALIGNMENT)
    stream(image, number, '$J', payload, holes, case == 'fragmented-history')
    config = bytearray(CONFIG_BYTES)
    put(config, 0, CONFIG_MAXIMUM_SIZE, ALIGNMENT)
    put(config, ALIGNMENT, CONFIG_ALLOCATION_DELTA, ALIGNMENT)
    put(config, ID_OFFSET, JOURNAL_ID, ALIGNMENT)
    if case in ('trimmed-prefix', 'empty-sparse'):
        put(config, LOW_OFFSET, ADVANCE_BYTES, ALIGNMENT)
    if case == 'zero-generation':
        put(config, ID_OFFSET, 0, ALIGNMENT)
    if case == 'low-beyond-end':
        put(config, LOW_OFFSET, ADVANCE_BYTES, ALIGNMENT)
    if case == 'unaligned-low':
        put(config, LOW_OFFSET, 1, ALIGNMENT)
    if case == 'extended-max':
        config.extend(EXTRA_PARAMETERS)
    replace_max(image, number, config)
    if case == 'missing-max':
        replace_max(image, number, None)
    elif case == 'short-max':
        replace_max(image, number, config[:ID_OFFSET])
    elif case == 'external-max':
        stream(image, number, '$Max', config)
    elif case == 'resident-j':
        raw = image.get(number)
        values = attributes(raw)
        old = next(a for a in values if name(a) == '$J')
        values[values.index(old)] = named(DATA_ATTRIBUTE, '$J', payload, u(old, ATTRIBUTE_ID, 2))
        image.save(number, rewrite(raw, values))
    elif case == 'missing-j':
        raw = image.get(number)
        image.save(number, rewrite(raw, [a for a in attributes(raw) if name(a) != '$J']))
    elif case == 'missing-sparse-flag':
        raw = image.get(number)
        values = attributes(raw)
        old = next(a for a in values if name(a) == '$J')
        put(old, FLAGS_OFFSET, 0, 2)
        image.save(number, rewrite(raw, values))
    elif case == 'sparse-interior':
        stream(image, number, '$J', record() + bytes(PAGE_BYTES - len(record())) + record(offset=PAGE_BYTES * 2))
        raw = image.get(number)
        values = attributes(raw)
        old = next(a for a in values if name(a) == '$J')
        allocated = list(extents(old))
        replacement = mapped(old, [allocated[0], (None, 1), allocated[1]])
        put(replacement, DATA_OFFSET, PAGE_BYTES * 2 + len(record()), ALIGNMENT)
        put(replacement, INITIALIZED_OFFSET, PAGE_BYTES * 2 + len(record()), ALIGNMENT)
        put(replacement, ALLOCATION_OFFSET, PAGE_BYTES * 3, ALIGNMENT)
        values[values.index(old)] = replacement
        image.save(number, rewrite(raw, values))
    if case == 'preallocated-sparse-tail':
        raw = image.get(number)
        values = attributes(raw)
        old = next(a for a in values if name(a) == '$J')
        replacement = mapped(old, list(extents(old)) + [(None, 1)])
        put(replacement, ALLOCATION_OFFSET, u(old, ALLOCATION_OFFSET, ALIGNMENT) + image.cluster, ALIGNMENT)
        values[values.index(old)] = replacement
        image.save(number, rewrite(raw, values))
    if case in DELETED or case == 'orphan-file-usns':
        change_file_usns(image, TEST_FILE_USN)
    if case == 'maximum-file-usn':
        change_file_usns(image, (1 << (ALIGNMENT * BITS_PER_BYTE)) - 1)
    if case in DELETED:
        raw = image.get(VOLUME_RECORD)
        at = next_index(raw, VOLUME_ATTRIBUTE)
        value_at = at + u(raw, at + RESIDENT_OFFSET, 2) + VOLUME_FLAGS_OFFSET
        put(raw, value_at, u(raw, value_at, 2) | DELETE_UNDERWAY, 2)
        image.save(VOLUME_RECORD, raw)
    if case == 'extension-max':
        move(image, number, DATA_ATTRIBUTE, '$Max')
    elif case == 'extension-j':
        move(image, number, DATA_ATTRIBUTE, '$J')
    elif case == 'extension-si-deletion':
        move(image, files['journal-dir'], STANDARD_ATTRIBUTE)
    elif case == 'orphan-file-usns':
        raw = image.get(number)
        values = attributes(raw)
        filename = next(a for a in values if u(a, ATTRIBUTE_KIND, 4) == FILENAME_ATTRIBUTE)
        at = u(filename, RESIDENT_OFFSET, 2)
        replacement_name = 'OldJrnl_'.encode('utf-16le')
        filename[at + FILENAME_TEXT:at + FILENAME_TEXT + len(replacement_name)] = replacement_name
        identifier = u(raw, RECORD_NEXT_ATTRIBUTE, 2)
        values.append(named(DATA_ATTRIBUTE, '', b'', identifier))
        values.sort(key=lambda a: (u(a, ATTRIBUTE_KIND, 4), name(a).upper()))
        put(raw, RECORD_NEXT_ATTRIBUTE, identifier + 1, 2)
        image.save(number, rewrite(raw, values))
    image.close()
    return files


def cat(path, number, label):
    return run('ntfscat', '-f', '-n', label, '--inode', str(number), path).stdout


def verify(source, target, case, files):
    image = Image(target)
    after_files = names(image)
    old_journal = files['$UsnJrnl']
    if case in DELETED:
        assert '$UsnJrnl' not in after_files
    elif case != 'orphan-file-usns':
        max_value = cat(target, after_files['$UsnJrnl'], '$Max')
        journal = cat(target, after_files['$UsnJrnl'], '$J')
        if case in RESET:
            boundary = 0 if case == 'maximum-file-usn' else ADVANCE_BYTES
            assert u(max_value, LOW_OFFSET, ALIGNMENT) == boundary, case
            assert len(journal) == boundary and not any(journal), case
            assert u(max_value, ID_OFFSET, ALIGNMENT) != 0
            if case not in {'missing-max', 'short-max', 'zero-generation', 'maximum-file-usn'}:
                assert u(max_value, ID_OFFSET, ALIGNMENT) == JOURNAL_ID, case
        else:
            assert cat(source, old_journal, '$J') == journal, case
            assert cat(source, old_journal, '$Max') == max_value, case
    for label in ['payload.bin', 'other.bin']:
        assert cat(source, files[label], '') == cat(target, files[label], ''), case
        before = Image(source)
        assert value_of(family_values(before, files[label]), SECURITY_ATTRIBUTE) == value_of(
            family_values(image, files[label]), SECURITY_ATTRIBUTE)
        before.close()
    if case in DELETED or case in {'orphan-file-usns', 'maximum-file-usn'}:
        for number in set(after_files.values()):
            si = value_of(family_values(image, number), STANDARD_ATTRIBUTE)
            if si is not None and len(si) == MODERN_SI_BYTES:
                assert u(si, SI_USN, ALIGNMENT) == 0, (case, number)
    image.close()


def execute(directory, seed, selected):
    results = []
    for case in selected:
        source, target = directory / (case + '.img'), directory / (case + '-fixed.img')
        run('cp', '--reflink=auto', '--sparse=always', seed, source)
        files = make_case(source, case)
        before = digest(source)
        run(CHECKER, '--repair-to', source, target)
        run(CHECKER, '--audit', target)
        verify(source, target, case, files)
        repeat = directory / (case + '-again.img')
        run(CHECKER, '--repair-to', target, repeat)
        assert digest(repeat) == digest(target), case
        repeat.unlink()
        assert digest(source) == before
        results.append({'case': case, 'source': str(source), 'source_sha256': before,
                        'path': str(target), 'sha256': digest(target), 'passed': True})
        print('PASS', case, 'history or explicit reset, data, ACLs and repeat repair', flush=True)
    (directory / 'results.json').write_text(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--cases', help='Comma-separated case names')
    parser.add_argument('--image', type=Path, help='Windows-created NTFS seed with a USN journal and two payload files')
    parser.add_argument('--keep', type=Path, help='Retain fixtures in a new directory')
    options = parser.parse_args()
    if not options.all and not options.cases:
        print('\n'.join(CASES))
        return
    if options.image is None:
        parser.error('--image is required')
    selected = options.cases.split(',') if options.cases else CASES
    if any(case not in CASES for case in selected):
        parser.error('Unknown case name')
    if options.keep:
        options.keep.mkdir(parents=True, exist_ok=False)
        execute(options.keep, options.image, selected)
    else:
        with tempfile.TemporaryDirectory(prefix='slate-usn-') as directory:
            execute(Path(directory), options.image, selected)


if __name__ == '__main__':
    main()
