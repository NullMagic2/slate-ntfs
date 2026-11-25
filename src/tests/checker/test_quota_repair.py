#!/usr/bin/env python3
"""Module: tests.checker.quota_repair
Purpose: Verify quota policy recovery and explicit rescan state on private images.
Created: 2026-11-25
Architecture: Independent byte fixtures exercise the real offline checker;
DATA, ACLs, policy limits and repeat repair are checked without host mounts.
"""
import argparse
import json
from pathlib import Path
import tempfile

from test_object_reparse_repair import (
    Image, names, attributes, name, u, put, attr, named, resident, rewrite,
    replace_value, set_index, drop_root, move_attribute, family_values, value_of,
    digest, DATA_ATTRIBUTE, SECURITY_ATTRIBUTE, INDEX_ROOT, RESIDENT_OFFSET,
    RESIDENT_LENGTH, ATTRIBUTE_ID, RECORD_NEXT_ATTRIBUTE, REFERENCE_BYTES,
    DATA_LENGTH, ALLOCATED_LENGTH, INITIALIZED_LENGTH, BITS_PER_BYTE,
)
from test_semantic_repair import mapped, first_extent, rows, root
from ntfs_image import CHECKER, run, protect, decode

MIB = 1024 * 1024
IMAGE_BYTES = 64 * MIB
STANDARD_ATTRIBUTE = 0x10
STANDARD_BYTES = 72
OWNER_OFFSET = 48
CHARGE_OFFSET = 56
CONTROL_BYTES = 48
FLAGS_OFFSET = 4
USAGE_OFFSET = 8
THRESHOLD_OFFSET = 24
LIMIT_OFFSET = 32
OUT_OF_DATE = 0x200
DEFAULT_OWNER = 1
FIRST_OWNER = 256
DEFAULT_THRESHOLD = 4 * MIB
DEFAULT_LIMIT = 8 * MIB
CUSTOM_THRESHOLD = 1234567
CUSTOM_LIMIT = 7654321
CONTENT = b'quota-preserved-user-data' * 4096
SID = bytes([1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 232, 3, 0, 0])
SMALL_SID = bytes([1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0])
VIEW_HEADER = 16
VIEW_ALIGNMENT = 8
VIEW_LENGTH = 8
VIEW_KEY_LENGTH = 10
VIEW_FLAGS = 12
INDEX_ALLOCATION = 0xa0
BITMAP_ATTRIBUTE = 0xb0
BITMAP_RECORD = 6
FIRST_FREE_CLUSTER = 256
PAGE_BYTES = 4096
SECTOR_BYTES = 512
PAGE_NODE = 24
PAGE_USA = 40
PAGE_ENTRIES = 64
NONRESIDENT_HEADER = 64
ATTRIBUTE_LENGTH = 4
ATTRIBUTE_NAME_LENGTH = 9
ATTRIBUTE_NAME_OFFSET = 10
MAPPING_OFFSET = 32
NODE_USED = 4
NODE_ALLOCATED = 8
NODE_FLAGS = 12
ENTRY_END = 2
ENTRY_CHILD = 1
COLLATION_QUOTA = 16
LARGE_OWNER_COUNT = 40
SID_SUBAUTHORITY_OFFSET = len(SID) - 4
SID_FIRST_ACCOUNT = 1000
CASES = (
    'intact', 'missing-default', 'empty-controls', 'missing-controls-root',
    'missing-owner', 'missing-lookup', 'missing-both', 'wrong-lookup',
    'orphan-lookup', 'duplicate-lookup', 'duplicate-control', 'conflicting-control',
    'conflicting-sid', 'usage-mismatch', 'legacy-version', 'padded-sid',
    'invalid-sid', 'invalid-default', 'reserved-owner', 'unknown-billing-owner',
    'reserved-billing-owner', 'extension-controls', 'extension-lookup',
    'paged-controls', 'disconnected-controls', 'destroyed-controls-page',
    'bad-root-controls', 'pending-rescan', 'large-controls',
)


def entry(key, value):
    at = VIEW_HEADER + len(key)
    result = bytearray((at + len(value) + VIEW_ALIGNMENT - 1) & ~(VIEW_ALIGNMENT - 1))
    for offset, size, number in [(0, 2, at), (2, 2, len(value)),
                                  (VIEW_LENGTH, 2, len(result)), (VIEW_KEY_LENGTH, 2, len(key))]:
        put(result, offset, number, size)
    result[VIEW_HEADER:at] = key
    result[at:at + len(value)] = value
    return result


def control(sid=None, version=2):
    value = bytearray(CONTROL_BYTES)
    put(value, 0, version, 4)
    put(value, THRESHOLD_OFFSET, DEFAULT_THRESHOLD if sid is None else CUSTOM_THRESHOLD, REFERENCE_BYTES)
    put(value, LIMIT_OFFSET, DEFAULT_LIMIT if sid is None else CUSTOM_LIMIT, REFERENCE_BYTES)
    if sid is not None:
        value.extend(sid)
        put(value, USAGE_OFFSET, len(CONTENT), REFERENCE_BYTES)
    return value


def quota_rows(image, number, label):
    values = family_values(image, number)
    attribute = next(a for a in values if u(a, 0, 4) == INDEX_ROOT and name(a) == label)
    result = rows(rewrite(image.get(number), [attribute]), label)[1]
    if any(u(a, 0, 4) == INDEX_ALLOCATION and name(a) == label for a in values):
        allocation = run('ntfscat', '-f', '--raw', '-a', hex(INDEX_ALLOCATION), '-n', label,
                         '--inode', str(number), image.f.name).stdout
        bitmap = run('ntfscat', '-f', '-a', hex(BITMAP_ATTRIBUTE), '-n', label,
                     '--inode', str(number), image.f.name).stdout
        for index in range(len(allocation) // PAGE_BYTES):
            if not bitmap[index // BITS_PER_BYTE] & (1 << (index % BITS_PER_BYTE)):
                continue
            page = decode(allocation[index * PAGE_BYTES:(index + 1) * PAGE_BYTES])
            at = PAGE_NODE + u(page, PAGE_NODE, 4)
            while not u(page, at + VIEW_FLAGS, 2) & ENTRY_END:
                length = u(page, at + VIEW_LENGTH, 2)
                assert length >= VIEW_HEADER
                result.append(page[at:at + length])
                at += length
    return result


def quota_values(image, number):
    return {u(row, VIEW_HEADER, 4): bytes(row[u(row, 0, 2):u(row, 0, 2) + u(row, 2, 2)])
            for row in quota_rows(image, number, '$Q')}


def billing(image, number, owner):
    record = image.get(number)
    at = attr(record, STANDARD_ATTRIBUTE)
    value = bytearray(record[at + u(record, at + RESIDENT_OFFSET, 2):
                             at + u(record, at + RESIDENT_OFFSET, 2) + u(record, at + RESIDENT_LENGTH, 4)])
    value.extend(bytes(STANDARD_BYTES - len(value)))
    put(value, OWNER_OFFSET, owner, 4)
    put(value, CHARGE_OFFSET, len(CONTENT), REFERENCE_BYTES)
    replace_value(image, number, STANDARD_ATTRIBUTE, value)


def paged_controls(image, number, items, disconnected=False, destroyed=False):
    record = image.get(number)
    values = attributes(record)
    q = next(a for a in values if u(a, 0, 4) == INDEX_ROOT and name(a) == '$Q')
    original_root = q[u(q, RESIDENT_OFFSET, 2):u(q, RESIDENT_OFFSET, 2) + u(q, RESIDENT_LENGTH, 4)]
    bitmap = image.get(BITMAP_RECORD)
    lcn, _ = first_extent(bitmap, attr(bitmap, DATA_ATTRIBUTE))
    image.f.seek(lcn * image.cluster)
    bits = bytearray(image.f.read(u(bitmap, attr(bitmap, DATA_ATTRIBUTE) + DATA_LENGTH, REFERENCE_BYTES)))
    allocated = [n for n in range(FIRST_FREE_CLUSTER, len(bits) * BITS_PER_BYTE)
                 if not bits[n // BITS_PER_BYTE] & (1 << (n % BITS_PER_BYTE))][:2]
    assert len(allocated) == 2 and allocated[1] == allocated[0] + 1
    for n in allocated:
        bits[n // BITS_PER_BYTE] |= 1 << (n % BITS_PER_BYTE)
    image.f.seek(lcn * image.cluster)
    image.f.write(bits)
    template = next(a for a in attributes(image.get(names(image)['payload.bin'])) if u(a, 0, 4) == DATA_ATTRIBUTE)
    allocation = mapped(template, [(allocated[0], len(allocated))])
    put(allocation, 0, INDEX_ALLOCATION, 4)
    encoded_name = '$Q'.encode('utf-16le')
    pairs = allocation[u(allocation, MAPPING_OFFSET, 2):]
    name_bytes = (len(encoded_name) + VIEW_ALIGNMENT - 1) & ~(VIEW_ALIGNMENT - 1)
    allocation = bytearray(allocation[:NONRESIDENT_HEADER]) + bytearray(name_bytes) + pairs
    put(allocation, ATTRIBUTE_LENGTH, len(allocation), 4)
    allocation[ATTRIBUTE_NAME_LENGTH] = len('$Q')
    put(allocation, ATTRIBUTE_NAME_OFFSET, NONRESIDENT_HEADER, 2)
    put(allocation, MAPPING_OFFSET, NONRESIDENT_HEADER + name_bytes, 2)
    allocation[NONRESIDENT_HEADER:NONRESIDENT_HEADER + len(encoded_name)] = encoded_name
    for offset in [DATA_LENGTH, ALLOCATED_LENGTH, INITIALIZED_LENGTH]:
        put(allocation, offset, len(allocated) * PAGE_BYTES, REFERENCE_BYTES)
    next_id = u(record, RECORD_NEXT_ATTRIBUTE, 2)
    put(allocation, ATTRIBUTE_ID, next_id, 2)
    values.append(allocation)
    values.append(named(BITMAP_ATTRIBUTE, '$Q', bytes([3]), next_id + 1))
    put(record, RECORD_NEXT_ATTRIBUTE, next_id + 2, 2)
    terminal = bytearray(VIEW_HEADER + REFERENCE_BYTES)
    put(terminal, VIEW_LENGTH, len(terminal), 2)
    put(terminal, VIEW_FLAGS, ENTRY_END | ENTRY_CHILD, 2)
    root_value = bytearray(original_root[:VIEW_HEADER]) + bytearray(VIEW_HEADER) + terminal
    if not disconnected and not destroyed:
        separator = bytearray(items[1]) + bytearray(REFERENCE_BYTES)
        put(separator, VIEW_LENGTH, len(separator), 2)
        put(separator, VIEW_FLAGS, ENTRY_CHILD, 2)
        put(terminal, len(terminal) - REFERENCE_BYTES, 1, REFERENCE_BYTES)
        root_value = bytearray(original_root[:VIEW_HEADER]) + bytearray(VIEW_HEADER) + separator + terminal
    for offset, value in [(VIEW_HEADER, VIEW_HEADER),
                          (VIEW_HEADER + NODE_USED, len(root_value) - VIEW_HEADER),
                          (VIEW_HEADER + NODE_ALLOCATED, len(root_value) - VIEW_HEADER)]:
        put(root_value, offset, value, 4)
    root_value[VIEW_HEADER + NODE_FLAGS] = 1
    values[values.index(q)] = named(INDEX_ROOT, '$Q', root_value, u(q, ATTRIBUTE_ID, 2))
    image.save(number, rewrite(record, values))
    page_rows = [items[:1], items[1:] if disconnected or destroyed else []]
    for index, entries in enumerate(page_rows):
        page = bytearray(PAGE_BYTES)
        page[:4] = b'INDX'
        put(page, 4, PAGE_USA, 2)
        put(page, 6, PAGE_BYTES // SECTOR_BYTES + 1, 2)
        put(page, VIEW_HEADER, index, REFERENCE_BYTES)
        end = bytearray(VIEW_HEADER)
        put(end, VIEW_LENGTH, VIEW_HEADER, 2)
        put(end, VIEW_FLAGS, ENTRY_END, 2)
        payload = b''.join(entries) + end
        put(page, PAGE_NODE, PAGE_ENTRIES - PAGE_NODE, 4)
        put(page, PAGE_NODE + NODE_USED, PAGE_ENTRIES - PAGE_NODE + len(payload), 4)
        put(page, PAGE_NODE + NODE_ALLOCATED, PAGE_BYTES - PAGE_NODE, 4)
        page[PAGE_ENTRIES:PAGE_ENTRIES + len(payload)] = payload
        raw = protect(page)
        if destroyed and index == 1:
            raw[:4] = b'FAIL'
        image.f.seek(allocated[index] * image.cluster)
        image.f.write(raw)


def make_case(path, case):
    image = Image(path)
    files = names(image)
    number = files['$Quota']
    defaults, owner = control(), control(SID)
    billing(image, files['payload.bin'], FIRST_OWNER)
    q = [entry(DEFAULT_OWNER.to_bytes(4, 'little'), defaults), entry(FIRST_OWNER.to_bytes(4, 'little'), owner)]
    o = [entry(SID, FIRST_OWNER.to_bytes(4, 'little'))]
    if case == 'missing-default':
        q = q[1:]
    elif case == 'empty-controls':
        q = []
    elif case == 'missing-owner':
        q = q[:1]
    elif case == 'wrong-lookup':
        o = [entry(SID, (FIRST_OWNER + 1).to_bytes(4, 'little'))]
    elif case == 'orphan-lookup':
        o.append(entry(SMALL_SID, (FIRST_OWNER + 1).to_bytes(4, 'little')))
    elif case == 'duplicate-lookup':
        o += o
    elif case in ('duplicate-control', 'conflicting-control'):
        duplicate = bytearray(owner)
        if case == 'conflicting-control':
            put(duplicate, LIMIT_OFFSET, CUSTOM_LIMIT + 1, REFERENCE_BYTES)
        q.append(entry(FIRST_OWNER.to_bytes(4, 'little'), duplicate))
    elif case == 'conflicting-sid':
        q.append(entry((FIRST_OWNER + 1).to_bytes(4, 'little'), owner))
    elif case == 'usage-mismatch':
        put(q[1], u(q[1], 0, 2) + USAGE_OFFSET, 0, REFERENCE_BYTES)
    elif case == 'legacy-version':
        for item in q:
            put(item, u(item, 0, 2), 1, 4)
    elif case == 'padded-sid':
        q[1] = entry(FIRST_OWNER.to_bytes(4, 'little'), control(SMALL_SID) + bytes(4))
        o = [entry(SMALL_SID, FIRST_OWNER.to_bytes(4, 'little'))]
    elif case == 'invalid-sid':
        q[1][u(q[1], 0, 2) + CONTROL_BYTES] = 0
    elif case == 'invalid-default':
        q[0] = entry(DEFAULT_OWNER.to_bytes(4, 'little'), defaults + bytes(4))
    elif case == 'reserved-owner':
        q.append(entry((FIRST_OWNER - 1).to_bytes(4, 'little'), owner))
    elif case in ('unknown-billing-owner', 'reserved-billing-owner'):
        billing(image, files['payload.bin'], FIRST_OWNER + 9 if case == 'unknown-billing-owner' else DEFAULT_OWNER)
    elif case == 'pending-rescan':
        put(q[0], u(q[0], 0, 2) + FLAGS_OFFSET, OUT_OF_DATE, 4)
    if case == 'large-controls':
        q = q[:1]
        for index in range(LARGE_OWNER_COUNT):
            sid = bytearray(SID)
            put(sid, SID_SUBAUTHORITY_OFFSET, SID_FIRST_ACCOUNT + index, 4)
            value = control(sid)
            put(value, LIMIT_OFFSET, CUSTOM_LIMIT + index, REFERENCE_BYTES)
            q.append(entry((FIRST_OWNER + index).to_bytes(4, 'little'), value))
    set_index(image, number, '$Q', q[:2] if case == 'large-controls' else q)
    set_index(image, number, '$O', o)
    if case in ('missing-controls-root', 'missing-both'):
        drop_root(image, number, '$Q')
    if case in ('missing-lookup', 'missing-both'):
        drop_root(image, number, '$O')
    if case == 'extension-controls':
        move_attribute(image, number, INDEX_ROOT, '$Q')
    if case == 'extension-lookup':
        move_attribute(image, number, INDEX_ROOT, '$O')
    if case in ('paged-controls', 'disconnected-controls', 'destroyed-controls-page', 'large-controls'):
        paged_controls(image, number, q, case in {'disconnected-controls', 'large-controls'},
                       case == 'destroyed-controls-page')
    if case == 'bad-root-controls':
        drop_root(image, number, '$Q', broken=True)
    image.close()
    return files


def verify(source, target, case, files):
    image = Image(target)
    values = quota_values(image, files['$Quota'])
    defaults = values[DEFAULT_OWNER]
    if case not in {'intact', 'legacy-version', 'paged-controls', 'extension-controls', 'extension-lookup'}:
        assert u(defaults, FLAGS_OFFSET, 4) & OUT_OF_DATE, case
    readable_policy = case not in {
        'empty-controls', 'missing-controls-root', 'missing-owner', 'missing-both',
        'destroyed-controls-page', 'bad-root-controls',
    }
    if readable_policy:
        assert u(values[FIRST_OWNER], THRESHOLD_OFFSET, REFERENCE_BYTES) == CUSTOM_THRESHOLD, case
        assert u(values[FIRST_OWNER], LIMIT_OFFSET, REFERENCE_BYTES) == CUSTOM_LIMIT, case
    if case == 'large-controls':
        for index in range(LARGE_OWNER_COUNT):
            assert u(values[FIRST_OWNER + index], LIMIT_OFFSET, REFERENCE_BYTES) == CUSTOM_LIMIT + index
    if case == 'padded-sid':
        assert len(values[FIRST_OWNER]) == CONTROL_BYTES + len(SMALL_SID)
    if case == 'conflicting-sid':
        assert u(values[FIRST_OWNER + 1], LIMIT_OFFSET, REFERENCE_BYTES) == CUSTOM_LIMIT
    for label in ['payload.bin', 'other.bin']:
        expected = run('ntfscat', '-f', source, '/' + label).stdout
        assert run('ntfscat', '-f', target, '/' + label).stdout == expected, (case, label)
        before = Image(source)
        assert value_of(family_values(before, files[label]), SECURITY_ATTRIBUTE) == value_of(
            family_values(image, files[label]), SECURITY_ATTRIBUTE)
        before_si = value_of(family_values(before, files[label]), STANDARD_ATTRIBUTE)
        after_si = value_of(family_values(image, files[label]), STANDARD_ATTRIBUTE)
        assert before_si[:OWNER_OFFSET] == after_si[:OWNER_OFFSET]
        assert before_si[OWNER_OFFSET + 4:CHARGE_OFFSET] == after_si[OWNER_OFFSET + 4:CHARGE_OFFSET]
        assert before_si[CHARGE_OFFSET + REFERENCE_BYTES:] == after_si[CHARGE_OFFSET + REFERENCE_BYTES:]
        before.close()
    image.close()


def execute(directory, selected):
    base = directory / 'base.img'
    with base.open('xb') as file:
        file.truncate(IMAGE_BYTES)
    run('mkfs.ntfs', '-F', '-Q', base)
    payload = directory / 'payload'
    payload.write_bytes(CONTENT)
    for label in ['payload.bin', 'other.bin']:
        run('ntfscp', '-f', base, payload, '/' + label)
    results = []
    for case in selected:
        source, target = directory / (case + '.img'), directory / (case + '-fixed.img')
        run('cp', '--reflink=auto', '--sparse=always', base, source)
        files = make_case(source, case)
        original = digest(source)
        run(CHECKER, '--repair-to', source, target)
        report = run(CHECKER, '--audit', target).stdout
        verify(source, target, case, files)
        repeat = directory / (case + '-again.img')
        run(CHECKER, '--repair-to', target, repeat)
        assert digest(repeat) == digest(target), case
        repeat.unlink()
        assert digest(source) == original, case
        results.append({'case': case, 'path': str(target), 'sha256': digest(target),
                        'source': str(source), 'source_sha256': original, 'passed': True,
                        'rescan_reported': b'quota-rescan-required' in report})
        print('PASS', case, 'audit, custom policy, data, ACLs and repeat repair', flush=True)
    (directory / 'results.json').write_text(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--all', action='store_true')
    parser.add_argument('--cases', help='Comma-separated cases')
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
        with tempfile.TemporaryDirectory(prefix='slate-quota-') as directory:
            execute(Path(directory), selected)


if __name__ == '__main__':
    main()
