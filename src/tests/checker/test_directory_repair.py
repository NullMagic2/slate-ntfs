#!/usr/bin/env python3
"""Module: checker_directory_repair_tests
Purpose: Verify directory framing and filename-family repairs on private images.
Created: 2026-10-01
Architecture: Shares independent fixture encoders with paired host validation;
    copy repairs retain original hashes and validate resulting names and DATA.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT / 'src/tests/checker'))
from test_readonly_assessment import Image, attributes, integer as u, put, decode, protect
from test_broader_consistency import resident, rewrite

WORK = None
BASE = None
from ntfs_image import CHECKER
SYSTEM_RECORDS = {
    'mft': 0, 'mftmirr': 1, 'logfile': 2, 'volume': 3, 'attrdef': 4,
    'bitmap': 6, 'boot': 7, 'badclus': 8, 'secure': 9, 'upcase': 10, 'extend': 11,
}
CASES = (
    'duplicate-exact', 'duplicate-cache', 'duplicate-namespace',
    'duplicate-extension', 'invalid-parent', 'directory-parent-conflict',
    'directory-cycle', 'index-allocation-size', 'index-offset-unaligned',
    'index-entry-oversized', 'index-empty-name', 'index-terminal-oversized',
    'root-offset-unaligned', 'duplicate-exact-links-one',
    'duplicate-exact-links-three', 'duplicate-exact-links-max',
    'duplicate-exact-unindexed', 'duplicate-exact-swapped-ids',
    'duplicate-long-triple', 'duplicate-posix-pair',
    'duplicate-namespace-win-dos', 'duplicate-namespace-win-combined',
    'duplicate-namespace-posix-dos',
    'collision-existing-higher', 'collision-existing-lower',
    'collision-extra-link', 'collision-posix-case',
    'directory-valid-root-dos', 'directory-valid-nonroot-parents',
    'directory-valid-root-long-self-alias',
    'directory-anchored-posix-self', 'directory-anchored-posix-two-node',
    'directory-anchored-win32-self',
    'directory-anchored-posix-self-quick',
    'directory-anchored-posix-two-node-quick',
    'directory-anchored-win32-self-quick',
    'directory-anchored-posix-three-node',
    'directory-root-extra-parent', 'directory-root-parent-moved',
    'directory-root-extra-parent-indexed',
    'directory-root-extra-parent-quick', 'directory-root-parent-moved-quick',
    'directory-root-extra-parent-indexed-quick',
    'directory-anchored-posix-three-node-single-edge',
    'directory-disconnected-posix-three-node',
    'directory-disconnected-posix-three-node-sequence',
    'directory-disconnected-posix-three-node-sequence-quick',
    'directory-existing-parent-stale-sequence',
    'directory-existing-parent-stale-sequence-quick',
    'directory-root-self-extra-name', 'directory-root-self-misnamed',
    'directory-root-self-posix-name', 'directory-root-filename-missing',
    'directory-root-self-extra-name-quick', 'directory-root-self-misnamed-quick',
    'directory-root-self-posix-name-quick', 'directory-root-filename-missing-quick',
    'directory-root-self-posix-indexed', 'directory-root-self-posix-indexed-quick',
    'filename-long-truncated', 'filename-all-truncated', 'filename-missing',
    'filename-long-truncated-quick', 'filename-all-truncated-quick',
    'filename-missing-quick',
    'filename-long-empty', 'filename-long-count-short',
    'filename-long-slash', 'filename-posix-slash', 'filename-dos-plus',
    'filename-long-empty-quick', 'filename-long-count-short-quick',
    'filename-long-slash-quick', 'filename-posix-slash-quick',
    'filename-dos-plus-quick', 'directory-root-truncated',
    'directory-root-truncated-quick', 'filename-long-namespace-high',
    'filename-namespace-high-indexed', 'filename-namespace-high-indexed-quick',
    'directory-root-high-namespace-indexed',
    'directory-root-high-namespace-indexed-quick',
    'filename-posix-colon-single-indexed', 'filename-posix-backslash-single-indexed',
    'filename-posix-control-single-indexed', 'filename-posix-slash-single-indexed',
    'filename-posix-valid-single-indexed', 'filename-win32-colon-indexed',
    'filename-win32-backslash-indexed',
    'filename-posix-colon-single-indexed-quick',
    'filename-posix-backslash-single-indexed-quick',
    'filename-posix-control-single-indexed-quick',
    'filename-posix-slash-single-indexed-quick',
    'filename-posix-valid-single-indexed-quick', 'filename-win32-colon-indexed-quick',
    'filename-win32-backslash-indexed-quick',
    'directory-root-unindexed', 'directory-root-unindexed-quick',
    'filename-long-resident-flags-high', 'filename-long-resident-flags-high-quick',
    'filename-long-resident-flags-unindexed-high',
    'filename-long-resident-flags-unindexed-high-quick',
    'filename-long-resident-flags-high-alias-repair',
    'filename-long-resident-flags-high-alias-repair-quick',
    'filename-indexed-resident-high255', 'filename-indexed-resident-high255-quick',
    'directory-root-indexed-resident-high3',
    'directory-root-indexed-resident-high3-quick',
    'duplicate-long-triple-mixed-flags-first3',
    'duplicate-long-triple-mixed-flags-first3-quick',
    'duplicate-long-triple-mixed-flags-first1',
    'duplicate-long-triple-mixed-flags-first1-quick',
    'filename-long-nonresident-mapped', 'filename-all-nonresident-mapped',
    'filename-long-nonresident-mapped-quick', 'filename-all-nonresident-mapped-quick',
    'directory-root-nonresident-mapped', 'directory-root-nonresident-mapped-quick',
    'filename-win32-single-indexed', 'filename-win32-single-indexed-quick',
    'filename-win32-dosshape-single-indexed',
    'filename-win32-dosshape-single-indexed-quick',
    'filename-posix-dosshape-single-indexed',
    'filename-posix-dosshape-single-indexed-quick',
    'directory-record-flag-cleared', 'directory-record-flag-cleared-quick',
    'filename-record-directory-flag-set', 'filename-record-directory-flag-set-quick',
    'filename-two-win32-matched', 'filename-two-win32-matched-quick',
    'filename-two-dos-matched', 'filename-two-dos-matched-quick',
    'filename-combined-plus-pair-matched', 'filename-combined-plus-pair-matched-quick',
    'filename-alias-parent-mismatch-matched', 'filename-alias-parent-mismatch-matched-quick',
    'filename-alias-casefold-match', 'filename-alias-casefold-match-quick',
    'filename-win32-plus-posix-matched', 'filename-win32-plus-posix-matched-quick',
    'reserved-extend-posix-matched', 'reserved-extend-posix-matched-quick',
    'reserved-extend-high-namespace-matched', 'reserved-extend-high-namespace-matched-quick',
    'reserved-extend-text-matched', 'reserved-extend-text-matched-quick',
    'reserved-extend-name-missing', 'reserved-extend-name-missing-quick',
    'reserved-attrdef-posix-matched', 'reserved-attrdef-posix-matched-quick',
    'reserved-upcase-posix-matched', 'reserved-upcase-posix-matched-quick',
    'ordinary-file-slot16-valid-matched', 'ordinary-file-slot16-valid-matched-quick',
    'ordinary-file-slot16-invalid-name-matched', 'ordinary-file-slot16-invalid-name-matched-quick',
)


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def values(record):
    return [bytearray(record[at:at + u(record, at + 4, 4)]) for at in attributes(record)]


def filenames(record):
    result = []
    for at in attributes(record):
        if u(record, at, 4) != 0x30:
            continue
        start = Image.value(record, at)
        value = record[start:start + u(record, at + 16, 4)]
        result.append({
            'id': u(record, at + 14, 2), 'parent': u(value, 0, 8),
            'resident_flags': record[at + 22],
            'namespace': value[65], 'name': bytes(value[66:66 + value[64] * 2]).decode('utf-16le'),
        })
    return result


def family_filenames(image, number):
    base = image.get(number)
    reference = number | (u(base, 16, 2) << 48)
    slots = u(image.zero, Image.attribute(image.zero, 0x80) + 56, 8) // image.record_bytes
    result = []
    for member in range(slots):
        record = image.get(member)
        if member == number or u(record, 32, 8) == reference:
            result.extend(filenames(record))
    return result


def data_hash(image, number=37):
    record = image.get(number)
    at = Image.attribute(record, 0x80)
    if not record[at + 8]:
        start = Image.value(record, at)
        data = record[start:start + u(record, at + 16, 4)]
    else:
        length = u(record, at + 48, 8)
        mapping = Image.runs(record, at)
        data = bytearray()
        offset = 0
        while offset < length:
            run = next(r for r in mapping if r[0] <= offset // image.cluster < r[0] + r[2])
            count = min(length - offset, (run[0] + run[2]) * image.cluster - offset)
            image.file.seek(Image.physical(image, mapping, offset))
            data.extend(image.file.read(count))
            offset += count
    return hashlib.sha256(data).hexdigest()


def insert_collision_root_key(image, number):
    root = image.get(5)
    allocation = next(at for at in attributes(root) if u(root, at, 4) == 0xa0)
    offset = image.physical(image.runs(root, allocation), 0)
    image.file.seek(offset)
    block = decode(image.file.read(4096), image.sector)
    assert block[36] == 0
    start = 24 + u(block, 24, 4)
    end = 24 + u(block, 28, 4)
    entries = []
    at = start
    while not u(block, at + 12, 2) & 2:
        size = u(block, at + 8, 2)
        entries.append(bytearray(block[at:at + size]))
        at += size
    terminal = block[at:end]
    record = image.get(number)
    filename = next(
        a for a in values(record)
        if u(a, 0, 4) == 0x30 and a[u(a, 20, 2) + 65] == 1
    )
    at = u(filename, 20, 2)
    value = filename[at:at + u(filename, 16, 4)]
    entry = bytearray((16 + len(value) + 7) & ~7)
    put(entry, 0, number | (u(record, 16, 2) << 48), 8)
    put(entry, 8, len(entry), 2)
    put(entry, 10, len(value), 2)
    entry[16:16 + len(value)] = value
    entries.append(entry)
    entries.sort(key=lambda item: bytes(item[82:82 + item[80] * 2]).decode('utf-16le').upper())
    content = b''.join(entries) + terminal
    assert start + len(content) <= len(block)
    block[start:] = bytes(len(block) - start)
    block[start:start + len(content)] = content
    put(block, 28, start + len(content) - 24, 4)
    image.file.seek(offset)
    image.file.write(protect(block, image.sector))


def mutate_collision(image, case):
    root = 5 | (u(image.get(5), 16, 2) << 48)
    for number in (35, 37):
        record = image.get(number)
        items = values(record)
        for filename in list(items):
            if u(filename, 0, 4) != 0x30:
                continue
            at = u(filename, 20, 2)
            value = filename[at:at + u(filename, 16, 4)]
            if case == 'collision-posix-case' and value[65] == 2:
                items.remove(filename)
                continue
            if value[65] == 1:
                label = (
                    'COLLIDING.TXT'
                    if case == 'collision-posix-case' and number == 35
                    else 'colliding.txt'
                )
                value = value[:66] + label.encode('utf-16le')
                value[64] = len(label)
                if case == 'collision-posix-case':
                    value[65] = 0
            put(value, 0, root, 8)
            replacement = resident(0x30, value, u(filename, 14, 2))
            replacement[22] = 1
            items[items.index(filename)] = replacement
        if case == 'collision-extra-link' and number == 37:
            filename = next(a for a in items if u(a, 0, 4) == 0x30)
            at = u(filename, 20, 2)
            value = filename[at:at + 66] + 'alternate.txt'.encode('utf-16le')
            value[64] = len('alternate.txt')
            value[65] = 0
            put(value, 0, 11 | (u(image.get(11), 16, 2) << 48), 8)
            identifier = u(record, 40, 2)
            added = resident(0x30, value, identifier)
            added[22] = 1
            items.append(added)
            put(record, 40, identifier + 1, 2)
        image.save(number, rewrite(record, items))
    if case.startswith('collision-existing-'):
        insert_collision_root_key(image, 37 if case.endswith('higher') else 35)


def add_directory_parent(image, number, parent, label, keep_aliases):
    record = image.get(number)
    items = values(record)
    selected = next(
        claim for claim in items
        if u(claim, 0, 4) == 0x30 and claim[u(claim, 20, 2) + 65] != 2
    )
    at = u(selected, 20, 2)
    original = bytearray(selected[at:at + u(selected, 16, 4)])
    if not keep_aliases:
        items = [claim for claim in items if u(claim, 0, 4) != 0x30]
        original[65] = 0
        retained = resident(0x30, original, u(selected, 14, 2))
        retained[22] = 1
        items.append(retained)
    value = original[:66] + label.encode('utf-16le')
    value[64] = len(label)
    value[65] = 0
    put(value, 0, parent | (u(image.get(parent), 16, 2) << 48), 8)
    identifier = u(record, 40, 2)
    added = resident(0x30, value, identifier)
    added[22] = 1
    items.append(added)
    put(record, 40, identifier + 1, 2)
    put(record, 18, sum(u(claim, 0, 4) == 0x30 for claim in items), 2)
    image.save(number, rewrite(record, items))


def insert_resident_directory_key(image, parent, number, namespace):
    record = image.get(number)
    claim = next(
        item for item in values(record)
        if u(item, 0, 4) == 0x30 and item[u(item, 20, 2) + 65] == namespace
    )
    offset = u(claim, 20, 2)
    value = claim[offset:offset + u(claim, 16, 4)]
    entry = bytearray((16 + len(value) + 7) & ~7)
    put(entry, 0, number | (u(record, 16, 2) << 48), 8)
    put(entry, 8, len(entry), 2)
    put(entry, 10, len(value), 2)
    entry[16:16 + len(value)] = value
    record = image.get(parent)
    items = values(record)
    root = next(item for item in items if u(item, 0, 4) == 0x90)
    offset = u(root, 20, 2)
    value = bytearray(root[offset:offset + u(root, 16, 4)])
    assert value[28] == 0
    start = 16 + u(value, 16, 4)
    end = 16 + u(value, 20, 4)
    entries = []
    at = start
    while not u(value, at + 12, 2) & 2:
        size = u(value, at + 8, 2)
        entries.append(value[at:at + size])
        at += size
    terminal = value[at:end]
    entries.append(entry)
    entries.sort(
        key=lambda item: bytes(item[82:82 + item[80] * 2]).decode('utf-16le').upper()
    )
    value = value[:start] + b''.join(entries) + terminal
    put(value, 20, len(value) - 16, 4)
    put(value, 24, len(value) - 16, 4)
    replacement = root[:offset] + value
    replacement.extend(bytes((-len(replacement)) % 8))
    put(replacement, 4, len(replacement), 4)
    put(replacement, 16, len(value), 4)
    items[items.index(root)] = replacement
    image.save(parent, rewrite(record, items))


def set_index_namespace(image, parent, target, namespace):
    record = image.get(parent)
    root_at = next(at for at in attributes(record) if u(record, at, 4) == 0x90)
    root_value = Image.value(record, root_at)
    allocation = next(
        (at for at in attributes(record) if u(record, at, 4) == 0xa0), None
    )
    if allocation is None:
        block = record
        head = root_value + 16
    else:
        physical = image.physical(image.runs(record, allocation), 0)
        image.file.seek(physical)
        block = decode(image.file.read(4096), image.sector)
        head = 24
    at = head + u(block, head, 4)
    found = False
    while not u(block, at + 12, 2) & 2:
        if u(block, at, 8) & 0xffffffffffff == target and block[at + 81] & 3 == 1:
            block[at + 81] = namespace
            found = True
        at += u(block, at + 8, 2)
    assert found
    if allocation is None:
        image.save(parent, block)
    else:
        image.file.seek(physical)
        image.file.write(protect(block, image.sector))


def index_name_keys(image, parent, target):
    record = image.get(parent)
    root_at = next(at for at in attributes(record) if u(record, at, 4) == 0x90)
    allocation = next(
        (at for at in attributes(record) if u(record, at, 4) == 0xa0), None
    )
    if allocation is None:
        block = record
        head = Image.value(record, root_at) + 16
    else:
        physical = image.physical(image.runs(record, allocation), 0)
        image.file.seek(physical)
        block = decode(image.file.read(4096), image.sector)
        head = 24
    at = head + u(block, head, 4)
    result = []
    while not u(block, at + 12, 2) & 2:
        if u(block, at, 8) & 0xffffffffffff == target:
            name = bytes(block[at + 82:at + 82 + block[at + 80] * 2])
            result.append((block[at + 81], name.decode('utf-16le')))
        at += u(block, at + 8, 2)
    return sorted(result)


def edit_resident_filename_key(image, parent, target, namespace, text, single):
    record = image.get(parent)
    items = values(record)
    root = next(item for item in items if u(item, 0, 4) == 0x90)
    offset = u(root, 20, 2)
    value = bytearray(root[offset:offset + u(root, 16, 4)])
    start = 16 + u(value, 16, 4)
    at = start
    entries = []
    matched = False
    while not u(value, at + 12, 2) & 2:
        entry = bytearray(value[at:at + u(value, at + 8, 2)])
        at += len(entry)
        if u(entry, 0, 8) & 0xffffffffffff == target:
            if entry[81] == 2 and single:
                continue
            if entry[81] == 1:
                encoded = text.encode('utf-16le')
                assert u(entry, 12, 2) == 0
                key = entry[16:16 + u(entry, 10, 2)]
                key = key[:66] + encoded
                key[64] = len(encoded) // 2
                key[65] = namespace
                entry = entry[:16] + key
                entry.extend(bytes((-len(entry)) % 8))
                put(entry, 8, len(entry), 2)
                put(entry, 10, len(key), 2)
                matched = True
        entries.append(entry)
    assert matched
    terminal = value[at:at + u(value, at + 8, 2)]
    value = value[:start] + b''.join(entries) + terminal
    put(value, 20, len(value) - 16, 4)
    put(value, 24, len(value) - 16, 4)
    replacement = root[:offset] + value
    replacement.extend(bytes((-len(replacement)) % 8))
    put(replacement, 4, len(replacement), 4)
    put(replacement, 16, len(value), 4)
    items[items.index(root)] = replacement
    image.save(parent, rewrite(record, items))


def publish_fixture_filename_keys(image, parent, target):
    # Match the deliberately altered claims so alias validation is independent
    # of stale index keys. Preserve unrelated entries and the existing layout.

    record = image.get(parent)
    root_at = next(at for at in attributes(record) if u(record, at, 4) == 0x90)
    allocation = next((at for at in attributes(record) if u(record, at, 4) == 0xa0), None)
    if allocation is None:
        start = Image.value(record, root_at)
        block = bytearray(record[start:start + u(record, root_at + 16, 4)])
        head = 16
    else:
        physical = image.physical(image.runs(record, allocation), 0)
        image.file.seek(physical)
        block = decode(image.file.read(4096), image.sector)
        head = 24
    assert block[head + 12] == 0
    first = head + u(block, head, 4)
    at = first
    entries = []
    while not u(block, at + 12, 2) & 2:
        size = u(block, at + 8, 2)
        if u(block, at, 8) & 0xffffffffffff != target:
            entries.append(bytearray(block[at:at + size]))
        at += size
    terminal = block[at:at + u(block, at + 8, 2)]
    parent_reference = parent | (u(record, 16, 2) << 48)
    child = image.get(target)
    for claim in values(child) if u(child, 22, 2) & 1 else []:
        if u(claim, 0, 4) != 0x30:
            continue
        offset = u(claim, 20, 2)
        value = claim[offset:offset + u(claim, 16, 4)]
        if u(value, 0, 8) != parent_reference:
            continue
        entry = bytearray((16 + len(value) + 7) & ~7)
        put(entry, 0, target | (u(child, 16, 2) << 48), 8)
        put(entry, 8, len(entry), 2)
        put(entry, 10, len(value), 2)
        entry[16:16 + len(value)] = value
        entries.append(entry)
    def key(entry):
        text = bytes(entry[82:82 + entry[80] * 2]).decode('utf-16le')
        return text.upper(), text
    entries.sort(key=key)
    payload = b''.join(entries) + terminal
    if allocation is None:
        block = block[:first] + payload
        put(block, head + 4, len(block) - head, 4)
        put(block, head + 8, len(block) - head, 4)
        items = values(record)
        root = next(item for item in items if u(item, 0, 4) == 0x90)
        offset = u(root, 20, 2)
        replacement = root[:offset] + block
        replacement.extend(bytes((-len(replacement)) % 8))
        put(replacement, 4, len(replacement), 4)
        put(replacement, 16, len(block), 4)
        items[items.index(root)] = replacement
        image.save(parent, rewrite(record, items))
    else:
        assert first + len(payload) <= len(block)
        block[first:] = payload + bytes(len(block) - first - len(payload))
        put(block, head + 4, first + len(payload) - head, 4)
        image.file.seek(physical)
        image.file.write(protect(block, image.sector))


def mutate(path, case):
    case = case.removesuffix('-quick')
    if case.startswith('duplicate-long-triple-mixed-flags-'):
        mutate(path, 'duplicate-long-triple')
        image = Image(path)
        try:
            record = image.get(37)
            claims = [
                at for at in attributes(record)
                if u(record, at, 4) == 0x30 and record[Image.value(record, at) + 65] == 1
            ]
            flags = [3, 1, 1] if case.endswith('first3') else [1, 3, 3]
            assert len(claims) == len(flags)
            for at, flag in zip(claims, flags):
                record[at + 22] = flag
            image.save(37, record)
        finally:
            image.file.close()
        return
    shutil.copyfile(BASE, path)
    image = Image(path)
    try:
        if case.startswith('ordinary-file-slot16-'):
            record = image.get(37)
            put(record, 44, 16, 4)
            if 'invalid-name' in case:
                for at in attributes(record):
                    if u(record, at, 4) == 0x30:
                        offset = Image.value(record, at)
                        if record[offset + 65] == 1:
                            record[offset + 66:offset + 94] = 'WPSettings:dat'.encode('utf-16le')
            image.save(16, record)
            old = image.get(37)
            put(old, 22, 0, 2)
            image.save(37, old)
            bitmap = Image.attribute(image.zero, 0xb0)
            mapping = Image.runs(image.zero, bitmap)
            image.bit(mapping, 16, True)
            image.bit(mapping, 37, False)
            publish_fixture_filename_keys(image, 36, 37)
            publish_fixture_filename_keys(image, 36, 16)
            return
        if case.startswith('reserved-'):
            number = SYSTEM_RECORDS[case.removeprefix('reserved-').split('-', 1)[0]]
            record = image.get(number)
            items = []
            for claim in values(record):
                if u(claim, 0, 4) == 0x30:
                    if 'name-missing' in case:
                        continue
                    offset = u(claim, 20, 2)
                    claim[offset + 65] = 7 if 'high-namespace' in case else 0
                    if 'text-matched' in case:
                        claim[offset + 65] = 3
                        claim[offset + 66:offset + 80] = '$Exlend'.encode('utf-16le')
                items.append(claim)
            if 'name-missing' in case:
                put(record, 18, 0, 2)
            image.save(number, rewrite(record, items))
            if 'name-missing' not in case:
                publish_fixture_filename_keys(image, 5, number)
            return
        if case in (
            'filename-two-win32-matched', 'filename-two-dos-matched',
            'filename-combined-plus-pair-matched', 'filename-alias-parent-mismatch-matched',
            'filename-alias-casefold-match', 'filename-win32-plus-posix-matched',
        ):
            record = image.get(37)
            items = [item for item in values(record) if u(item, 0, 4) != 0x30]
            original = next(at for at in attributes(record) if u(record, at, 4) == 0x30)
            offset = Image.value(record, original)
            cached = record[offset:offset + 66]
            root = 5 | (u(image.get(5), 16, 2) << 48)
            parent = 36 | (u(image.get(36), 16, 2) << 48)
            claims = [(1, parent, 'WPSettings.dat'), (2, parent, 'WPSETT~1.DAT')]
            if case == 'filename-two-win32-matched':
                claims.append((1, parent, 'AnotherName.dat'))
            elif case == 'filename-two-dos-matched':
                claims.append((2, parent, 'OTHER~1.DAT'))
            elif case == 'filename-combined-plus-pair-matched':
                claims.append((3, parent, 'OTHER.TXT'))
            elif case == 'filename-alias-parent-mismatch-matched':
                claims[1] = (2, root, 'WPSETT~1.DAT')
            elif case == 'filename-alias-casefold-match':
                claims = [(1, parent, 'ABCDEFGH.TXT'), (2, parent, 'abcdefgh.txt')]
            else:
                claims = [(1, parent, 'WPSettings.dat'), (0, parent, 'another-posix.dat')]
            identifier = u(record, 40, 2)
            for namespace, destination, label in claims:
                value = bytearray(cached) + label.encode('utf-16le')
                put(value, 0, destination, 8)
                value[64] = len(label)
                value[65] = namespace
                attribute = resident(0x30, value, identifier)
                attribute[22] = 1
                items.append(attribute)
                identifier += 1
            put(record, 18, len(claims), 2)
            put(record, 40, identifier, 2)
            image.save(37, rewrite(record, items))
            publish_fixture_filename_keys(image, 36, 37)
            publish_fixture_filename_keys(image, 5, 37)
            return
        elif case in ('directory-record-flag-cleared', 'filename-record-directory-flag-set'):
            number = 36 if case.startswith('directory-') else 37
            record = image.get(number)
            put(record, 22, 1 if number == 36 else 3, 2)
            image.save(number, record)
            return
        if (
            case == 'directory-root-unindexed' or 'resident-flags' in case
            or 'indexed-resident-high' in case
        ):
            number = 5 if case.startswith('directory-root-') else 37
            record = image.get(number)
            items = []
            for claim in values(record):
                if u(claim, 0, 4) == 0x30:
                    offset = u(claim, 20, 2)
                    namespace = claim[offset + 65]
                    if number == 5 or namespace == 1:
                        claim[22] = (
                            0 if case == 'directory-root-unindexed' else
                            255 if case.endswith('high255') else
                            2 if 'unindexed' in case else 3
                        )
                    elif case.endswith('alias-repair'):
                        value = claim[offset:offset + u(claim, 16, 4)]
                        text = 'WP+SETT.DAT'.encode('utf-16le')
                        value = value[:66] + text
                        value[64] = len(text) // 2
                        flags = claim[22]
                        claim = resident(0x30, value, u(claim, 14, 2))
                        claim[22] = flags
                items.append(claim)
            image.save(number, rewrite(record, items))
            return
        if case in (
            'filename-long-nonresident-mapped', 'filename-all-nonresident-mapped',
            'directory-root-nonresident-mapped',
        ):
            bitmap = image.get(6)
            mapping = image.runs(bitmap, image.attribute(bitmap, 0x80))
            total = u(image.boot, 40, 8) * image.sector // image.cluster
            image.file.seek(image.physical(mapping, 0))
            bits = image.file.read((total + 7) // 8)
            free = (
                number for number in range(16, total)
                if bits[number // 8] & (1 << (number % 8)) == 0
            )
            number = 5 if case.startswith('directory-root-') else 37
            record = image.get(number)
            items = []
            for claim in values(record):
                if u(claim, 0, 4) == 0x30:
                    offset = u(claim, 20, 2)
                    value = claim[offset:offset + u(claim, 16, 4)]
                    if number == 5 or case.startswith('filename-all-') or value[65] == 1:
                        cluster = next(free)
                        width = max(1, (cluster.bit_length() + 8) // 8)
                        run = bytes([(width << 4) | 1, 1])
                        run += cluster.to_bytes(width, 'little', signed=True) + b'\0'
                        replacement = bytearray((64 + len(run) + 7) & ~7)
                        for at, size, field in (
                            (0, 4, 0x30), (4, 4, len(replacement)),
                            (14, 2, u(claim, 14, 2)), (32, 2, 64),
                            (40, 8, image.cluster), (48, 8, len(value)),
                            (56, 8, len(value)),
                        ):
                            put(replacement, at, field, size)
                        replacement[8] = 1
                        replacement[64:64 + len(run)] = run
                        image.file.seek(cluster * image.cluster)
                        image.file.write(value + bytes(image.cluster - len(value)))
                        image.bit(mapping, cluster, True)
                        claim = replacement
                items.append(claim)
            image.save(number, rewrite(record, items))
            return
        if case.startswith('filename-'):
            record = image.get(37)
            items = []
            indexed_content = (
                case.startswith(('filename-posix-', 'filename-win32-'))
                and case.endswith('indexed')
            )
            alias_single = case in (
                'filename-win32-single-indexed', 'filename-win32-dosshape-single-indexed',
                'filename-posix-dosshape-single-indexed',
            )
            single = alias_single or (case.startswith('filename-posix-') and indexed_content)
            namespace = 0 if case.startswith('filename-posix-') else 1
            if alias_single:
                text = 'ABCDEFGH.TXT' if 'dosshape' in case else 'WPSettings.dat'
            elif indexed_content:
                character = {
                    'colon': ':', 'backslash': '\\', 'control': '\x1f',
                    'slash': '/', 'valid': '.',
                }[case.split('-')[2]]
                text = 'WPSettings' + character + 'dat'
            for claim in values(record):
                if u(claim, 0, 4) == 0x30:
                    if case == 'filename-missing':
                        continue
                    offset = u(claim, 20, 2)
                    value = claim[offset:offset + u(claim, 16, 4)]
                    if single and value[65] == 2:
                        continue
                    selected = (
                        case == 'filename-all-truncated'
                        or value[65] == (2 if case == 'filename-dos-plus' else 1)
                    )
                    if selected:
                        if indexed_content:
                            value = value[:66] + text.encode('utf-16le')
                            value[64] = len(text)
                            value[65] = namespace
                        elif case.endswith('truncated'):
                            value = value[:32]
                        elif case.endswith('empty'):
                            value = value[:66]
                            value[64] = 0
                        elif case.endswith('count-short'):
                            value[64] -= 1
                        elif case.endswith(('namespace-high', 'namespace-high-indexed')):
                            value[65] = 5
                        elif case.endswith(('slash', 'plus')):
                            text = 'WP+SETT.DAT' if case.endswith('plus') else 'invalid/name'
                            value = value[:66] + text.encode('utf-16le')
                            value[64] = len(text)
                            if case.startswith('filename-posix-'):
                                value[65] = 0
                        claim = resident(0x30, value, u(claim, 14, 2))
                        claim[22] = 1
                items.append(claim)
            if case == 'filename-missing' or single:
                put(record, 18, 1 if single else 0, 2)
            image.save(37, rewrite(record, items))
            if case == 'filename-namespace-high-indexed':
                set_index_namespace(image, 36, 37, 5)
            elif indexed_content:
                edit_resident_filename_key(image, 36, 37, namespace, text, single)
            return
        if case.startswith('collision-'):
            mutate_collision(image, case)
            return
        if case.startswith('directory-disconnected-posix-three-node'):
            for number, parent in ((27, 36), (36, 30)):
                record = image.get(number)
                items = values(record)
                selected = next(
                    claim for claim in items
                    if u(claim, 0, 4) == 0x30 and claim[u(claim, 20, 2) + 65] != 2
                )
                offset = u(selected, 20, 2)
                value = bytearray(selected[offset:offset + u(selected, 16, 4)])
                value[65] = 0
                put(value, 0, parent | (u(image.get(parent), 16, 2) << 48), 8)
                claim = resident(0x30, value, u(selected, 14, 2))
                claim[22] = 1
                items = [item for item in items if u(item, 0, 4) != 0x30] + [claim]
                put(record, 18, 1, 2)
                image.save(number, rewrite(record, items))
            if case.endswith('sequence'):
                record = image.get(27)
                put(record, 16, 2, 2)
                image.save(27, record)
                # Every child keeps the current full parent identity. This
                # isolates graph ordering from missing-parent reconnection.

                for number in range(64):
                    record = image.get(number)
                    changed = False
                    for at in attributes(record):
                        if u(record, at, 4) != 0x30:
                            continue
                        offset = Image.value(record, at)
                        if u(record, offset, 8) == 27 | (1 << 48):
                            put(record, offset, 27 | (2 << 48), 8)
                            changed = True
                    if changed:
                        image.save(number, record)
            return
        if case == 'directory-existing-parent-stale-sequence':
            record = image.get(37)
            for at in attributes(record):
                if u(record, at, 4) == 0x30:
                    put(record, Image.value(record, at), 36 | (2 << 48), 8)
            image.save(37, record)
            return
        if case.startswith('directory-root-'):
            if case == 'directory-root-truncated':
                record = image.get(5)
                items = values(record)
                claim = next(item for item in items if u(item, 0, 4) == 0x30)
                offset = u(claim, 20, 2)
                value = claim[offset:offset + 32]
                replacement = resident(0x30, value, u(claim, 14, 2))
                replacement[22] = 1
                items[items.index(claim)] = replacement
                image.save(5, rewrite(record, items))
            elif case == 'directory-root-filename-missing':
                record = image.get(5)
                items = [claim for claim in values(record) if u(claim, 0, 4) != 0x30]
                put(record, 18, 0, 2)
                image.save(5, rewrite(record, items))
            elif case == 'directory-root-self-extra-name':
                add_directory_parent(image, 5, 5, 'root-alias', True)
            elif case in (
                'directory-root-self-misnamed', 'directory-root-self-posix-name',
                'directory-root-self-posix-indexed',
                'directory-root-high-namespace-indexed',
            ):
                record = image.get(5)
                items = values(record)
                claim = next(item for item in items if u(item, 0, 4) == 0x30)
                offset = u(claim, 20, 2)
                value = bytearray(claim[offset:offset + u(claim, 16, 4)])
                if case.endswith('misnamed'):
                    value = value[:66] + 'not-root'.encode('utf-16le')
                    value[64] = len('not-root')
                else:
                    value[65] = 7 if case.startswith('directory-root-high-') else 0
                replacement = resident(0x30, value, u(claim, 14, 2))
                replacement[22] = 1
                items[items.index(claim)] = replacement
                image.save(5, rewrite(record, items))
                if case.endswith('indexed'):
                    allocation = next(
                        at for at in attributes(record) if u(record, at, 4) == 0xa0
                    )
                    physical = image.physical(image.runs(record, allocation), 0)
                    image.file.seek(physical)
                    block = decode(image.file.read(4096), image.sector)
                    at = 24 + u(block, 24, 4)
                    found = False
                    while not u(block, at + 12, 2) & 2:
                        if u(block, at, 8) & 0xffffffffffff == 5:
                            assert block[at + 82:at + 82 + block[at + 80] * 2] == b'.\x00'
                            block[at + 81] = value[65]
                            found = True
                        at += u(block, at + 8, 2)
                    assert found
                    image.file.seek(physical)
                    image.file.write(protect(block, image.sector))
            elif case == 'directory-root-parent-moved':
                record = image.get(5)
                for at in attributes(record):
                    if u(record, at, 4) == 0x30:
                        put(record, Image.value(record, at), 36 | (1 << 48), 8)
                image.save(5, record)
            else:
                add_directory_parent(image, 5, 36, 'root-back-link', True)
                if case.endswith('indexed'):
                    insert_resident_directory_key(image, 36, 5, 0)
            return
        if case.startswith('directory-anchored-'):
            if case in (
                'directory-anchored-posix-three-node',
                'directory-anchored-posix-three-node-single-edge',
            ):
                add_directory_parent(image, 27, 36, 'under-svi', False)
                add_directory_parent(image, 36, 30, 'under-txflog', False)
                if case == 'directory-anchored-posix-three-node':
                    add_directory_parent(image, 30, 27, 'duplicate-parent-name', False)
            elif case == 'directory-anchored-posix-two-node':
                add_directory_parent(image, 36, 30, 'under-txflog', False)
                add_directory_parent(image, 30, 36, 'back-edge', False)
            else:
                add_directory_parent(image, 36, 36, 'self-link', case.endswith('win32-self'))
            return
        if case.startswith('directory-valid-'):
            record = image.get(36)
            for at in attributes(record):
                if u(record, at, 4) != 0x30:
                    continue
                value = Image.value(record, at)
                namespace = record[value + 65]
                if case == 'directory-valid-root-dos':
                    parent = 30 if namespace == 1 else 5
                elif case == 'directory-valid-nonroot-parents':
                    parent = 30 if namespace == 1 else 11
                else:
                    parent = 5 if namespace == 1 else 36
                put(record, value, parent | (u(image.get(parent), 16, 2) << 48), 8)
            image.save(36, record)
            return
        if case.startswith('duplicate-'):
            record = image.get(37)
            if case == 'duplicate-posix-pair' or case.startswith('duplicate-namespace-'):
                selected = next(
                    a for a in values(record)
                    if u(a, 0, 4) == 0x30 and a[u(a, 20, 2) + 65] == 2
                )
                at = u(selected, 20, 2)
                value = selected[at:at + u(selected, 16, 4)]
                namespaces = {
                    'duplicate-posix-pair': (0, 0),
                    'duplicate-namespace-win-dos': (1, 2),
                    'duplicate-namespace-win-combined': (1, 3),
                    'duplicate-namespace-posix-dos': (0, 2),
                }
                # These distinct namespace identities share one exact text key.
                # The POSIX pair instead tests cancellation with no alias left.

                first, second = namespaces[case]
                value[65] = first
                first_claim = resident(0x30, value, 2)
                first_claim[22] = 1
                value[65] = second
                second_claim = resident(0x30, value, 4)
                second_claim[22] = 1
                other = [a for a in values(record) if u(a, 0, 4) != 0x30]
                put(record, 18, 2, 2)
                put(record, 40, 5, 2)
                image.save(37, rewrite(record, other + [first_claim, second_claim]))
                return
            items = values(record)
            selected = next(a for a in items if u(a, 0, 4) == 0x30 and a[u(a, 20, 2) + 65] == 1)
            duplicate = bytearray(selected)
            identifier = u(record, 40, 2)
            put(duplicate, 14, identifier, 2)
            put(record, 40, identifier + 1, 2)
            if case == 'duplicate-cache':
                duplicate[u(duplicate, 20, 2) + 8] ^= 1
            elif case == 'duplicate-namespace':
                duplicate[u(duplicate, 20, 2) + 65] = 0
            if case == 'duplicate-extension':
                extension = image.get(38)
                assert not u(extension, 22, 2) & 1
                put(extension, 16, 1, 2)
                put(extension, 22, 1, 2)
                put(extension, 32, 37 | (u(record, 16, 2) << 48), 8)
                put(extension, 18, 0, 2)
                put(extension, 40, identifier + 1, 2)
                image.save(38, rewrite(extension, [duplicate]))
                image.bit(Image.runs(image.zero, Image.attribute(image.zero, 0xB0)), 38, True)
                from test_broader_consistency import listed
                entries = [listed(a, 37 | (u(record, 16, 2) << 48)) for a in items]
                entries.append(listed(duplicate, 38 | (1 << 48)))
                entries.sort(key=lambda e: (u(e, 0, 4), bytes(e[26:]), u(e, 8, 8)))
                items.append(resident(0x20, b''.join(entries), identifier + 1))
                put(record, 40, identifier + 2, 2)
            else:
                items.append(duplicate)
                if case == 'duplicate-long-triple':
                    third = bytearray(duplicate)
                    put(third, 14, identifier + 1, 2)
                    items.append(third)
                    put(record, 40, identifier + 2, 2)
            if case.endswith('unindexed'):
                items[-1][22] = 0
            elif case.endswith('swapped-ids'):
                put(selected, 14, identifier, 2)
                put(items[-1], 14, u(record, 40, 2) - 3, 2)
            if case.startswith('duplicate-exact-links-'):
                links = {'one': 1, 'three': 3, 'max': 65535}[case.rsplit('-', 1)[1]]
                put(record, 18, links, 2)
            image.save(37, rewrite(record, items))
            return
        if case in ('invalid-parent', 'directory-parent-conflict', 'directory-cycle'):
            number = 37 if case == 'invalid-parent' else 36
            record = image.get(number)
            for at in attributes(record):
                if u(record, at, 4) != 0x30:
                    continue
                start = Image.value(record, at)
                if case == 'invalid-parent':
                    parent = 63 | (1 << 48)
                elif case == 'directory-cycle':
                    parent = 36 | (u(record, 16, 2) << 48)
                elif record[start + 65] == 2:
                    parent = 11 | (u(image.get(11), 16, 2) << 48)
                else:
                    continue
                put(record, start, parent, 8)
            image.save(number, record)
            return
        root = image.get(5)
        if case == 'root-offset-unaligned':
            items = values(root)
            at = next(i for i, a in enumerate(items) if u(a, 0, 4) == 0x90)
            old = items[at]
            start = u(old, 20, 2)
            value = bytearray(old[start:start + u(old, 16, 4)])
            first = 16 + u(value, 16, 4)
            value[first:first] = bytes(1)
            put(value, 16, u(value, 16, 4) + 1, 4)
            put(value, 20, u(value, 20, 4) + 1, 4)
            put(value, 24, u(value, 24, 4) + 1, 4)
            from test_semantic_repair import named
            items[at] = named(0x90, '$I30', value, u(old, 14, 2))
            image.save(5, rewrite(root, items))
            return
        allocation = next(at for at in attributes(root) if u(root, at, 4) == 0xA0)
        offset = image.physical(image.runs(root, allocation), 0)
        image.file.seek(offset)
        block = decode(image.file.read(4096), image.sector)
        first = 24 + u(block, 24, 4)
        stop = 24 + u(block, 28, 4)
        if case == 'index-allocation-size':
            put(block, 32, u(block, 32, 4) - 8, 4)
        elif case == 'index-offset-unaligned':
            block[first + 1:stop + 1] = block[first:stop]
            put(block, 24, u(block, 24, 4) + 1, 4)
            put(block, 28, u(block, 28, 4) + 1, 4)
        elif case == 'index-entry-oversized':
            old = u(block, first + 8, 2)
            block[first + old + 8:stop + 8] = block[first + old:stop]
            block[first + old:first + old + 8] = bytes(8)
            put(block, first + 8, old + 8, 2)
            put(block, 28, u(block, 28, 4) + 8, 4)
        elif case == 'index-empty-name':
            block[first + 16 + 64] = 0
        elif case == 'index-terminal-oversized':
            terminal = first
            while not u(block, terminal + 12, 2) & 2:
                terminal += u(block, terminal + 8, 2)
            put(block, terminal + 8, u(block, terminal + 8, 2) + 8, 2)
            put(block, 28, u(block, 28, 4) + 8, 4)
        else:
            raise AssertionError(case)
        image.file.seek(offset)
        image.file.write(protect(block, image.sector))
    finally:
        image.file.close()


def main():
    global BASE, WORK
    parser = argparse.ArgumentParser()
    parser.add_argument('base', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    BASE = args.base
    WORK = args.output
    WORK.mkdir(exist_ok=False)
    original = digest(BASE)
    baseline = subprocess.run([str(CHECKER), '--json', '--check', str(BASE)], capture_output=True, text=True)
    assert baseline.returncode == 0, (baseline.stdout, baseline.stderr)
    results = []
    for case in CASES:
        behavior_case = case.removesuffix('-quick')
        clean_control = behavior_case in (
            'filename-namespace-high-indexed', 'directory-root-high-namespace-indexed',
            'filename-posix-valid-single-indexed', 'filename-long-resident-flags-high',
            'filename-indexed-resident-high255', 'directory-root-indexed-resident-high3',
            'filename-posix-dosshape-single-indexed',
            'reserved-extend-high-namespace-matched',
            'ordinary-file-slot16-valid-matched',
        )
        path = WORK / (case + '.img')
        mutate(path, case)
        retained_unrelated = None
        if (
            case.endswith('-quick') and not clean_control
            and not case.startswith('directory-disconnected-')
            and not case.startswith('reserved-extend-')
        ):
            image = Image(path)
            # The changed live timestamp is informational during a full audit.
            # Quick cycle repair must retain this unrelated parent index.

            quota = image.get(24)
            at = Image.attribute(quota, 0x10)
            offset = Image.value(quota, at)
            put(quota, offset, u(quota, offset, 8) + 123, 8)
            image.save(24, quota)
            retained_unrelated = image.get(11)
            image.file.close()
        source_hash = digest(path)
        image = Image(path)
        target = 16 if case.startswith('ordinary-file-slot16-') else 37
        data_numbers = (35, target)
        before_data = {number: data_hash(image, number) for number in data_numbers}
        before_file_times = None
        times_number = (
            4 if case.startswith('reserved-attrdef-') else
            10 if case.startswith('reserved-upcase-') else
            11 if case.startswith('reserved-extend-') else
            16 if case.startswith('ordinary-file-slot16-') else
            5 if case.startswith('directory-root-') else
            36 if case.startswith('directory-record-flag-cleared') else 37
        )
        if case.startswith(('reserved-attrdef-', 'reserved-upcase-')):
            before_data[times_number] = data_hash(image, times_number)
            data_numbers = tuple(before_data)
        if case.startswith((
            'filename-', 'duplicate-long-triple-mixed-flags-', 'directory-root-',
            'directory-record-flag-cleared',
            'reserved-',
            'ordinary-file-slot16-',
        )):
            record = image.get(times_number)
            offset = Image.value(record, Image.attribute(record, 0x10))
            before_file_times = bytes(record[offset:offset + 32])
        image.file.close()
        assessment = subprocess.run([str(CHECKER), '--json', '--audit', str(path)], capture_output=True, text=True)
        destination = WORK / (case + '-host.img')
        destination.unlink(missing_ok=True)
        repair_options = ['--index-check=quick'] if case.endswith('-quick') else []
        repair = subprocess.run(
            [str(CHECKER), *repair_options, '--repair-to', str(path), str(destination)],
            capture_output=True, text=True,
        )
        item = {'case': case, 'source_sha256': source_hash, 'assessment_exit': assessment.returncode,
                'assessment': assessment.stdout, 'assessment_stderr': assessment.stderr,
                'repair_exit': repair.returncode, 'repair_output': repair.stdout, 'repair_stderr': repair.stderr}
        expected_assessment = 0 if case == 'root-offset-unaligned' or clean_control else 4
        assert assessment.returncode == expected_assessment, (
            case, assessment.stdout, assessment.stderr,
        )
        assert repair.returncode == 0, (case, repair.stdout, repair.stderr)
        if repair.returncode == 0:
            image = Image(destination)
            item['names'] = family_filenames(image, target)
            item['directory_names'] = family_filenames(image, 36)
            if retained_unrelated is not None:
                assert image.get(11) == retained_unrelated, case
            if before_file_times is not None:
                record = image.get(times_number)
                offset = Image.value(record, Image.attribute(record, 0x10))
                assert bytes(record[offset:offset + 32]) == before_file_times, case
            item['data_preserved'] = {
                number: data_hash(image, number) for number in data_numbers
            } == before_data
            image.file.close()
            assert item['data_preserved'], case
            post = subprocess.run([str(CHECKER), '--json', '--check', str(destination)], capture_output=True, text=True)
            assert post.returncode == 0, (case, post.stdout, post.stderr)
            identities = [(name['namespace'], name['name']) for name in item['names']]
            if behavior_case.startswith('ordinary-file-slot16-'):
                expected = (
                    [(1, 'WPSettings.dat'), (2, 'WPSETT~1.DAT')]
                    if clean_control else [(0, 'WPSETT~1.DAT')]
                )
                assert sorted(identities) == expected, (case, identities)
                image = Image(destination)
                assert index_name_keys(image, 36, 16) == expected
                image.file.close()
            if behavior_case.startswith('reserved-'):
                image = Image(destination)
                name = {4: '$AttrDef', 10: '$UpCase', 11: '$Extend'}[times_number]
                namespace = 7 if clean_control else 3
                claims = family_filenames(image, times_number)
                assert [
                    (claim['parent'] & 0xffffffffffff, claim['namespace'], claim['name'])
                    for claim in claims
                ] == [(5, namespace, name)], (case, claims)
                assert index_name_keys(image, 5, times_number) == [(namespace, name)]
                image.file.close()
            if case.startswith('filename-'):
                if behavior_case in (
                    'filename-two-win32-matched', 'filename-two-dos-matched',
                    'filename-combined-plus-pair-matched', 'filename-alias-parent-mismatch-matched',
                    'filename-alias-casefold-match', 'filename-win32-plus-posix-matched',
                ):
                    expected = {
                        'filename-two-win32-matched': [
                            (0, 'AnotherName.dat'), (0, 'WPSETT~1.DAT'), (0, 'WPSettings.dat'),
                        ],
                        'filename-two-dos-matched': [
                            (0, 'OTHER~1.DAT'), (0, 'WPSETT~1.DAT'), (0, 'WPSettings.dat'),
                        ],
                        'filename-combined-plus-pair-matched': [
                            (0, 'OTHER.TXT'), (0, 'WPSETT~1.DAT'), (0, 'WPSettings.dat'),
                        ],
                        'filename-alias-parent-mismatch-matched': [
                            (0, 'WPSETT~1.DAT'), (0, 'WPSettings.dat'),
                        ],
                        'filename-alias-casefold-match': [(3, 'ABCDEFGH.TXT')],
                        'filename-win32-plus-posix-matched': [
                            (0, 'WPSettings.dat'), (0, 'another-posix.dat'),
                        ],
                    }[behavior_case]
                    assert sorted(identities) == expected, (case, identities)
                    image = Image(destination)
                    for parent in (5, 36):
                        parent_names = sorted(
                            (name['namespace'], name['name']) for name in item['names']
                            if name['parent'] & 0xffffffffffff == parent
                        )
                        assert index_name_keys(image, parent, 37) == parent_names, case
                    assert all(name['resident_flags'] == 1 for name in item['names'])
                    image.file.close()
                elif behavior_case == 'filename-record-directory-flag-set':
                    assert sorted(identities) == [(1, 'WPSettings.dat'), (2, 'WPSETT~1.DAT')]
                    image = Image(destination)
                    assert u(image.get(37), 22, 2) == 1
                    image.file.close()
                elif 'resident-flags' in case or 'indexed-resident-high' in case:
                    if 'alias-repair' in case:
                        expected = [(0, 'WPSettings.dat', 3)]
                    elif 'unindexed' in case:
                        expected = [(0, 'WPSETT~1.DAT', 1)]
                    else:
                        expected = [
                            (1, 'WPSettings.dat', 255 if behavior_case.endswith('high255') else 3),
                            (2, 'WPSETT~1.DAT', 1),
                        ]
                    assert sorted(
                        (name['namespace'], name['name'], name['resident_flags'])
                        for name in item['names']
                    ) == expected, (case, item['names'])
                elif 'namespace-high' in case:
                    assert sorted(identities) == [(2, 'WPSETT~1.DAT'), (5, 'WPSettings.dat')]
                    image = Image(destination)
                    assert index_name_keys(image, 36, 37) == sorted(identities)
                    image.file.close()
                else:
                    if 'dosshape-single-indexed' in case:
                        name = 'ABCDEFGH.TXT'
                    elif behavior_case == 'filename-win32-single-indexed':
                        name = 'WPSettings.dat'
                    elif 'valid-single-indexed' in case:
                        name = 'WPSettings.dat'
                    elif (
                        case.startswith(('filename-all-', 'filename-missing'))
                        or 'single-indexed' in case
                    ):
                        name = '00000000file.chk'
                    elif case.startswith('filename-dos-'):
                        name = 'WPSettings.dat'
                    else:
                        name = 'WPSETT~1.DAT'
                    assert identities == [(0, name)], (case, identities)
            if behavior_case == 'directory-record-flag-cleared':
                image = Image(destination)
                assert u(image.get(36), 22, 2) == 3
                assert all(name['parent'] & 0xffffffffffff == 36 for name in item['names'])
                assert sorted(identities) == [(1, 'WPSettings.dat'), (2, 'WPSETT~1.DAT')]
                image.file.close()
            if case.startswith('directory-disconnected-'):
                image = Image(destination)
                recovered = family_filenames(image, 27)
                assert len(recovered) == 1
                assert (recovered[0]['namespace'], recovered[0]['name']) == (
                    0, '00000000_dir.chk',
                )
                assert recovered[0]['parent'] & 0xffffffffffff not in (27, 30, 36)
                assert [
                    (claim['parent'], claim['namespace'], claim['name'])
                    for claim in family_filenames(image, 30)
                ] == [(27 | (u(image.get(27), 16, 2) << 48), 0, '$TxfLog')]
                image.file.close()
            if case.startswith('directory-existing-parent-stale-'):
                assert identities == [(0, '00000000-WPSettings.dat')]
            if case.startswith('directory-root-'):
                image = Image(destination)
                assert [
                    (claim['parent'] & 0xffffffffffff, claim['namespace'], claim['name'])
                    for claim in family_filenames(image, 5)
                ] == [(5, 7 if 'high-namespace' in case else 3, '.')]
                if clean_control:
                    assert index_name_keys(image, 5, 5) == [
                        (7 if 'high-namespace' in case else 3, '.')
                    ]
                if 'resident' in case or behavior_case == 'directory-root-unindexed':
                    expected_flags = 3 if clean_control else 1
                    assert family_filenames(image, 5)[0]['resident_flags'] == expected_flags
                image.file.close()
            if case.startswith('directory-anchored-'):
                behavior_case = case.removesuffix('-quick')
                identities36 = sorted(
                    (claim['parent'] & 0xffffffffffff, claim['namespace'], claim['name'])
                    for claim in item['directory_names']
                )
                if behavior_case == 'directory-anchored-win32-self':
                    expected = [(5, 1, 'System Volume Information'), (5, 2, 'SYSTEM~1')]
                else:
                    expected = [(5, 0, 'System Volume Information')]
                    if behavior_case in (
                        'directory-anchored-posix-two-node',
                        'directory-anchored-posix-three-node',
                        'directory-anchored-posix-three-node-single-edge',
                    ):
                        expected.append((30, 0, 'under-txflog'))
                assert identities36 == expected
                image = Image(destination)
                expected30 = [(27, 0, '$TxfLog')]
                if behavior_case == 'directory-anchored-posix-three-node':
                    expected30.append((27, 0, 'duplicate-parent-name'))
                if behavior_case.startswith('directory-anchored-posix-three-node'):
                    assert [
                        (claim['parent'] & 0xffffffffffff, claim['namespace'], claim['name'])
                        for claim in family_filenames(image, 27)
                    ] == [(11, 0, '$RmMetadata')]
                assert sorted(
                    (claim['parent'] & 0xffffffffffff, claim['namespace'], claim['name'])
                    for claim in family_filenames(image, 30)
                ) == expected30
                image.file.close()
            if case.startswith('directory-valid-'):
                identities36 = sorted(
                    (claim['parent'] & 0xffffffffffff, claim['namespace'], claim['name'])
                    for claim in item['directory_names']
                )
                if case == 'directory-valid-root-dos':
                    expected = [(5, 0, 'SYSTEM~1'), (30, 0, 'System Volume Information')]
                elif case == 'directory-valid-nonroot-parents':
                    expected = [(30, 0, 'System Volume Information')]
                else:
                    expected = [(5, 0, 'System Volume Information')]
                assert identities36 == expected

            if case.startswith('collision-'):
                image = Image(destination)
                earlier = [
                    (claim['namespace'], claim['name'])
                    for claim in family_filenames(image, 35)
                ]
                image.file.close()
                if case == 'collision-existing-higher':
                    assert earlier == [(0, '$TXFLO~2')]
                    assert sorted(identities) == [(1, 'colliding.txt'), (2, 'WPSETT~1.DAT')]
                elif case == 'collision-posix-case':
                    assert earlier == [(0, 'COLLIDING.TXT')]
                    assert identities == [(0, 'colliding.txt')]
                else:
                    assert sorted(earlier) == [(1, 'colliding.txt'), (2, '$TXFLO~2')]
                    expected = [(0, 'WPSETT~1.DAT')]
                    if case == 'collision-extra-link':
                        expected.append((0, 'alternate.txt'))
                    assert sorted(identities) == sorted(expected)

            if case.startswith('duplicate-long-triple-mixed-flags-'):
                assert sorted(identities) == [(1, 'WPSettings.dat'), (2, 'WPSETT~1.DAT')]
                long_name = next(name for name in item['names'] if name['namespace'] == 1)
                assert long_name['resident_flags'] == (
                    1 if behavior_case.endswith('first3') else 3
                )
            elif case == 'duplicate-posix-pair':
                assert identities == [(0, '00000000file.chk')]
            elif case.startswith('duplicate-namespace-'):
                namespace = 3 if case.endswith('combined') else 0
                assert identities == [(namespace, 'WPSETT~1.DAT')]
            elif case.startswith('duplicate-exact') and not case.endswith('unindexed'):
                assert identities == [(0, 'WPSETT~1.DAT')], (case, identities)
            elif case.startswith('duplicate-'):
                assert sorted(identities) == [(1, 'WPSettings.dat'), (2, 'WPSETT~1.DAT')], (case, identities)
        if case.startswith((
            'directory-anchored-', 'directory-root-', 'directory-disconnected-',
            'directory-existing-parent-stale-',
            'filename-', 'duplicate-long-triple-mixed-flags-',
            'directory-record-flag-cleared',
            'reserved-', 'ordinary-file-slot16-',
        )):
            repeated = WORK / (case + '-repeat.img')
            repeat = subprocess.run(
                [str(CHECKER), *repair_options, '--repair-to', str(destination), str(repeated)],
                capture_output=True, text=True,
            )
            assert repeat.returncode == 0, (case, repeat.stdout, repeat.stderr)
            assert digest(repeated) == digest(destination), case
        assert digest(path) == source_hash
        results.append(item)
        print(case, 'assessment', assessment.returncode, 'repair', repair.returncode, flush=True)
    assert digest(BASE) == original
    (WORK / 'host-results.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
