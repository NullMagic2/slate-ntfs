#!/usr/bin/env python3
"""
Module: src.tests.checker.test_semantic_repair
Purpose: Independent semantic corruptions on disposable mkntfs images; never mounts.
Created: 2026-10-01
Architecture: Disposable byte fixtures exercise CLI audit and copy repair;
source hashes, recovered data and repeat repairs verify the resulting state.
"""
from pathlib import Path
import shutil
import os
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'tests/support'))
from ntfs_image import CHECKER,run,u,put,attrs,attr,first_extent,digest,restart,decode,protect
from test_broader_consistency import Image,rewrite,resident,listed

def attributes(record):
    return [bytearray(record[a:a+u(record,a+4,4)]) for a,_ in attrs(record)]

def name(a):
    return bytes(a[u(a,10,2):u(a,10,2)+a[9]*2]).decode('utf-16le') if a[9] else ''

def named(kind,label,value,ident):
    key=label.encode('utf-16le');offset=(24+len(key)+7)&~7
    a=bytearray((offset+len(value)+7)&~7);put(a,0,kind,4);put(a,4,len(a),4);a[9]=len(key)//2
    put(a,10,24,2);put(a,14,ident,2);put(a,16,len(value),4);put(a,20,offset,2)
    a[24:24+len(key)]=key;a[offset:offset+len(value)]=value;return a

def row(key,value):
    at=(16+len(key)+7)&~7;b=bytearray((at+len(value)+7)&~7)
    put(b,0,at,2);put(b,2,len(value),2);put(b,8,len(b),2);put(b,10,len(key),2)
    b[16:16+len(key)]=key;b[at:at+len(value)]=value;return b

def root(old,rows):
    end=bytearray(16);put(end,8,16,2);put(end,12,2,2)
    value=bytearray(old[:16])+bytearray(16)+b''.join(rows)+end
    put(value,16,16,4);put(value,20,len(value)-16,4);put(value,24,len(value)-16,4);return value

def rows(record,label):
    a=next(a for a in attributes(record) if u(a,0,4)==0x90 and name(a)==label)
    value=a[u(a,20,2):u(a,20,2)+u(a,16,4)];at=16+u(value,16,4);out=[]
    while not u(value,at+12,2)&2:
        size=u(value,at+8,2);out.append(value[at:at+size]);at+=size
    return value,out

def names(image):
    zero=image.get(0);count=u(zero,attr(zero,0x80)+48,8)//image.size;result={}
    for n in range(count):
        b=image.get(n)
        if not u(b,22,2)&1 or u(b,32,8):continue
        for a,k in attrs(b):
            if k==0x30:
                at=a+u(b,a+20,2);result[bytes(b[at+66:at+66+b[at+64]*2]).decode('utf-16le')]=n
    return result

def redirect(image,number,lcn):
    b=image.get(number);values=attributes(b);a=next(a for a in values if u(a,0,4)==0x80 and not a[9])
    at=u(a,32,2);length=a[at]&15;width=(lcn.bit_length()+8)//8
    pairs=bytes([(width<<4)|length])+a[at+1:at+1+length]+lcn.to_bytes(width,'little',signed=True)+b'\0'
    replacement=a[:at]+pairs;replacement.extend(bytes((-len(replacement))%8));put(replacement,4,len(replacement),4)
    values[values.index(a)]=replacement;image.save(number,rewrite(b,values))

def mapped(a,runs):
    pairs=bytearray();previous=0;clusters=0
    for lcn,length in runs:
        n=max(1,(length.bit_length()+7)//8);clusters+=length
        if lcn is None:offset=b''
        else:
            delta=lcn-previous;previous=lcn
            width=next(w for w in range(1,9) if -(1<<(w*8-1))<=delta<(1<<(w*8-1)))
            offset=delta.to_bytes(width,'little',signed=True)
        pairs+=bytes([(len(offset)<<4)|n])+length.to_bytes(n,'little')+offset
    pairs+=b'\0';out=a[:u(a,32,2)]+pairs;out.extend(bytes((-len(out))%8))
    put(out,4,len(out),4);put(out,24,clusters-1,8);return out

def create_directory(image, security_id, claims):
    zero = image.get(0)
    slots = u(zero, attr(zero, 0x80) + 56, 8) // image.size
    directory = next(n for n in range(24, slots) if not u(image.get(n), 22, 2) & 1)
    b = image.get(directory)
    put(b, 16, 1, 2)
    put(b, 22, 3, 2)
    put(b, 32, 0, 8)
    put(b, 18, len(claims), 2)
    put(b, 40, len(claims) + 2, 2)
    si = next(a for a in attributes(image.get(5)) if u(a, 0, 4) == 0x10)
    at = u(si, 20, 2)
    value = bytearray(si[at:at + u(si, 16, 4)])
    value.extend(bytes(72 - len(value)))
    put(value, 52, security_id, 4)
    put(value, 32, 0x10000000, 4)
    values = [resident(0x10, value, 0)]
    for ident, (label, parent, namespace) in enumerate(claims, 1):
        parent = directory if parent is None else parent
        sequence = 1 if parent == directory else u(image.get(parent), 16, 2)
        value = bytearray(66) + label.encode('utf-16le')
        value[64] = len(label)
        value[65] = namespace
        put(value, 0, parent | (sequence << 48), 8)
        put(value, 56, 0x10000000, 4)
        filename = resident(0x30, value, ident)
        filename[22] = 1
        values.append(filename)
    template, _ = rows(image.get(5), '$I30')
    values.append(named(0x90, '$I30', root(template, []), len(claims) + 1))
    image.save(directory, rewrite(b, values))
    image.bitmap(directory)
    return directory


def fragment_mft_family(
    image, extension, initialized_slots, missing_base_data, unaligned_bitmap,
):
    # Keep every initialized slot, while forcing the complete DATA descriptor
    # to exceed the base record's space alongside its other attributes.

    records = [image.get(number) for number in range(initialized_slots)]
    zero = records[0]
    values = attributes(zero)
    data = next(a for a in values if u(a, 0, 4) == 0x80)
    previous_clusters = u(data, 40, 8) // image.cluster
    bitmap_record = records[6]
    volume_bitmap_lcn, _ = first_extent(bitmap_record, attr(bitmap_record, 0x80))
    total_clusters = u(image.boot, 40, 8) // image.boot[13]
    image.f.seek(volume_bitmap_lcn * image.cluster)
    bits = bytearray(image.f.read((total_clusters + 7) // 8))
    free = [
        n for n in range(256, total_clusters)
        if not bits[n // 8] & (1 << (n % 8))
    ]
    extents = [(u(image.boot, 48, 8), 1)]
    extents.extend(
        (free[index * 2] if index % 2 == 0 else free[-1 - index * 2], 1)
        for index in range(199)
    )
    assert len({lcn for lcn, _ in extents}) == len(extents)
    stream_bytes = len(extents) * image.cluster
    for offset in (40, 48, 56):
        put(data, offset, stream_bytes, 8)
    prefix = mapped(data, extents[:8])
    values[values.index(data)] = prefix
    if missing_base_data:
        values.remove(prefix)
    member_values = attributes(records[extension])
    old_tail = next(a for a in member_values if u(a, 0, 4) == 0x80)
    tail = mapped(old_tail, extents[8:])
    put(tail, 16, 8, 8)
    put(tail, 24, len(extents) - 1, 8)
    for offset in (40, 48, 56):
        put(tail, offset, 0, 8)
    member_values[member_values.index(old_tail)] = tail
    mft_bitmap = next(
        a for a in values + member_values if u(a, 0, 4) == 0xb0
    )
    slots = stream_bytes // image.size
    bitmap_size = (slots + 7) // 8 if unaligned_bitmap else ((slots + 63) // 64) * 8
    put(mft_bitmap, 48, bitmap_size, 8)
    put(mft_bitmap, 56, bitmap_size, 8)
    records[0] = rewrite(zero, values)
    records[extension] = rewrite(records[extension], member_values)
    template = records[23]
    for number in range(stream_bytes // image.size):
        record = records[number] if number < len(records) else bytearray(template)
        if number >= len(records):
            put(record, 16, 1, 2)
        put(record, 44, number, 4)
        lcn = extents[(number * image.size) // image.cluster][0]
        image.f.seek(lcn * image.cluster + (number * image.size) % image.cluster)
        image.f.write(protect(record))
        if number < 4:
            image.f.seek(u(image.boot, 56, 8) * image.cluster + number * image.size)
            image.f.write(protect(record))
    # Remove stale FILE copies from the abandoned contiguous allocation.

    for lcn in range(u(image.boot, 48, 8) + 1, u(image.boot, 48, 8) + previous_clusters):
        image.f.seek(lcn * image.cluster)
        image.f.write(bytes(image.cluster))
        bits[lcn // 8] &= ~(1 << (lcn % 8))
    for lcn, _ in extents:
        bits[lcn // 8] |= 1 << (lcn % 8)
    image.f.seek(volume_bitmap_lcn * image.cluster)
    image.f.write(bits)
    return stream_bytes, extents


def large_cluster_mirror_cases(selected):
    cases = ('mirror-large-cluster-clean', 'mirror-large-cluster-torn-zero')
    if selected[0] and not any(case in selected for case in cases):
        return
    with tempfile.TemporaryDirectory(prefix='slate-mirror-cluster-') as tmp:
        directory = Path(tmp)
        base = directory / 'base.img'
        with base.open('xb') as image_file:
            image_file.truncate(64 << 20)
        run('mkfs.ntfs', '-F', '-Q', '-c', '65536', base)
        payload = directory / 'payload'
        payload.write_bytes(b'large cluster payload' * 4096)
        for filename in ('payload.bin', 'other.bin'):
            run('ntfscp', '-f', base, payload, '/' + filename)
        image = Image(base)
        _, security = rows(image.get(9), '$SII')
        security_id = u(security[0], 16, 4)
        for number in range(16):
            record = image.get(number)
            if not u(record, 22, 2) & 1:
                continue
            si = next((at for at, kind in attrs(record) if kind == 0x10), None)
            if si is None or u(record, si + 16, 4) != 72:
                continue
            value = si + u(record, si + 20, 2)
            if u(record, value + 52, 4) == 0 and not any(kind == 0x50 for _, kind in attrs(record)):
                put(record, value + 52, security_id, 4)
                image.save(number, record)
        image.close()
        run(CHECKER, '--audit', base)
        for case in cases:
            if selected[0] and case not in selected:
                continue
            source = directory / (case + '.img')
            target = directory / (case + '-fixed.img')
            again = directory / (case + '-again.img')
            shutil.copyfile(base, source)
            image = Image(source)
            mirror_at = u(image.boot, 56, 8) * image.cluster
            image.f.seek(mirror_at + 16 * image.size)
            spare_before = image.f.read(image.cluster - 16 * image.size)
            assert not u(image.get(16), 22, 2) & 1
            mirror_record = image.get(1)
            mirror_data = attr(mirror_record, 0x80)
            mirror_mapping = first_extent(mirror_record, mirror_data)
            mirror_sizes = tuple(u(mirror_record, mirror_data + at, 8) for at in (40, 48, 56))
            assert mirror_sizes == (65536, 65536, 65536)
            if case.endswith('torn-zero'):
                image.f.seek(image.mft + 510)
                image.f.write(b'\0\0')
            image.close()
            before = digest(source)
            run(CHECKER, '--repair-to', source, target)
            run(CHECKER, '--audit', target)
            assert digest(source) == before
            for filename in ('payload.bin', 'other.bin'):
                assert run('ntfscat', '-f', target, '/' + filename).stdout == payload.read_bytes()
            image = Image(target)
            image.f.seek(mirror_at + 16 * image.size)
            assert image.f.read(len(spare_before)) == spare_before
            mirror_record = image.get(1)
            mirror_data = attr(mirror_record, 0x80)
            assert first_extent(mirror_record, mirror_data) == mirror_mapping
            assert tuple(u(mirror_record, mirror_data + at, 8) for at in (40, 48, 56)) == mirror_sizes
            image.close()
            run(CHECKER, '--repair-to', target, again)
            assert digest(target) == digest(again)
            print('PASS', case, 'spare mirror slots preserved, readable data, idempotence', flush=True)


def main():
    selected = os.environ.get('SLATE_REPAIR_CASES', '').split(',')
    large_cluster_mirror_cases(selected)
    if selected[0] and all(case.startswith('mirror-large-cluster-') for case in selected):
        return
    with tempfile.TemporaryDirectory(prefix='slate-semantic-cli-') as tmp:
        d=Path(tmp);base=d/'base.img'
        with base.open('xb') as f:f.truncate(64<<20)
        run('mkfs.ntfs','-F','-Q',base);content=d/'payload';content.write_bytes(b'preserved user content'*4096)
        run('ntfscp','-f',base,content,'/payload.bin')
        run('ntfscp','-f',base,content,'/other.bin')
        image=Image(base);files=names(image)
        # Give formatter placeholder system records an explicit fixture ACL.
        # The descriptor already exists in $SII; this is fixture construction.
        _,security=rows(image.get(9),'$SII');security_id=u(security[0],16,4)
        for number in sorted(set(range(16))|set(files.values())):
            b=image.get(number)
            if not u(b,22,2)&1 or u(b,32,8):continue
            si=next((a for a,k in attrs(b) if k==0x10),None)
            if si is None or u(b,si+16,4)!=72:continue
            at=si+u(b,si+20,2)
            if u(b,at+52,4)==0 and not any(k==0x50 for _,k in attrs(b)):
                put(b,at+52,security_id,4);image.save(number,b)
        image.close();run(CHECKER,'--audit',base)
        log_content=run('ntfscat','-f',base,'/$LogFile').stdout
        security_content=run('ntfscat','-f','-n','$SDS',base,'/$Secure').stdout
        for case in (
            'quota-missing-lookup',
            'object-missing-lookup',
            'object-damaged-root',
            'duplicate-file-names',
            'duplicate-crowded-file-names',
            'collision-single',
            'collision-alias',
            'collision-higher-earlier-sequence',
            'collision-single-quick',
            'collision-alias-quick',
            'directory-parent-conflict',
            'directory-cycle-aliases',
            'directory-multiple-cycles',
            'directory-orphan-subtree',
            'orphan-invalid-parent',
            'orphan-valid-hardlink',
            'orphan-long-name',
            'orphan-multiple-files',
            'orphan-multiple-files-quick',
            'orphan-distinct-parents',
            'orphan-out-of-range-parents',
            'orphan-occupied-file',
            'orphan-occupied-directory',
            'fragmented-crosslink',
            'bitmap-reserved-crosslink',
            'mirror-reserved-crosslink',
            'boot-reserved-crosslink',
            'bitmap-missing-data',
            'bitmap-short-data',
            'mirror-missing-data',
            'badclus-sizes',
            'badclus-wrong-reservation',
            'boot-missing-data',
            'boot-short-data',
            'boot-short-mapping',
            'boot-resident-data',
            'mft-resident-bitmap-known-free',
            'mft-resident-bitmap-known-free-retired',
            'mft-resident-bitmap-known-free-foreign',
            'mft-resident-bitmap-known-free-unknown',
            'mft-resident-bitmap-known-free-owned',
            'mft-split-bitmap-known-free',
            'mft-split-bitmap-known-free-nonempty',
            'mft-split-bitmap-known-free-malformed',
            'mft-resident-bitmap-padding',
            'mft-resident-bitmap-unaligned',
            'mft-resident-bitmap-missing-data',
            'mft-resident-bitmap-invalid-runlist',
            'mft-resident-bitmap-missing-bits',
            'mft-resident-bitmap-missing-bits-missing-data',
            'mft-missing-data',
            'mft-missing-data-high-identity',
            'mft-missing-data-sequence-zero',
            'mft-invalid-runlist',
            'mft-short-data',
            'mft-anchor-shift-short-size',
            'mft-anchor-shift-size-mismatch',
            'mft-short-mapping',
            'mft-duplicate-equal',
            'mft-duplicate-stronger',
            'mft-duplicate-adjacent',
            'mft-duplicate-contiguous',
            'mft-split-resident-bitmap-valid',
            'mft-split-resident-bitmap-missing-data',
            'mft-split-resident-bitmap-invalid-runlist',
            'mft-split-large-resident-bitmap-missing-data',
            'mft-split-large-resident-bitmap-invalid-runlist',
            'mft-split-large-resident-bitmap-new-extension',
            'mft-split-large-resident-bitmap-empty-bits',
            'mft-split-large-resident-bitmap-empty-bits-missing-data',
            'mft-split-large-resident-bitmap-missing-bits',
            'mft-split-large-resident-bitmap-missing-bits-live',
            'mft-split-large-resident-bitmap-missing-bits-cleared-live',
            'mft-split-large-resident-bitmap-missing-bits-malformed',
            'mft-split-large-resident-bitmap-missing-bits-competing',
            'mft-split-large-resident-bitmap-missing-bits-ready',
            'mft-partial-initialized',
            'mft-split-bitmap-absent-malformed',
            'mft-split-bitmap-extension-invalid-runlist',
            'mft-split-bitmap-known-free-nonempty-missing-tail',
            'mft-split-bitmap-absent',
            'mft-split-bitmap-invalid-runlist',
            'mft-split-bitmap-known-free-missing-tail',
            'mft-split-partial-initialized',
            'mft-split-partial-initialized-missing-tail',
            'mft-split-valid',
            'mft-split-missing-data',
            'mft-split-missing-data-high-identity',
            'mft-split-missing-data-sequence-zero',
            'mft-split-invalid-runlist',
            'mft-split-short-data',
            'mft-split-lost-list-prefix',
            'mft-split-malformed-list',
            'mft-split-list-ready-malformed',
            'mft-split-lost-list-bitmap-extension',
            'mft-split-lost-list-zero-sequence',
            'mft-split-lost-list-foreign-owner',
            'mft-split-lost-list-foreign-huge-run',
            'mft-split-lost-list-foreign-outside-volume',
            'mft-split-tail-missing-data',
            'mft-split-tail-invalid-runlist',
            'mft-split-tail-wrong-vcn',
            'mft-split-tail-stale-attribute-id',
            'mft-split-tail-missing-data-bitmap-extension',
            'mft-split-tail-zero-sequence',
            'mft-split-tail-zero-sequence-bitmap-extension',
            'mft-split-tail-zero-sequence-unlisted-bitmap-extension',
            'mft-split-tail-zero-sequence-duplicate',
            'mft-split-tail-nonzero-sequence',
            'mft-split-tail-stale-owner',
            'mft-split-tail-foreign-owner',
            'mft-split-bitmap-extension',
            'mft-split-external-list',
            'mft-split-missing-data-external-list',
            'mft-split-malformed-external-list',
            'mft-split-missing-data-malformed-external-list',
            'mft-split-missing-data-bitmap-invalid-malformed-external-list',
            'mft-split-bitmap-extension-malformed-external-list',
            'mft-split-empty-external-list',
            'mft-split-omitted-base-data-external-list',
            'mft-split-invalid-runlist-external-list',
            'mft-split-omitted-base-data-foreign-external-list',
            'mft-split-omitted-base-data-wrong-id-external-list',
            'mft-split-large-valid',
            'mft-split-large-missing-data',
            'mft-split-large-bitmap-extension',
            'mft-split-large-ready-high-identity',
            'mft-split-large-ready-sequence-zero',
            'mft-split-large-ready-lost-list',
            'mft-split-large-unaligned-bitmap',
            'mft-split-large-unaligned-bitmap-extension',
            'mft-split-large-ready-unaligned-bitmap',
            'mft-split-large-ready-bitmap-short-init',
            'mft-split-large-ready-bitmap-missing-bits',
            'mft-split-large-ready-bitmap-missing-bits-live',
            'mft-split-large-ready-bitmap-missing-bits-cleared-live',
            'mft-split-large-ready-bitmap-extra-init',
            'mft-split-large-ready-bitmap-data108-init104',
            'mft-split-large-ready-bitmap-data108-init108',
            'mft-split-large-ready-bitmap-padding',
            'legacy-mft-zero',
            'legacy-mft-zero-torn',
            'legacy-payload',
            'legacy-payload-bitmap-absent',
            'legacy-payload-bitmap-absent-list',
            'legacy-payload-bitmap-absent-owner',
            'secure-family-index',
            'secure-family-torn-copy',
            'log-badclus-crosslink',
            'log-fragmented-crosslink',
            'log-torn-restart',
            'log-torn-primary',
            'log-ambiguous-restart',
            'log-conflicting-clients',
        ):
            selected = os.environ.get('SLATE_REPAIR_CASES', '').split(',')
            if selected[0] and case not in selected:
                continue
            source = d / (case + '.img')
            target = d / (case + '-fixed.img')
            shutil.copyfile(base, source)
            image = Image(source)
            if case=='quota-missing-lookup':
                number=files['$Quota'];b=image.get(number);values=attributes(b);old,qrows=rows(b,'$Q')
                control=bytearray(64);put(control,0,2,4);put(control,8,9999,8);put(control,32,123456,8)
                control[48:60]=bytes([1,1,0,0,0,0,0,5,21,0,0,0]);qrows=[r for r in qrows if u(r,16,4)!=256];qrows.append(row((256).to_bytes(4,'little'),control))
                q=next(a for a in values if u(a,0,4)==0x90 and name(a)=='$Q')
                values=[a for a in values if not (u(a,0,4)==0x90 and name(a) in ('$O','$Q'))]
                values.append(named(0x90,'$Q',root(old,qrows),u(q,14,2)));image.save(number,rewrite(b,values))
                b=image.get(files['payload.bin']);values=attributes(b);si=next(a for a in values if u(a,0,4)==0x10)
                value=bytearray(si[u(si,20,2):u(si,20,2)+u(si,16,4)]);value.extend(bytes(72-len(value)))
                put(value,48,256,4);put(value,56,321,8);values.remove(si);values.append(resident(0x10,value,u(si,14,2)))
                image.save(files['payload.bin'],rewrite(b,values))
            elif case.startswith('object-'):
                b=image.get(files['payload.bin']);values=attributes(b);ident=bytes(range(1,65))
                values.append(resident(0x40,ident,u(b,40,2)));put(b,40,u(b,40,2)+1,2)
                image.save(files['payload.bin'],rewrite(b,values))
                if case=='object-damaged-root':
                    b=image.get(files['$ObjId']);values=attributes(b)
                    a=next(a for a in values if u(a,0,4)==0x90 and name(a)=='$O')
                    at=u(a,20,2);put(a,at+16,0xfffffff0,4)
                    image.save(files['$ObjId'],rewrite(b,values))
            elif case.startswith('duplicate-'):
                b = image.get(files['payload.bin'])
                values = attributes(b)
                duplicate = bytearray(next(a for a in values if u(a, 0, 4) == 0x30))
                put(duplicate, 14, u(b, 40, 2), 2)
                put(b, 40, u(b, 40, 2) + 1, 2)
                values.append(duplicate)
                b = rewrite(b, values)
                if case == 'duplicate-crowded-file-names':
                    free = len(b) - u(b, 24, 4)
                    assert free >= 40
                    values.append(named(0x80, 'padding', bytes(free - 40), u(b, 40, 2)))
                    put(b, 40, u(b, 40, 2) + 1, 2)
                image.save(files['payload.bin'], rewrite(b, values))
            elif case.startswith('collision-'):
                collision_labels = sorted(
                    ('payload.bin', 'other.bin'), key=lambda label: files[label],
                )
                collision_standard = {}
                for ordinal, label in enumerate(collision_labels):
                    b = image.get(files[label])
                    values = attributes(b)
                    si = next(a for a in values if u(a, 0, 4) == 0x10)
                    si_at = u(si, 20, 2)
                    collision_standard[label] = bytes(si[si_at:si_at + 32])
                    filename = next(a for a in values if u(a, 0, 4) == 0x30)
                    at = u(filename, 20, 2)
                    value = bytearray(filename[at:at + 66]) + 'colliding.txt'.encode('utf-16le')
                    value[64] = len('colliding.txt')
                    aliases = 'single' not in case or ordinal == 0
                    value[65] = 1 if aliases else 0
                    replacement = resident(0x30, value, u(filename, 14, 2))
                    replacement[22] = 1
                    values[values.index(filename)] = replacement
                    if aliases:
                        alias = value[:66] + f'FILE{ordinal}~1'.encode('utf-16le')
                        alias[64] = len(f'FILE{ordinal}~1')
                        alias[65] = 2
                        short = resident(0x30, alias, u(b, 40, 2))
                        short[22] = 1
                        values.append(short)
                        put(b, 40, u(b, 40, 2) + 1, 2)
                        put(b, 18, 2, 2)
                    if case == 'collision-higher-earlier-sequence' and ordinal == 0:
                        put(b, 16, 2, 2)
                    image.save(files[label], rewrite(b, values))
                if case.endswith('-quick'):
                    # An unrelated stale cache remains outside the repaired parents.

                    quota = image.get(files['$Quota'])
                    si = next(a for a, kind in attrs(quota) if kind == 0x10)
                    at = si + u(quota, si + 20, 2)
                    put(quota, at + 8, u(quota, at + 8, 8) + 1, 8)
                    image.save(files['$Quota'], quota)
                    unrelated_index = [a for a in attributes(image.get(11))
                                       if u(a, 0, 4) in (0x90, 0xa0, 0xb0) and name(a) == '$I30']
            elif case.startswith('orphan-'):
                orphan_labels = ['payload.bin']
                if case in ('orphan-multiple-files', 'orphan-multiple-files-quick', 'orphan-distinct-parents', 'orphan-out-of-range-parents'):
                    orphan_labels.append('other.bin')
                for original_label in orphan_labels:
                    b = image.get(files[original_label])
                    values = attributes(b)
                    filename = next(a for a in values if u(a, 0, 4) == 0x30)
                    at = u(filename, 20, 2)
                    value = bytearray(filename[at:at + u(filename, 16, 4)])
                    parent = 62 if case == 'orphan-distinct-parents' and original_label == 'other.bin' else 63
                    if case == 'orphan-out-of-range-parents':
                        zero = image.get(0)
                        parent = u(zero, attr(zero, 0x80) + 56, 8) // image.size
                    put(value, 0, parent | (1 << 48), 8)
                    if case == 'orphan-valid-hardlink':
                        label = 'bad-link'
                        identifier = u(b, 40, 2)
                        put(b, 40, identifier + 1, 2)
                        put(b, 18, 2, 2)
                    else:
                        values.remove(filename)
                        identifier = u(filename, 14, 2)
                        label = 'a' * 246 + '.txt' if case == 'orphan-long-name' else original_label
                    value = value[:66] + label.encode('utf-16le')
                    value[64] = len(label)
                    value[65] = 0
                    replacement = resident(0x30, value, identifier)
                    replacement[22] = 1
                    values.append(replacement)
                    image.save(files[original_label], rewrite(b, values))
                if case == 'orphan-multiple-files-quick':
                    # An unrelated balanced directory keeps its stale cached
                    # information while changed parents and destinations rebuild.

                    quota = image.get(files['$Quota'])
                    standard = attr(quota, 0x10)
                    quota[standard + u(quota, standard + 20, 2) + 8] ^= 1
                    image.save(files['$Quota'], quota)
                    unrelated_index = [a for a in attributes(image.get(11))
                                       if u(a, 0, 4) in (0x90, 0xa0, 0xb0) and name(a) == '$I30']
                    assert unrelated_index and all(u(a, 0, 4) == 0x90 for a in unrelated_index)
                if case == 'orphan-occupied-file':
                    b = image.get(files['other.bin'])
                    values = attributes(b)
                    filename = next(a for a in values if u(a, 0, 4) == 0x30)
                    at = u(filename, 20, 2)
                    value = filename[at:at + 66] + 'FoUnD.000'.encode('utf-16le')
                    value[64] = 9
                    replacement = resident(0x30, value, u(filename, 14, 2))
                    replacement[22] = 1
                    values[values.index(filename)] = replacement
                    image.save(files['other.bin'], rewrite(b, values))
                elif case == 'orphan-occupied-directory':
                    directory = create_directory(image, security_id, [('FoUnD.000', 5, 3)])
            elif case.startswith('directory-'):
                claims = [('recover-a', 5, 1), ('recover-b', 11, 1)]
                if case in ('directory-cycle-aliases', 'directory-multiple-cycles'):
                    # None denotes this new directory's own record reference.

                    claims = [(label, None, namespace) for label, _, namespace in claims]
                elif case == 'directory-orphan-subtree':
                    claims = [('recover-a', 63, 1)]
                directory = create_directory(image, security_id, claims)
                cycle_directories = [directory]
                if case == 'directory-multiple-cycles':
                    cycle_directories.append(create_directory(image, security_id, claims))
                elif case == 'directory-orphan-subtree':
                    b = image.get(files['payload.bin'])
                    filename = attr(b, 0x30)
                    put(b, filename + u(b, filename + 20, 2), directory | (1 << 48), 8)
                    image.save(files['payload.bin'], b)
            elif case in ('bitmap-missing-data','bitmap-short-data','mirror-missing-data'):
                number=1 if case=='mirror-missing-data' else 6
                b=image.get(number);values=attributes(b)
                a=next(a for a in values if u(a,0,4)==0x80 and not a[9])
                if case=='bitmap-short-data':put(a,48,32,8);put(a,56,32,8)
                else:values.remove(a)
                image.save(number,rewrite(b,values))
            elif case.startswith('legacy-'):
                number = files['payload.bin'] if case.startswith('legacy-payload') else 0
                b = image.get(number)
                usa = u(b, 4, 2)
                count = u(b, 6, 2)
                replacements = bytes(b[usa:usa + count * 2])
                b[42:42 + count * 2] = replacements
                put(b, 4, 42, 2)
                if case == 'legacy-payload-bitmap-absent-list':
                    reference = number | (u(b, 16, 2) << 48)
                    values = attributes(b)
                    entries = b''.join(listed(a, reference) for a in values)
                    values.append(resident(0x20, entries, u(b, 40, 2)))
                    b = rewrite(b, values)
                elif case == 'legacy-payload-bitmap-absent-owner':
                    put(b, 32, files['other.bin'] | (1 << 48), 8)
                legacy_before = bytes(b)
                image.save(number, b)
                if case.startswith('legacy-payload-bitmap-absent'):
                    zero = image.get(0)
                    slots = u(zero, attr(zero, 0x80) + 56, 8) // image.size
                    for slot_number in range(16, slots):
                        if slot_number == number:
                            continue
                        slot = image.get(slot_number)
                        put(slot, 44, slot_number, 4)
                        image.save(slot_number, slot)
                    values = [a for a in attributes(zero) if u(a, 0, 4) != 0xb0]
                    image.save(0, rewrite(zero, values))
                if case == 'legacy-mft-zero-torn':
                    image.f.seek(image.mft + 510)
                    image.f.write(b'\0\0')
            elif case.startswith('mft-'):
                # Formatter placeholders lack physical record identities.
                # Give this reconstruction fixture a complete identity range.

                for number in range(16, 24):
                    slot = image.get(number)
                    assert not u(slot, 22, 2) & 1
                    put(slot, 44, number, 4)
                    image.save(number, slot)
                b = image.get(0)
                values = attributes(b)
                data = next(a for a in values if u(a, 0, 4) == 0x80 and not a[9])
                if case.startswith('mft-split-'):
                    # Initialize the reserved tail slots so reconstruction has
                    # a complete physical identity range for this allocation.

                    allocation = u(data, 40, 8)
                    initialized_slots = u(data, 56, 8) // image.size
                    allocated_slots = allocation // image.size
                    template = image.get(27)
                    assert not u(template, 22, 2) & 1
                    for number in range(initialized_slots, allocated_slots):
                        slot = bytearray(template)
                        put(slot, 44, number, 4)
                        image.save(number, slot)
                    put(data, 48, allocation, 8)
                    put(data, 56, allocation, 8)
                    prefix_clusters = 8
                    clusters = allocation // image.cluster
                    prefix = mapped(data, [(u(image.boot, 48, 8), prefix_clusters)])
                    tail = mapped(data, [(
                        u(image.boot, 48, 8) + prefix_clusters,
                        clusters - prefix_clusters,
                    )])
                    put(tail, 16, prefix_clusters, 8)
                    put(tail, 24, clusters - 1, 8)
                    extension = 27
                    member = image.get(extension)
                    sequence = u(member, 16, 2)
                    base_reference = u(b, 16, 2) << 48
                    member_reference = extension | (sequence << 48)
                    put(member, 22, 1, 2)
                    put(member, 32, base_reference, 8)
                    member_values = [tail]
                    values[values.index(data)] = prefix
                    if 'bitmap-extension' in case:
                        bitmap = next(a for a in values if u(a, 0, 4) == 0xb0)
                        values.remove(bitmap)
                        member_values.append(bitmap)
                    put(member, 40, max(u(a, 14, 2) for a in member_values) + 1, 2)
                    image.save(extension, rewrite(member, member_values))
                    image.bitmap(extension)
                    entries = [listed(a, base_reference) for a in values]
                    entries.extend(listed(a, member_reference) for a in member_values)
                    entries.sort(key=lambda e: (u(e, 0, 4), u(e, 8, 8)))
                    list_id = u(b, 40, 2)
                    if 'omitted-base-data' in case:
                        entries = [e for e in entries if not (
                            u(e, 0, 4) == 0x80 and u(e, 8, 8) == 0
                            and u(e, 16, 8) == base_reference
                        )]
                        if 'foreign-external-list' in case:
                            claim = next(e for e in entries if u(e, 0, 4) == 0x80)
                            foreign = files['other.bin']
                            put(claim, 16, foreign | (u(image.get(foreign), 16, 2) << 48), 8)
                        elif 'wrong-id-external-list' in case:
                            claim = next(e for e in entries if u(e, 0, 4) == 0x80)
                            put(claim, 24, 99, 2)
                    list_value = b''.join(entries)
                    if case == 'mft-split-empty-external-list':
                        list_value = b''
                    list_attribute = resident(0x20, list_value, list_id)
                    if case.endswith('external-list'):
                        bitmap = image.get(6)
                        bitmap_lcn, _ = first_extent(bitmap, attr(bitmap, 0x80))
                        total_clusters = u(image.boot, 40, 8) // image.boot[13]
                        image.f.seek(bitmap_lcn * image.cluster)
                        bits = image.f.read((total_clusters + 7) // 8)
                        list_lcn = next(
                            n for n in range(256, total_clusters)
                            if not bits[n // 8] & (1 << (n % 8))
                        )
                        if 'malformed-external-list' in case:
                            list_value = bytearray(list_value)
                            put(list_value, 4, 31, 2)
                        image.f.seek(list_lcn * image.cluster)
                        image.f.write(list_value + bytes(image.cluster - len(list_value)))
                        image.f.seek(bitmap_lcn * image.cluster + list_lcn // 8)
                        image.f.write(bytes([bits[list_lcn // 8] | (1 << (list_lcn % 8))]))
                        list_attribute = mapped(data, [(list_lcn, 1)])
                        put(list_attribute, 0, 0x20, 4)
                        put(list_attribute, 14, list_id, 2)
                        put(list_attribute, 40, image.cluster, 8)
                        put(list_attribute, 48, len(list_value), 8)
                        put(list_attribute, 56, len(list_value), 8)
                        if case == 'mft-split-invalid-runlist-external-list':
                            list_attribute[u(list_attribute, 32, 2)] = 0
                    values.append(list_attribute)
                    put(b, 40, list_id + 1, 2)
                    if case.startswith('mft-split-lost-list-'):
                        values.remove(list_attribute)
                        if case.endswith('zero-sequence'):
                            put(member, 16, 0, 2)
                        elif 'lost-list-foreign-' in case:
                            other = files['other.bin']
                            put(member, 32, other | (u(image.get(other), 16, 2) << 48), 8)
                            if case.endswith('huge-run'):
                                replacement = mapped(tail, [(1, (1 << 64) - 1)])
                                put(replacement, 16, 0, 8)
                                member_values[member_values.index(tail)] = replacement
                            elif case.endswith('outside-volume'):
                                clusters = u(image.boot, 40, 8) // image.boot[13]
                                replacement = mapped(tail, [(clusters + 1, 1)])
                                member_values[member_values.index(tail)] = replacement
                        image.save(extension, rewrite(member, member_values))
                    elif case == 'mft-split-malformed-list':
                        put(list_attribute, u(list_attribute, 20, 2) + 4, 31, 2)
                    if case.startswith('mft-split-tail-'):
                        if 'missing-data' in case:
                            member_values.remove(tail)
                        elif case.endswith('invalid-runlist'):
                            tail[u(tail, 32, 2)] = 0
                        elif case.endswith('wrong-vcn'):
                            put(tail, 16, prefix_clusters - 1, 8)
                        elif case.endswith('stale-attribute-id'):
                            at = u(list_attribute, 20, 2)
                            end = at + u(list_attribute, 16, 4)
                            while at < end:
                                if u(list_attribute, at, 4) == 0x80 and u(list_attribute, at + 8, 8):
                                    put(list_attribute, at + 24, 99, 2)
                                    break
                                at += u(list_attribute, at + 4, 2)
                        elif 'tail-zero-sequence' in case:
                            put(member, 16, 0, 2)
                            if 'unlisted-bitmap' in case:
                                entries = [entry for entry in entries if not (
                                    u(entry, 0, 4) == 0xb0 and u(entry, 16, 8) == member_reference
                                )]
                                list_attribute = resident(0x20, b''.join(entries), list_id)
                                values[-1] = list_attribute
                        elif case.endswith('nonzero-sequence'):
                            put(member, 16, sequence + 1, 2)
                        elif case.endswith('stale-owner'):
                            put(member, 32, 2 << 48, 8)
                        elif case.endswith('foreign-owner'):
                            other = files['other.bin']
                            put(member, 32, other | (u(image.get(other), 16, 2) << 48), 8)
                        image.save(extension, rewrite(member, member_values))
                        if case.endswith('zero-sequence-duplicate'):
                            bitmap_record = image.get(6)
                            bitmap_lcn, _ = first_extent(bitmap_record, attr(bitmap_record, 0x80))
                            total_clusters = u(image.boot, 40, 8) // image.boot[13]
                            image.f.seek(bitmap_lcn * image.cluster)
                            bits = image.f.read((total_clusters + 7) // 8)
                            destination = next(
                                number for number in range(256, total_clusters)
                                if not bits[number // 8] & (1 << (number % 8))
                            )
                            image.f.seek(image.mft + image.cluster)
                            duplicate = image.f.read(image.cluster)
                            image.f.seek(destination * image.cluster)
                            image.f.write(duplicate)
                    if case in (
                        'mft-split-missing-data', 'mft-split-missing-data-external-list',
                        'mft-split-missing-data-malformed-external-list',
                        'mft-split-missing-data-bitmap-invalid-malformed-external-list',
                        'mft-split-missing-data-high-identity',
                        'mft-split-missing-data-sequence-zero',
                    ):
                        values.remove(prefix)
                    elif case == 'mft-split-invalid-runlist':
                        prefix[u(prefix, 32, 2)] = 0
                    elif case == 'mft-split-short-data':
                        put(prefix, 48, 4 * image.size, 8)
                        put(prefix, 56, 4 * image.size, 8)
                elif case.startswith('mft-duplicate-'):
                    bitmap = image.get(6)
                    bitmap_lcn, _ = first_extent(bitmap, attr(bitmap, 0x80))
                    clusters = u(image.boot, 40, 8) // image.boot[13]
                    image.f.seek(bitmap_lcn * image.cluster)
                    bits = image.f.read((clusters + 7) // 8)
                    free = [
                        n for n in range(256, clusters - 2)
                        if not bits[n // 8] & (1 << (n % 8))
                    ]
                    destinations = [free[0]]
                    if case.endswith('adjacent'):
                        destinations.append(free[-1])
                    elif case.endswith('contiguous'):
                        destinations.append(free[0] + 1)
                        assert destinations[-1] in free
                    for vcn, lcn in enumerate(destinations, 1):
                        image.f.seek(image.mft + vcn * image.cluster)
                        contents = image.f.read(image.cluster)
                        image.f.seek(lcn * image.cluster)
                        image.f.write(contents)
                    if case.endswith('stronger'):
                        image.f.seek(image.mft + image.cluster)
                        image.f.write(b'BAAD')
                    values.remove(data)
                elif case.startswith('mft-resident-bitmap-'):
                    old_bitmap = next(a for a in values if u(a, 0, 4) == 0xb0)
                    if old_bitmap[8]:
                        lcn, _ = first_extent(old_bitmap, 0)
                        image.f.seek(lcn * image.cluster)
                        bitmap_before = image.f.read(u(old_bitmap, 56, 8))
                    else:
                        at = u(old_bitmap, 20, 2)
                        bitmap_before = bytes(old_bitmap[at:at + u(old_bitmap, 16, 4)])
                    capacity_slots = (u(data, 24, 8) + 1) * image.cluster // image.size
                    actual_bytes = (u(data, 56, 8) // image.size + 7) // 8
                    if 'missing-bits' in case:
                        assert actual_bytes > 0
                        value = bitmap_before[:actual_bytes - 1]
                    elif case.endswith('unaligned'):
                        value = bitmap_before[:actual_bytes]
                        if len(value) % 8 == 0:
                            value += b'\0'
                    elif case.endswith('padding'):
                        value = bytearray(bitmap_before)
                        value.extend(bytes(max(0, capacity_slots // 8 + 1 - len(value))))
                        value[capacity_slots // 8] |= 1 << (capacity_slots % 8)
                        value.extend(bytes((-len(value)) % 8))
                    else:
                        value = bitmap_before
                    if case.startswith('mft-resident-bitmap-known-free'):
                        value = bytearray(value)
                        historical_owner = 0
                        if case.endswith('retired'):
                            historical_owner = u(b, 16, 2) << 48
                        elif case.endswith(('foreign', 'owned')):
                            owner_number = files['other.bin']
                            historical_owner = owner_number | (u(image.get(owner_number), 16, 2) << 48)
                        elif case.endswith('unknown'):
                            historical_owner = (1 << 48) | 1024
                        for free_number in (20, 21):
                            free_record = image.get(free_number)
                            assert not u(free_record, 22, 2) & 1
                            put(free_record, 16, 1, 2)
                            put(free_record, 22, 0, 2)
                            put(free_record, 32, historical_owner, 8)
                            image.save(free_number, rewrite(free_record, []))
                            value[free_number // 8] |= 1 << (free_number % 8)
                        if case.endswith('owned'):
                            owner = image.get(owner_number)
                            owner_values = attributes(owner)
                            claims = [listed(a, historical_owner) for a in owner_values]
                            claims.append(listed(resident(0x80, b'', 99), (1 << 48) | 20))
                            claims.sort(key=lambda e: (u(e, 0, 4), u(e, 8, 8)))
                            ident = u(owner, 40, 2)
                            owner_values.append(resident(0x20, b''.join(claims), ident))
                            put(owner, 40, ident + 1, 2)
                            image.save(owner_number, rewrite(owner, owner_values))
                    values[values.index(old_bitmap)] = resident(0xb0, value, u(old_bitmap, 14, 2))
                    bitmap_expected = bytearray(bitmap_before if 'missing-bits' in case else value)
                    bitmap_expected.extend(bytes((-len(bitmap_expected)) % 8))
                    if case.startswith('mft-resident-bitmap-known-free'):
                        for free_number in (20, 21):
                            bitmap_expected[free_number // 8] &= ~(1 << (free_number % 8))
                    byte, partial = divmod(capacity_slots, 8)
                    if byte < len(bitmap_expected):
                        bitmap_expected[byte] &= (1 << partial) - 1 if partial else 0
                        bitmap_expected[byte + 1:] = bytes(len(bitmap_expected) - byte - 1)
                    if case.endswith('missing-data'):
                        values.remove(data)
                    elif case.endswith('invalid-runlist'):
                        data[u(data, 32, 2)] = 0
                elif case.startswith('mft-missing-data'):
                    values.remove(data)
                elif case == 'mft-invalid-runlist':
                    data[u(data, 32, 2)] = 0
                elif case == 'mft-partial-initialized':
                    original_initialized = u(data, 56, 8)
                    original_allocation = u(data, 40, 8)
                    assert original_initialized + image.size <= original_allocation
                    put(data, 48, original_initialized + image.size, 8)
                elif case == 'mft-short-data':
                    put(data, 48, 4 * image.size, 8)
                    put(data, 56, 4 * image.size, 8)
                elif case.startswith('mft-anchor-shift-'):
                    data = mapped(data, [(u(image.boot, 48, 8) + 1, u(data, 24, 8) + 1)])
                    values[next(i for i, a in enumerate(values) if u(a, 0, 4) == 0x80)] = data
                    if case.endswith('short-size'):
                        put(data, 48, 4 * image.size, 8)
                        put(data, 56, 4 * image.size, 8)
                    else:
                        put(data, 48, u(data, 56, 8) - image.size, 8)
                else:
                    values[values.index(data)] = mapped(data, [(u(image.boot, 48, 8), 1)])
                if (
                    case.endswith('high-identity')
                    and not case.startswith('mft-split-large-ready-')
                ):
                    put(b, 42, 7, 2)
                elif (
                    case.endswith('sequence-zero')
                    and not case.startswith('mft-split-large-ready-')
                ):
                    put(b, 16, 0, 2)
                image.save(0, rewrite(b, values))
                if case.startswith('mft-split-large-'):
                    allocation, fragment_extents = fragment_mft_family(
                        image, extension, allocated_slots,
                        case == 'mft-split-large-missing-data',
                        'unaligned-bitmap' in case and '-ready-' not in case,
                    )
            elif case in (
                'boot-missing-data', 'boot-short-data',
                'boot-short-mapping', 'boot-resident-data',
            ):
                b = image.get(7)
                values = attributes(b)
                data = next(a for a in values if u(a, 0, 4) == 0x80 and not a[9])
                if case == 'boot-missing-data':
                    values.remove(data)
                elif case == 'boot-short-data':
                    put(data, 48, 512, 8)
                    put(data, 56, 512, 8)
                elif case == 'boot-short-mapping':
                    replacement = mapped(data, [(0, 1)])
                    for offset in (40, 48, 56):
                        put(replacement, offset, image.cluster, 8)
                    values[values.index(data)] = replacement
                else:
                    values[values.index(data)] = resident(0x80, image.boot, u(data, 14, 2))
                image.save(7, rewrite(b, values))
            elif case in ('badclus-sizes','badclus-wrong-reservation'):
                b=image.get(8);values=attributes(b);a=next(a for a in values if u(a,0,4)==0x80 and name(a)=='$Bad')
                if case=='badclus-sizes':put(a,48,4096,8)
                else:
                    clusters=u(image.boot,40,8)//image.boot[13]
                    replacement=mapped(a,[(None,100),(101,1),(None,clusters-101)])
                    if u(a,12,2)&0x8001:put(replacement,64,image.cluster,8)
                    values[values.index(a)]=replacement
                image.save(8,rewrite(b,values))
            elif case.startswith('secure-family'):
                b=image.get(9);values=attributes(b);base_ref=9 | (u(b,16,2)<<48)
                sds=next(a for a in values if u(a,0,4)==0x80 and name(a)=='$SDS');values.remove(sds)
                values=[a for a in values if not (u(a,0,4)==0x90 and name(a)=='$SII')]
                extension=27;ex=image.get(extension);assert not u(ex,22,2)&1
                put(ex,16,1,2);put(ex,22,1,2);put(ex,32,base_ref,8);put(ex,18,0,2);put(ex,40,u(sds,14,2)+1,2)
                image.save(extension,rewrite(ex,[sds]));image.bitmap(extension)
                entries=[listed(a,base_ref) for a in values]+[listed(sds,extension|(1<<48))]
                entries.sort(key=lambda e:(u(e,0,4),bytes(e[26:]),u(e,8,8)))
                values.append(resident(0x20,b''.join(entries),u(b,40,2)));put(b,40,u(b,40,2)+1,2)
                image.save(9,rewrite(b,values))
                if case=='secure-family-torn-copy':
                    lcn,_=first_extent(sds,0);image.f.seek(lcn*image.cluster);first=image.f.read(1)
                    image.f.seek(lcn*image.cluster);image.f.write(bytes([first[0]^1]))
            elif case in ('log-badclus-crosslink','log-fragmented-crosslink'):
                log=image.get(2);lcn,_=first_extent(log,attr(log,0x80));clusters=u(image.boot,40,8)//image.boot[13]
                b=image.get(8);values=attributes(b);a=next(a for a in values if u(a,0,4)==0x80 and name(a)=='$Bad')
                replacement=mapped(a,[(None,lcn),(lcn,1),(None,clusters-lcn-1)])
                if u(a,12,2)&0x8001:put(replacement,64,image.cluster,8)
                values[values.index(a)]=replacement;image.save(8,rewrite(b,values))
                if case=='log-fragmented-crosslink':
                    b=image.get(6);a=attr(b,0x80);map_lcn,_=first_extent(b,a);length=u(b,a+48,8)
                    image.f.seek(map_lcn*image.cluster);bits=image.f.read(length)
                    image.f.seek(map_lcn*image.cluster);image.f.write(bytes(value|0xaa for value in bits))
            elif case.startswith('log-'):
                log=image.get(2);a=attr(log,0x80);lcn,_=first_extent(log,a);length=u(log,a+48,8)
                control=decode(restart(length,0,0,0));put(control,58,0,2);put(control,60,0xffff,2)
                good=protect(control)
                if case=='log-ambiguous-restart':put(control,48,1,8)
                torn=bytearray(protect(control));torn[1022]^=1
                if case=='log-conflicting-clients':
                    put(control,58,0xffff,2);put(control,60,0,2);torn=protect(control)
                image.f.seek(lcn*image.cluster);image.f.write(torn+good if case=='log-torn-primary' else good+torn)
            elif case=='fragmented-crosslink':
                b=image.get(files['payload.bin']);lcn,_=first_extent(b,attr(b,0x80))
                redirect(image,files['other.bin'],lcn)
                b=image.get(6);a=attr(b,0x80);lcn,_=first_extent(b,a);length=u(b,a+48,8)
                image.f.seek(lcn*image.cluster);bits=image.f.read(length)
                # Leave only isolated bitmap-free clusters. Original allocated
                # storage remains allocated; the final ownership audit reclaims
                # the artificial reservations after relocation.
                image.f.seek(lcn*image.cluster);image.f.write(bytes(value|0xaa for value in bits))
            else:
                number={'bitmap-reserved-crosslink':6,'mirror-reserved-crosslink':1,'boot-reserved-crosslink':7}[case]
                log=image.get(2);lcn,_=first_extent(log,attr(log,0x80))
                redirect(image,number,lcn)
            image.close()
            if case in (
                'mft-split-bitmap-absent', 'mft-split-bitmap-invalid-runlist',
                'mft-split-bitmap-absent-malformed',
                'mft-split-bitmap-extension-invalid-runlist',
                'mft-split-missing-data-bitmap-invalid-malformed-external-list',
                'mft-split-bitmap-known-free-nonempty-missing-tail',
                'mft-split-bitmap-known-free',
                'mft-split-bitmap-known-free-nonempty',
                'mft-split-bitmap-known-free-malformed',
                'mft-split-bitmap-known-free-missing-tail',
                'mft-split-partial-initialized',
                'mft-split-partial-initialized-missing-tail',
            ):
                image = Image(source)
                zero = image.get(0)
                values = attributes(zero)
                data = next((a for a in values if u(a, 0, 4) == 0x80 and not a[9]), None)
                bitmap = next((a for a in values if u(a, 0, 4) == 0xb0), None)
                if 'bitmap-extension-invalid-runlist' in case:
                    member = image.get(extension)
                    member_values = attributes(member)
                    bitmap = next(a for a in member_values if u(a, 0, 4) == 0xb0)
                    bitmap[u(bitmap, 32, 2)] = 0
                    image.save(extension, rewrite(member, member_values))
                elif 'bitmap-absent' in case:
                    values.remove(bitmap)
                    if case.endswith('malformed'):
                        number = allocated_slots - 1
                        image.f.seek(image.mft + number * image.size + 510)
                        byte = image.f.read(1)[0]
                        image.f.seek(-1, 1)
                        image.f.write(bytes([byte ^ 1]))
                elif 'bitmap-invalid' in case:
                    bitmap[u(bitmap, 32, 2)] = 0
                else:
                    if 'partial-initialized' in case:
                        put(data, 56, allocation - image.size, 8)
                    if case.endswith('missing-tail'):
                        put(bitmap, 56, (allocated_slots + 7) // 8 - 1, 8)
                    if 'known-free' in case:
                        claimed_free = allocated_slots - 16
                        free_record = image.get(claimed_free)
                        assert u(free_record, 22, 2) == 0 and not attributes(free_record)
                        bitmap_lcn, _ = first_extent(bitmap, 0)
                        image.f.seek(bitmap_lcn * image.cluster + claimed_free // 8)
                        bit = image.f.read(1)[0]
                        image.f.seek(-1, 1)
                        image.f.write(bytes([bit | (1 << (claimed_free % 8))]))
                        if case.endswith('malformed'):
                            image.f.seek(image.mft + claimed_free * image.size + 510)
                            byte = image.f.read(1)[0]
                            image.f.seek(-1, 1)
                            image.f.write(bytes([byte ^ 1]))
                        if 'nonempty' in case:
                            image.save(claimed_free, rewrite(free_record, [
                                resident(0x80, b'uncertain ownership', 0),
                            ]))
                image.save(0, rewrite(zero, values))
                image.close()
            if case.startswith('mft-split-') and 'resident-bitmap' in case:
                bitmap_before = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', source).stdout
                mft_bytes = run('ntfscat', '-f', '-i', '0', source).stdout
                image = Image(source)
                for number in range(len(mft_bytes) // image.size):
                    member = bytearray(mft_bytes[number * image.size:(number + 1) * image.size])
                    if number != 0 and u(member, 32, 8) != base_reference:
                        continue
                    values = attributes(member)
                    old_bitmap = next((a for a in values if u(a, 0, 4) == 0xb0), None)
                    if old_bitmap is None:
                        continue
                    value = bitmap_before[:100] if case.startswith('mft-split-large-') else bitmap_before
                    if 'empty-bits' in case:
                        value = b''
                    elif 'missing-bits' in case:
                        value = value[:4] if case.endswith('bits-live') else value[:99]
                    if case.endswith('cleared-live'):
                        value = bytearray(value)
                        live_number = files['payload.bin']
                        value[live_number // 8] &= ~(1 << (live_number % 8))
                    values[values.index(old_bitmap)] = resident(0xb0, value, u(old_bitmap, 14, 2))
                    member = rewrite(member, values)
                    if case.startswith('mft-split-large-'):
                        physical = fragment_extents[(number * image.size) // image.cluster][0]
                        image.f.seek(physical * image.cluster + (number * image.size) % image.cluster)
                        image.f.write(protect(member))
                    else:
                        image.save(number, member)
                    if number == 0:
                        mft_bytes = bytes(member) + mft_bytes[image.size:]
                    break
                zero = bytearray(mft_bytes[:image.size])
                values = attributes(zero)
                data = next(a for a in values if u(a, 0, 4) == 0x80 and not a[9])
                if case.endswith('new-extension'):
                    values = [a for a in values if u(a, 0, 4) not in (0x20, 0x80)]
                    bitmap = next(a for a in values if u(a, 0, 4) == 0xb0)
                    at = u(bitmap, 20, 2) + extension // 8
                    bitmap[at] &= ~(1 << (extension % 8))
                    member = bytearray(mft_bytes[extension * image.size:(extension + 1) * image.size])
                    put(member, 22, 0, 2)
                    put(member, 16, 0, 2)
                    member = rewrite(member, [])
                    physical = fragment_extents[(extension * image.size) // image.cluster][0]
                    image.f.seek(physical * image.cluster + (extension * image.size) % image.cluster)
                    image.f.write(protect(member))
                elif case.endswith('missing-data') or ('missing-bits' in case and not case.endswith('ready')):
                    values.remove(data)
                elif case.endswith('invalid-runlist'):
                    data[u(data, 32, 2)] = 0
                image.save(0, rewrite(zero, values))
                if case.endswith('missing-bits-malformed'):
                    physical = fragment_extents[(792 * image.size) // image.cluster][0]
                    image.f.seek(physical * image.cluster + (792 * image.size) % image.cluster + 510)
                    old = image.f.read(1)
                    image.f.seek(-1, 1)
                    image.f.write(bytes([old[0] ^ 1]))
                elif case.endswith('missing-bits-competing'):
                    bitmap_record = bytearray(mft_bytes[6 * image.size:7 * image.size])
                    lcn, _ = first_extent(bitmap_record, attr(bitmap_record, 0x80))
                    total_clusters = u(image.boot, 40, 8) // image.boot[13]
                    image.f.seek(lcn * image.cluster)
                    allocated = image.f.read((total_clusters + 7) // 8)
                    destination = next(n for n in range(256, total_clusters) if not allocated[n // 8] & (1 << (n % 8)))
                    image.f.seek(fragment_extents[198][0] * image.cluster)
                    duplicate = image.f.read(image.cluster)
                    image.f.seek(destination * image.cluster)
                    image.f.write(duplicate)
                image.close()
            if case == 'mft-split-list-ready-malformed':
                prepared = d / (case + '-prepared.img')
                run(CHECKER, '--repair-to', source, prepared)
                shutil.copyfile(prepared, source)
                image = Image(source)
                zero = image.get(0)
                list_at = attr(zero, 0x20)
                assert not zero[list_at + 8]
                put(zero, list_at + u(zero, list_at + 20, 2) + 4, 31, 2)
                image.save(0, zero)
                image.close()
            if case.startswith('mft-split-large-ready-'):
                # Start with the publisher's own split boundaries, then
                # damage only the admitted reserved header field.

                prepared = d / (case + '-prepared.img')
                run(CHECKER, '--repair-to', source, prepared)
                shutil.copyfile(prepared, source)
                image = Image(source)
                zero = image.get(0)
                bitmap_resize = (
                    case.endswith('unaligned-bitmap')
                    or case.startswith('mft-split-large-ready-bitmap-')
                )
                if bitmap_resize:
                    bitmap_before = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', source).stdout
                    mft_bytes = run('ntfscat', '-f', '-i', '0', source).stdout
                    for number in range(len(mft_bytes) // image.size):
                        member = bytearray(mft_bytes[number * image.size:(number + 1) * image.size])
                        if number != 0 and u(member, 32, 8) != base_reference:
                            continue
                        bitmap_at = next((at for at, kind in attrs(member) if kind == 0xb0), None)
                        if bitmap_at is None:
                            continue
                        data_size = 112 if case.endswith('bitmap-extra-init') else 104
                        initialized_size = 108 if case.endswith('bitmap-extra-init') else 100
                        if 'bitmap-missing-bits' in case:
                            initialized_size = 4 if case.endswith('bits-live') else 99
                        if 'bitmap-data108-' in case:
                            data_size = 108
                            initialized_size = 104 if case.endswith('init104') else 108
                        if case.endswith('bitmap-padding'):
                            data_size = 104
                            initialized_size = 104
                        if case.endswith('unaligned-bitmap'):
                            data_size = 100
                        put(member, bitmap_at + 48, data_size, 8)
                        put(member, bitmap_at + 56, initialized_size, 8)
                        bitmap_attribute_before = bytes(member[
                            bitmap_at:bitmap_at + u(member, bitmap_at + 4, 4)
                        ])
                        physical = fragment_extents[(number * image.size) // image.cluster][0]
                        image.f.seek(physical * image.cluster + (number * image.size) % image.cluster)
                        image.f.write(protect(member))
                        if number < 4:
                            image.f.seek(u(image.boot, 56, 8) * image.cluster + number * image.size)
                            image.f.write(protect(member))
                        bitmap_lcn, _ = first_extent(member, bitmap_at)
                        if case.endswith('bitmap-missing-bits-cleared-live'):
                            live_number = files['payload.bin']
                            image.f.seek(bitmap_lcn * image.cluster + live_number // 8)
                            byte = image.f.read(1)[0]
                            image.f.seek(-1, 1)
                            image.f.write(bytes([byte & ~(1 << (live_number % 8))]))
                        if initialized_size == 100:
                            image.f.seek(bitmap_lcn * image.cluster + 100)
                            image.f.write(b'\xff' * 4)
                        elif case.endswith('bitmap-padding'):
                            image.f.seek(bitmap_lcn * image.cluster + 100)
                            image.f.write(b'\x01\0\0\0')
                        break
                    else:
                        raise AssertionError('prepared MFT family has no bitmap')
                elif case.endswith('high-identity'):
                    put(zero, 42, 7, 2)
                elif case.endswith('lost-list'):
                    zero = rewrite(zero, [
                        attribute for attribute in attributes(zero)
                        if u(attribute, 0, 4) != 0x20
                    ])
                else:
                    put(zero, 16, 0, 2)
                if not bitmap_resize:
                    image.save(0, zero)
                image.close()
            before = digest(source)
            if 'partial-initialized' in case:
                assessment = run(CHECKER, '--check', source, ok=False)
                assert b'mft-data-size' in assessment.stdout
            if 'unaligned-bitmap' in case or case.endswith('bitmap-short-init') or 'bitmap-data108-' in case:
                bitmap_before = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', source).stdout
                assessment = run(CHECKER, '--check', source, ok=False)
                assert b'mft-bitmap-size' in assessment.stdout
            if case.endswith('bitmap-padding'):
                bitmap_before = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', source).stdout
                assessment = run(CHECKER, '--check', source, ok=False)
                assert b'mft-bitmap-padding' in assessment.stdout
            if case in ('mft-split-large-valid', 'mft-split-large-bitmap-extension'):
                run(CHECKER, '--audit', source)
            if case in (
                'log-ambiguous-restart', 'log-conflicting-clients',
                'legacy-payload-bitmap-absent-list',
                'legacy-payload-bitmap-absent-owner',
                'badclus-wrong-reservation', 'mft-duplicate-contiguous',
                'mft-split-large-resident-bitmap-missing-bits-malformed',
                'mft-split-large-resident-bitmap-missing-bits-competing',
                'mft-resident-bitmap-known-free-owned',
                'mft-anchor-shift-short-size', 'mft-anchor-shift-size-mismatch',
                'mft-split-omitted-base-data-foreign-external-list',
                'mft-split-omitted-base-data-wrong-id-external-list',
                'mft-split-bitmap-absent-malformed',
                'mft-split-bitmap-known-free-nonempty-missing-tail',
                'mft-split-bitmap-known-free-nonempty',
                'mft-split-bitmap-known-free-malformed',
                'mft-split-tail-nonzero-sequence',
                'mft-split-tail-zero-sequence-unlisted-bitmap-extension',
                'mft-split-tail-zero-sequence-duplicate',
                'mft-split-lost-list-zero-sequence',
                'mft-split-lost-list-foreign-owner',
                'mft-split-lost-list-foreign-huge-run',
                'mft-split-lost-list-foreign-outside-volume',
                'mft-split-tail-foreign-owner',
            ):
                run(CHECKER,'--repair-to',source,target,ok=False)
                assert digest(source)==before and not target.exists()
                print('PASS',case,'conflicting evidence refused, source unchanged',flush=True);continue
            repair_args = ['--index-check=quick'] if case.endswith('-quick') else []
            run(CHECKER, *repair_args, '--repair-to', source, target)
            run(CHECKER, '--audit', target)
            assert digest(source)==before
            recovered_orphan = case.startswith('orphan-') and case != 'orphan-valid-hardlink'
            if (
                not case.startswith(('duplicate-', 'collision-'))
                and not recovered_orphan
                and case != 'directory-orphan-subtree'
            ):
                assert run('ntfscat','-f',target,'/payload.bin').stdout==content.read_bytes()
            if not case.startswith('collision-') and case not in (
                'orphan-multiple-files', 'orphan-multiple-files-quick',
                'orphan-distinct-parents', 'orphan-out-of-range-parents',
            ):
                other_path = '/FoUnD.000' if case == 'orphan-occupied-file' else '/other.bin'
                assert run('ntfscat', '-f', target, other_path).stdout == content.read_bytes()
            if case in ('bitmap-reserved-crosslink','mirror-reserved-crosslink','boot-reserved-crosslink'):
                # ntfs-3g rejects the deliberately damaged mirror mapping on
                # the source. Its unchanged log is recorded before corruption.
                assert run('ntfscat','-f',target,'/$LogFile').stdout==log_content
            image=Image(target)
            if case.startswith('mft-resident-bitmap-'):
                zero = image.get(0)
                bitmap_at = attr(zero, 0xb0)
                if 'missing-bits' in case:
                    assert zero[bitmap_at + 8]
                    assert run('ntfscat', '-f', '-a', '0xb0', '-i', '0', target).stdout == bitmap_expected
                else:
                    assert not zero[bitmap_at + 8]
                    at = bitmap_at + u(zero, bitmap_at + 20, 2)
                    assert zero[at:at + u(zero, bitmap_at + 16, 4)] == bitmap_expected
                if case.startswith('mft-resident-bitmap-known-free'):
                    for free_number in (20, 21):
                        record = image.get(free_number)
                        assert u(record, 16, 2) == 1 and u(record, 22, 2) == 0
                        assert u(record, 32, 8) == historical_owner
                        assert not attributes(record)
            if case.startswith('mft-split-') and 'resident-bitmap' in case:
                repaired_stream = run('ntfscat', '-f', '-i', '0', target).stdout
                repaired_bits = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', target).stdout
                family_slots = {0, extension, *range(16, 24)}
                repaired_family_slots = {0}
                for number in range(len(repaired_stream) // image.size):
                    member = repaired_stream[number * image.size:(number + 1) * image.size]
                    if u(member, 22, 2) & 1 and u(member, 32, 8) == base_reference:
                        family_slots.add(number)
                        repaired_family_slots.add(number)
                for number in range(allocation // image.size):
                    if number not in family_slots:
                        mask = 1 << (number % 8)
                        assert repaired_bits[number // 8] & mask == bitmap_before[number // 8] & mask
                if case.startswith('mft-split-large-'):
                    assert len(repaired_bits) == 104 and repaired_bits[100:] == bytes(4)
            if case.startswith('mft-split-'):
                zero = image.get(0)
                assert u(zero, 16, 2) == 1 and u(zero, 42, 2) == 0
                data = next(a for a in attributes(zero) if u(a, 0, 4) == 0x80)
                assert u(data, 16, 8) == 0
                expected_data_size = (
                    allocation - image.size if 'partial-initialized' in case else allocation
                )
                assert u(data, 48, 8) == expected_data_size
                assert u(data, 56, 8) == expected_data_size
                if case in (
                    'mft-split-bitmap-known-free', 'mft-split-bitmap-known-free-missing-tail',
                ):
                    repaired_bitmap = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', target).stdout
                    assert not repaired_bitmap[claimed_free // 8] & (1 << (claimed_free % 8))
                if case.startswith('mft-split-large-'):
                    # The independent NTFS reader presents decoded MFT slots.

                    mft_bytes = run('ntfscat', '-f', '-i', '0', target).stdout
                    member = mft_bytes[extension * image.size:(extension + 1) * image.size]
                    segments = []
                    for number in range(len(mft_bytes) // image.size):
                        record = mft_bytes[number * image.size:(number + 1) * image.size]
                        if number != 0 and (
                            not u(record, 22, 2) & 1 or u(record, 32, 8) != base_reference
                        ):
                            continue
                        for a in attributes(record):
                            if u(a, 0, 4) == 0x80:
                                segments.append((u(a, 16, 8), u(a, 24, 8)))
                    segments.sort()
                    assert len(segments) > 1
                    assert segments[0][0] == 0
                    assert segments[-1][1] + 1 == allocation // image.cluster
                    assert all(
                        left[1] + 1 == right[0]
                        for left, right in zip(segments, segments[1:])
                    )
                    bitmap_value = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', target).stdout
                    expected_bitmap_size = (
                        112 if case.endswith('bitmap-extra-init') or 'bitmap-data108-' in case else 104
                    )
                    assert len(bitmap_value) == expected_bitmap_size
                    if 'unaligned-bitmap' in case:
                        assert bitmap_value[:100] == bitmap_before[:100]
                        assert bitmap_value[100:] == bytes(4)
                    if case == 'mft-split-large-ready-unaligned-bitmap':
                        assert bitmap_value[:100] == bitmap_before[:100]
                    if 'bitmap-missing-bits' in case and 'resident-bitmap' not in case:
                        slots_in_family = {0}
                        for number in range(len(mft_bytes) // image.size):
                            record = mft_bytes[number * image.size:(number + 1) * image.size]
                            if u(record, 22, 2) & 1 and u(record, 32, 8) == base_reference:
                                slots_in_family.add(number)
                        for number in range(allocation // image.size):
                            if number not in slots_in_family:
                                mask = 1 << (number % 8)
                                assert bitmap_value[number // 8] & mask == bitmap_before[number // 8] & mask
                        assert bitmap_value[100:] == bytes(4)
                    if case.endswith('bitmap-short-init'):
                        assert bitmap_value[:100] == bitmap_before[:100]
                        assert bitmap_value[100:] == bytes(4)
                    if case.endswith('bitmap-padding'):
                        assert bitmap_value[:100] == bitmap_before[:100]
                        assert bitmap_value[100:] == bytes(4)
                    if case.endswith('bitmap-extra-init'):
                        bitmap_attributes = []
                        for number in range(len(mft_bytes) // image.size):
                            record = mft_bytes[number * image.size:(number + 1) * image.size]
                            if not u(record, 22, 2) & 1:
                                continue
                            if number != 0 and u(record, 32, 8) != base_reference:
                                continue
                            bitmap_attributes.extend(
                                bytes(attribute) for attribute in attributes(record)
                                if u(attribute, 0, 4) == 0xb0
                            )
                        assert bitmap_attributes == [bitmap_attribute_before]
                    if 'bitmap-data108-' in case:
                        assert bitmap_value[:104] == bitmap_before[:104]
                        for number in range(len(mft_bytes) // image.size):
                            record = mft_bytes[number * image.size:(number + 1) * image.size]
                            if number != 0 and u(record, 32, 8) != base_reference:
                                continue
                            for attribute in attributes(record):
                                if u(attribute, 0, 4) == 0xb0:
                                    assert u(attribute, 48, 8) == 112
                                    assert u(attribute, 56, 8) == initialized_size
                else:
                    member = image.get(extension)
                if not case.endswith('new-extension'):
                    assert u(member, 16, 2) == sequence
                    assert u(member, 32, 8) == base_reference
                else:
                    assert repaired_family_slots - {0, extension}
                    assert not u(member, 22, 2) & 1
                if not case.startswith('mft-split-large-'):
                    assert not any(u(a, 0, 4) == 0x80 for a in attributes(member))
                    if 'resident-bitmap' in case:
                        if u(member, 22, 2) & 1:
                            assert u(member, 32, 8) == base_reference
                            assert any(u(a, 0, 4) == 0xb0 for a in attributes(member))
                            assert all(u(a, 0, 4) != 0x80 for a in attributes(member))
                    elif case in (
                        'mft-split-bitmap-absent', 'mft-split-bitmap-invalid-runlist',
                        'mft-split-missing-data-bitmap-invalid-malformed-external-list',
                        'mft-split-bitmap-known-free-missing-tail',
                        'mft-split-bitmap-known-free',
                        'mft-split-partial-initialized',
                        'mft-split-partial-initialized-missing-tail',
                    ):
                        if u(member, 22, 2) & 1:
                            assert all(u(a, 0, 4) == 0xb0 for a in attributes(member))
                    else:
                        assert bool(u(member, 22, 2) & 1) == ('bitmap-extension' in case)
                if 'bitmap-extension' in case:
                    assert u(member, 22, 2) & 1
                    assert any(u(a, 0, 4) == 0xb0 for a in attributes(member))
            elif case == 'mft-partial-initialized':
                zero = image.get(0)
                data_at = attr(zero, 0x80)
                assert u(zero, data_at + 40, 8) == original_allocation
                assert u(zero, data_at + 48, 8) == original_initialized
                assert u(zero, data_at + 56, 8) == original_initialized
            elif case.startswith('mft-missing-data-'):
                zero = image.get(0)
                assert u(zero, 16, 2) == 1 and u(zero, 42, 2) == 0
            elif case.startswith('legacy-'):
                number = files['payload.bin'] if case.startswith('legacy-payload') else 0
                legacy = image.get(number)
                assert u(legacy, 4, 2) == 42
                if case == 'legacy-payload-bitmap-absent':
                    assert u(legacy, 16, 2) == u(legacy_before, 16, 2)
                    assert u(legacy, 32, 8) == 0
                    before_values = attributes(legacy_before)
                    after_values = attributes(legacy)
                    assert [(u(a, 0, 4), u(a, 14, 2)) for a in after_values] == [
                        (u(a, 0, 4), u(a, 14, 2)) for a in before_values
                    ]
                    assert [a for a in after_values if u(a, 0, 4) == 0x80] == [
                        a for a in before_values if u(a, 0, 4) == 0x80
                    ]
                    bitmap_value = run('ntfscat', '-f', '-a', '0xb0', '-i', '0', target).stdout
                    assert bitmap_value[number // 8] & (1 << (number % 8))
            elif case.startswith('secure-family'):
                assert run('ntfscat','-f','-n','$SDS',target,'/$Secure').stdout==security_content
            elif case in ('log-torn-restart','log-torn-primary'):
                restored=run('ntfscat','-f',target,'/$LogFile').stdout
                assert restored[:4096]==good and restored[4096:8192]==good and restored[8192:]==log_content[8192:]
            elif case in ('log-badclus-crosslink','log-fragmented-crosslink'):
                assert run('ntfscat','-f',target,'/$LogFile').stdout==log_content
            elif case=='badclus-sizes':
                a=next(a for a in attributes(image.get(8)) if u(a,0,4)==0x80 and name(a)=='$Bad')
                assert u(a,48,8)==(u(image.boot,40,8)//image.boot[13])*image.cluster
            elif case=='quota-missing-lookup':
                _,qrows=rows(image.get(files['$Quota']),'$Q');entry=next(r for r in qrows if u(r,16,4)==256);at=u(entry,0,2)
                assert u(entry,at+8,8)==321 and u(entry,at+32,8)==123456
                _,lookup=rows(image.get(files['$Quota']),'$O');assert any(u(r,u(r,0,2),4)==256 for r in lookup)
            elif case.startswith('object-'):
                _,lookup=rows(image.get(files['$ObjId']),'$O');assert any(r[16:32]==ident[:16] and r[u(r,0,2)+8:u(r,0,2)+56]==ident[16:] for r in lookup)
            elif case.startswith('duplicate-'):
                base_record = image.get(files['payload.bin'])
                base_ref = files['payload.bin'] | (u(base_record, 16, 2) << 48)
                zero = image.get(0)
                slots = u(zero, attr(zero, 0x80) + 56, 8) // image.size
                members = [
                    image.get(n) for n in range(slots)
                    if n == files['payload.bin'] or u(image.get(n), 32, 8) == base_ref
                ]
                links = [a for member in members for a in attributes(member) if u(a, 0, 4) == 0x30]
                assert len(links) == 1
                labels = [
                    bytes(a[u(a, 20, 2) + 66:u(a, 20, 2) + u(a, 16, 4)]).decode('utf-16le')
                    for a in links
                ]
                assert labels == ['00000000file.chk']
                link_value = u(links[0], 20, 2)
                assert links[0][link_value + 65] == 0
                parent = u(links[0], link_value, 8)
                folder = image.get(parent & 0xffffffffffff)
                assert u(folder, 16, 2) == parent >> 48
                assert u(folder, 22, 2) == 3
                folder_links = [a for a in attributes(folder) if u(a, 0, 4) == 0x30]
                assert len(folder_links) == 1
                folder_name = folder_links[0]
                folder_value = u(folder_name, 20, 2)
                assert folder_name[folder_value + 65] == 3
                assert u(folder_name, folder_value, 8) & 0xffffffffffff == 5
                folder_label = bytes(folder_name[folder_value + 66:
                                                 folder_value + u(folder_name, 16, 4)]).decode('utf-16le')
                assert folder_label == 'found.000'
                standard = next(a for a in attributes(folder) if u(a, 0, 4) == 0x10)
                assert u(standard, u(standard, 20, 2) + 32, 4) & 6 == 6
                recovered_path = '/' + folder_label + '/' + labels[0]
                assert run('ntfscat', '-f', target, recovered_path).stdout == content.read_bytes()
            elif case.startswith('collision-'):
                for ordinal, original_label in enumerate(collision_labels):
                    b = image.get(files[original_label])
                    si = next(a for a in attributes(b) if u(a, 0, 4) == 0x10)
                    si_at = u(si, 20, 2)
                    assert bytes(si[si_at:si_at + 32]) == collision_standard[original_label]
                    links = [a for a in attributes(b) if u(a, 0, 4) == 0x30]
                    labels = {}
                    for link in links:
                        at = u(link, 20, 2)
                        label = bytes(link[at + 66:at + u(link, 16, 4)]).decode('utf-16le')
                        labels[label] = link[at + 65]
                    if ordinal == 0:
                        assert labels == {'colliding.txt': 1, 'FILE0~1': 2}
                        path = '/colliding.txt'
                    elif 'single' in case:
                        assert labels == {'00000000-colliding.txt': 0}
                        at = u(links[0], 20, 2)
                        assert u(links[0], at, 8) & 0xffffffffffff == names(image)['found.000']
                        path = '/found.000/00000000-colliding.txt'
                    else:
                        assert labels == {'FILE1~1': 0}
                        at = u(links[0], 20, 2)
                        assert u(links[0], at, 8) & 0xffffffffffff == 5
                        assert 'found.000' not in names(image)
                        path = '/FILE1~1'
                    assert run('ntfscat', '-f', target, path).stdout == content.read_bytes()
                if case.endswith('-quick'):
                    after_index = [a for a in attributes(image.get(11))
                                   if u(a, 0, 4) in (0x90, 0xa0, 0xb0) and name(a) == '$I30']
                    assert after_index == unrelated_index
            elif case.startswith('orphan-'):
                recovery_folder = 'found.001' if case.startswith('orphan-occupied-') else 'found.000'
                ordered_labels = sorted(orphan_labels, key=lambda label: files[label])
                for ordinal, original_label in enumerate(ordered_labels):
                    b = image.get(files[original_label])
                    links = [a for a in attributes(b) if u(a, 0, 4) == 0x30]
                    assert len(links) == 1
                    value_at = u(links[0], 20, 2)
                    assert links[0][value_at + 65] == 0
                    assert u(b, 18, 2) == 1
                    label = bytes(links[0][value_at + 66:
                                          value_at + u(links[0], 16, 4)]).decode('utf-16le')
                    if case == 'orphan-valid-hardlink':
                        assert label == 'payload.bin'
                        assert u(links[0], value_at, 8) & 0xffffffffffff == 5
                        assert 'found.000' not in names(image)
                    else:
                        suffix = 'a' * 227 + '.txt' if case == 'orphan-long-name' else original_label
                        grouped = case.startswith('orphan-multiple-files')
                        expected = original_label if grouped else f'{ordinal:08X}'[::-1] + '-' + suffix
                        assert label == expected and len(label) <= 240
                        parent = u(links[0], value_at, 8) & 0xffffffffffff
                        if grouped:
                            assert names(image)['dir0000.chk'] == parent
                            group = image.get(parent)
                            group_name = next(a for a in attributes(group) if u(a, 0, 4) == 0x30)
                            group_value = u(group_name, 20, 2)
                            assert group_name[group_value + 65] == 3
                            assert u(group_name, group_value, 8) & 0xffffffffffff == names(image)[recovery_folder]
                            standard = next(a for a in attributes(group) if u(a, 0, 4) == 0x10)
                            assert u(standard, u(standard, 20, 2) + 32, 4) == 0
                            path = '/' + recovery_folder + '/dir0000.chk/' + label
                        else:
                            assert names(image)[recovery_folder] == parent
                            assert 'dir0000.chk' not in names(image)
                            path = '/' + recovery_folder + '/' + label
                        assert run('ntfscat', '-f', target, path).stdout == content.read_bytes()
                if case == 'orphan-multiple-files-quick':
                    after_index = [a for a in attributes(image.get(11))
                                   if u(a, 0, 4) in (0x90, 0xa0, 0xb0) and name(a) == '$I30']
                    assert after_index == unrelated_index
                if case == 'orphan-occupied-directory':
                    assert names(image)['FoUnD.000'] == directory
                    assert rows(image.get(directory), '$I30')[1] == []
            elif case.startswith('directory-'):
                links = [a for a in attributes(image.get(directory)) if u(a, 0, 4) == 0x30]
                assert len(links) == 1
                value_at = u(links[0], 20, 2)
                assert links[0][value_at + 65] == 0
                label = bytes(links[0][value_at + 66:
                                      value_at + u(links[0], 16, 4)]).decode('utf-16le')
                parent = u(links[0], value_at, 8)
                if case in ('directory-cycle-aliases', 'directory-multiple-cycles'):
                    recovery_parent = names(image)['found.000']
                    for ordinal, number in enumerate(cycle_directories):
                        b = image.get(number)
                        links = [a for a in attributes(b) if u(a, 0, 4) == 0x30]
                        assert len(links) == 1
                        value_at = u(links[0], 20, 2)
                        parent = u(links[0], value_at, 8)
                        label = bytes(links[0][value_at + 66:
                                              value_at + u(links[0], 16, 4)]).decode('utf-16le')
                        assert label == f'{ordinal:08X}'[::-1] + '_dir.chk'
                        assert links[0][value_at + 65] == 0
                        assert u(b, 18, 2) == 1
                        parent_record = image.get(parent & 0xffffffffffff)
                        assert u(parent_record, 16, 2) == parent >> 48
                        assert u(parent_record, 22, 2) == 3
                        assert recovery_parent == parent & 0xffffffffffff
                elif case == 'directory-orphan-subtree':
                    assert label == '00000000-recover-a'
                    assert names(image)['found.000'] == parent & 0xffffffffffff
                    child = image.get(files['payload.bin'])
                    filename = attr(child, 0x30)
                    assert u(child, filename + u(child, filename + 20, 2), 8) == directory | (1 << 48)
                    path = '/found.000/' + label + '/payload.bin'
                    assert run('ntfscat', '-f', target, path).stdout == content.read_bytes()
                else:
                    assert label == 'recover-a'
                    assert parent & 0xffffffffffff == 5
            elif case in ('mirror-reserved-crosslink','boot-reserved-crosslink'):
                number=1 if case.startswith('mirror') else 7
                expected=u(image.boot,56,8) if number==1 else 0
                assert first_extent(image.get(number),attr(image.get(number),0x80))[0]==expected
            elif case.startswith('boot-'):
                b = image.get(7)
                a = attr(b, 0x80)
                clusters = (8192 + image.cluster - 1) // image.cluster
                assert first_extent(b, a) == (0, clusters)
                assert u(b, a + 40, 8) == clusters * image.cluster
                expected = 512 if case == 'boot-short-data' else clusters * image.cluster
                assert all(u(b, a + offset, 8) == expected for offset in (48, 56))
            image.close()
            again = d / (case + '-again.img')
            run(CHECKER, *repair_args, '--repair-to', target, again)
            assert digest(again) == digest(target)
            print('PASS', case, 'source unchanged, complete audit, readable data, idempotence', flush=True)


if __name__ == '__main__':
    main()
