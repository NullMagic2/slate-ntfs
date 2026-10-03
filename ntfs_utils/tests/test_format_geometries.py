#!/usr/bin/env python3
"""
Module: ntfs_utils.tests.test_format_geometries
Purpose: Native formatter geometry matrix; fresh sparse files only.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Native formatter geometry matrix; fresh sparse files only.
"""
from test_format_admin import ROOT, run, ntfs, Status
from pathlib import Path
import tempfile, json, struct, hashlib, subprocess, os

def main():
    out=Path(tempfile.mkdtemp(prefix='slate-format-geometry-',dir='/var/tmp'))
    cases=[]
    def test(name,size=64*1024*1024,**options):
        p=out/(name+'.img')
        with p.open('xb') as f:f.truncate(size)
        r=ntfs.format_device(p,**options)
        assert r.success,(name,r)
        info=ntfs.get_device(p)
        checked=p
        if options.get('sectors'):
            # Inspect the selected volume boundary, not unused target capacity.
            checked=out/(name+'-bounded.img')
            with p.open('rb') as f: checked.write_bytes(f.read(options['sectors']*options.get('sector_size',512)))
        run('ntfsfix','-n',checked)
        run('ntfsls','-s',checked)
        # Actual allocation and file creation through an independent driver.
        content=out/'input';content.write_bytes(bytes(range(256))*300)
        run('ntfscp',checked,content,'/geometry.bin')
        output=subprocess.check_output(['ntfscat',str(checked),'/geometry.bin'])
        assert output==content.read_bytes(),name
        case=dict(name=name,size=size,options=options,cluster=info.cluster_size_bytes)
        cases.append(case);print('PASS',case,flush=True)
        return p
    for cluster in [512,1024,2048,4096,8192,16384,32768,65536,131072,262144,524288,1048576,2097152]:
        test('cluster-'+str(cluster),cluster_size=cluster)
    for sector,cluster in [(1024,1024),(1024,4096),(2048,2048),(2048,8192),(4096,4096),(4096,65536)]:
        test(f'sector-{sector}-cluster-{cluster}',sector_size=sector,cluster_size=cluster)
    for size in [1048576,2*1048576,4*1048576]:test('size-'+str(size),size=size)
    test('defaults',compression=True,disable_indexing=True,epoch_time=True,with_uuid=True,
         partition_start=2048,heads=255,sectors_per_track=63,mft_zone_multiplier=4)
    partial=test('partial',sectors=65536)
    with partial.open('rb') as f:
        boot=f.read(512);f.seek(32*1024*1024-512);assert f.read(512)==boot
        assert f.read()==bytes(32*1024*1024)
    p=out/'dry.img'
    with p.open('xb') as f:f.truncate(64*1024*1024)
    before=hashlib.sha256(p.read_bytes()).digest()
    for options in [dict(dry_run=True),dict(cluster_size=8192,compression=True),dict(sector_size=513),
                    dict(mft_zone_multiplier=5),dict(sectors=2**63),dict(cluster_size=256)]:
        r=ntfs.format_device(p,**options)
        assert r.success == bool(options.get('dry_run')),r
        assert hashlib.sha256(p.read_bytes()).digest()==before
    print('PASS invalid geometry and dry-run preserve bytes',flush=True)
    (out/'results.json').write_text(json.dumps(cases,indent=2))
    print('RESULT_DIRECTORY='+str(out),flush=True)

if __name__=='__main__':main()
