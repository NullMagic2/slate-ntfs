#!/usr/bin/env python3
"""
Module: src.tests.writer.test_namespace_safety
Purpose: Direct shared-engine directory moves must not create ancestor cycles.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Direct shared-engine directory moves must not create ancestor cycles.
"""
import hashlib
import sys
from pathlib import Path
import test_metadata_writer as m

def main():
    out=Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=False)
    source=out/'source.img';m.mkimage(source,32)
    with m.Mounted(source,out/'populate') as root:
        (root/'parent').mkdir();(root/'parent'/'child').mkdir()
        (root/'parent'/'child'/'file').write_bytes(b'preserve')
        (root/'destination').mkdir()
    digest=hashlib.sha256(source.read_bytes()).digest()
    rejected=out/'rejected.img'
    result=m.lab(source,rejected,('move','/parent','/parent/child/cycle'),ok=False)
    assert b'InvalidIndex' in result.stderr,result.stderr
    assert m.names(rejected,'/parent')==['child']
    assert m.names(rejected,'/parent/child')==['file']
    accepted=out/'accepted.img'
    m.lab(source,accepted,('move','/parent/child','/destination/moved'))
    assert m.names(accepted,'/parent')==[]
    assert m.content(accepted,'/destination/moved/file')==b'preserve'
    assert hashlib.sha256(source.read_bytes()).digest()==digest
    print('PASS direct-engine descendant refusal and valid directory move')

if __name__=='__main__':main()
