#!/usr/bin/env python3
"""
Module: kernel.tests.kernel_permission_checks
Purpose: Verify kernel permission checks behavior on disposable fixtures.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.
"""

import errno,os,sys
root=sys.argv[1]
def check(name,uid,gid,groups,allowed,operation='read'):
    pid=os.fork()
    if pid==0:
        try:
            os.setgroups(groups);os.setgid(gid);os.setuid(uid)
            path=os.path.join(root,name)
            try:
                if operation=='read':
                    with open(path,'rb') as file: assert file.read() in (b'payload',b'secret')
                elif operation=='stat':
                    info=os.stat(path);assert (info.st_uid,info.st_gid)==(1001,2001)
                elif operation=='execute':
                    if not os.access(path,os.X_OK,effective_ids=True): raise PermissionError()
                elif operation=='list': assert os.listdir(path)==['child']
                elif operation=='write':
                    with open(path,'wb') as file:file.write(b'forbidden')
                success=True
            except OSError: success=False
            os._exit(0 if success==allowed else 1)
        except BaseException:os._exit(2)
    _,status=os.waitpid(pid,0)
    assert status==0,(name,uid,gid,groups,allowed,operation,status)

check('allow_user',1001,2001,[],True)
check('allow_user',1002,2001,[],False)
check('allow_user',0,0,[],False) # CAP_DAC_OVERRIDE must not bypass native ACLs.
check('allow_user',1001,2001,[],True,'stat')
check('allow_user',1001,2001,[],True,'execute')
check('deny_user',1001,2001,[],False)
check('deny_user',1002,2001,[],True)
check('primary_group',1002,2001,[],True)
check('primary_group',1002,2002,[],False)
check('supp_group',1001,2001,[2002],True)
check('supp_group',1001,2001,[],False)
check('deny_group',1001,2001,[2002],False)
check('deny_group',1001,2001,[],True)
check('everyone',1001,2001,[],True)
check('everyone',12345,2001,[],False)
check('everyone',1001,23456,[],False)
check('everyone',1001,2001,[23456],False)
check('everyone',1001,2001,[],False,'execute')
check('empty',1001,2001,[],False)
check('null',1001,2001,[],True)
check('inherit_only',1001,2001,[],False)
check('unknown',1001,2001,[],False)
check('no_attributes',1001,2001,[],True)
check('no_attributes',1001,2001,[],False,'stat')
check('blocked',1001,2001,[],True,'list')
check('blocked/child',1001,2001,[],False)
check('allow_user',1001,2001,[],False,'write')
check('everyone',1001,2001,[2001]*63,True)
check('everyone',1001,2001,[2001]*64,False)
check('everyone',1001,2001,[2001]*62+[23456],False)
print('30 credential/DACL cases passed: owner mapping, users, primary/supplementary groups, deny ACEs, root, missing mappings, execute/traverse, attributes, null/empty/unknown policies, group bounds and write refusal.')

# Concurrent path walks reuse the same descriptors but must never reuse grants.
children=[]
for worker in range(8):
    pid=os.fork()
    if pid==0:
        try:
            allowed=worker%2==0
            os.setgroups([]);os.setgid(2001);os.setuid(1001 if allowed else 1002)
            for _ in range(1000):
                try:
                    with open(os.path.join(root,'allow_user'),'rb') as stream:
                        assert stream.read()==b'payload'
                    os.stat(os.path.join(root,'allow_user'))
                    success=True
                except OSError as error:
                    assert error.errno==errno.EACCES
                    success=False
                assert success==allowed
            os._exit(0)
        except BaseException: os._exit(1)
    children.append(pid)
for pid in children:
    assert os.waitpid(pid,0)[1]==0,'concurrent credential isolation failed'
print('8,000 concurrent allowed/denied path walks passed.')
