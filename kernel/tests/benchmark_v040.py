#!/usr/bin/env python3
"""
Module: kernel.tests.benchmark_v040
Purpose: Fresh matched images, alternating order, one warm-up and seven measured rounds.
Created: 2026-10-01
Architecture: Disposable fixtures exercise the production core or its mounted adapter and verify resulting state.

Fresh matched images, alternating order, one warm-up and seven measured rounds.
"""
from pathlib import Path
import hashlib,json,os,platform,shutil,statistics,subprocess,tempfile,time
from benchmark_writes import measure_round,timed
from run_wsl_fresh_benchmark import run,mounted
ROOT=Path(__file__).resolve().parents[2]
def additional(m):
 result={}
 for name,size,block in [('resident_fsync_1b_100',128,b'R'),('overwrite_fsync_4k_100',1<<20,b'W'*4096)]:
  p=m/name
  with p.open('wb',buffering=0) as f:
   f.write(bytes(size));os.fsync(f.fileno())
   def action():
    for _ in range(100):f.seek(0);f.write(block);os.fsync(f.fileno())
   result[name]=timed(action)
  assert p.read_bytes()==block+bytes(size-len(block))
  p.unlink()
 p=m/'idle';p.write_bytes(b'idle')
 with p.open('rb') as f:
  os.fsync(f.fileno())
  def action():
   for _ in range(1000):os.fsync(f.fileno())
  result['idle_fsync_1000']=timed(action)
 p.unlink();return result
run('insmod',str(ROOT/'kernel/slate-ntfs.ko'))
samples={driver:{} for driver in ['slate_ntfs','slate_linux','ntfs3g']}
start=time.time()
try:
 with tempfile.TemporaryDirectory(prefix='slate-v040-bench-',dir='/var/tmp') as d:
  base=Path(d);source=base/'source.img';source.touch();os.truncate(source,128<<20)
  run('mkntfs','-F','-Q','-c','4096',str(source),capture_output=True)
  for round in range(8):
   order=list(samples)
   order=order[round%3:]+order[:round%3]
   if round%2:order.reverse()
   for driver in order:
    image=base/(driver+'.img');m=base/driver;m.mkdir(exist_ok=True);shutil.copyfile(source,image);loop=None
    try:
     if driver=='slate_linux':
      loop=run('losetup','--find','--show',str(image),capture_output=True,text=True).stdout.strip()
      run('mount','-t','ntfsrs','-o','rw,compatibility=linux,sidmap=u:0:S-1-5-32-544;g:0:S-1-5-18',loop,str(m))
     else:loop=mounted(m,image,'slate' if driver=='slate_ntfs' else 'ntfs3g')
     values={**measure_round(m),**additional(m)}
     if round:
      for name,value in values.items():samples[driver].setdefault(name,[]).append(value)
     print('round',round,driver,json.dumps(values),flush=True)
    finally:
     if os.path.ismount(m):run('umount',str(m))
     if loop:run('losetup','-d',loop)
finally:run('rmmod','slate_ntfs')
results={driver:{name:{'median_seconds':statistics.median(v),'min_seconds':min(v),'max_seconds':max(v),'rounds':v} for name,v in workloads.items()} for driver,workloads in samples.items()}
version=subprocess.run(['ntfs-3g','--version'],capture_output=True,text=True)
report={'kernel':platform.release(),'os_release':Path('/etc/os-release').read_text(),'started_unix':start,'finished_unix':time.time(),'ntfs3g':version.stdout+version.stderr,'module_sha256':hashlib.sha256((ROOT/'kernel/slate-ntfs.ko').read_bytes()).hexdigest(),'results':results}
Path('/results/benchmark-v040.json').write_text(json.dumps(report,indent=2))
print('PASS all workload byte checks; seven measured rounds per driver',flush=True)
