"""Public deep contract and bounded traversal on synthetic data."""
import base64
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

from audit import audit

root=os.environ['HWH_TEST_ROOT']

def scan(name, code, traced=False):
    directory=root+'/'+name
    command=['/opt/hwh','scan','--root',directory,'--deep','--json']
    trace=Path('/results')/('deep-'+name+'.trace')
    if traced:
        command=['strace','-f','-qq','-yy','-s','256','-o',str(trace),'-e',
          'trace=open,openat,openat2,read,pread64,readv,preadv,preadv2,mmap,getdents64,statx,fstatfs,close,mount,umount2,chmod,fchmod,fchmodat,chown,fchown,fchownat,socket,connect,sendto,sendmsg,execve,execveat']+command
    started=time.monotonic()
    p=subprocess.run(command,capture_output=True,timeout=320,
        env={**os.environ,'GOMAXPROCS':'1','GODEBUG':'asyncpreemptoff=1'})
    elapsed=time.monotonic()-started
    assert p.returncode==code,(name,p.returncode,p.stdout[:2000],p.stderr)
    assert not p.stderr and len(p.stdout)<=8*1024*1024
    report=json.loads(p.stdout)
    assert report['scope']=={'kind':'deep','max_depth':64,'content_scanned':True}
    assert report['coverage']['enumerated_entries']<=200000
    assert report['coverage']['read_bytes']<=512*1024*1024
    assert report['origins'][0]['path']=='.' and report['origins'][0]['max_depth']==64
    assert len(report['origins'])==1
    return report,trace.read_text() if traced else '',elapsed

quick=subprocess.run(['/opt/hwh','scan','--root',root+'/deep-small','--quick','--json'],
                     capture_output=True,timeout=30)
assert quick.returncode==0 and json.loads(quick.stdout)['summary']['candidate_count']==0
r,trace,_=scan('deep-small',1,traced=True)
paths=[base64.b64decode(f['representative_path']['bytes_base64']).decode() for f in r['findings']]
assert paths==['a/b/c/d/e/PLAY_Readme.txt']
excluded={x['reason']:x['count'] for x in r['policy_exclusions']}
assert excluded['symlink_excluded']==1 and excluded['special_file']==1 and excluded['mount_excluded']==2
directory=root+'/deep-small'
dirs={directory}
current=directory
for part in ['a','b','c','d','e']:
    current+='/'+part
    dirs.add(current)
plain=re.sub(r'(?m)^(\d+)\s+\d+\.\d+\s+',r'\1 ',trace)
peak=audit(plain,directory,bodies=True,directories=dirs)
print('PASS: deep adds the out-of-quick candidate while preserving boundaries; peak FD',peak)

interrupt_root=root+'/deep-interrupt'
interrupted_process=subprocess.Popen(
    ['/opt/hwh','scan','--root',interrupt_root,'--deep','--json'],
    stdout=subprocess.PIPE,stderr=subprocess.PIPE)
time.sleep(0.3)
assert interrupted_process.poll() is None,'deep interruption fixture completed before signal'
interrupted_process.send_signal(signal.SIGINT)
stdout,stderr=interrupted_process.communicate(timeout=40)
assert interrupted_process.returncode==130,(interrupted_process.returncode,stdout[:2000],stderr)
interrupted=json.loads(stdout)
assert interrupted['reason']=='interrupted' and interrupted['scan_status']=='incomplete'
assert interrupted['summary']['candidate_count']>=2 and len(interrupted['findings'])==1, interrupted['summary']
assert interrupted['findings'][0]['copy_count']>=2, interrupted['findings'][0]
print('PASS: deep aggregation preserves validated candidates on cooperative SIGINT')

r,_,_=scan('deep-depth',1)
paths=[base64.b64decode(f['representative_path']['bytes_base64']).decode() for f in r['findings']]
assert len(paths)==1 and paths[0].endswith('/README.blacksuit.txt')
assert {x['reason']:x['count'] for x in r['policy_exclusions']}['depth_limit']==1
assert 'PLAY_Readme.txt' not in ''.join(paths)
print('PASS: depth 64 is included but deeper directory contents remain unexplored')

r,_,elapsed=scan('deep-queues',2)
assert 'queued_paths' in r['limits']
assert r['coverage']['enumerated_entries']==4100 and r['scan_status']=='incomplete'
r,_,_=scan('deep-long',2)
assert 'path_bytes' in r['limits'] and r['scan_status']=='incomplete'
print('PASS: deep queue and path-byte limits stop finitely')

p=subprocess.run([
    'strace','-f','-qq','-o','/results/deep-signal.trace','-e',
    'trace=getdents64','-e','inject=getdents64:signal=SIGTERM:delay_exit=100ms:when=1',
    '/opt/hwh','scan','--root',root+'/deep-small','--deep','--json'
],capture_output=True,timeout=30)
assert p.returncode==143,(p.returncode,p.stdout,p.stderr)
assert json.loads(p.stdout)['reason']=='interrupted'

for args in [
    ['scan','--root',root+'/deep-small','--quick','--deep','--json'],
    ['scan','--root',root+'/deep-small','--deep','--deep','--json'],
    ['check','--root',root+'/deep-small','--deep','--json'],
]:
    p=subprocess.run(['/opt/hwh',*args],capture_output=True,timeout=10)
    assert p.returncode==3 and json.loads(p.stdout)['reason']=='invalid_arguments'

with open('/results/deep-resource-output.json','wb') as out:
    started=time.monotonic()
    measured=subprocess.Popen(['/opt/hwh','scan','--root',root+'/deep-queues','--deep','--json'],
                              stdout=out,stderr=subprocess.PIPE)
    _,status,usage=os.wait4(measured.pid,0)
    measured.returncode=os.waitstatus_to_exitcode(status)
    assert measured.returncode==2 and not measured.stderr.read()
resource_elapsed=time.monotonic()-started

Path('/results/deep-resources.json').write_text(json.dumps({
    'queue_elapsed_seconds':elapsed,
    'resource_elapsed_seconds':resource_elapsed,
    'max_rss_kib':usage.ru_maxrss,
    'peak_observed_fds':peak,
    'queue_enumerated_entries':4100,
}))
print('PASS: explicit mode conflict and cooperative SIGTERM; V03 initial observations recorded')
