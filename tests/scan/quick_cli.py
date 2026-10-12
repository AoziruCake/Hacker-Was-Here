"""Public quick contract and independent syscall observation on synthetic data."""
import base64
import json
import os
import re
import subprocess
import time
from pathlib import Path
from audit import audit

root=os.environ['HWH_TEST_ROOT']
def scan(name, code, extra=(), traced=False):
    directory=root+'/'+name
    command=['/opt/hwh','scan','--root',directory,'--json',*extra]
    trace=Path('/results')/(name+'.trace')
    if traced:
        command=['strace','-f','-qq','-ttt','-yy','-s','256','-o',str(trace),'-e',
          'trace=open,openat,openat2,read,pread64,readv,preadv,preadv2,mmap,getdents64,statx,fstatfs,close,mount,umount2,chmod,fchmod,fchmodat,chown,fchown,fchownat,socket,connect,sendto,sendmsg,execve,execveat']+command
    start=time.monotonic()
    p=subprocess.run(command,capture_output=True,timeout=60,
        env={**os.environ,'GOMAXPROCS':'1','GODEBUG':'asyncpreemptoff=1'})
    elapsed=time.monotonic()-start
    assert p.returncode==code,(name,p.returncode,p.stdout[:2000],p.stderr)
    assert not p.stderr and len(p.stdout)<=8*1024*1024
    r=json.loads(p.stdout)
    assert r['coverage']['enumerated_entries']<=20000
    assert r['coverage']['read_bytes']<=64*1024*1024
    assert len(r['origins'])==15
    assert sum(o['enumerated_entries'] for o in r['origins'])==r['coverage']['enumerated_entries']
    assert sum(o['read_bytes'] for o in r['origins'])==r['coverage']['read_bytes']
    assert all(o['read_bytes']<=8*1024*1024 and o['enumerated_entries']<=4096 for o in r['origins'])
    return r, trace.read_text() if traced else '',elapsed

r,trace,_=scan('quick-small',2,traced=True)
paths=[base64.b64decode(p['bytes_base64']).decode() for f in r['findings'] for p in f['paths']]
assert set(paths)=={'home/alice/PLAY_Readme.txt','home/alice/a/b/README.blacksuit.txt',
                   'srv/README.blacksuit.txt','tmp/PLAY_Readme.txt','opt/PLAY_Readme.txt',
                   'etc/motd'}
assert len(paths)==len(set(paths))==6
assert len(r['findings'])==2
assert sorted(f['copy_count'] for f in r['findings'])==[1,5]
fixed=next(f for f in r['findings'] if
           base64.b64decode(f['representative_path']['bytes_base64']).decode()=='etc/motd')
assert fixed['rule_ids']==['content.encryption-recovery-payment']
assert fixed['detection_basis']=='content_pattern' and fixed['content_status']=='complete'
assert fixed['sha256'] is not None
named=next(f for f in r['findings'] if f is not fixed)
assert set(named['rule_ids'])=={'name.play-readme','name.blacksuit-readme'}
ex={e['reason']:e['count'] for e in r['policy_exclusions']}
assert ex['symlink_excluded']==3 and ex['mount_excluded']==2 and ex['special_file']==1 and ex['depth_limit']==1
assert len(r['errors'])==1 and r['errors'][0]['reason']=='permission_denied'
origins={o['path']:o['status'] for o in r['origins']}
assert origins['backup']=='incomplete' and origins['backups']=='not_present'
assert all(origins[p]=='completed' for p in ['etc/motd','tmp/motd','tmp/index.html'])
directory=root+'/quick-small'
dirs={directory+'/'+p for p in ['home','home/alice','home/alice/a','home/alice/a/b','srv','tmp','etc','opt','data','backup']}
dirs.add(directory)
plain=re.sub(r'(?m)^(\d+)\s+\d+\.\d+\s+',r'\1 ',trace)
peak=audit(plain,directory,bodies=True,directories=dirs)
# Each fixed file is pinned once, then regular files are reopened only from that pin.
for fixed in ['etc/motd','tmp/motd','tmp/index.html']:
    assert len(re.findall(r'openat2\([^\n]*"'+re.escape(fixed)+r'"',trace))==1
opened=re.findall(r'openat\(\d+</proc/\d+/fd>, "\d+", [^\n]*O_DIRECTORY[^\n]* = \d+<([^>]+)>',trace)
owned=[p for p in opened if p==directory or p.startswith(directory+'/')]
# Admission opens and closes root once before traversal.
assert owned.count(directory)==2
assert all(owned.count(d)==1 for d in set(owned)-{directory})
r2,_,_=scan('quick-small',2,extra=['--quick'])
for report in (r,r2): report.pop('finished_at')
assert r==r2
print('PASS: quick paths/depth/overlap/default flag, F01-F03 recursive boundaries; peak FD',peak)

r,trace,elapsed=scan('quick-fair',2,traced=True)
assert 'origin_entries' in r['limits'] and r['summary']['candidate_count']==2
o={o['path']:o for o in r['origins']}
assert o['home']['enumerated_entries']==4096 and o['home']['status']=='incomplete'
assert o['opt']['status']=='completed'
first_candidate=next(i for i,l in enumerate(trace.splitlines()) if '/quick-fair/opt/PLAY_Readme.txt>' in l)
last_home=max(i for i,l in enumerate(trace.splitlines()) if 'getdents64(' in l and '/quick-fair/home>' in l)
assert first_candidate<last_home
times=[float(m[1]) for m in re.finditer(r'(?m)^\d+\s+(\d+\.\d+)\s+',trace)]
candidate_time=float(re.search(r'^\d+\s+(\d+\.\d+)',trace.splitlines()[first_candidate])[1])-times[0]
plain=re.sub(r'(?m)^(\d+)\s+\d+\.\d+\s+',r'\1 ',trace)
peak=audit(plain,root+'/quick-fair',bodies=True,directories=[root+'/quick-fair'+p for p in ['', '/home','/srv','/opt']])
observations={'traced_elapsed_seconds':elapsed,'later_candidate_pin_seconds':candidate_time,'peak_observed_fds':peak,'enumerated_entries':r['coverage']['enumerated_entries'],'read_bytes':r['coverage']['read_bytes']}
print('PASS: huge early origin yields to later candidates and closes all owned FDs')

r,_,_=scan('quick-queues',2)
assert 'queued_paths' in r['limits'] and 'origin_entries' in r['limits']
r,_,_=scan('quick-global',2)
assert r['coverage']['enumerated_entries']==20000 and 'enumeration_entries' in r['limits']
r,_,_=scan('quick-read',2)
assert 'origin_read_bytes' in r['limits'] and 'total_read_bytes' in r['limits']
assert r['coverage']['bodies_read']==64 and r['coverage']['read_bytes']==64*(1024*1024-1)
assert next(o for o in r['origins'] if o['path']=='opt')['status']=='incomplete'
print('PASS: queue/global enumeration and origin/global read budgets preserve partial coverage')

with open('/results/quick-resource-output.json','wb') as out:
    start=time.monotonic()
    p=subprocess.Popen(['/opt/hwh','scan','--root',root+'/quick-fair','--json'],stdout=out,stderr=subprocess.PIPE)
    _,status,usage=os.wait4(p.pid,0)
    p.returncode=os.waitstatus_to_exitcode(status)
    assert p.returncode==2 and not p.stderr.read()
observations.update(max_rss_kib=usage.ru_maxrss,untraced_elapsed_seconds=time.monotonic()-start)
Path('/results/quick-resources.json').write_text(json.dumps(observations))
print('PASS: V03 initial observations',observations)
