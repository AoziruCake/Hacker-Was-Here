"""Tests of the public scan executable using synthetic copies only."""
import json
import os
import subprocess

root=os.environ["HWH_TEST_ROOT"]
p=subprocess.run(["/opt/hwh","scan","--root",root+"/scan-empty","--json"],capture_output=True,timeout=10)
assert p.returncode==0,(p.returncode,p.stdout,p.stderr)
r=json.loads(p.stdout)
assert r["command"]=="scan" and r["scan_status"]=="completed"
assert r["scope"]=={"kind":"quick","max_depth":4,"content_scanned":True}
assert r["findings"]==[] and r["summary"]["candidate_count"]==0
assert not p.stderr
print("PASS: empty scan completes only the declared root-children scope")
p=subprocess.run(["/opt/hwh","scan","--root",root+"/scan-small","--json"],capture_output=True,timeout=10)
assert p.returncode==1,(p.returncode,p.stdout,p.stderr)
r=json.loads(p.stdout)
assert r["summary"]["candidate_count"]==3
assert r["summary"]["group_count"]==1 and len(r["findings"])==1
assert set(r["findings"][0]["rule_ids"])=={"name.blacksuit-readme","name.play-readme","name.crypted-restore"}
assert r["findings"][0]["copy_count"]==3 and len(r["findings"][0]["paths"])==3
assert all(f["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" and f["excerpt"] is None and f["content_status"]=="complete" for f in r["findings"])
assert all(f["size_bytes"]==3 and f["mtime"] and f["reasons"] for f in r["findings"])
print("PASS: equal complete hashes aggregate while preserving name reasons")
p=subprocess.run(["/opt/hwh","scan","--root",root+"/scan-excluded","--json"],capture_output=True,timeout=10)
assert p.returncode==1,(p.returncode,p.stdout,p.stderr)
r=json.loads(p.stdout)
assert {x["reason"]:x["count"] for x in r["policy_exclusions"]}=={"directory_not_scanned":1,"symlink_excluded":1,"special_file":1,"hardlink_excluded":2}
assert r["summary"]["candidate_count"]==1 and r["scan_status"]=="completed"
assert r["findings"][0]["content_status"]=="name_only" and r["findings"][0]["sha256"] is None
assert r["errors"]==[] and r["limits"]==[] and r["errors_truncated"] is False
print("PASS: exclusions are separate from name-only candidates and coverage")
for directory, expected, limit in [("scan-many",0,"origin_entries"),("scan-candidates",2001,"candidate_paths")]:
    p=subprocess.run(["/opt/hwh","scan","--root",root+"/"+directory,"--json"],capture_output=True,timeout=40)
    assert p.returncode==2,(directory,p.returncode,p.stdout[:1000])
    r=json.loads(p.stdout)
    assert r["status"]=="partial" and r["scan_status"]=="incomplete"
    assert limit in r["limits"] and r["summary"]["candidate_count"]==expected
    assert r["coverage"]["enumerated_entries"]<=20000
    assert len(r["findings"])<=2000 and len(p.stdout)<=8*1024*1024
    if directory=="scan-candidates":
        assert r["summary"]["group_count"]==1 and len(r["findings"])==1
        assert r["findings"][0]["copy_count"]==2001
        assert len(r["findings"][0]["paths"])==2000 and r["findings"][0]["paths_truncated"]
print("PASS: enumeration and retained-candidate budgets preserve valid partial reports")
import base64
for args in [["scan","--json"],["scan","--root",root,"--quick","--quick","--json"],["scan","--root",root,"--quick","--deep","--json"],["scan","--root",root,"--quiet","--json"]]:
    p=subprocess.run(["/opt/hwh"]+args,capture_output=True,timeout=10)
    assert p.returncode==3 and json.loads(p.stdout)["command"]=="scan"
for extra in [[],["--quiet"]]:
    p=subprocess.run(["/opt/hwh","scan","--root",root+"/scan-small"]+extra,capture_output=True,timeout=10)
    assert p.returncode==1 and not p.stderr
    assert (not p.stdout) if extra else b'name.blacksuit-readme' in p.stdout
p=subprocess.run(["/opt/hwh","scan","--root",root+"/scan-hostile","--json"],capture_output=True,timeout=10)
r=json.loads(p.stdout)
assert p.returncode==1 and len(r["findings"])==1 and r["findings"][0]["copy_count"]==2
for path in r["findings"][0]["paths"]:
    raw=base64.b64decode(path["bytes_base64"])
    assert raw.endswith(b'.crypted.README_TO_RESTORE')
    display=path["display"]
    assert all(32<=ord(c)<127 for c in display)
assert b'SYNTHETIC' not in p.stdout and b'\x1b' not in p.stdout
print("PASS: hostile names remain escaped data; CLI modes and rejection retain scan identity")
from pathlib import Path
from audit import audit
import re

def traced(name, directory, code, inject=None, seconds=15):
    trace=Path('/results')/('scan-'+name+'.trace')
    command=['strace','-f','-qq','-yy','-s','256','-o',str(trace),'-e',
             'trace=open,openat,openat2,read,pread64,readv,preadv,preadv2,mmap,getdents,getdents64,statx,fstatfs,close,mount,umount2,chmod,fchmod,fchmodat,chown,fchown,fchownat,socket,connect,sendto,sendmsg,execve,execveat']
    if inject: command+=['-e','inject='+inject]
    p=subprocess.run(command+['/opt/hwh','scan','--root',directory,'--json'],capture_output=True,timeout=seconds,
                     env={**os.environ,'GOMAXPROCS':'1','GODEBUG':'asyncpreemptoff=1'})
    assert p.returncode==code,(name,p.returncode,p.stdout[:1500],p.stderr)
    r=json.loads(p.stdout)
    assert r['command']=='scan' and r['exit_code']==code and not p.stderr
    text=trace.read_text()
    audit(text,directory,bodies=True,extra_bodies={root+'/note.txt',root+'/unreadable'})
    if inject: assert 'INJECTED' in text or 'DELAYED' in text or '--- SIG' in text,(name,'injection not observed')
    print('PASS:',name)
    return r,text

r,baseline=traced('F01-F05',root,2)
assert r['errors']==[{'reason':'permission_denied','path':{'display':'"unreadable"','bytes_base64':'dW5yZWFkYWJsZQ==','display_truncated':False}}]
excluded={x['reason']:x['count'] for x in r['policy_exclusions']}
assert excluded['mount_excluded']==2 and excluded['hardlink_excluded']==3
assert excluded['symlink_excluded']==4 and excluded['special_file']==4
traced('O01-O02-O06',root+'/scan-hostile',1)
r,_=traced('directory-io',root+'/scan-small',6,'getdents64:error=EIO:when=1')
assert r['scan_status']=='incomplete' and r['reason']=='io_error'
r,_=traced('signal',root+'/scan-small',143,'getdents64:signal=SIGTERM:delay_exit=100ms:when=1')
assert r['scan_status']=='incomplete' and r['reason']=='interrupted'
r,_=traced('deadline',root+'/scan-small',2,'getdents64:delay_exit=31s:when=1',seconds=40)
assert r['scan_status']=='incomplete' and 'deadline' in r['limits']
p=subprocess.Popen(['/opt/hwh','scan','--root',root+'/scan-small','--json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p.stdout.close()
assert p.wait(timeout=10)==7
print('PASS: disconnected output exits 7')
r,_=traced('leaf-baseline',root+'/scan-small',1)
# Ordinals come from this binary's trace, keeping fault injection outside the product.
lines=Path('/results/scan-leaf-baseline.trace').read_text().splitlines()
fstatfs_ordinal=0
leaf_fstatfs=[]
seen_leaf_fstatfs=set()
for line in lines:
    if re.search(r'\bfstatfs\(',line):
        fstatfs_ordinal+=1
        match=re.search(r'fstatfs\(\d+<('+re.escape(root+'/scan-small/')+r'[^>]+)>',line)
        if match and match[1] not in seen_leaf_fstatfs:
            seen_leaf_fstatfs.add(match[1])
            leaf_fstatfs.append(fstatfs_ordinal)
ordinal=0
for line in lines:
    if re.search(r'\bopenat2\(',line):
        ordinal+=1
        if re.search(r'openat2\(\d+<'+re.escape(root+'/scan-small')+r'>,',line): break
else: raise AssertionError('leaf pin not observed')
r,_=traced('permission-flood',root+'/scan-candidates',2,'openat2:error=EACCES:when='+str(ordinal)+'+',seconds=40)
assert len(r['errors'])==200 and r['errors_truncated'] and 'error_paths' in r['limits']
assert r['summary']['candidate_count']==0 and r['coverage']['enumerated_entries']==2001
r,_=traced('target-changed',root+'/scan-candidates',5,'openat2:error=ENOENT:when='+str(ordinal+1),seconds=40)
assert r['reason']=='target_changed' and r['scan_status']=='incomplete'
assert r['summary']['candidate_count']==1 and len(r['findings'])==1
r,_=traced('io-after-candidate',root+'/scan-candidates',6,'openat2:error=EIO:when='+str(ordinal+1),seconds=40)
assert r['reason']=='io_error' and r['summary']['candidate_count']==1 and len(r['findings'])==1
r,_=traced('signal-after-candidate',root+'/scan-candidates',143,'openat2:signal=SIGTERM:delay_exit=100ms:when='+str(ordinal+1),seconds=40)
assert r['reason']=='interrupted' and r['summary']['candidate_count']>=1 and len(r['findings'])>=1
quiet_trace=Path('/results/scan-signal-quiet.trace')
quiet_command=['strace','-f','-qq','-o',str(quiet_trace),'-e','trace=openat2',
               '-e','inject=openat2:signal=SIGTERM:delay_exit=100ms:when='+str(ordinal+1),
               '/opt/hwh','scan','--root',root+'/scan-candidates','--quiet']
p=subprocess.run(quiet_command,capture_output=True,timeout=40,
                 env={**os.environ,'GOMAXPROCS':'1','GODEBUG':'asyncpreemptoff=1'})
assert p.returncode==143 and not p.stdout
assert b'interrupted:' in p.stderr and b'candidates=' in p.stderr
assert b'name.crypted-restore' not in p.stderr
assert len(leaf_fstatfs)>=2
r,_=traced('environment-changed',root+'/scan-small',5,
           'fstatfs:poke_exit=@arg2=0000000000000000:when='+str(leaf_fstatfs[1]))
assert r['reason']=='environment_changed' and r['scan_status']=='incomplete'
p=subprocess.run(['/opt/hwh','scan','--root',root+'/scan-output','--json'],capture_output=True,timeout=40)
r=json.loads(p.stdout)
assert p.returncode==2 and 'output_bytes' in r['limits']
assert len(p.stdout)<=8*1024*1024 and r['summary']['candidate_count']==2000 and r['summary']['findings_truncated']
print('PASS: output reserve preserves summary and JSON terminator with maximal byte escaping')

# Resource observation for R03, isolated from earlier subprocess peak RSS.
with open('/results/scan-resource.json-output','wb') as out:
    p=subprocess.Popen(['/opt/hwh','scan','--root',root+'/scan-many','--json'],stdout=out,stderr=subprocess.PIPE)
    pid,status,usage=os.wait4(p.pid,0)
    p.returncode=os.waitstatus_to_exitcode(status)
    assert p.returncode==2 and not p.stderr.read()
Path('/results/scan-resources.json').write_text(json.dumps({'max_rss_kib':usage.ru_maxrss,'enumerated_entries':4096}))
print('PASS: R03 bounded enumeration; max RSS KiB:',usage.ru_maxrss)
r,_=traced('feature-lost-after-candidate',root+'/scan-candidates',4,'openat2:error=ENOSYS:signal=SIGTERM:delay_exit=100ms:when='+str(ordinal+1))
assert r['reason']=='security_invariant_failed' and r['scan_status']=='incomplete'
assert len(r['findings'])==1 and r['summary']['candidate_count']==1
print('PASS: lost mandatory feature outranks cancellation and preserves validated candidate')

for extra in [[],['--quiet']]:
    p=subprocess.run(['/opt/hwh','scan','--root',root+'/quick-small',*extra],
                     capture_output=True,timeout=20)
    assert p.returncode==2 and not p.stdout
    assert b'entry_errors:' in p.stderr and b'candidates=6' in p.stderr
    assert (b'name.blacksuit-readme' not in p.stderr) if extra else (b'name.blacksuit-readme' in p.stderr)
p=subprocess.Popen(['/opt/hwh','scan','--root',root+'/quick-small'],
                   stdout=subprocess.PIPE,stderr=subprocess.PIPE)
p.stderr.close()
assert p.wait(timeout=20)==7
print('PASS: partial terminal/quiet output stays on stderr and disconnection exits 7')
