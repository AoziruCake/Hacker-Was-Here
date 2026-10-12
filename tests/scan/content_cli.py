"""Synthetic corpus expectations were defined before the content matcher."""
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path
from audit import audit

cases=json.loads(Path('/src/tests/scan/content_cases.json').read_text())
root=os.environ['HWH_TEST_ROOT']+'/scan-content'
trace=Path('/results/content.trace')
command=['strace','-f','-qq','-yy','-s','256','-o',str(trace),'-e',
 'trace=open,openat,openat2,read,pread64,readv,preadv,preadv2,mmap,getdents64,statx,fstatfs,close,mount,umount2,chmod,fchmod,fchmodat,chown,fchown,fchownat,socket,connect,sendto,sendmsg,execve,execveat']
p=subprocess.run(command+['/opt/hwh','scan','--root',root,'--json'],capture_output=True,timeout=60)
assert p.returncode==1 and not p.stderr
r=json.loads(p.stdout)
assert r['scan_status']=='completed' and r['scope']['content_scanned']
findings={
    base64.b64decode(path['bytes_base64']).decode():finding
    for finding in r['findings'] for path in finding['paths']
}
metrics={rule:dict(tp=0,fp=0,fn=0,tn=0) for rule in ['payment','contact']}
for case in cases:
    f=findings.get(case['name'])
    expected=['content.encryption-recovery-'+rule for rule in case['rules']]
    actual=[rule for rule in (f['rule_ids'] if f else []) if rule.startswith('content.')]
    assert actual==expected,case['name']
    if f:
        assert f['detection_basis']=='content_pattern' and f['content_status']=='complete'
        assert f['sha256']==hashlib.sha256(case['text'].encode()).hexdigest()
        assert f['text_status']=='utf8' and f['excerpt'] is None
    for rule,m in metrics.items():
        # Each rule alone against the semantic label; alternative-branch misses count.
        m[('t' if case['positive'] else 'f')+'p' if rule in case['rules'] else ('f' if case['positive'] else 't')+'n']+=1
assert findings['PLAY_Readme.txt']['detection_basis']=='name_pattern'
assert findings['README.blacksuit.txt']['detection_basis']=='content_pattern'
assert len(findings['README.blacksuit.txt']['rule_ids'])==2
assert findings['README.blacksuit.txt']['copy_count']==2
assert len(r['findings'])==sum(bool(c['rules']) for c in cases)+1
assert r['summary']['candidate_count']==sum(bool(c['rules']) for c in cases)+2
assert r['coverage']['bodies_read']==len(cases)+2
audit(trace.read_text(),root,bodies=True,extra_bodies={root+'/'+c['name'] for c in cases})
p=subprocess.run(['/opt/hwh','scan','--root',root],capture_output=True,timeout=30)
assert p.returncode==1 and not p.stderr
assert b'content.encryption-recovery-payment' in p.stdout and b'content.encryption-recovery-contact' in p.stdout
assert b'detection_basis=content_pattern' in p.stdout and b'detection_basis=name_pattern' in p.stdout
for forbidden in [b'FAKE_RESULT',b'/bin/sh',b'invalid.example',b'\x1b','\u202e'.encode()]:
    assert forbidden not in p.stdout
assert not Path('/tmp/hwh-untrusted-executed').exists()
metrics['combined']={k:sum(1 for c in cases if (('t' if c['positive'] else 'f')+'p' if c['rules'] else ('f' if c['positive'] else 't')+'n')==k) for k in ['tp','fp','fn','tn']}
Path('/results/content-evaluation.json').write_text(json.dumps(metrics,indent=2))
print('PASS: content corpus, raw hashes, name/content basis, O01/O06 and syscall audit',metrics)
