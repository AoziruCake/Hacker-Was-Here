"""Public CLI body/hash contract, using only synthetic data."""
import hashlib
import json
import os
import subprocess
import re
from pathlib import Path
from audit import audit

root=os.environ['HWH_TEST_ROOT']
def scan(name, code, inject=None):
    directory=root+'/'+name
    trace=Path('/results')/(name+('-'+inject.replace(':','-') if inject else '')+'.trace')
    command=['strace','-f','-qq','-yy','-s','256','-o',str(trace),'-e',
        'trace=open,openat,openat2,read,close,statx,fstatfs,getdents64,mmap,execve']
    if inject: command+=['-e','inject='+inject]
    p=subprocess.run(command+['/opt/hwh','scan','--root',directory,'--json'],capture_output=True,timeout=60,
                     env={**os.environ,'GOMAXPROCS':'1','GODEBUG':'asyncpreemptoff=1'})
    assert p.returncode==code,(p.returncode,p.stdout[:1000],p.stderr)
    text=trace.read_text()
    if inject: assert 'INJECTED' in text or '--- SIG' in text
    audit(text,directory,bodies=True)
    return json.loads(p.stdout),text

r,baseline=scan('scan-body-fault',1)
def ordinal(call):
    count=0
    matches=0
    for line in baseline.splitlines():
        if re.search(r'\b'+call+r'\(',line):
            count+=1
            if root+'/scan-body-fault/' in line and 'O_PATH' not in line:
                matches+=1
                if call=='statx' and matches==1: continue # pin, then reopened body
                return count
    raise AssertionError('body syscall not observed: '+call)
for call, fault, code, reason in [('openat','error=EIO',6,'io_error'),
                                ('read','error=EIO',6,'io_error'),
                                ('statx','error=ENOSYS',4,'security_invariant_failed'),
                                ('read','signal=SIGTERM:delay_exit=100ms',143,'interrupted')]:
    r,_=scan('scan-body-fault',code,call+':'+fault+':when='+str(ordinal(call)))
    assert r['scan_status']=='incomplete' and r['reason']==reason
    assert all(f['sha256'] is None for f in r['findings'])
    if call!='statx':
        assert len(r['findings'])==1 and r['findings'][0]['content_status']=='name_only'
print('PASS: public body reopen/read failure and cancellation discard hash and stop')

r,trace=scan('scan-body',2)
found={f['representative_path']['display'].strip('"').split('.')[0]:f for f in r['findings']}
assert len(found)==11 and r['coverage']['bodies_read']==7
for name in ['equal','above','sparse','denied']:
    f=found[name]
    assert f['sha256'] is None and f['content_status']=='name_only'
    assert f['content_reason']==('permission_denied' if name=='denied' else 'file_size_limit')
    for line in trace.splitlines():
        if name+'.crypted.README_TO_RESTORE>' in line:
            assert ' read(' not in line
            if name!='denied' and ' openat(' in line: raise AssertionError('oversized body opened')
payloads={'empty':b'', 'utf8':b'\xef\xbb\xbfhello', 'html':b'<script>throw 1</script>',
          'utf16':b'\xff\xfeh\x00i\x00', 'binary':b'a\x00b', 'invalid':b'\xff', 'below':b'x'*(1024*1024-1)}
for name,data in payloads.items():
    f=found[name]
    assert f['sha256']==hashlib.sha256(data).hexdigest() and f['content_status']=='complete'
    assert f['text_status']==('unsupported_encoding_or_binary' if name in ['utf16','binary','invalid'] else 'utf8')
    assert f['excerpt'] is None and f['content_reason'] is None
assert r['coverage']['read_bytes']==sum(map(len,payloads.values()))
assert r['scope']['content_scanned'] is True
assert len(r['errors'])==1 and r['errors'][0]['reason']=='permission_denied'
print('PASS: R01/F06 body policy, raw hashes, UTF-8 classification, sparse and exact boundary')
r,trace=scan('scan-total',2)
assert 'origin_read_bytes' in r['limits'] and r['scan_status']=='incomplete'
assert r['coverage']['bodies_read']==8 and r['coverage']['read_bytes']==8*(1024*1024-1)
assert sum(f['copy_count'] for f in r['findings'] if f['sha256'])==8
assert len([f for f in r['findings'] if f['content_reason']=='origin_read_bytes'])==1
print('PASS: R02 aggregate budget stops before opening next body')
