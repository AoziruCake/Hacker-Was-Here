"""Public CLI checks for bounded complete-hash aggregation."""
import base64
import json
import os
import subprocess

root=os.environ['HWH_TEST_ROOT']+'/scan-dedup'
p=subprocess.run(['/opt/hwh','scan','--root',root,'--deep','--json'],
                 capture_output=True,timeout=30)
assert p.returncode==1,(p.returncode,p.stdout[:2000],p.stderr)
assert not p.stderr and len(p.stdout)<=8*1024*1024
r=json.loads(p.stdout)
assert r['summary']['candidate_count']==5
assert r['summary']['group_count']==4
assert r['summary']['retained_group_count']==4

groups=[]
for finding in r['findings']:
    paths=[base64.b64decode(path['bytes_base64']).decode() for path in finding['paths']]
    groups.append((finding,paths))

merged,paths=next((finding,paths) for finding,paths in groups if finding['copy_count']==2)
assert set(paths)=={'a/PLAY_Readme.txt','c/README.blacksuit.txt'}
assert merged['representative_path']==merged['paths'][0]
assert set(merged['rule_ids'])=={'name.play-readme','name.blacksuit-readme'}
assert not merged['paths_truncated'] and merged['sha256']

different=next(finding for finding,paths in groups if paths==['b/PLAY_Readme.txt'])
assert different['copy_count']==1 and different['sha256']!=merged['sha256']
hashless=[finding for finding,_ in groups if finding['sha256'] is None]
assert len(hashless)==2 and all(finding['copy_count']==1 for finding in hashless)
assert all(finding['content_status']=='name_only' and
           finding['content_reason']=='file_size_limit' for finding in hashless)

p=subprocess.run(['/opt/hwh','scan','--root',root,'--deep'],
                 capture_output=True,timeout=30)
assert p.returncode==1 and not p.stderr
assert b'copies=2' in p.stdout and b'paths_truncated=false' in p.stdout
assert b'identical synthetic note' not in p.stdout

p=subprocess.run(['/opt/hwh','scan','--root',
                  os.environ['HWH_TEST_ROOT']+'/scan-candidate-bytes','--deep','--json'],
                 capture_output=True,timeout=30)
assert p.returncode==2,(p.returncode,p.stdout[:2000],p.stderr)
r=json.loads(p.stdout)
assert r['summary']['candidate_count']==600 and r['summary']['group_count']==1
assert r['findings'][0]['copy_count']==600 and r['findings'][0]['paths_truncated']
assert 'candidate_bytes' in r['limits'] and 'candidate_paths' not in r['limits']

p=subprocess.run(['/opt/hwh','scan','--root',
                  os.environ['HWH_TEST_ROOT']+'/scan-error-bytes','--deep','--json'],
                 capture_output=True,timeout=30)
assert p.returncode==2,(p.returncode,p.stdout[:2000],p.stderr)
r=json.loads(p.stdout)
assert r['summary']['candidate_count']==70 and len(r['errors'])<70
assert r['errors_truncated'] and 'error_bytes' in r['limits']
assert 'error_paths' not in r['limits']
print('PASS: R08 grouping, hashless candidates, terminal counts and byte budgets')
