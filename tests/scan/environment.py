"""Trusted parent changes only its disposable synthetic fixture mount."""
import subprocess
import os
import json
root=os.environ['HWH_TEST_ROOT']
user=['setpriv','--reuid=1000','--regid=1000','--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','/opt/hwh']
p=subprocess.run(user+['check','--root',root,'--json'],capture_output=True,check=True)
try:
    subprocess.run(['mount','-o','remount,bind,rw,nodev,nosuid,noexec',root],check=True)
    p=subprocess.run(user+['scan','--root',root,'--json'],capture_output=True)
    assert p.returncode==3 and json.loads(p.stdout)['reason']=='unsupported_mount'
    assert json.loads(p.stdout)['scan_status']=='not_started'
finally:
    subprocess.run(['mount','-o','remount,bind,ro,nodev,nosuid,noexec',root],check=True)
print('PASS: E10 scan rejects changed conditions after successful check')
