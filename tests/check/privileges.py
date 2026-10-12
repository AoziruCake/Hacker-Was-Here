"""Trusted fixture supervisor exercises public CLI credentials and proc mounts."""
import json
import os
import subprocess

assert os.getuid() == 0
root = os.environ["HWH_TEST_ROOT"]
command = ["/opt/hwh", "check", "--root", root, "--json"]
cases = [
    ("E03-root", [], 3, "privileged_execution"),
    ("E03-uid-mismatch", ["setpriv","--ruid=1000","--euid=1001","--regid=1000","--clear-groups"],3,"privileged_execution"),
    ("E03-gid-mismatch", ["setpriv","--reuid=1000","--rgid=1000","--egid=1001","--clear-groups"],3,"privileged_execution"),
    ("E03-capabilities", ["setpriv","--reuid=1000","--regid=1000","--clear-groups","--inh-caps=+chown","--ambient-caps=+chown"],3,"privileged_execution"),
    ("E03-bounding-only", ["setpriv","--reuid=1000","--regid=1000","--clear-groups"],0,"conditions_passed"),
]
for name, prefix, code, reason in cases:
    p = subprocess.run(prefix+command, capture_output=True, timeout=10)
    assert p.returncode==code and json.loads(p.stdout)["reason"]==reason, (name,p.returncode,p.stdout,p.stderr)
    print("PASS:",name)

# A private mount namespace shields all other tests from the fake host procfs.
fake = ["unshare","--mount","--propagation","private","/bin/sh","-eu","-c",
        'mount -t tmpfs -o nodev,nosuid,noexec tmpfs /proc; exec setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs /opt/hwh check --root "$1" --json',"fixture",root]
p = subprocess.run(fake,capture_output=True,timeout=10)
assert p.returncode==3 and json.loads(p.stdout)["reason"]=="unsupported_environment",(p.returncode,p.stdout,p.stderr)
print("PASS: E05-fake-procfs")
