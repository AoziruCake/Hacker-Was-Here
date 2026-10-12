"""Public executable contract tests; only synthetic inputs."""
import json
import os
import posixpath
import base64
from pathlib import Path
import re
import subprocess

p = subprocess.run(["/opt/hwh", "check", "--json"], capture_output=True, timeout=10)
assert p.returncode == 3, (p.returncode, p.stdout, p.stderr)
report = json.loads(p.stdout)
assert report["schema_version"] == 1
assert report["command"] == "check"
assert report["status"] == "rejected"
assert report["reason"] == "invalid_root"
assert report["scan_status"] == "not_started"
assert report["root"] is None and report["findings"] == []
assert not p.stderr
print("PASS: missing root rejected as structured JSON")

root = os.environ.get("HWH_TEST_ROOT")
if root:
    p = subprocess.run(["/opt/hwh", "check", "--root", root, "--json"], capture_output=True, timeout=10)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    report = json.loads(p.stdout)
    assert report["status"] == "passed" and report["reason"] == "conditions_passed"
    assert report["scan_status"] == "not_started" and report["findings"] == []
    print("PASS: prepared copy passes check without claiming scan completion")
    for invalid in ["relative", "/", root+"/..", root+"/missing", root+"/note.txt", root+"/in-link", root+"/ancestor-link/note.txt"]:
        p = subprocess.run(["/opt/hwh", "check", "--root", invalid, "--json"], capture_output=True, timeout=10)
        assert p.returncode == 3, (invalid, p.returncode, p.stdout)
        assert json.loads(p.stdout)["reason"] == "invalid_root", p.stdout
    print("PASS: E01/E02 invalid and linked root paths rejected")

def audit(text):
    pending = {}
    calls = []
    for line in text.splitlines():
        match = re.match(r"(\d+)\s+(.*)",line)
        assert match, "unrecognized trace line"
        pid,call = match.groups()
        if call.endswith("<unfinished ...>"):
            assert pid not in pending
            pending[pid]=call.removesuffix("<unfinished ...>")
        elif call.startswith("<... "):
            assert pid in pending
            calls.append(pending.pop(pid)+call.split("resumed>",1)[1])
        else:
            calls.append(call)
    assert not pending, "incomplete observation"
    text="\n".join(calls)
    assert not re.search(r"\bgetdents(?:64)?\(", text), "directory enumeration"
    assert not re.search(r"\b(?:read|pread64|readv|preadv|preadv2)\(\d+</fixture-store/", text), "target read"
    assert not re.search(r"\bmmap\(.*\d+</fixture-store/", text), "target mmap"
    assert not re.search(r"\b(?:mount|umount2|chmod|fchmod|fchmodat|chown|fchown|fchownat)\(", text), "environment mutation"
    pins = {}
    for line in text.splitlines():
        if re.match(r"(?:open|openat|openat2)\(", line):
            result=re.search(r"= (\d+)<([^>]+)>",line)
            target=result[2] if result else None
            if "O_PATH" in line:
                if result:
                    pins[result[1]]=target
                continue
            via_proc=re.search(r'openat\(\d+</proc/\d+/fd>, "(\d+)"',line)
            if via_proc:
                target=pins.get(via_proc[1])
                assert target is not None, "reopen without live pin"
            elif target is None:
                direct=re.match(r'open\("([^"\\]+)"',line)
                relative=re.match(r'openat2?\((?:\d+<([^>]+)>|AT_FDCWD(?:<[^>]+>)?), "([^"\\]+)"',line)
                if direct:
                    target=direct[1]
                elif relative:
                    directory,name=relative.groups()
                    target=posixpath.normpath(posixpath.join(directory or "/src",name))
                if "/fixture-store/" in line:
                    assert target is not None, "unparsed fixture open attempt"
            if target and target.startswith("/fixture-store/"):
                assert "O_DIRECTORY" in line, "body open attempt"
        closed=re.match(r"close\((\d+)(?:<[^>]+>)?\) = 0$",line)
        if closed:
            pins.pop(closed[1],None)

# Negative controls ensure the monitor itself rejects forbidden operations.
for forbidden in ['1 read(8</fixture-store/canary>, "x", 1) = 1',
                  '1 getdents64(8</fixture-store/root>, [], 1024) = 0',
                  '1 openat(3</proc/1/fd>, "8", O_RDONLY) = 9</fixture-store/canary>',
                  '1 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 8</fixture-store/canary>, 0) = 0x1234',
                  '1 openat(3</proc/1/fd>, "8", O_RDONLY <unfinished ...>\n1 <... openat resumed>) = 9</fixture-store/canary>',
                  '1 chmod("/fixture-store/root", 0777) = 0']:
    try:
        audit(forbidden)
    except AssertionError:
        continue
    raise AssertionError("audit negative control accepted: "+forbidden)

for forbidden in [
    '1 openat(3</fixture-store/root>, "fifo", O_RDONLY|O_NONBLOCK) = -1 EACCES (Permission denied)',
    '1 openat(AT_FDCWD</src>, "/fixture-store/canary", O_RDONLY) = -1 EACCES (Permission denied)',
    '1 openat2(3</fixture-store/root>, "fifo", {flags=O_PATH}, 24) = 8</fixture-store/root/fifo>\n1 openat(3</proc/1/fd>, "8", O_RDONLY) = -1 EACCES (Permission denied)',
]:
    try:
        audit(forbidden)
    except AssertionError:
        continue
    raise AssertionError("audit accepted failed forbidden open: "+forbidden)

def check_case(name, args, code, reason=None, inject=None):
    trace = Path("/results") / ("check-"+name+".trace")
    command = ["strace", "-f", "-qq", "-yy", "-s", "256", "-o", str(trace),
               "-e", "trace=open,openat,openat2,read,pread64,readv,preadv,preadv2,mmap,getdents,getdents64,statx,fstatfs,close,mount,umount2,chmod,fchmod,fchmodat,chown,fchown,fchownat"]
    if inject:
        command += ["-e", "inject="+inject]
    p = subprocess.run(command+["/opt/hwh"]+args, capture_output=True, timeout=15,
                       env={**os.environ, "GOMAXPROCS":"1", "GODEBUG":"asyncpreemptoff=1"})
    assert p.returncode == code, (name, p.returncode, p.stdout, p.stderr)
    if reason:
        report = json.loads(p.stdout)
        assert report["reason"] == reason and report["exit_code"] == code, (name, report)
        assert report["scan_status"] == "not_started" and report["findings"] == []
        assert not p.stderr, (name, p.stderr)
    text = trace.read_text()
    audit(text)
    if inject:
        observed = ("--- "+inject.split("signal=")[1].split(":")[0]) in text if "signal=" in inject else "INJECTED" in text
        assert observed, (name, "fault injection not observed")
    print("PASS:", name)
    return p, text

if root:
    p, baseline = check_case("E08", ["check","--root",root,"--json"], 0, "conditions_passed")
    assert base64.b64decode(json.loads(p.stdout)["root"]["bytes_base64"]) == os.fsencode(root)
    for i,path in enumerate(["relative","/",root+"/..",root+"/missing",root+"/note.txt",root+"/in-link",root+"/ancestor-link/note.txt"]):
        check_case("E01-E02-"+str(i),["check","--root",path,"--json"],3,"invalid_root")
    check_case("E01-missing",["check","--json"],3,"invalid_root")
    # Determine the per-thread read ordinal from observed startup, not a Go-version constant.
    counts = {}
    mount_read = None
    for line in baseline.splitlines():
        match = re.match(r"(\d+)\s+read\(", line)
        if match:
            pid = match[1]
            counts[pid] = counts.get(pid, 0) + 1
            if re.search(r"</proc/\d+/mountinfo>.*?, 4096\)", line):
                mount_read = counts[pid]
                break
    assert mount_read is not None, "safefs mountinfo read not observed"
    first_id = Path("/proc/self/mountinfo").read_bytes().split(b" ", 1)[0]
    for name, replacement in [("bad-id", b"x"*len(first_id)), ("zero-id", b"0"*len(first_id))]:
        check_case("E09-"+name,["check","--root",root,"--json"],3,"unsupported_environment",
                   "read:poke_exit=@arg2="+replacement.hex()+":when="+str(mount_read))
    _,budget_trace=check_case("E09-byte-budget",["check","--root",root,"--json"],3,"unsupported_environment",
               "read:retval=4096:when="+str(mount_read)+"+")
    assert len(re.findall(r"read\(\d+</proc/\d+/mountinfo>.*4096\).*INJECTED",budget_trace))==256
    check_case("E09-line-budget",["check","--root",root,"--json"],3,"unsupported_environment",
               "read:retval=128:poke_exit=@arg2="+(b"\n"*128).hex()+":when="+str(mount_read)+".."+str(mount_read+64))
    check_case("io-error",["check","--root",root,"--json"],6,"io_error","statx:error=EIO:when=1")
    check_case("metadata-io-error",["check","--root",root,"--json"],6,"io_error","read:error=EIO:when="+str(mount_read))
    check_case("io-over-signal",["check","--root",root,"--json"],6,"io_error","statx:error=EIO:signal=SIGTERM:delay_exit=100ms:when=1")
    mount_data=Path("/proc/self/mountinfo").read_bytes()
    first_size=int(re.search(r"read\(\d+</proc/\d+/mountinfo>.*?, 4096\) = (\d+)",baseline)[1])
    fields=mount_data[first_size:].splitlines()[0].split(b" ")
    assert fields[4]==os.fsencode(root), "fixture mount must start the second kernel chunk for these faults"
    prefix=b" ".join(fields[:3])+b" "
    for name,replacement,reason in [
        ("missing-id", b"9"*len(fields[0])+prefix[len(fields[0]):],"unsupported_mount"),
        ("device-mismatch", prefix[:-2]+(b"1" if prefix[-2:-1]!=b"1" else b"2")+b" ","unsupported_environment"),
    ]:
        check_case("E09-"+name,["check","--root",root,"--json"],3,reason,
                   "read:poke_exit=@arg2="+replacement.hex()+":when="+str(mount_read+1))
    for sig,code in [("SIGINT",130),("SIGTERM",143)]:
        check_case("signal-"+sig,["check","--root",root,"--json"],code,"interrupted",
                   "openat2:signal="+sig+":delay_exit=100ms:when=1")
    # A consumer that closes stdout must produce exit 7, not death by SIGPIPE.
    p = subprocess.Popen(["/opt/hwh","check","--root",root,"--json"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    p.stdout.close()
    err = p.stderr.read()
    assert p.wait(timeout=10)==7 and not err, (p.returncode,err)
    print("PASS: output-disconnected")
    for name, args in {
        "unknown":["check","--no-such-option","--json"],
        "duplicate":["check","--root",root,"--root",root,"--json"],
        "conflict":["check","--root",root,"--quiet","--json"],
        "quick":["check","--root",root,"--quick","--json"],
        "help-conflict":["check","--help","--json"],
    }.items():
        check_case(name,args,3,"invalid_arguments")
    for args in [["--help"],["check","--help"],["--version"]]:
        p,_=check_case("info-"+str(len(args))+args[-1],args,0)
        assert p.stdout and not p.stderr
    p,_=check_case("quiet",["check","--root",root,"--quiet"],0)
    assert not p.stdout and not p.stderr
    for flag in ["nodev","nosuid","noexec"]:
        check_case("E06-"+flag,["check","--root",os.path.dirname(root)+"/missing-"+flag,"--json"],3,"unsupported_mount")
    check_case("E06-rw",["check","--root",os.environ["HWH_TEST_WRITABLE"],"--json"],3,"unsupported_mount")
    for name,path in [("tmpfs",root+"/otherfs"),("overlay","/src")]:
        check_case("E07-"+name,["check","--root",path,"--json"],3,"unsupported_mount")
    for syscall in ["openat2","statx"]:
        for error in ["ENOSYS","EINVAL","EPERM"]:
            check_case("E04-"+syscall+error,["check","--root",root,"--json"],3,"unsupported_environment",syscall+":error="+error)
    check_case("E04-statx-mask",["check","--root",root,"--json"],3,"unsupported_environment","statx:poke_exit=@arg5=00000000")
    check_case("E04-reopened-mask",["check","--root",root,"--json"],3,"unsupported_environment","statx:poke_exit=@arg5=00000000:when=3")
    check_case("E06-reopened-fs",["check","--root",root,"--json"],5,"environment_changed","fstatfs:poke_exit=@arg2=0000000000000000:when=4")
    check_case("E05-proc-type",["check","--root",root,"--json"],3,"unsupported_environment","fstatfs:poke_exit=@arg2=0000000000000000:when=1")
    check_case("E05-proc-missing",["check","--root",root,"--json"],3,"unsupported_environment","openat2:error=ENOENT:when=1")
    check_case("E05-proc-unreadable",["check","--root",root,"--json"],3,"unsupported_environment","read:error=EACCES:when="+str(mount_read-2))
    close_count=0
    root_fd=re.search(r"statx\((\d+)<"+re.escape(root)+r">",baseline)[1]
    for line in baseline.splitlines():
        if "close(" in line:
            close_count+=1
        if "close("+root_fd+"<"+root+">" in line:
            break
    else:
        raise AssertionError("root FD close not observed")
    check_case("internal-close-error",["check","--root",root,"--json"],4,"internal_error","close:error=EIO:when="+str(close_count))
    close_count=0
    owned_metadata=set()
    for line in baseline.splitlines():
        opening=re.search(r'openat2\(.*"(?:status|mountinfo)".* = (\d+)<',line)
        if opening:
            owned_metadata.add(opening[1])
        closing=re.search(r'close\((\d+)<([^>]+)>',line)
        if closing:
            close_count+=1
            if closing[1] in owned_metadata or closing[2] in [root,"/"]:
                check_case("close-all-"+str(close_count),["check","--root",root,"--json"],4,"internal_error","close:error=EIO:when="+str(close_count))
            owned_metadata.discard(closing[1])
    for name,raw in [("controls",os.fsencode(root)+b'/\n\x1b[31m\r\t"\\'),("invalid-utf8",os.fsencode(root)+b'/\xff\xfe'),("bidi",os.fsencode(root)+"/\u202eevil".encode())]:
        p,_=check_case("O01-"+name,["check","--root",raw,"--json"],3,"invalid_root")
        obj=json.loads(p.stdout)["root"]
        assert base64.b64decode(obj["bytes_base64"])==raw
        assert obj["display"].isascii() and not any(ord(c)<32 for c in obj["display"])
        p,_=check_case("O01-text-"+name,["check","--root",raw],3)
        assert not p.stdout and b"\x1b" not in p.stderr and b"\xff" not in p.stderr
        assert p.stderr.count(b"\n")==2
    for length in [255,256,257,4095,4096]:
        raw=b"/"+b"x"*(length-1)
        p,_=check_case("O02-length-"+str(length),["check","--root",raw,"--json"],3,"invalid_root")
        obj=json.loads(p.stdout)["root"]
        assert len(p.stdout)<=16384
        if length==4096:
            assert obj is None
        else:
            assert obj["display_truncated"]==(length>256)
            assert base64.b64decode(obj["bytes_base64"])==raw
