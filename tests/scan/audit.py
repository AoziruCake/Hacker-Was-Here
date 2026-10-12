"""Independent syscall monitor with negative controls; synthetic inputs only."""
import re
import posixpath
def audit(text, root, bodies=False, directories=None, extra_bodies=()):
    directories = {root} if directories is None else set(directories)
    assert all(d == root or d.startswith(root + '/') for d in directories)
    def allowed_body(path):
        if not bodies or posixpath.dirname(path) not in directories:
            return False
        name=posixpath.basename(path).lower()
        return path in extra_bodies or name.isdecimal() or name in ['readme.blacksuit.txt','play_readme.txt','readme.txt','index.html','agents.md','.hwh.json','hwh.yaml','motd'] or name.endswith('.crypted.readme_to_restore')
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
    for directory in re.findall(r"getdents(?:64)?\(\d+<([^>]+)>",text):
        assert directory in directories, "unplanned directory enumeration"
    for target in re.findall(r"\b(?:read|pread64|readv|preadv|preadv2)\(\d+<(/fixture-store/[^>]+)>", text):
        assert allowed_body(target), "target read"
    assert not re.search(r"\bmmap\(.*\d+</fixture-store/", text), "target mmap"
    assert not re.search(r"\b(?:mount|umount2|chmod|fchmod|fchmodat|chown|fchown|fchownat)\(", text), "environment mutation"
    pins = {}
    for line in text.splitlines():
        if re.match(r"(?:open|openat|openat2)\(", line):
            result=re.search(r"= (\d+)<([^>]+)>",line)
            target=result[2] if result else None
            if "O_PATH" in line:
                if result:
                    if target.startswith('/fixture-store/'):
                        assert target == root or target.startswith(root + '/'), 'outside pin'
                        assert line.startswith('openat2('), 'unconstrained target pin'
                        for flag in ['RESOLVE_BENEATH','RESOLVE_NO_MAGICLINKS','RESOLVE_NO_SYMLINKS']:
                            assert flag in line, 'missing pin protection'
                        if target != root:
                            assert 'RESOLVE_NO_XDEV' in line and 'O_NOFOLLOW' in line, 'missing child boundary'
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
                assert via_proc and (("O_DIRECTORY" in line and target in directories) or allowed_body(target)), "unprotected or unplanned open attempt"
        closed=re.match(r"close\((\d+)(?:<.*>)?\)\s+= 0$",line)
        if closed:
            pins.pop(closed[1],None)


    assert not re.search(r'\b(?:socket|connect|sendto|sendmsg|execveat)\(',text), "external action"
    assert len(re.findall(r'\bexecve\(',text))<=1, "extra executable"
    for line in calls:
        if line.startswith('statx('):
            assert ', "", AT_' in line and 'AT_EMPTY_PATH' in line, "pathname attributes"

    live={}
    peak=0
    for line in calls:
        opened=re.match(r'(?:open|openat|openat2)\(.* = (\d+)<(.*)>$',line)
        if opened:
            live[opened[1]]=opened[2]
            peak=max(peak,len(live))
        closed=re.match(r'close\((\d+)(?:<.*>)?\)\s+= 0$',line)
        if closed: live.pop(closed[1],None)
    assert peak<=32, 'FD budget exceeded'
    assert not any(p.startswith(('/fixture-store/','/proc/')) for p in live.values()), 'owned FD leak'
    return peak

for forbidden in [
 '1 openat2(3</fixture-store/root>, "../outside/canary", {flags=O_PATH}, 24) = 8</fixture-store/outside/canary>\n1 statx(8</fixture-store/outside/canary>, "", AT_EMPTY_PATH, STATX_ALL, {}) = 0\n1 close(8</fixture-store/outside/canary>) = 0',
 '1 getdents64(8</fixture-store/root/subdir>, [], 1024) = 0',
 '1 read(8</fixture-store/root/note>, "x", 1) = 1',
 '1 openat(8</fixture-store/root>, "note", O_RDONLY) = -1 EACCES (Permission denied)',
 '1 openat(8</fixture-store/root>, "subdir", O_RDONLY|O_DIRECTORY) = 9</fixture-store/root/subdir>',
 '1 socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM (Operation not permitted)',
 '1 execve("/opt/hwh", [], []) = 0\n1 execve("/bin/sh", [], []) = 0',
 '1 statx(8</fixture-store/root>, "note", 0, STATX_ALL, {}) = 0',
]:
    try:
        audit(forbidden,"/fixture-store/root")
    except AssertionError:
        continue
    raise AssertionError("monitor accepted forbidden operation: "+forbidden)
