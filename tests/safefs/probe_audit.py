"""Trace only the lab probe: fixture creation is deliberately outside observation."""
import json
import os
import posixpath
from pathlib import Path
import re
import subprocess

root = os.environ["HWH_TEST_ROOT"]
outside = os.environ["HWH_TEST_OUTSIDE"]
cases = ["note.txt", "../outside/note.txt", outside + "/note.txt",
         "out-link", "relative-link", "in-link", "ancestor-link/note.txt",
         "bind/note.txt", "otherfs/missing", "fifo", "socket", "char", "block",
         "hard-a", "hard-b", "external-hard", "unreadable"]
assert os.getuid() == 1000, "run audit after dropping privileges"


def complete_calls(text):
    pending = {}
    for line in text.splitlines():
        match = re.match(r"(\d+)\s+(.*)", line)
        if not match:
            raise AssertionError("unrecognized trace line: " + line)
        pid, call = match.groups()
        if call.endswith("<unfinished ...>"):
            assert pid not in pending
            pending[pid] = call.removesuffix("<unfinished ...>")
        elif call.startswith("<... "):
            assert pid in pending
            yield pending.pop(pid) + call.split("resumed>", 1)[1]
        else:
            yield call
    assert not pending, "incomplete syscall observation"


def audit(text, allowed):
    pins = {}
    body_opens = reads = 0
    for call in complete_calls(text):
        opening = re.match(r"(open|openat|openat2)\(", call)
        result = re.search(r" = (\d+)<([^>]+)>$", call)
        if opening:
            target = result.group(2) if result else None
            if target and target.startswith(outside):
                raise AssertionError("outside canary opened: " + call)
            if "O_PATH" in call:
                if result:
                    pins[result.group(1)] = target
                continue
            # Also catch failed attempts to reopen excluded O_PATH descriptors.
            via_proc = re.search(r'openat\(\d+</proc/\d+/fd>, "(\d+)"', call)
            if via_proc:
                target = pins.get(via_proc.group(1))
                assert target is not None, "reopen without observed live pin"
            elif not result:
                direct = re.match(r'open\("([^"\\]+)"', call)
                relative = re.match(r'openat2?\((?:\d+<([^>]+)>|AT_FDCWD), "([^"\\]+)"', call)
                if direct:
                    target = direct.group(1)
                elif relative:
                    directory, name = relative.groups()
                    if name.startswith("/"):
                        target = name
                    elif directory:
                        target = posixpath.normpath(posixpath.join(directory, name))
                    else:
                        target = posixpath.normpath(posixpath.join("/src", name))
                if root in call or outside in call:
                    assert target is not None, "unparsed fixture open attempt: " + call
                if target and target.startswith(outside):
                    raise AssertionError("outside open attempt: " + call)
            if target and target.startswith(root + "/"):
                assert target == root + "/note.txt" and allowed or target == root + "/unreadable", call
                body_opens += int(result is not None)
        if re.match(r"(read|pread64|readv|preadv)\(", call):
            fd_path = re.match(r"\w+\(\d+<([^>]+)>", call)
            if fd_path and fd_path.group(1).startswith("/fixture-store/"):
                assert allowed and fd_path.group(1) == root + "/note.txt", call
                reads += 1
        closed = re.match(r"close\((\d+)(?:<[^>]+>)?\) = 0$", call)
        if closed:
            pins.pop(closed.group(1), None)
    if allowed:
        assert body_opens == 1 and reads >= 2, "positive observation control missing"
    else:
        assert body_opens == 0 and reads == 0, "forbidden body access"
    return {"successful_body_opens": body_opens, "body_read_calls": reads}


# Negative controls prove that a failed forbidden open is still detected.
for bad in [
    f'7 openat(10<{root}>, "fifo", O_RDONLY) = -1 EACCES (Permission denied)',
    f'7 open("{outside}/note.txt", O_RDONLY) = -1 EACCES (Permission denied)',
    f'7 openat2(10<{root}>, "char", {{flags=O_RDONLY}}, 24) = -1 EPERM (Operation not permitted)',
    f'7 read(11<{root}/socket>, "", 32) = -1 EINVAL (Invalid argument)',
]:
    try:
        audit(bad, False)
    except AssertionError:
        pass
    else:
        raise AssertionError("auditor negative control missed forbidden access")

report = []
for index, relative in enumerate(cases):
    trace = Path(f"/results/probe-{index:02d}.trace")
    command = ["strace", "-f", "-qq", "-yy", "-s", "256", "-o", str(trace),
                      "-e", "trace=open,openat,openat2,read,pread64,readv,preadv,close",
                      "/opt/safefs-probe", root, relative]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=10, cwd="/src")
    allowed = relative == "note.txt"
    assert completed.returncode == (0 if allowed else 1), (relative, completed.stderr)
    if allowed:
        assert "bytes=3 sha256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" in completed.stdout
    counts = audit(trace.read_text(), allowed)
    report.append({"case": relative, "exit": completed.returncode, **counts})

Path("/results/probe-audit.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"PASS: {len(report)} independent probe traces; forbidden body opens/reads = 0")
