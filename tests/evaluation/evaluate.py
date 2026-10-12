"""Measure the public CLI against the predeclared ticket-11 criteria."""
import base64
import json
import re
import resource
import subprocess
import sys
import threading
import time
from pathlib import Path

root = Path(sys.argv[1])
results = Path(sys.argv[2])
MIB = 1024 * 1024
thresholds = {
    "quick": {"seconds": 30, "rss_bytes": 256 * MIB, "read_bytes": 64 * MIB},
    "deep": {"seconds": 300, "rss_bytes": 384 * MIB, "read_bytes": 512 * MIB},
    "observed_fds": 40,
    "output_bytes": 8 * MIB,
    "candidate_paths": 2_000,
    "error_paths": 200,
    "quality_precision": 0.80,
    "quality_recall": 0.40,
}
NONPRIVILEGED = [
    "setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
    "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
    "--no-new-privs",
]


def nonprivileged(command):
    return NONPRIVILEGED + command


def drain(pipe, output, first_elapsed, started):
    while True:
        chunk = pipe.read(65536)
        if not chunk:
            return
        if first_elapsed is not None and first_elapsed["seconds"] is None:
            first_elapsed["seconds"] = time.monotonic() - started
        output.extend(chunk)


def proc_values(pid):
    values = {"rss_bytes": 0}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                values["rss_bytes"] = int(line.split()[1]) * 1024
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        pass
    return values


def measure(
    name, mode, expected_code, expected_limits=(),
    expected_candidates=None, expected_groups=None,
):
    command = nonprivileged([
        "/opt/hwh", "scan", "--root", str(root / name), f"--{mode}", "--json",
    ])
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = bytearray(), bytearray()
    first_elapsed = {"seconds": None}
    threads = [
        threading.Thread(target=drain, args=(process.stdout, stdout, first_elapsed, started)),
        threading.Thread(target=drain, args=(process.stderr, stderr, None, started)),
    ]
    for thread in threads:
        thread.start()
    observed = {"rss_bytes": 0}
    hard_timeout = thresholds[mode]["seconds"] + 30
    while process.poll() is None:
        sample = proc_values(process.pid)
        for key in observed:
            observed[key] = max(observed[key], sample[key])
        if time.monotonic() - started > hard_timeout:
            process.kill()
            raise AssertionError(f"{name}: exceeded {hard_timeout}s harness timeout")
        time.sleep(0.002)
    for thread in threads:
        thread.join()
    elapsed = time.monotonic() - started
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    assert process.returncode == expected_code, (name, process.returncode, stderr[:1000])
    assert not stderr, (name, stderr[:1000])
    report = json.loads(stdout)
    if expected_candidates is not None:
        assert report["summary"]["candidate_count"] == expected_candidates, (
            name, report["summary"]
        )
    if expected_groups is not None:
        assert report["summary"]["group_count"] == expected_groups, (
            name, report["summary"]
        )
    for limit in expected_limits:
        assert limit in report["limits"], (name, limit, report["limits"])

    retained_paths = sum(len(finding["paths"]) for finding in report["findings"])
    metric = {
        "mode": mode,
        "elapsed_seconds": round(elapsed, 6),
        "first_stdout_seconds": (
            round(first_elapsed["seconds"], 6)
            if first_elapsed["seconds"] is not None else None
        ),
        "peak_rss_bytes": observed["rss_bytes"],
        "block_input_operations": usage_after.ru_inblock - usage_before.ru_inblock,
        "block_output_operations": usage_after.ru_oublock - usage_before.ru_oublock,
        "output_bytes": len(stdout),
        "exit_code": process.returncode,
        "scan_status": report["scan_status"],
        "reason": report["reason"],
        "limits": report["limits"],
        "coverage": report["coverage"],
        "summary": report["summary"],
        "retained_candidate_paths": retained_paths,
        "retained_errors": len(report["errors"]),
        "errors_truncated": report["errors_truncated"],
    }
    mode_limits = thresholds[mode]
    assert elapsed <= mode_limits["seconds"], metric
    assert (
        first_elapsed["seconds"] is not None
        and first_elapsed["seconds"] <= mode_limits["seconds"]
    ), metric
    assert observed["rss_bytes"] <= mode_limits["rss_bytes"], metric
    assert len(stdout) <= thresholds["output_bytes"], metric
    assert report["coverage"]["read_bytes"] <= mode_limits["read_bytes"], metric
    assert retained_paths <= thresholds["candidate_paths"], metric
    assert len(report["errors"]) <= thresholds["error_paths"], metric
    print(f"PASS: {name}", json.dumps(metric, sort_keys=True))
    return metric, report


def audit_fds(name, mode):
    trace = Path(f"/tmp/hwh-{name}-fds.trace")
    command = nonprivileged([
        "strace", "-f", "-qq", "-yy", "-o", str(trace),
        "-e", "trace=open,openat,openat2,close", "/opt/hwh", "scan",
        "--root", str(root / name), f"--{mode}", "--json",
    ])
    process = subprocess.run(command, capture_output=True, timeout=330)
    assert process.returncode in (1, 2), (name, process.returncode, process.stderr[:1000])
    assert not process.stderr
    opened, peak = {0, 1, 2}, 3
    open_result = re.compile(r"\b(?:open|openat|openat2)\(.*\)\s+=\s+(\d+)(?:<[^>]*>)?$")
    close_arg = re.compile(r"\bclose\((\d+)(?:<[^>]*>)?\)\s+=\s+0$")
    for line in trace.read_text(errors="replace").splitlines():
        match = open_result.search(line)
        if match:
            opened.add(int(match.group(1)))
            peak = max(peak, len(opened))
            continue
        match = close_arg.search(line)
        if match:
            opened.discard(int(match.group(1)))
    trace.unlink()
    assert peak <= thresholds["observed_fds"], (name, peak)
    print(f"PASS: {name} FD audit peak={peak}")
    return peak


measurements = {}
for args in [
    ("quick-scale", "quick", 2, ("enumeration_entries",), 1, 1),
    (
        "deep-scale", "deep", 2,
        ("enumeration_entries", "candidate_paths"), 200_000, 198_001,
    ),
    ("deep-read", "deep", 2, ("total_read_bytes",), 0, 0),
    ("deep-queues", "deep", 2, ("queued_paths",), 0, 0),
    ("deep-depth", "deep", 1, (), 1, 1),
    ("errors", "deep", 2, ("error_paths",), 1_000, 1_000),
]:
    metric, _ = measure(*args)
    measurements[args[0]] = metric
measurements["quick-scale"]["trace_peak_fds"] = audit_fds("quick-scale", "quick")
measurements["deep-queues"]["trace_peak_fds"] = audit_fds("deep-queues", "deep")

# Detection quality remains separate from safety/resource acceptance.
quality_metric, quality_report = measure("content", "deep", 1, (), 7, 7)
measurements["content"] = quality_metric
findings = {}
for finding in quality_report["findings"]:
    for path in finding["paths"]:
        findings[base64.b64decode(path["bytes_base64"]).decode()] = finding
cases = json.loads(Path("/src/tests/scan/content_cases.json").read_text())
tp = fp = fn = tn = 0
for case in cases:
    finding = findings.get(case["name"])
    actual = [
        rule for rule in (finding["rule_ids"] if finding else [])
        if rule.startswith("content.")
    ]
    expected = [f"content.encryption-recovery-{rule}" for rule in case["rules"]]
    assert actual == expected, (case["name"], actual, expected)
    detected = bool(actual)
    if case["positive"] and detected:
        tp += 1
    elif case["positive"]:
        fn += 1
    elif detected:
        fp += 1
    else:
        tn += 1
precision = tp / (tp + fp)
recall = tp / (tp + fn)
quality = {
    "corpus_cases": len(cases),
    "positive_cases": sum(case["positive"] for case in cases),
    "negative_cases": sum(not case["positive"] for case in cases),
    "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    "precision": precision, "recall": recall,
    "unsupported_content_cases": ["utf16", "invalid", "nul", "escape"],
}
assert precision >= thresholds["quality_precision"], quality
assert recall >= thresholds["quality_recall"], quality
assert all(name not in findings for name in quality["unsupported_content_cases"]), quality

payload = {"thresholds": thresholds, "measurements": measurements, "quality": quality}
(results / "ticket11-evaluation.json").write_text(json.dumps(payload, indent=2) + "\n")
print("PASS: ticket-11 resource and detection evaluation", json.dumps(quality, sort_keys=True))
