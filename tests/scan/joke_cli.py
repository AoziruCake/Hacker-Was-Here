"""O05 tests for display-only jokes through the public executable."""
import json
import os
import subprocess

root = os.environ["HWH_TEST_ROOT"]
jokes = ["--detective", "--fortune", "--no-hope"]


def run(*args):
    return subprocess.run(
        ["/opt/hwh", "scan", *args],
        capture_output=True,
        timeout=20,
    )


def stable_report(stdout):
    report = json.loads(stdout)
    report.pop("finished_at")
    return report


for directory, code in [
    ("scan-empty", 0),
    ("scan-small", 1),
    ("quick-small", 2),
]:
    target = root + "/" + directory
    baseline = run("--root", target, "--json")
    decorated = run("--root", target, *jokes, "--json")
    assert baseline.returncode == decorated.returncode == code
    assert stable_report(baseline.stdout) == stable_report(decorated.stdout)
    assert b"JOKE" not in decorated.stdout and not decorated.stderr

rejected = run("--root", "relative", *jokes, "--json")
baseline_rejected = run("--root", "relative", "--json")
assert rejected.returncode == baseline_rejected.returncode == 3
assert stable_report(rejected.stdout) == stable_report(baseline_rejected.stdout)
assert b"JOKE" not in rejected.stdout and not rejected.stderr
print("PASS: O05 JSON results and exit states are invariant with every joke")

for directory, code in [
    ("scan-empty", 0),
    ("scan-small", 1),
    ("quick-small", 2),
]:
    target = root + "/" + directory
    displayed = run("--root", target, "--no-hope", "--fortune", "--detective")
    assert displayed.returncode == code
    output = displayed.stdout if code in (0, 1) else displayed.stderr
    assert output.count(b"JOKE[") == 3
    assert output.index(b"JOKE[detective]") < output.index(b"JOKE[fortune]")
    assert output.index(b"JOKE[fortune]") < output.index(b"JOKE[no-hope]")

rejected = run("--root", "relative", *jokes)
assert rejected.returncode == 3 and not rejected.stdout
assert rejected.stderr.count(b"JOKE[") == 3
print("PASS: all jokes use a fixed, labelled order for complete, partial, and rejected scans")

for flag in jokes:
    quiet = run("--root", root + "/scan-small", flag, "--quiet")
    assert quiet.returncode == 1 and not quiet.stdout and not quiet.stderr

for target, code in [
    (root + "/quick-small", 2),
    ("relative", 3),
]:
    quiet = run("--root", target, *jokes, "--quiet")
    assert quiet.returncode == code and not quiet.stdout
    assert quiet.stderr and b"JOKE" not in quiet.stderr

for directory, code in [
    ("scan-empty", 0),
    ("scan-small", 1),
    ("quick-small", 2),
]:
    target = root + "/" + directory
    displayed = run("--root", target)
    assert displayed.returncode == code
    output = displayed.stdout if code in (0, 1) else displayed.stderr
    assert output.count(b"JOKE[") == 2
    assert output.index(b"JOKE[detective]") < output.index(b"JOKE[fortune]")
    assert b"JOKE[no-hope]" not in output
    off = run("--root", target, "--no-joke")
    assert off.returncode == code
    off_output = off.stdout if code in (0, 1) else off.stderr
    assert b"JOKE" not in off_output
rejected = run("--root", "relative")
assert rejected.returncode == 3 and rejected.stderr.count(b"JOKE[") == 2
assert b"JOKE" not in run("--root", "relative", "--no-joke").stderr
print("PASS: default normal display shows detective and fortune; --no-joke removes them")

help_result = subprocess.run(["/opt/hwh", "scan", "--help"], capture_output=True, timeout=10)
assert help_result.returncode == 0 and not help_result.stderr
assert b"--detective" in help_result.stdout and b"--fortune" in help_result.stdout
assert b"--no-joke" in help_result.stdout
assert b"--no-hope" not in help_result.stdout

for args in [
    ["scan", "--root", root + "/scan-empty", "--detective", "--detective", "--json"],
    ["scan", "--root", root + "/scan-empty", "--fortune=yes", "--json"],
    ["scan", "--root", root + "/scan-empty", "--no-joke", "--detective", "--json"],
    ["check", "--root", root, "--detective", "--json"],
    ["check", "--root", root, "--no-joke", "--json"],
]:
    invalid = subprocess.run(["/opt/hwh", *args], capture_output=True, timeout=10)
    assert invalid.returncode == 3 and json.loads(invalid.stdout)["reason"] == "invalid_arguments"
    assert b"JOKE" not in invalid.stdout and not invalid.stderr
print("PASS: quiet suppresses jokes; hidden, duplicate, valued, and check options follow the contract")
