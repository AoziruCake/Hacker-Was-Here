"""Verify the public demo outputs without reading the synthetic target."""
import base64
import json
from pathlib import Path

results = Path("/results")


def load(name):
    return json.loads((results / name).read_bytes())


def paths(report):
    return {
        base64.b64decode(path["bytes_base64"]).decode("utf-8")
        for finding in report["findings"]
        for path in finding["paths"]
    }


NON_CANDIDATES = {
    "docs/handbook.txt",
    "AGENTS.md",
    "restricted.txt",
    "outside-link",
    "hard-copy",
}

check = load("check.json")
assert check["command"] == "check"
assert check["exit_code"] == 0
assert check["status"] == "passed"
assert check["reason"] == "conditions_passed"
assert check["scan_status"] == "not_started"
assert check["findings"] == []
assert "証明するものではありません" in check["message"]
assert "安全です" not in check["message"]
assert "侵害なし" not in check["message"]

rw_check = load("rw-check.json")
assert rw_check["command"] == "check"
assert rw_check["exit_code"] == 3
assert rw_check["status"] == "rejected"
assert rw_check["reason"] == "unsupported_mount"
assert rw_check["scan_status"] == "not_started"
assert rw_check["findings"] == []

quick = load("quick.json")
assert quick["command"] == "scan"
assert quick["exit_code"] == 2
assert quick["status"] == "partial"
assert quick["scan_status"] == "incomplete"
assert quick["summary"]["candidate_count"] == 2
assert paths(quick) == {
    "README.blacksuit.txt",
    "hard.crypted.README_TO_RESTORE",
}
assert NON_CANDIDATES.isdisjoint(paths(quick))
assert quick["coverage"]["enumerated_entries"] != quick["summary"]["candidate_count"]
quick_exclusions = {item["reason"]: item["count"] for item in quick["policy_exclusions"]}
assert quick_exclusions["symlink_excluded"] == 1
assert quick_exclusions["special_file"] == 1
assert quick_exclusions["hardlink_excluded"] == 2
assert quick_exclusions["directory_not_scanned"] == 2
assert [error["reason"] for error in quick["errors"]] == ["permission_denied"]
assert "安全" not in quick["message"]

deep = load("deep.json")
assert deep["exit_code"] == 2
assert deep["status"] == "partial"
assert deep["scan_status"] == "incomplete"
assert deep["summary"]["candidate_count"] == 3
assert paths(deep) == {
    "README.blacksuit.txt",
    "hard.crypted.README_TO_RESTORE",
    "deep/a/b/c/d/PLAY_Readme.txt",
}
assert NON_CANDIDATES.isdisjoint(paths(deep))
assert deep["coverage"]["enumerated_entries"] != deep["summary"]["candidate_count"]
deep_exclusions = {item["reason"]: item["count"] for item in deep["policy_exclusions"]}
assert deep_exclusions["symlink_excluded"] == 1
assert deep_exclusions["special_file"] == 1
assert deep_exclusions["hardlink_excluded"] == 2
assert [error["reason"] for error in deep["errors"]] == ["permission_denied"]
assert "安全" not in deep["message"]

for name in ("quick.json", "deep.json", "check.json", "rw-check.json"):
    text = (results / name).read_text()
    assert "OUTSIDE_SYNTHETIC_CANARY" not in text
    assert "hwh-demo-instruction-ran" not in text
