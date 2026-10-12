"""Verify the local release-candidate package and that the hashed artifact was used."""
import hashlib
import os
import struct
from pathlib import Path

RESULTS = Path(os.environ.get("HWH_RELEASE_RESULTS", "/results"))
DIST = RESULTS / "dist"
SUMS = DIST / "SHA256SUMS"
INFO = DIST / "build-info.txt"
AMD64 = DIST / "hwh-linux-amd64"

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EM_X86_64 = 62
PT_INTERP = 3
PT_DYNAMIC = 2


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def parse_elf(path: Path) -> tuple[int, bool, bool]:
    data = path.read_bytes()
    assert data[:4] == ELF_MAGIC, f"{path.name} is not ELF"
    assert data[4] == ELFCLASS64, f"{path.name} is not ELF64"
    assert data[5] == ELFDATA2LSB, f"{path.name} is not little-endian"
    machine = struct.unpack_from("<H", data, 18)[0]
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    has_interp = False
    has_dynamic = False
    for index in range(phnum):
        p_type = struct.unpack_from("<I", data, phoff + index * phentsize)[0]
        if p_type == PT_INTERP:
            has_interp = True
        if p_type == PT_DYNAMIC:
            has_dynamic = True
    return machine, has_interp, has_dynamic


def parse_sums(path: Path) -> dict[str, str]:
    mapping = {}
    for raw in path.read_text(encoding="ascii").splitlines():
        if not raw:
            continue
        digest, name = raw.split("  ", 1)
        mapping[name] = digest
    return mapping


def parse_info(path: Path) -> dict[str, str]:
    mapping = {}
    for raw in path.read_text(encoding="ascii").splitlines():
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        mapping[key] = value
    return mapping


sums = parse_sums(SUMS)
assert set(sums) == {"hwh-linux-amd64"}
assert sha256(AMD64) == sums["hwh-linux-amd64"]
assert "hwh-linux-arm64" not in sums

amd64_machine, amd64_interp, amd64_dynamic = parse_elf(AMD64)
assert amd64_machine == EM_X86_64
assert not amd64_interp and not amd64_dynamic

info = parse_info(INFO)
assert info["product"] == "hwh"
assert info["version"] == "0.1.0-dev"
assert info["go"] == "go1.27.2"
assert info["x_sys"] == "v0.49.0"
assert info["cgo"] == "0"
assert info["flags"] == "-trimpath"
assert info["artifact_amd64_sha256"] == sums["hwh-linux-amd64"]
assert "artifact_arm64_sha256" not in info
assert info["source_commit"]
assert info["direct_modules"] == "golang.org/x/sys"

license_text = (DIST / "LICENSE").read_text(encoding="ascii")
assert license_text.startswith("MIT License\n")
assert 'THE SOFTWARE IS PROVIDED "AS IS"' in license_text
assert "WITHOUT WARRANTY OF ANY KIND" in license_text

executed = (RESULTS / "executed-sha256.txt").read_text(encoding="ascii").strip()
executed_path = (RESULTS / "executed-path.txt").read_text(encoding="ascii").strip()
assert executed == sums["hwh-linux-amd64"]
assert executed_path == "/results/dist/hwh-linux-amd64"

version = (RESULTS / "version.txt").read_text(encoding="ascii")
assert version == "hwh 0.1.0-dev\n"

direct = [line for line in (RESULTS / "direct-modules.txt").read_text(encoding="ascii").splitlines() if line]
assert direct == ["golang.org/x/sys"]

deps = (RESULTS / "deps.txt").read_text(encoding="ascii").splitlines()
forbidden = {"net/http", "net/http/httptest", "crypto/tls", "golang.org/x/net"}
assert forbidden.isdisjoint(deps)
