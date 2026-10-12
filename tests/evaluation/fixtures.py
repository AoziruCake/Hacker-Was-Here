"""Create the ticket-11 synthetic corpus; never use real incident data."""
import json
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])


def touch_many(directory: Path, count: int) -> None:
    directory.mkdir(parents=True)
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for i in range(count):
            child = os.open(f"{i:06d}", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=fd)
            os.close(child)
    finally:
        os.close(fd)


# Quick reaches its global entry budget across several priority origins.
quick = root / "quick-scale"
for origin in ["home", "srv", "tmp", "data", "opt"]:
    touch_many(quick / origin, 4_000)
(quick / "opt/first.crypted.README_TO_RESTORE").write_bytes(b"duplicate")

# Deep reaches 200,000 entries while exercising duplicate and distinct hashes.
scale = root / "deep-scale"
scale.mkdir()
fd = os.open(scale, os.O_RDONLY | os.O_DIRECTORY)
try:
    for i in range(200_000):
        name = f"{i:06d}.crypted.README_TO_RESTORE"
        data = b"duplicate" if i < 2_000 else f"unique-{i:06d}".encode()
        child = os.open(name, os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=fd)
        os.write(child, data)
        os.close(child)
finally:
    os.close(fd)

# Sparse files force the real 512 MiB body budget without storing 512 MiB.
read = root / "deep-read"
read.mkdir()
for i in range(513):
    with (read / f"{i:04d}").open("wb") as file:
        file.truncate(1024 * 1024 - 1)

queues = root / "deep-queues"
queues.mkdir()
for i in range(4_100):
    (queues / f"{i:04d}").mkdir()

depth = root / "deep-depth"
depth.mkdir()
current = depth
for i in range(64):
    current = current / f"d{i:02d}"
    current.mkdir()
    if i == 62:
        (current / "PLAY_Readme.txt").write_bytes(b"depth candidate")

errors = root / "errors"
errors.mkdir()
for i in range(1_000):
    (errors / f"{i:04d}.crypted.README_TO_RESTORE").write_bytes(b"denied")

# Reuse the expectations fixed before the matcher was implemented.
content = root / "content"
content.mkdir()
cases = json.loads(Path("/src/tests/scan/content_cases.json").read_text())
for case in cases:
    encoding = case["encoding"]
    data = case["text"].encode("utf-8" if encoding == "invalid" else encoding)
    if encoding == "invalid":
        data += b"\xff"
    (content / case["name"]).write_bytes(data)
