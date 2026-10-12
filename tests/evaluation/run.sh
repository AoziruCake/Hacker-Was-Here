#!/bin/sh
# Root prepares only synthetic evaluation fixtures in a fresh managed volume.
# hwh and the evaluator run as UID/GID 1000 without capabilities or network.
set -eu
test "$(id -u)" = 0
test -n "${HWH_TEST_RUN:-}"
case "$HWH_TEST_RUN" in *[!a-zA-Z0-9_-]*|'') exit 2;; esac

base="/fixture-store/$HWH_TEST_RUN"
test ! -e "$base"
mkdir -p "$base/rw" "$base/ro" /results
python3 /src/tests/evaluation/fixtures.py "$base/rw"
find "$base/rw/errors" -type f -exec chmod 000 {} +
chown -R 1000:1000 "$base/rw"
mount --bind "$base/rw" "$base/ro"
mount -o remount,bind,ro,nodev,nosuid,noexec "$base/ro"

uname -a > /results/environment.txt
findmnt -T "$base/ro" -o TARGET,FSTYPE,OPTIONS >> /results/environment.txt
lscpu >> /results/environment.txt
go version >> /results/environment.txt
go list -m all >> /results/environment.txt
printf 'container_cpus=2\ncontainer_memory_bytes=536870912\n' >> /results/environment.txt
sha256sum \
  /opt/hwh \
  /src/go.mod \
  /src/go.sum \
  /src/tests/scan/content_cases.json \
  /src/tests/safefs/Dockerfile \
  /src/tests/evaluation/run.ps1 \
  /src/tests/evaluation/run.sh \
  /src/tests/evaluation/fixtures.py \
  /src/tests/evaluation/evaluate.py \
  > /results/source-manifest.sha256
python3 /src/tests/evaluation/evaluate.py "$base/ro" /results
