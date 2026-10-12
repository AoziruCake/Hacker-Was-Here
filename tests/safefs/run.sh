#!/bin/sh
# Root prepares only synthetic fixtures inside a fresh Docker-managed volume.
# The test/probe processes themselves run as UID/GID 1000 with no capabilities.
set -eu
test "$(id -u)" = 0
test -d /fixture-store
test -n "${HWH_TEST_RUN:-}"
case "$HWH_TEST_RUN" in *[!a-zA-Z0-9_-]*|'') exit 2;; esac
base="/fixture-store/$HWH_TEST_RUN"
test ! -e "$base"
mkdir -p "$base/rw/dir" "$base/outside" "$base/ro"
printf abc > "$base/rw/note.txt"
printf OUTSIDE_CANARY_NOT_A_NOTE > "$base/outside/note.txt"
printf unreadable > "$base/rw/unreadable"
chmod 000 "$base/rw/unreadable"
ln -s "$base/outside/note.txt" "$base/rw/out-link"
ln -s note.txt "$base/rw/in-link"
ln -s ../outside/note.txt "$base/rw/relative-link"
ln -s "$base/outside" "$base/rw/ancestor-link"
printf hardlink > "$base/rw/hard-a"
ln "$base/rw/hard-a" "$base/rw/hard-b"
ln "$base/outside/note.txt" "$base/rw/external-hard"
mkfifo "$base/rw/fifo"
mknod "$base/rw/char" c 1 3
mknod "$base/rw/block" b 7 255
python3 - "$base/rw/socket" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.close()
PY
mkdir "$base/rw/bind" "$base/rw/otherfs"
python3 /src/tests/scan/fixtures.py "$base/rw"
chown -R 1000:1000 "$base/rw" "$base/outside"
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  chmod 000 "$base/rw/quick-small/backup"
mount --bind "$base/rw" "$base/ro"
mount -o remount,bind,ro,nodev,nosuid,noexec "$base/ro"
mount --bind "$base/outside" "$base/ro/bind"
mount -o remount,bind,ro,nodev,nosuid,noexec "$base/ro/bind"
mount -t tmpfs -o ro,nodev,nosuid,noexec,size=1m tmpfs "$base/ro/otherfs"
mount --bind "$base/outside" "$base/ro/quick-small/srv/bind"
mount -o remount,bind,ro,nodev,nosuid,noexec "$base/ro/quick-small/srv/bind"
mount -t tmpfs -o ro,nodev,nosuid,noexec,size=1m tmpfs "$base/ro/quick-small/srv/otherfs"
mount --bind "$base/outside" "$base/ro/deep-small/bind"
mount -o remount,bind,ro,nodev,nosuid,noexec "$base/ro/deep-small/bind"
mount -t tmpfs -o ro,nodev,nosuid,noexec,size=1m tmpfs "$base/ro/deep-small/otherfs"
for missing in nodev nosuid noexec; do
  mkdir "$base/missing-$missing"
  mount --bind "$base/rw" "$base/missing-$missing"
  case "$missing" in
    nodev) flags=ro,dev,nosuid,noexec;;
    nosuid) flags=ro,nodev,suid,noexec;;
    noexec) flags=ro,nodev,nosuid,exec;;
  esac
  mount -o "remount,bind,$flags" "$base/missing-$missing"
done
mkdir -p /results
export HWH_TEST_ROOT="$base/ro" HWH_TEST_WRITABLE="$base/rw" HWH_TEST_OUTSIDE="$base/outside"
uname -a > /results/environment.txt
findmnt -T "$base/ro" -o TARGET,FSTYPE,OPTIONS >> /results/environment.txt
go version >> /results/environment.txt
go list -m all >> /results/environment.txt
chown 1000:1000 /results
# No privileged option is exposed by the probe or production reader.
if [ "${HWH_SCAN_ONLY:-0}" != 1 ]; then
if [ "${HWH_CHECK_ONLY:-0}" != 1 ]; then
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  strace -f -yy -s 256 -o /results/trace.log -e trace=openat,openat2,read,close,newfstatat,statx,fstatfs \
  /opt/safefs.test -test.v -test.timeout=90s "${@}"
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/safefs/probe_audit.py
fi
python3 /src/tests/check/privileges.py
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/check/check_cli.py
fi
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/scan/scan_cli.py
python3 /src/tests/scan/environment.py
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/scan/body_cli.py
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/scan/quick_cli.py
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/scan/content_cli.py
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/scan/dedup_cli.py
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/scan/deep_cli.py
setpriv --reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  python3 /src/tests/scan/joke_cli.py
