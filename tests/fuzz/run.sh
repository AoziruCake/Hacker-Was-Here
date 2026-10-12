#!/bin/sh
set -eu

test "$(id -u)" = 0
duration="${HWH_FUZZ_TIME:-30s}"
case "$duration" in
  *[!0-9a-zA-Z.]*) echo "invalid HWH_FUZZ_TIME" >&2; exit 2 ;;
esac

work=/tmp/hwh-fuzz-src
home=/tmp/hwh-fuzz-home
rm -rf "$work" "$home"
cp -a /src "$work"
mkdir -p "$home/cache"
chown -R 1000:1000 "$work" "$home"

run_fuzz() {
  package=$1
  target=$2
  echo "FUZZ: $package $target duration=$duration"
  setpriv --reuid=1000 --regid=1000 --clear-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
    env HOME="$home" GOCACHE="$home/cache" GOTOOLCHAIN=local CGO_ENABLED=0 \
    go test "$package" -run='^$' -fuzz="^${target}$" -fuzztime="$duration"
}

cd "$work"
run_fuzz ./internal/safefs FuzzRelativePathValidation
run_fuzz ./internal/safefs FuzzMountinfoParsing
run_fuzz ./internal/cli FuzzSafePathDisplay
