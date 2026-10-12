#!/bin/sh
# Build the local linux amd64 artifact from the same pinned source.
set -eu
test -d /src
test -n "${HWH_SOURCE_COMMIT:-}"
case "$HWH_SOURCE_COMMIT" in *[!a-fA-F0-9]*|'') exit 2;; esac
test -n "${HWH_SOURCE_DIRTY:-}"

mkdir -p /results/dist
cd /src

test "$(go env GOVERSION)" = "go1.27.2"
test "$(go env CGO_ENABLED)" = "0"
test "$(go list -m golang.org/x/sys)" = "golang.org/x/sys v0.49.0"
go vet ./...

go list -m -f '{{if and (not .Main) (not .Indirect)}}{{.Path}}{{end}}' all | sed '/^$/d' > /results/direct-modules.txt
test "$(cat /results/direct-modules.txt)" = "golang.org/x/sys"
go list -f '{{.ImportPath}}' -deps ./cmd/hwh | sort > /results/deps.txt

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /results/dist/hwh-linux-amd64 ./cmd/hwh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /tmp/hwh-linux-arm64-compilecheck ./cmd/hwh
rm -f /tmp/hwh-linux-arm64-compilecheck

cp /src/LICENSE /results/dist/LICENSE

amd64_sha="$(sha256sum /results/dist/hwh-linux-amd64 | awk '{print $1}')"

{
  printf '%s  %s\n' "$amd64_sha" hwh-linux-amd64
} > /results/dist/SHA256SUMS

{
  printf 'product=hwh\n'
  printf 'version=0.1.0-dev\n'
  printf 'go=%s\n' "$(go env GOVERSION)"
  printf 'module=%s\n' "$(go list -m)"
  printf 'x_sys=v0.49.0\n'
  printf 'cgo=0\n'
  printf 'flags=-trimpath\n'
  printf 'source_commit=%s\n' "$HWH_SOURCE_COMMIT"
  printf 'source_dirty=%s\n' "$HWH_SOURCE_DIRTY"
  printf 'direct_modules=%s\n' "$(tr '\n' ',' < /results/direct-modules.txt | sed 's/,$//')"
  printf 'artifact_amd64_sha256=%s\n' "$amd64_sha"
} > /results/dist/build-info.txt
