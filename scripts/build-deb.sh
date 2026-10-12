#!/bin/sh
# Build a local .deb from a static Linux amd64 hwh binary.
# This does not create an apt repository or grant a license to use hwh.
set -eu

usage() {
	echo "usage: scripts/build-deb.sh [binary] [version] [output.deb]" >&2
	echo "defaults: dist/hwh-linux-amd64  0.1.0-dev  dist/hwh_0.1.0-dev_amd64.deb" >&2
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
	usage
	exit 0
fi

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
version=${2:-0.1.0-dev}
bin=${1:-"$root/dist/hwh-linux-amd64"}
out=${3:-"$root/dist/hwh_${version}_amd64.deb"}

case "$version" in
	*[!0-9A-Za-z.+~-]*)
		echo "version contains characters dpkg will not accept: $version" >&2
		exit 1
		;;
esac

if ! command -v dpkg-deb >/dev/null 2>&1; then
	echo "dpkg-deb is required. Run this on Debian or Ubuntu, or in WSL." >&2
	exit 1
fi
if [ ! -f "$bin" ] || [ ! -s "$bin" ]; then
	echo "binary not found or empty: $bin" >&2
	echo "Build the Linux amd64 binary first, then pass its path." >&2
	exit 1
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
mkdir -p "$workdir/DEBIAN" "$workdir/usr/bin" "$workdir/usr/share/doc/hwh"
install -m 0755 "$bin" "$workdir/usr/bin/hwh"
install -m 0644 "$root/LICENSE" "$workdir/usr/share/doc/hwh/copyright"
awk -v v="$version" '{gsub(/@VERSION@/, v); print}' "$root/packaging/deb/control" > "$workdir/DEBIAN/control"
size=$(du -sk "$workdir/usr" | awk '{print $1}')
printf 'Installed-Size: %s\n' "$size" >> "$workdir/DEBIAN/control"
mkdir -p "$(dirname "$out")"
dpkg-deb --root-owner-group --build "$workdir" "$out"
echo "$out"
