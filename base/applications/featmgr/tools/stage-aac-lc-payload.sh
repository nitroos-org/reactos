#!/bin/bash
# Produce the hosted files of the aac-lc feature (AAC audio decoder, AAC-LC only), about 1.5 MB.
#   stage-aac-lc-payload.sh <outdir>
# <outdir> gets the five files listed in [Download] of catalog/aac-lc.ini (each checked against the SHA-256 and size pinned there),
# the source tarball nitroaacdec-src-<ver>-<rev>.tar.xz (the written source offer points to it; featmgr does not download it),
# and SHA256SUMS of all of them.
# The files are built here: dll/3rdparty/nitro-aacdec/build-aacdec.sh (mingw-w64 GCC for x86_64 and i686, make, patch, xz, curl;
# set FFMPEG_TARBALL to a local ffmpeg-9.0.2.tar.xz to skip the download). The build is reproducible: the pins hold on any host with
# the same toolchain version; a different mingw GCC gives other DLL bytes and fails the check on purpose (update the pins in
# catalog/aac-lc.ini and the [Source] Path, which ends in the first 8 hex digits of the SHA-256 of SHA256SUMS).
#   AAC_LC_ARTIFACTS=<dir>  use an existing build output (the same files) instead of building
# Use:
#  - hosting: upload <outdir> to <PayloadBaseUrl>/<[Source] Path>/   (e.g. https://repo.nitroos.org/featmgr/aac-lc/9.0.2-<hash>/)
#  - offline target: copy the five [Download] files to %SystemRoot%\Featmgr\Payload\aac-lc\ ; featmgr verifies and uses them.
set -euo pipefail
OUT=${1:?usage: $0 <outdir>}
HERE=$(cd "$(dirname "$0")" && pwd)
INI=$HERE/../catalog/aac-lc.ini
NA=$HERE/../../../../dll/3rdparty/nitro-aacdec
key() { sed -n "s/^$1=//p" "$INI" | tr -d '\r' | head -n1; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -n "${AAC_LC_ARTIFACTS:-}" ]; then cp -a "$AAC_LC_ARTIFACTS"/. "$TMP/"; else bash "$NA/build-aacdec.sh" "$TMP"; fi
mkdir -p "$OUT"
sed -n '/^\[Download\]/,/^\[/p' "$INI" | tr -d '\r' | sed -n 's/^File[0-9]*=//p' | while IFS='|' read -r name sum size; do
  src=$TMP/$name
  [ -f "$src" ] || { echo "missing $name" >&2; exit 1; }
  echo "$sum  $src" | sha256sum -c - >/dev/null || { echo "SHA-256 of $name does not match the catalog (different toolchain?)" >&2; exit 1; }
  [ "$(stat -c %s "$src")" = "$size" ] || { echo "size of $name does not match the catalog" >&2; exit 1; }
  install -m 0644 "$src" "$OUT/$name"
done
for f in "$TMP"/nitroaacdec-src-*.tar.xz; do install -m 0644 "$f" "$OUT/$(basename "$f")"; done
( cd "$OUT" && ls | grep -v '^SHA256SUMS' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS )
want=$(key Path); have=$(sha256sum "$OUT/SHA256SUMS" | cut -c1-8)
case "$want" in *-"$have") ;; *) echo "[Source] Path ($want) does not end in the hash of SHA256SUMS ($have): update catalog/aac-lc.ini" >&2; exit 1;; esac
echo "staged aac-lc hosted files in $OUT (upload to <PayloadBaseUrl>/$want/)"
