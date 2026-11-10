#!/bin/bash
# Produce the hosted files of the lavapipe-pack feature (Mesa lavapipe + llvmpipe, amd64), ~129 MB.
#   stage-lavapipe-payload.sh <outdir>
# <outdir> gets the six files listed in [Download] of catalog/lavapipe-pack.ini, each checked against the SHA-256
# pinned there, plus SHA256SUMS. The catalog is the single source of truth (file names, hashes, sizes, Path).
#
# Use:
#  - hosting: upload the six files (SHA256SUMS too, for people who check by hand) to
#      <PayloadBaseUrl>/<[Source] Path>/        e.g. https://<domain>/featmgr/lavapipe-pack/26.3.0-beed97f8/
#    featmgr fetches <base>/<Path>/<file> over https when the pack is turned on.
#  - offline target: copy them to %SystemRoot%\Featmgr\Payload\lavapipe-pack\ ; featmgr then verifies and uses
#    them without a download.
# Sources: the GFX-01 build artifact ([Source] BuildArtifact, private S3 cold tier via rclone remote "vultr", or a
# local copy in LAVAPIPE_ARTIFACT) for the Mesa/LLVM files; the in-tree Vulkan-Loader licence text
# (dll/3rdparty/vulkan-loader/vulkan-loader-licenses.txt).
set -euo pipefail
OUT=${1:?usage: $0 <outdir>}
HERE=$(cd "$(dirname "$0")" && pwd)
INI=$HERE/../catalog/lavapipe-pack.ini
VKLIC=$HERE/../../../../dll/3rdparty/vulkan-loader/vulkan-loader-licenses.txt
key() { sed -n "s/^$1=//p" "$INI" | tr -d '\r' | head -n1; }
ART=$(key BuildArtifact)
SHA=$(key BuildArtifactSHA256)
REM=${ART#s3://}; REM=vultr:${REM}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
if [ -n "${LAVAPIPE_ARTIFACT:-}" ]; then cp "$LAVAPIPE_ARTIFACT" "$TMP/a.tar.xz"; else rclone copyto "$REM" "$TMP/a.tar.xz"; fi
echo "$SHA  $TMP/a.tar.xz" | sha256sum -c - >/dev/null
tar -xJf "$TMP/a.tar.xz" -C "$TMP"
( cd "$TMP/amd64-llvm" && sha256sum -c SHA256SUMS >/dev/null )
cp "$VKLIC" "$TMP/amd64-llvm/vulkan-loader-licenses.txt"
mkdir -p "$OUT"
: > "$OUT/SHA256SUMS.tmp"
# [Download] lines: File<N>=<name>|<sha256>|<size>
sed -n '/^\[Download\]/,/^\[/p' "$INI" | tr -d '\r' | sed -n 's/^File[0-9]*=//p' | while IFS='|' read -r name sum size; do
  src=$TMP/amd64-llvm/$name
  [ -f "$src" ] || { echo "missing $name" >&2; exit 1; }
  echo "$sum  $src" | sha256sum -c - >/dev/null || { echo "SHA-256 of $name does not match the catalog" >&2; exit 1; }
  [ "$(stat -c %s "$src")" = "$size" ] || { echo "size of $name does not match the catalog" >&2; exit 1; }
  install -m 0644 "$src" "$OUT/$name"
  echo "$sum  $name" >> "$OUT/SHA256SUMS.tmp"
done
mv "$OUT/SHA256SUMS.tmp" "$OUT/SHA256SUMS"
echo "staged lavapipe-pack hosted files in $OUT (upload to <PayloadBaseUrl>/$(key Path)/)"
