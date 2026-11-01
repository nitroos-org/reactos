#!/bin/bash
# Stage the official PowerShell 7 LTS x64 MSI (MIT, github.com/PowerShell/PowerShell) next to this script so that the
# image carries it (CMakeLists.txt, "PowerShell 7 preinstall") and setup installs it silently on amd64.
#
#   stage-powershell7.sh [OUTFILE]      (default: PowerShell-x64.msi next to this script; the image uses that fixed name)
#
# The MSI (~112 MiB) is NOT in git. It is downloaded from the pinned release URL and verified against the pinned
# SHA-256 (the value in the release's hashes.sha256 and in the GitHub asset digest). Set POWERSHELL7_MSI=/path/to.msi
# to use a local copy instead of downloading (offline build host / CI mirror); it is verified against the same pin.
# The pin is the single source of truth shared with catalog/powershell-7.ini and powershell-7.txt (keep all three equal).
#
# Exit 0 = OUTFILE present and verified (or already was; no network is used then). Any failure exits non-zero, prints
# a one-line reason as its last line and leaves no partial file; the build then goes on WITHOUT the MSI (no preinstall;
# the Optional Features entry downloads it at install time). Exit codes: 1 verify failure, 3 no downloader, 4 download.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
VERSION=7.6.9
FILE=PowerShell-$VERSION-win-x64.msi
URL=https://github.com/PowerShell/PowerShell/releases/download/v$VERSION/$FILE
SHA256=50d33c7494aaf82b987cfd4de3f232d04f91fdd4c0deeca8a669cced3e7cf8f9
OUT=${1:-$HERE/PowerShell-x64.msi}
NAME=stage-powershell7

die() { echo "$NAME: $*" >&2; exit "${RC:-1}"; }
have() { [ -f "$1" ] && [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$SHA256" ]; }

mkdir -p "$(dirname "$OUT")" || die "cannot create $(dirname "$OUT")"
# serialize concurrent configures of a shared source tree (amd64 Debug + amd64 Release)
exec 9>"$HERE/.stage-powershell7.lock" || die "cannot open the lock file"
flock 9

if have "$OUT"; then echo "$NAME: PowerShell $VERSION already staged and verified (sha256 ${SHA256:0:8})"; exit 0; fi

TMP=$(mktemp "$(dirname "$OUT")/.stage-powershell7.XXXXXX") || die "mktemp failed"
trap 'rm -f "$TMP"' EXIT
if [ -n "${POWERSHELL7_MSI:-}" ]; then
  cp "$POWERSHELL7_MSI" "$TMP" || die "cannot read $POWERSHELL7_MSI"
elif command -v curl >/dev/null 2>&1; then
  curl -fsSL --connect-timeout 15 --max-time 600 --retry 2 -o "$TMP" "$URL" || RC=4 die "download of $URL failed"
elif command -v wget >/dev/null 2>&1; then
  wget -q --timeout=60 --tries=3 -O "$TMP" "$URL" || RC=4 die "download of $URL failed"
else
  RC=3 die "neither curl nor wget found (set POWERSHELL7_MSI=<local msi>)"
fi
have "$TMP" || die "SHA-256 of the downloaded MSI is not the pinned ${SHA256:0:16}...; refusing it"
chmod 644 "$TMP"
mv -f "$TMP" "$OUT"
trap - EXIT
echo "$NAME: staged $FILE as $(basename "$OUT") (sha256 ${SHA256:0:8})"
