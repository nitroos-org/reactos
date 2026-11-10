#!/bin/bash
# Stage the i386 llvmpipe OpenGL driver (LLVM build of libgallium_wgl.dll, ~19 MB download, 73 MB installed) into
# dll/3rdparty/mesa3d/i386-llvm/ so that the SysWOW64 part of an amd64 image gives 32-bit programs llvmpipe
# (OpenGL 4.6) like the 64-bit side, instead of the in-tree softpipe (OpenGL 3.3, no compute shaders).
#
#   stage-i386-llvm.sh [OUTDIR]        (default: i386-llvm/ next to this script)
#
# Built by build-mesa.sh with ARCHES=i386 I386_LLVM=1; mesa3d-licenses.txt of the pack has the LLVM licence appended.
# Fetched from the S3 cold tier (rclone remote "vultr"; 15 s connect / 60 s idle timeouts, 2 retries) and verified
# like stage-amd64-llvm.sh; set LLVMPIPE_I386_ARTIFACT=/path/to/wow64-llvmpipe-i386-artifacts.tar.xz to use a local copy.
#
# The pinned artifact sha256 is stored in i386-llvm/.artifact-sha256; when it differs from the pin below the pack is
# staged again. The new pack is extracted and verified in a temporary directory next to i386-llvm/ and put in place
# with rm + mv, so no failure leaves a half-staged directory.
#
# Exit 0 = staged and verified (or already was); any failure exits non-zero, prints a one-line reason as its last line,
# and leaves i386-llvm/ as it was; the build keeps softpipe. Exit codes: 1 verify/install failure, 3 no rclone/remote,
# 4 download.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/i386-llvm}
ARTIFACT=s3://reactos-nitro-archive/wow64-llvmpipe-i386/26.3.0/wow64-llvmpipe-i386-artifacts.tar.xz
ARTIFACT_SHA256=ffbe26e2d376134d6380b08872a712b565597b30f4ce232da9aac85ca0d5c98b
FILES="libgallium_wgl.dll mesa3d-licenses.txt"
NAME=stage-i386-llvm

die() { echo "$NAME: $*" >&2; exit "${RC:-1}"; }

# serialize concurrent configures of a shared source tree (the SysWOW64 guest configures of one source tree)
mkdir -p "$(dirname "$OUT")" || die "cannot create $(dirname "$OUT")"
exec 9>"$HERE/.stage-i386-llvm.lock" || die "cannot open the lock file"
flock 9

# already staged with this pin and intact? then do nothing (idempotent, no network). The pin is
# stored in .artifact-sha256, so a bumped ARTIFACT_SHA256 makes a stale staging get replaced.
if [ -f "$OUT/.artifact-sha256" ] && [ "$(cat "$OUT/.artifact-sha256")" = "$ARTIFACT_SHA256" ] &&
   [ -f "$OUT/SHA256SUMS" ] && ( cd "$OUT" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
  all=1; for f in $FILES; do [ -f "$OUT/$f" ] || all=0; done
  if [ "$all" = 1 ]; then
    echo "$NAME: i386-llvm/ already staged and verified (artifact ${ARTIFACT_SHA256:0:8})"
    exit 0
  fi
fi

# Everything happens in temporary directories; $OUT is only touched by the final rm + mv, and
# TMPOUT is a sibling of $OUT so that the mv is a rename on one filesystem.
TMP=$(mktemp -d) || die "mktemp failed"
TMPOUT=$(mktemp -d "$(dirname "$OUT")/.stage-i386-llvm.tmp.XXXXXX") || die "cannot create a temporary directory next to $OUT"
trap 'rm -rf "$TMP" "$TMPOUT"' EXIT
if [ -n "${LLVMPIPE_I386_ARTIFACT:-}" ]; then
  cp "$LLVMPIPE_I386_ARTIFACT" "$TMP/a.tar.xz" || die "cannot read $LLVMPIPE_I386_ARTIFACT"
else
  command -v rclone >/dev/null 2>&1 || RC=3 die "rclone not found (set LLVMPIPE_I386_ARTIFACT=<local tar>)"
  remotes=$(rclone listremotes 2>/dev/null || true)
  printf '%s\n' "$remotes" | grep -qx 'vultr:' || RC=3 die "no rclone remote 'vultr' configured (set LLVMPIPE_I386_ARTIFACT=<local tar>)"
  REM=${ARTIFACT#s3://}; REM=vultr:${REM}
  rclone copyto --contimeout 15s --timeout 60s --retries 2 "$REM" "$TMP/a.tar.xz" || RC=4 die "download of the artifact from $REM failed"
fi
echo "$ARTIFACT_SHA256  $TMP/a.tar.xz" | sha256sum -c - >/dev/null || die "artifact sha256 mismatch (expected $ARTIFACT_SHA256)"
tar -xJf "$TMP/a.tar.xz" -C "$TMP" || die "cannot extract the artifact"
( cd "$TMP/i386-llvm" && sha256sum -c SHA256SUMS >/dev/null ) || die "SHA256SUMS of the pack does not match its files"
for f in $FILES SHA256SUMS; do install -m 0644 "$TMP/i386-llvm/$f" "$TMPOUT/$f" || die "install of $f failed"; done
echo "$ARTIFACT_SHA256" > "$TMPOUT/.artifact-sha256" || die "cannot write .artifact-sha256"
( cd "$TMPOUT" && sha256sum -c SHA256SUMS >/dev/null ) || die "staged files do not verify"
chmod 0755 "$TMPOUT"
rm -rf "$OUT" && mv "$TMPOUT" "$OUT" || die "cannot replace $OUT"
echo "$NAME: staged the i386 llvmpipe driver in $OUT (artifact ${ARTIFACT_SHA256:0:8})"
