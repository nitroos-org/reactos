#!/bin/bash
# Stage the amd64 LLVM Mesa pack (llvmpipe OpenGL + lavapipe Vulkan, GFX-01 artifact: ~35 MB
# download, ~116 MB installed) into dll/3rdparty/mesa3d/amd64-llvm/ so that CMakeLists.txt makes
# llvmpipe the DEFAULT OpenGL driver and installs the lavapipe Vulkan ICD in the base image.
#
#   stage-amd64-llvm.sh [OUTDIR]        (default: amd64-llvm/ next to this script)
#
# The binaries are NOT in git (66-69 MB each). They are fetched from the S3 cold tier (rclone
# remote "vultr" = Vultr ams2 object storage; 15 s connect / 60 s idle timeouts, 2 retries) and
# verified against SHA256SUMS. Set LAVAPIPE_ARTIFACT=/path/to/gfx01-lavapipe-amd64-artifacts.tar.xz
# to use a local copy instead of downloading (offline / CI mirror). The artifact + hash are the
# single source of truth shared with base/applications/featmgr/catalog/lavapipe-pack.ini.
#
# The pinned artifact sha256 is stored in amd64-llvm/.artifact-sha256; when it differs from the pin
# below (the pin was bumped) the pack is staged again. The new pack is extracted and verified in a
# temporary directory next to amd64-llvm/ and put in place with rm + mv, so no failure leaves a
# half-staged directory.
#
# Exit 0 = amd64-llvm/ populated and verified (or already was). Any failure exits non-zero, prints
# a one-line reason as its last line, and leaves amd64-llvm/ as it was; the build then keeps the
# in-tree softpipe OpenGL default (CMakeLists.txt falls back), so a host without rclone / network /
# the artifact still builds. Exit codes: 1 verify/install failure, 3 no rclone/remote, 4 download.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/amd64-llvm}
ARTIFACT=s3://reactos-nitro-archive/gfx01-lavapipe-amd64/26.3.0-dc2/gfx01-lavapipe-amd64-artifacts.tar.xz
ARTIFACT_SHA256=39d5f70c56fef5b13adde8147b859e9af3c5b1a265bf0ac00066b275a4778831
FILES="vulkan_lvp.dll lvp_icd.json libgallium_wgl.dll llvm-licenses.txt mesa3d-licenses.txt"
NAME=stage-amd64-llvm

die() { echo "$NAME: $*" >&2; exit "${RC:-1}"; }

# serialize concurrent configures of a shared source tree (amd64 Debug + amd64 Release)
mkdir -p "$(dirname "$OUT")" || die "cannot create $(dirname "$OUT")"
exec 9>"$HERE/.stage-amd64-llvm.lock" || die "cannot open the lock file"
flock 9

# already staged with this pin and intact? then do nothing (idempotent, no network). The pin is
# stored in .artifact-sha256, so a bumped ARTIFACT_SHA256 makes a stale staging get replaced.
if [ -f "$OUT/.artifact-sha256" ] && [ "$(cat "$OUT/.artifact-sha256")" = "$ARTIFACT_SHA256" ] &&
   [ -f "$OUT/SHA256SUMS" ] && ( cd "$OUT" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
  all=1; for f in $FILES; do [ -f "$OUT/$f" ] || all=0; done
  if [ "$all" = 1 ]; then
    echo "$NAME: amd64-llvm/ already staged and verified (artifact ${ARTIFACT_SHA256:0:8})"
    exit 0
  fi
fi

# Everything happens in temporary directories; $OUT is only touched by the final rm + mv, and
# TMPOUT is a sibling of $OUT so that the mv is a rename on one filesystem.
TMP=$(mktemp -d) || die "mktemp failed"
TMPOUT=$(mktemp -d "$(dirname "$OUT")/.stage-amd64-llvm.tmp.XXXXXX") || die "cannot create a temporary directory next to $OUT"
trap 'rm -rf "$TMP" "$TMPOUT"' EXIT
if [ -n "${LAVAPIPE_ARTIFACT:-}" ]; then
  cp "$LAVAPIPE_ARTIFACT" "$TMP/a.tar.xz" || die "cannot read $LAVAPIPE_ARTIFACT"
else
  command -v rclone >/dev/null 2>&1 || RC=3 die "rclone not found (set LAVAPIPE_ARTIFACT=<local tar>)"
  remotes=$(rclone listremotes 2>/dev/null || true)
  printf '%s\n' "$remotes" | grep -qx 'vultr:' || RC=3 die "no rclone remote 'vultr' configured (set LAVAPIPE_ARTIFACT=<local tar>)"
  REM=${ARTIFACT#s3://}; REM=vultr:${REM}
  rclone copyto --contimeout 15s --timeout 60s --retries 2 "$REM" "$TMP/a.tar.xz" || RC=4 die "download of the artifact from $REM failed"
fi
echo "$ARTIFACT_SHA256  $TMP/a.tar.xz" | sha256sum -c - >/dev/null || die "artifact sha256 mismatch (expected $ARTIFACT_SHA256)"
tar -xJf "$TMP/a.tar.xz" -C "$TMP" || die "cannot extract the artifact"
( cd "$TMP/amd64-llvm" && sha256sum -c SHA256SUMS >/dev/null ) || die "SHA256SUMS of the pack does not match its files"
for f in $FILES SHA256SUMS; do install -m 0644 "$TMP/amd64-llvm/$f" "$TMPOUT/$f" || die "install of $f failed"; done
echo "$ARTIFACT_SHA256" > "$TMPOUT/.artifact-sha256" || die "cannot write .artifact-sha256"
( cd "$TMPOUT" && sha256sum -c SHA256SUMS >/dev/null ) || die "staged files do not verify"
chmod 0755 "$TMPOUT"
rm -rf "$OUT" && mv "$TMPOUT" "$OUT" || die "cannot replace $OUT"
echo "$NAME: staged llvmpipe/lavapipe pack in $OUT (artifact ${ARTIFACT_SHA256:0:8})"
