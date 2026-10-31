#!/bin/sh
# Build and run the old-case-table hive upgrade test against the in-tree cmlib.
# Usage: run-lh-hash-upgrade-test.sh [output-binary] [-- args for the test]
#   with no args the test uses media/nls/l_intl.nls of the tree; "--check HIVE" times a hive file.
# Exit code 0 = PASS; a failed check, a crash or a signal = FAIL.
set -e
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${ROOT:-$(CDPATH= cd -- "$HERE/../../../.." && pwd)}
CMLIB="$ROOT/sdk/lib/cmlib"
OUT=${1:-/tmp/lh_hash_upgrade_test}
CC=${CC:-cc}
[ $# -gt 0 ] && shift
[ "${1:-}" = "--" ] && shift

"$CC" -std=gnu99 -fshort-wchar -Wno-multichar -g ${CFLAGS:-} \
    -DCMLIB_HOST -DNASSERT -DNDEBUG -DTARGET_amd64 -D_NTSYSTEM_ -D__NO_CTYPE_INLINES -D__REACTOS__ \
    -I"$CMLIB" -I"$ROOT/sdk/include/host" -I"$HERE" \
    "$HERE/LhHashUpgrade.c" \
    "$CMLIB"/hiveinit.c "$CMLIB"/hivecell.c "$CMLIB"/hivesum.c "$CMLIB"/hivebin.c \
    "$CMLIB"/hivewrt.c "$CMLIB"/cmindex.c "$CMLIB"/cmname.c "$CMLIB"/cmkeydel.c \
    "$CMLIB"/cminit.c "$CMLIB"/cmvalue.c "$CMLIB"/cmcheck.c "$CMLIB"/cmheal.c \
    -o "$OUT"

echo "built: $OUT"
if [ $# -gt 0 ]; then
    "$OUT" "$@"
else
    "$OUT" "$ROOT/media/nls/l_intl.nls"
fi
