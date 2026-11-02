#!/bin/sh
# Build and run the CmpAddSubKey allocation-failure test against the in-tree cmlib.
# Usage: run-addsubkey-fail-test.sh [output-binary]
# Exit code 0 = PASS; a failed check, a crash or a signal = FAIL.
set -e
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${ROOT:-$(CDPATH= cd -- "$HERE/../../../.." && pwd)}
CMLIB="$ROOT/sdk/lib/cmlib"
OUT=${1:-/tmp/addsubkey_fail_test}
CC=${CC:-cc}

"$CC" -std=gnu99 -fshort-wchar -Wno-multichar -g \
    -DCMLIB_HOST -DNASSERT -DTARGET_amd64 -D_NTSYSTEM_ -D__NO_CTYPE_INLINES -D__REACTOS__ \
    -I"$CMLIB" -I"$ROOT/sdk/include/host" \
    "$HERE/AddSubKeyFail.c" \
    "$CMLIB"/hiveinit.c "$CMLIB"/hivecell.c "$CMLIB"/hivesum.c "$CMLIB"/hivebin.c \
    "$CMLIB"/hivewrt.c "$CMLIB"/cmindex.c "$CMLIB"/cmname.c "$CMLIB"/cmkeydel.c \
    "$CMLIB"/cminit.c "$CMLIB"/cmvalue.c "$CMLIB"/cmse.c \
    -Wl,--wrap=HvAllocateCell,--wrap=HvReallocateCell \
    -o "$OUT"

echo "built: $OUT"
"$OUT"
