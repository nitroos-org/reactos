#!/bin/sh
# Build and run the 'sk' cell primitives / check test against the in-tree cmlib.
# Usage: run-security-cell-test.sh [output-binary]
#   CFLAGS="-fsanitize=address,undefined" runs it with the sanitizers.
# Exit code 0 = PASS; a failed check, a crash or a signal = FAIL.
set -e
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${ROOT:-$(CDPATH= cd -- "$HERE/../../../.." && pwd)}
CMLIB="$ROOT/sdk/lib/cmlib"
OUT=${1:-/tmp/security_cell_test}
CC=${CC:-cc}

"$CC" -std=gnu99 -fshort-wchar -Wno-multichar -g ${CFLAGS:-} \
    -DCMLIB_HOST -DNASSERT -DNDEBUG -DTARGET_amd64 -D_NTSYSTEM_ -D__NO_CTYPE_INLINES -D__REACTOS__ \
    -I"$CMLIB" -I"$ROOT/sdk/include/host" -I"$HERE" \
    "$HERE/SecurityCell.c" \
    "$CMLIB"/hiveinit.c "$CMLIB"/hivecell.c "$CMLIB"/hivesum.c "$CMLIB"/hivebin.c \
    "$CMLIB"/hivewrt.c "$CMLIB"/cmindex.c "$CMLIB"/cmname.c "$CMLIB"/cmkeydel.c \
    "$CMLIB"/cminit.c "$CMLIB"/cmvalue.c "$CMLIB"/cmse.c "$CMLIB"/cmcheck.c "$CMLIB"/cmheal.c \
    -o "$OUT"

echo "built: $OUT"
"$OUT"
