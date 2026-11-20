#!/bin/sh
# Build and run the big data value test (BigData.c) against the in-tree cmlib.
# Usage: run-big-data-test.sh [output-binary] [--max]
#   --max adds the largest chain (65535 segments, about 1 GB of data: needs ~4 GB of memory).
#   CFLAGS="-fsanitize=address,undefined" runs it with the sanitizers (ASAN_OPTIONS=detect_leaks=0).
# Exit code 0 = PASS; a failed check, a crash or a signal = FAIL.
set -e
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${ROOT:-$(CDPATH= cd -- "$HERE/../../../.." && pwd)}
CMLIB="$ROOT/sdk/lib/cmlib"
OUT=${1:-/tmp/big_data_test}
CC=${CC:-cc}

"$CC" -std=gnu99 -fshort-wchar -Wno-multichar -g ${CFLAGS:-} \
    -DCMLIB_HOST -DNASSERT -DTARGET_amd64 -D_NTSYSTEM_ -D__NO_CTYPE_INLINES -D__REACTOS__ \
    -I"$CMLIB" -I"$ROOT/sdk/include/host" -I"$HERE" \
    "$HERE/BigData.c" \
    "$CMLIB"/hiveinit.c "$CMLIB"/hivecell.c "$CMLIB"/hivesum.c "$CMLIB"/hivebin.c \
    "$CMLIB"/hivewrt.c "$CMLIB"/cmindex.c "$CMLIB"/cmname.c "$CMLIB"/cmkeydel.c \
    "$CMLIB"/cminit.c "$CMLIB"/cmvalue.c "$CMLIB"/cmse.c "$CMLIB"/cmcheck.c "$CMLIB"/cmheal.c \
    -o "$OUT"

echo "built: $OUT"
"$OUT" "$ROOT/media/nls/l_intl.nls" $2
