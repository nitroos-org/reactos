#!/bin/sh
# Build the structure-aware hive fuzz (HiveFuzz.c) against the in-tree cmlib with AddressSanitizer
# and run seeds FIRST..FIRST+COUNT-1, optionally on the hive files given (default: a base made by the test).
# Usage: run-hive-fuzz.sh FIRST COUNT [HIVEFILE...]
# Env: OUT (binary, default /tmp/hive_fuzz), CC, NOBUILD=1 (use OUT as it is).
# Exit code 0 = no crash, no hang, the live check and the reload held for every seed.
set -e
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=${ROOT:-$(CDPATH= cd -- "$HERE/../../../.." && pwd)}
CMLIB="$ROOT/sdk/lib/cmlib"
OUT=${OUT:-/tmp/hive_fuzz}
CC=${CC:-cc}

if [ "${NOBUILD:-0}" != 1 ]; then
"$CC" -std=gnu99 -fshort-wchar -Wno-multichar -g -O1 -fsanitize=address -fno-omit-frame-pointer ${CFLAGS:-} \
    -DCMLIB_HOST -DNDEBUG -DTARGET_amd64 -D_NTSYSTEM_ -D__NO_CTYPE_INLINES -D__REACTOS__ \
    -I"$CMLIB" -I"$ROOT/sdk/include/host" -I"$HERE" -I"$ROOT/media/nls" \
    "$HERE/HiveFuzz.c" \
    "$CMLIB"/hiveinit.c "$CMLIB"/hivecell.c "$CMLIB"/hivesum.c "$CMLIB"/hivebin.c \
    "$CMLIB"/hivewrt.c "$CMLIB"/cmindex.c "$CMLIB"/cmname.c "$CMLIB"/cmkeydel.c \
    "$CMLIB"/cminit.c "$CMLIB"/cmvalue.c "$CMLIB"/cmse.c "$CMLIB"/cmcheck.c "$CMLIB"/cmheal.c \
    -o "$OUT"
fi
ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1} "$OUT" "$ROOT/media/nls/l_intl.nls" "$@"
