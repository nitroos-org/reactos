#!/bin/bash
# build-tests.sh <outdir>: mfttest.exe for amd64 and i386 (mingw-w64)
set -euo pipefail
OUT=${1:?usage: $0 <outdir>}; HERE=$(cd "$(dirname "$0")" && pwd); mkdir -p "$OUT"
x86_64-w64-mingw32-gcc -O2 -Wall -o "$OUT/mfttest64.exe" "$HERE/mfttest.c" -lmfplat -lmfuuid -lole32 -luuid -static-libgcc
i686-w64-mingw32-gcc -O2 -Wall -o "$OUT/mfttest32.exe" "$HERE/mfttest.c" -lmfplat -lmfuuid -lole32 -luuid -static-libgcc
