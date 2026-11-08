#!/bin/bash
# Build the NitroOS AAC-LC decoder MFT (nitroaacdec.dll) for amd64 and i386, plus its licence/notice files.
#   build-aacdec.sh <outdir>
# Needs: x86_64-w64-mingw32-gcc and i686-w64-mingw32-gcc (mingw-w64, win32 threads model, msvcrt), make, patch, xz, curl or a
# local copy of the FFmpeg tarball in FFMPEG_TARBALL. Not part of the ReactOS build: the DLLs are NOT in the image, they are
# the hosted payload of the optional feature "aac-lc" (base/applications/featmgr/catalog/aac-lc.ini).
# Outputs (the files of catalog [Download]):
#   nitroaacdec64.dll nitroaacdec32.dll aac-lc-licenses.txt aac-lc-source-offer.txt aac-lc-patent-notice.txt
#   nitroaacdec-src-<ver>.tar.xz   (the corresponding source; hosted next to the payload, not installed)
# The FFmpeg tarball is pinned by SHA-256 below (release 9.0.2, signed by the FFmpeg release key; Fedora's ffmpeg package
# uses the same release). The only change to FFmpeg is ffmpeg-9.0.2-aac-lc-only.patch (removes SBR, PS and USAC).
set -euo pipefail
OUT=${1:?usage: $0 <outdir>}
HERE=$(cd "$(dirname "$0")" && pwd)
FFVER=9.0.2
FFURL=https://ffmpeg.org/releases/ffmpeg-$FFVER.tar.xz
FFSHA=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
PACK=1                                  # revision of this wrapper
JOBS=${JOBS:-8}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

TAR=$WORK/ffmpeg-$FFVER.tar.xz
if [ -n "${FFMPEG_TARBALL:-}" ]; then cp "$FFMPEG_TARBALL" "$TAR"; else curl -fsSL -o "$TAR" "$FFURL"; fi
echo "$FFSHA  $TAR" | sha256sum -c - >/dev/null || { echo "FFmpeg tarball does not match the pinned SHA-256" >&2; exit 1; }
tar -xJf "$TAR" -C "$WORK"
SRC=$WORK/ffmpeg-$FFVER
( cd "$SRC" && patch -p1 -s < "$HERE/ffmpeg-$FFVER-aac-lc-only.patch" )

# the same source path every time (it ends up in assert strings): build in a fixed-name tree
build_arch() {   # build_arch <name> <cross-prefix> <ffmpeg-arch> <extra cflags> <dll> <image base>
    local name=$1 cp=$2 farch=$3 xcflags=$4 dll=$5 base=$6 B=$WORK/build-$1
    mkdir -p "$B"
    ( cd "$B" && "$SRC/configure" --enable-cross-compile --cross-prefix=$cp --arch=$farch --target-os=mingw32 \
        --disable-everything --disable-programs --disable-doc --disable-avformat --disable-avfilter --disable-avdevice \
        --disable-swscale --disable-swresample --disable-network --disable-autodetect --disable-asm --disable-pthreads \
        --disable-w32threads --disable-debug --disable-iconv --disable-hwaccels --enable-static --disable-shared \
        --enable-small --enable-decoder=aac --disable-stripping \
        --extra-cflags="-O2 -fno-stack-protector -D_WIN32_WINNT=0x0601 -ffile-prefix-map=$SRC=. $xcflags" > configure.out 2>&1 \
      && sed -i 's/^#define HAVE_BCRYPT 1/#define HAVE_BCRYPT 0/' config.h \
      && make -j$JOBS libavcodec/libavcodec.a libavutil/libavutil.a > make.out 2>&1 ) || { tail -20 "$B/configure.out" "$B/make.out" >&2; exit 1; }
    ${cp}gcc -O2 -fno-stack-protector -D_WIN32_WINNT=0x0601 $xcflags -ffile-prefix-map=$SRC=. -I"$B" -I"$SRC" -shared \
        -o "$B/$dll" "$HERE/nitroaacdec.c" "$HERE/nitroaacdec.def" "$B/libavcodec/libavcodec.a" "$B/libavutil/libavutil.a" \
        -lmfplat -lmfuuid -lole32 -static-libgcc -Wl,--kill-at -Wl,--no-insert-timestamp -Wl,--disable-auto-image-base -Wl,--image-base=$base \
        -Wl,--exclude-libs,ALL -Wall
    ${cp}strip -s "$B/$dll"
    # strip stamps the current time into the PE header: zero TimeDateStamp and recompute nothing (CheckSum = 0), so that
    # two builds of the same source give the same bytes
    python3 -I - "$B/$dll" <<'PY'
import struct, sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
pe = struct.unpack_from('<I', b, 0x3c)[0]
assert b[pe:pe + 4] == b'PE\0\0'
struct.pack_into('<I', b, pe + 8, 0)            # TimeDateStamp
struct.pack_into('<I', b, pe + 24 + 64, 0)      # CheckSum (same offset in PE32 and PE32+)
open(p, 'wb').write(b)
PY
    install -m 0644 "$B/$dll" "$OUT/$dll"
}
build_arch amd64 x86_64-w64-mingw32- x86_64 "" nitroaacdec64.dll 0x1a0000000
build_arch i386 i686-w64-mingw32- x86 "-msse2 -mfpmath=sse" nitroaacdec32.dll 0x6a000000

# licence / notice files
{
    echo "NitroOS AAC audio decoder (AAC-LC): licence texts"
    echo "================================================"
    echo
    echo "nitroaacdec.dll (the Media Foundation transform) and the FFmpeg libraries linked into it are licensed under the"
    echo "GNU Lesser General Public License, version 2.1 or (at your option) any later version. Both libavcodec and libavutil"
    echo "are statically linked into the DLL; the complete corresponding source, including the build script that rebuilds"
    echo "(relinks) the DLLs, is offered in aac-lc-source-offer.txt. FFmpeg $FFVER with one patch (ffmpeg-$FFVER-aac-lc-only.patch)."
    echo "FFmpeg is a trademark of Fabrice Bellard, originator of the FFmpeg project."
    echo
    echo "Statically linked runtime of the build toolchain (mingw-w64 GCC, win32 threads, msvcrt): the GCC runtime library"
    echo "(libgcc: GPL-3.0-or-later WITH GCC-exception-3.1, https://www.gnu.org/licenses/gcc-exception-3.1.html) and the"
    echo "mingw-w64 runtime (ZPL-2.1, BSD-style, LGPL-2.1-or-later and public-domain files, https://www.mingw-w64.org/)."
    echo
    echo "---------------- FFmpeg LICENSE.md ----------------"
    cat "$SRC/LICENSE.md"
    echo
    echo "---------------- COPYING.LGPLv2.1 ----------------"
    cat "$SRC/COPYING.LGPLv2.1"
} > "$OUT/aac-lc-licenses.txt"
install -m 0644 "$HERE/aac-lc-source-offer.txt" "$OUT/aac-lc-source-offer.txt"
install -m 0644 "$HERE/aac-lc-patent-notice.txt" "$OUT/aac-lc-patent-notice.txt"

# corresponding source: this directory (wrapper, patch, scripts, notices); FFmpeg itself is the pinned upstream tarball
SRCTAR=nitroaacdec-src-$FFVER-$PACK.tar.xz
( cd "$HERE" && tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --transform 's,^\./,nitro-aacdec/,' \
    -cf - ./README.md ./build-aacdec.sh ./nitroaacdec.c ./nitroaacdec.def ./ffmpeg-$FFVER-aac-lc-only.patch \
    ./aac-lc-source-offer.txt ./aac-lc-patent-notice.txt | xz -9e > "$OUT/$SRCTAR" )
echo "built in $OUT: $(ls "$OUT" | tr '\n' ' ')"
