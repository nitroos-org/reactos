#!/bin/bash
# Reproducible build of the Mesa3D software drivers for ReactOS, i386 and amd64:
#   i386, amd64: libgallium_wgl.dll, the OpenGL driver (WGL ICD); softpipe (the amd64 build also has llvmpipe)
#   amd64:       vulkan_lvp.dll + lvp_icd.json, the lavapipe Vulkan ICD; both amd64 drivers JIT-compile with a static
#                LLVM that build-llvm.sh makes first (AMD64_LLVM=0 builds amd64 like i386: softpipe only, no Vulkan driver)
# Host: Ubuntu 24.04 with gcc-mingw-w64-{i686,x86-64}-win32, g++-mingw-w64-{i686,x86-64}-win32,
# python3-venv, ninja-build, bison, flex, curl, xz-utils, patch (llvmpipe/lavapipe builds also cmake and glslang-tools, which Mesa 26.3 needs for lavapipe). Needs network for the pinned downloads.
# Usage: build-mesa.sh [WORKDIR]   Output: WORKDIR/out/{i386,amd64}/libgallium_wgl.dll, out/amd64/{vulkan_lvp.dll,lvp_icd.json},
#                                  mesa3d-licenses.txt, llvm-licenses.txt, SHA256SUMS
set -euo pipefail

MESA_VERSION=26.3.0
MESA_URL=https://archive.mesa3d.org/mesa-${MESA_VERSION}.tar.xz
MESA_SHA256=91d729aa68bb89e4ec857841300bbe922bcb3e52b1f97566ca83930d3b28343a
PIP_PINS="meson==1.12.1 mako==1.4.3 MarkupSafe==3.0.4 PyYAML==6.0.3 packaging==26.3 ply==3.11"
GALLIUM_DRIVERS=${GALLIUM_DRIVERS:-softpipe}
AMD64_LLVM=${AMD64_LLVM:-1}
# I386_LLVM=1 also builds the i386 driver with LLVM (llvmpipe next to softpipe, no Vulkan driver), for SysWOW64
I386_LLVM=${I386_LLVM:-0}
ARCHES=${ARCHES:-i386 amd64}
OPT=${OPT:-2}
JOBS=${JOBS:-8}

HERE=$(dirname "$(realpath "$0")")
W=$(realpath -m "${1:-$PWD/mesa-build}")
mkdir -p "$W/dl" "$W/out"
cd "$W"

[ -f "dl/mesa-${MESA_VERSION}.tar.xz" ] || curl -fsSL --retry 8 --retry-all-errors --retry-delay 10 -o "dl/mesa-${MESA_VERSION}.tar.xz" "$MESA_URL"
echo "$MESA_SHA256  dl/mesa-${MESA_VERSION}.tar.xz" | sha256sum -c -
rm -rf src
mkdir src
tar -xf "dl/mesa-${MESA_VERSION}.tar.xz" -C src
for p in "$HERE"/patches/*.patch; do patch -p1 -d "src/mesa-${MESA_VERSION}" < "$p"; done

# the environment is rebuilt whenever the pins differ from the ones it was made with
if [ "$(cat venv/pins 2>/dev/null)" != "$PIP_PINS" ]; then
    rm -rf venv
    python3 -m venv venv
    ./venv/bin/pip -q install $PIP_PINS
    echo "$PIP_PINS" > venv/pins
fi
export PATH="$W/venv/bin:$PATH"
export SOURCE_DATE_EPOCH=1760400000

for arch in $ARCHES; do
    case $arch in i386) tool=i686; fam=x86;; amd64) tool=x86_64; fam=x86_64;; esac
    cat > "cross-$arch.ini" <<EOT
[binaries]
c = '$tool-w64-mingw32-gcc-win32'
cpp = '$tool-w64-mingw32-g++-win32'
ar = '$tool-w64-mingw32-gcc-ar-win32'
strip = '$tool-w64-mingw32-strip'
windres = '$tool-w64-mingw32-windres'
cmake = 'cmake'
exe_wrapper = 'true'

[host_machine]
system = 'windows'
cpu_family = '$fam'
cpu = '$tool'
endian = 'little'

[properties]
needs_exe_wrapper = true
EOT
    # The shader disk cache (patch 0003) is only built with llvmpipe, the one driver here that stores
    # compiled shaders in it; softpipe-only builds keep the cache disabled.
    drivers=$GALLIUM_DRIVERS; vulkan=; llvm_args=-Dllvm=disabled; shader_cache=disabled; targets=src/gallium/targets/wgl/libgallium_wgl.dll
    if [ "$arch" = amd64 ] && [ "$AMD64_LLVM" = 1 ]; then
        "$HERE/build-llvm.sh" "$W" amd64
        drivers=llvmpipe,softpipe; vulkan=swrast; llvm_args="-Dllvm=enabled -Dshared-llvm=disabled"; shader_cache=enabled
        targets="$targets src/gallium/targets/lavapipe/vulkan_lvp.dll src/gallium/targets/lavapipe/lvp_icd.$fam.json"
        # meson finds the cross-built LLVM through its CMake package
        printf "\n[built-in options]\ncmake_prefix_path = ['%s']\n" "$W/llvm-inst/amd64" >> "cross-$arch.ini"
    elif [ "$arch" = i386 ] && [ "$I386_LLVM" = 1 ]; then
        "$HERE/build-llvm.sh" "$W" i386
        drivers=llvmpipe,softpipe; llvm_args="-Dllvm=enabled -Dshared-llvm=disabled"; shader_cache=enabled
        printf "\n[built-in options]\ncmake_prefix_path = ['%s']\n" "$W/llvm-inst/i386" >> "cross-$arch.ini"
    fi
    rm -rf "build-$arch"
    # zlib comes from Mesa's own wrap (hash-pinned there), never from the build host
    meson setup "build-$arch" "src/mesa-${MESA_VERSION}" --cross-file "cross-$arch.ini" \
        --force-fallback-for=zlib -Dzlib:default_library=static \
        --buildtype=release -Doptimization="$OPT" -Db_ndebug=true \
        -Dplatforms=windows -Dgallium-drivers="$drivers" -Dvulkan-drivers="$vulkan" $llvm_args \
        -Dglx=disabled -Degl=disabled -Dgbm=disabled -Dgles1=disabled -Dgles2=disabled -Dopengl=true \
        -Dmin-windows-version=7 -Dxmlconfig=disabled -Dshader-cache=$shader_cache -Dzstd=disabled \
        -Dlibunwind=disabled -Dvalgrind=disabled -Dbuild-tests=false \
        -Dc_args="-ffile-prefix-map=$W=." -Dcpp_args="-ffile-prefix-map=$W=." \
        -Dc_link_args="-static-libgcc -Wl,--no-insert-timestamp" \
        -Dcpp_link_args="-static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp"
    ninja -C "build-$arch" -j"$JOBS" $targets
    mkdir -p "out/$arch"
    "$tool-w64-mingw32-strip" -s -o "out/$arch/libgallium_wgl.dll" "build-$arch/src/gallium/targets/wgl/libgallium_wgl.dll"
    if [ -n "$vulkan" ]; then
        "$tool-w64-mingw32-strip" -s -o "out/$arch/vulkan_lvp.dll" "build-$arch/src/gallium/targets/lavapipe/vulkan_lvp.dll"
        # the manifest sits next to the DLL in system32, so the DLL is named without a path
        python3 - "build-$arch/src/gallium/targets/lavapipe/lvp_icd.$fam.json" "out/$arch/lvp_icd.json" <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))
j["ICD"]["library_path"] = "vulkan_lvp.dll"
open(sys.argv[2], "w").write(json.dumps(j, indent=4, sort_keys=True) + "\n")
PY
    fi
done

# the notices come from the files that were compiled (both builds)
python3 "$HERE/gen-licenses.py" "$W" > out/mesa3d-licenses.txt

if [ "$AMD64_LLVM" = 1 ]; then
    cp "$W/llvmsrc/llvm/LICENSE.TXT" out/llvm-licenses.txt
    (cd out && sha256sum i386/libgallium_wgl.dll amd64/libgallium_wgl.dll amd64/vulkan_lvp.dll amd64/lvp_icd.json mesa3d-licenses.txt llvm-licenses.txt | tee SHA256SUMS)
else
    (cd out && sha256sum i386/libgallium_wgl.dll amd64/libgallium_wgl.dll mesa3d-licenses.txt | tee SHA256SUMS)
fi
