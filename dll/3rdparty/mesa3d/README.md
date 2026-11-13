# Mesa3D software OpenGL driver

This directory holds the Mesa3D OpenGL driver that ReactOS installs by default as the OpenGL
driver for displays that bring none of their own. It is the Gallium software rasterizer
(softpipe) behind the Windows OpenGL driver interface (WGL ICD) that Mesa ships, and it gives
programs OpenGL 3.3 (compatibility profile) with GLSL 3.30. The built-in OpenGL 1.1
implementation in `dll/opengl` stays as the fallback, and as the choice of the OpenGL control
panel ("ReactOS Software Implementation").

Programs that need more than OpenGL 1.1 need this driver: SDL 2 games, the OpenGL video output
of VLC and Direct3D 7 and 9 programs, which Wine's Direct3D layer (wined3d) runs on OpenGL 2.0
or newer.

## What is here

| Path | What |
|---|---|
| `i386/libgallium_wgl.dll`, `amd64/libgallium_wgl.dll` | The prebuilt driver, copied to `system32` of every image by `CMakeLists.txt` |
| `build-mesa.sh` | Builds both DLLs from the pinned Mesa release tarball |
| `patches/` | Local patches to Mesa that the build applies (three, see "Local patches carried on top of Mesa 26.3") |
| `SHA256SUMS` | Hashes of the tarball, the two DLLs and the licence file |
| `mesa3d-licenses.txt` | The licence texts and copyright lines of every file that was compiled into the DLLs (made by `gen-licenses.py`); installed as `system32\mesa3d-licenses.txt` next to the DLL |
| `gen-licenses.py` | Reads the compiled sources and headers of a build and writes `mesa3d-licenses.txt`, with the copyright files of the packages `mingw-w64-common` and `gcc-mingw-w64-base` of the build host appended (the statically linked runtime); `build-mesa.sh` runs it and stops when those files are missing |

The DLLs are committed instead of being built with the image because the build needs Python
(meson), a second toolchain and a download of 68 MB, and a ReactOS build must not depend on any
of them. Anyone can check a committed DLL: the build is reproducible, and `SHA256SUMS` lists
what it must produce.

## Version and build

* Mesa 26.3.0, `https://archive.mesa3d.org/mesa-26.3.0.tar.xz`, SHA-256
  `91d729aa68bb89e4ec857841300bbe922bcb3e52b1f97566ca83930d3b28343a` (the value Mesa publishes in
  `docs/relnotes/26.3.0.rst`; the download was checked against it).
* zlib 1.3.1 is fetched by meson through Mesa's own wrap file, which pins its hash, and is linked
  statically. The C++ and GCC runtimes are linked statically, so the DLL imports only
  `kernel32`, `user32`, `gdi32` and `msvcrt`.
* Toolchain: Ubuntu 24.04 packages `gcc-mingw-w64-{i686,x86-64}-win32` and
  `g++-mingw-w64-{i686,x86-64}-win32` (GCC 13-win32, mingw-w64 11.0.1), meson 1.12.1, Mako 1.4.3,
  PyYAML 6.0.3 (the exact list is in the script), Ninja, Bison, Flex.
* Run `./build-mesa.sh WORKDIR`; it needs about 45 seconds per architecture on 12 jobs and writes
  `WORKDIR/out/{i386,amd64}/libgallium_wgl.dll`. Building the same tarball in two different
  directories gave identical DLLs (checked 2026-10-14).
* The options turn off everything that is not the Windows OpenGL driver, and set
  `min-windows-version=7`, so that the DLL uses no function that Windows 7 lacks.

## Local patches carried on top of Mesa 26.3

`build-mesa.sh` applies every `patches/*.patch` (in name order, `patch -p1`) to the pinned tarball. We carry no Mesa fork: a
patch is a self-contained change to one Mesa file area, written in Mesa's coding style, so that it can be offered upstream. When Mesa
is updated (see "Updating"), each patch is re-applied, rebased, or dropped because Mesa has the change by now.


* `0001`: softpipe allocated a texture cache for each of its 768 sampler view slots when a
  context was created, about 250 MB of memory per context. A 32-bit process has 2 GB of address
  space and wined3d creates several contexts per Direct3D object, so the persistent buffer
  allocation of wined3d failed and the program crashed. The caches now exist for the slots that
  were used; a context takes about 4 MB.
* `0002`: softpipe built every blit shader when a context was created. That took more than
  100 ms of an idle machine per context, and the time of one `Direct3DCreate9` went from about
  3 seconds to 50 milliseconds on the i386 test VM. The shaders are now made on the first blit,
  with the shader creation function of the driver (the blitter binds them without the wrappers
  of the Draw stages, so they must not be made through the wrappers).

* `0003`: the shader disk cache (`src/util/disk_cache*.c/h`) for Windows (it was an empty `TODO` there, and meson refused
  `-Dshader-cache=enabled`). llvmpipe compiles each new fragment or vertex shader variant with LLVM on the draw thread (about 180 ms
  each; 298 of the 661 draws of Word's Start screen), and stored none of it between program starts. With the cache a later start
  loads the compiled variants from disk. `build-mesa.sh` builds the cache only into the LLVM builds (llvmpipe is the one driver here
  that stores compiled shaders in it). The softpipe-only DLLs in this directory were built before the patch (`SHA256SUMS` describes that
  build): a rebuild with `0003` has the cache compiled out and behaves the same, but it is not byte-identical (the barrier and exit
  handler fixes are in code every build contains), so rebuilding them gives new hashes.
  The patch also fixes the fallback `util_barrier_wait` (it returned true to every thread, and `util_queue_finish` destroyed the
  barrier under the other threads: a hang with three or more queue threads) that the cache's queue runs into.
  See "Shader disk cache" below for the behaviour.

## Shader disk cache (llvmpipe builds)

The cache directory is `%LOCALAPPDATA%\Mesa\shader_cache` (`%USERPROFILE%\AppData\Local` when `LOCALAPPDATA` is not set), or
`%MESA_SHADER_CACHE_DIR%\mesa_shader_cache`. One file per compiled shader, in two-hex-digit subdirectories, plus an `index` file
that holds the size of the cache. The cache key contains the driver DLL's file time, the CPU features and the vector width, so a
new `libgallium_wgl.dll` or another CPU does not use old entries. The environment variables are Mesa's: `MESA_SHADER_CACHE_DISABLE=true`
switches it off, `MESA_SHADER_CACHE_MAX_SIZE=<n>[K|M|G]` limits it (default 1 GB; oldest entries go first),
`MESA_SHADER_CACHE_SHOW_STATS=true` logs the hits and misses when the driver is unloaded (stderr and OutputDebugString, as Mesa's other log lines).

Several processes may share the directory. A directory that cannot be written (read-only volume, no permission) switches the cache
off for that process; nothing else changes. Entries are checked with a CRC when they are read, and one that fails is deleted. The CRC
guards against damaged files, not against someone who can write the directory: the entries are machine code that llvmpipe loads, so
the directory must be writable only by the user it belongs to (the default under `%LOCALAPPDATA%` is).

## How the system uses it

`dll/opengl/opengl32` asks the display driver for an OpenGL driver. The display drivers of
ReactOS give none, so it now reads the system default from the default value of
`HKLM\SOFTWARE\ReactOS\OpenGL` ("Mesa3D") and loads the driver that is registered under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\OpenGLDrivers\Mesa3D`. Both keys are in
`boot/bootdata/hivesft.inf`. A display driver that provides its own OpenGL driver still wins,
and so does the value in `HKCU\Software\ReactOS\OpenGL` (the OpenGL control panel writes it).
Windows that draw to a bitmap or a printer keep the built-in implementation. If the DLL is
missing, or the processor lacks SSE2 (the registration carries `RequiresSSE2`, because the DLLs
are compiled for it), the built-in implementation is used.

## Speed and size

Measured on the test VMs (2 vCPUs, QEMU with KVM on a loaded host) with a lit three-gear scene of
300 by 300 pixels, double buffered, no swap interval: softpipe renders 23 frames per second on
amd64 and 72 on i386, the built-in implementation 26 and 102. The speed of softpipe is that of a
reference rasterizer; the point of the driver is the OpenGL version, not the speed. The DLL is
18.6 MB (amd64) and 19.3 MB (i386); the images grow by the compressed size of the DLL, see the
lane note for the measured values.

llvmpipe (LLVM JIT) was built for i386 too (LLVM 19.1.7, the same toolchain). A native i386 image does not use
it (73 MB). On 2026-10-14 its rasterizer threads stopped after a few seconds on i386; that did not reproduce on
2026-10-31 (main f7f7ad5419d, i386 Debug, 2 and 4 vCPUs: 120 s of the gear scene without swap interval, 600-1000
frames per second, and 60 s of the GLSL scene, both without a stall, also with the keyed event fix 72cbf83131d
reverted). The SysWOW64 part of amd64 images ships it, see below.

## Known differences from Windows

Mesa's pixel formats and a few WGL details differ from what Wine's `opengl32` test expects of a
Windows driver (it offers `PFD_SUPPORT_GDI` together with double buffering, does not reject a
share list that was shared before, has one global swap interval). These are Mesa's choices and
no program of the test set depends on them.

## Updating (softpipe DLLs)

Change `MESA_VERSION` and `MESA_SHA256` in `build-mesa.sh`, rebuild, check that the patches
still apply (`patch -p1 --dry-run` in the unpacked tarball; re-make or drop the ones that do not), replace the two DLLs, rewrite `SHA256SUMS` and run
`opengl32_apitest icd_default` and `ddraw_apitest` on both architectures.

## llvmpipe and lavapipe (amd64 default GPU, fetched at configure, not committed)

`build-mesa.sh` also builds the amd64 driver with LLVM: `libgallium_wgl.dll` then contains llvmpipe (OpenGL 4.6
compatibility profile, LLVM JIT, all cores) next to softpipe, and `vulkan_lvp.dll` is lavapipe, a software Vulkan 1.4
driver. LLVM 19.1.7 (X86 target only, no tools) is built first, static, by `build-llvm.sh` (about 25 minutes on 16 cores,
1.5 GB of work space); `AMD64_LLVM=0` skips all of it. Build host additions: `cmake`, `glslang-tools`.

The two DLLs are 66-69 MB each (23 MB compressed each, 134 MB on disk against 18 MB for the softpipe-only driver), so
they are not committed. On amd64 they are now the DEFAULT GPU: `CMakeLists.txt` runs `stage-amd64-llvm.sh` at
configure time, which fetches the GFX-01 artifact `gfx01-lavapipe-amd64-artifacts.tar.xz` from the S3 cold tier
(`rclone` remote `vultr`), verifies it against `SHA256SUMS`, and populates `amd64-llvm/` with `libgallium_wgl.dll`,
`vulkan_lvp.dll`, `lvp_icd.json`, `mesa3d-licenses.txt` and `llvm-licenses.txt`. `CMakeLists.txt` then installs them in
place of the softpipe-only DLL (and installs the two licence files to `system32`). `-DMESA3D_AMD64_LLVM=OFF`, or a build
host without `rclone`/network/the artifact, skips the fetch and the in-tree softpipe-only driver stays the default (no
Vulkan ICD) so the build never breaks. Set `LAVAPIPE_ARTIFACT=<local tar>` to stage from a local copy instead of S3. A native i386 image keeps softpipe.

* OpenGL: nothing to register beyond what is above; `GALLIUM_DRIVER=softpipe` in the environment of a process selects
  softpipe from the same DLL.
* Vulkan: Mesa's lavapipe has no Vulkan loader of its own, and the system has none; programs that bring `vulkan-1.dll`
  (Chromium, Electron, games) find the driver through the Khronos registry list: each value name of
  `HKLM\SOFTWARE\Khronos\Vulkan\Drivers` is the absolute path of an ICD manifest, data 0 = enabled. The path depends on
  the Windows directory, so `syssetup` (`RegisterVulkanIcds`, in `InstallReactOS`) writes the value for
  `%SystemRoot%\system32\lvp_icd.json` when that file exists. An application that registers its own ICD as well
  (SwiftShader of Claude Desktop) makes the loader list two devices; remove that value to make lavapipe the one.
* Chromium and Electron do not use this driver for their windows: wined3d reports llvmpipe (its OpenGL renderer) as the
  Microsoft Basic Render Driver (1414:008c), as Windows does without a display driver, and Chromium's software
  rendering list then disables GPU compositing, so they composite in software and present with GDI. No per-app
  `Wine\AppDefaults\<app>.exe\Direct3D renderer=no3d` key is needed any more.

Checksums of the artifacts of the amd64 build (Mesa 26.3.0, LLVM 19.1.7, Ubuntu 24.04 mingw-w64 GCC 13-win32):

```
7fc352df8044a1c7dbdde79fd78be34f8a73842328d7a5ebbaf7bfb7eb63783a  amd64-llvm/libgallium_wgl.dll
cf934392fd0b14692fd950b68b4a776dae266adb2a387c33eecf1ef07cdbcde7  amd64-llvm/vulkan_lvp.dll
feb96dd7f1e2b183b080d215d6c676ce8e3a40925a01196e38cecddd4a29ec06  amd64-llvm/lvp_icd.json
8176f74c4065731f80ca230308c633b961203af6c60a78a06c187fa244a76fab  amd64-llvm/mesa3d-licenses.txt
8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee  amd64-llvm/llvm-licenses.txt
```

Speed (QEMU/KVM, 4 vCPUs, Intel host; 2026-10-24): the lit three-gear scene of 300 by 300 gives 1630 frames per second with
llvmpipe, 364 with softpipe and 1530 with the built-in OpenGL 1.1 implementation; a GLSL 1.10 fragment-bound scene
(400 by 400, 100 iterations) takes 16 ms per frame with llvmpipe and 452 ms with softpipe (the built-in implementation has
no shaders). Chromium 138 (Electron 37.6) with ANGLE on Vulkan, WebGL scene of 1280 by 720: 12.7 ms per frame with
lavapipe against 30.8 ms with SwiftShader (mean of 5 launches); a page of 150 blurred layers animated by CSS reaches 4.5 frames
per second against 3.0. The first draw call costs about 30 ms more with the JIT (130 ms against 100 ms).

### Staging and public builds

Both staging scripts (`stage-amd64-llvm.sh`, `stage-i386-llvm.sh`) run on every configure. They extract and verify the
pack in a temporary directory next to the target and move it into place, so a failure never leaves a half-staged
`amd64-llvm/` or `i386-llvm/`; the pinned artifact hash is stored in `.artifact-sha256` in the staged directory, and a
changed pin in the script stages the new pack again. CMake accepts the directory only with every DLL, both licence files
and `SHA256SUMS`. `rclone` runs with `--contimeout 15s --timeout 60s --retries 2`. At the end of the configure there is
one line per architecture, `Mesa3D amd64: llvmpipe (artifact beed97f8)` or
`Mesa3D amd64: softpipe fallback (<reason>)` (and the same for i386 in the SysWOW64 guest configure), so a silent fall
back to OpenGL 3.3 is visible.

**Public builds.** The `vultr` S3 remote is private. A builder without it (every public builder) gets the softpipe
fallback on both architectures: OpenGL 3.3, no compute shaders and no lavapipe Vulkan ICD on amd64, and softpipe in
SysWOW64. Such a build is complete and works; to get llvmpipe either set `LAVAPIPE_ARTIFACT` /
`LLVMPIPE_I386_ARTIFACT` to a local copy of the artifacts or build the packs with `build-llvm.sh` and `build-mesa.sh`.

## 32-bit programs on amd64 (SysWOW64)

The opengl32 of SysWOW64 finds its driver as the 64-bit one does, but a 32-bit process reads `HKLM\SOFTWARE` through
`SOFTWARE\Wow6432Node`, so `boot/bootdata/hivesft_amd64.inf` registers Mesa3D in that view too (as Windows registers
32-bit drivers), and `boot/bootdata/packages/syswow64.lst` puts the i386 `libgallium_wgl.dll` and its notices in
SysWOW64. Without both, 32-bit programs got the built-in OpenGL 1.1.

The i386 driver there is llvmpipe (OpenGL 4.6 core and compatibility, compute shaders), not softpipe: wgpu, the
renderer of the 32-bit WordCraft, needs compute shaders and does not start on softpipe's OpenGL 3.3. The nested i386
build of an amd64 image runs `stage-i386-llvm.sh` at configure time, which fetches
`wow64-llvmpipe-i386-artifacts.tar.xz` from the S3 cold tier (`LLVMPIPE_I386_ARTIFACT=<local tar>` for a local copy),
verifies it and populates `i386-llvm/` with `libgallium_wgl.dll` and `mesa3d-licenses.txt` (the Mesa notices of that
build with the LLVM licence appended). `-DMESA3D_WOW64_LLVM=OFF`, or a host without the artifact, keeps the in-tree
i386 softpipe driver in SysWOW64. The pack is `ARCHES=i386 I386_LLVM=1 ./build-mesa.sh WORKDIR` (the Mesa part
rebuilt to the same DLL twice); its size is 73 MB installed, 18.6 MB compressed.

```
ffbe26e2d376134d6380b08872a712b565597b30f4ce232da9aac85ca0d5c98b  wow64-llvmpipe-i386-artifacts.tar.xz
05f636f3dfb6923cf75e1861022093f5b8677b67e5be96e14a01833690bacd83  i386-llvm/libgallium_wgl.dll
e8261a3c1111986357368c0187823b5854d4cc0415d287232ef8d8566874802d  i386-llvm/mesa3d-licenses.txt
```

Under WoW64 (amd64 Release, 4 vCPUs) the 32-bit driver gave the gear scene 776 frames per second for 120 s and the
GLSL scene 22.8 ms per frame, without a stall.
