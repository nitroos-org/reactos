# nitro-aacdec: AAC decoder MFT (optional features `aac-lc` and `aac`, NOT in the image)

Two variants are built from this directory (`AAC_VARIANT=lc|full`, default `lc`):

| | feature | FFmpeg | wrapper | decodes |
|---|---|---|---|---|
| `lc` | `aac-lc` (catalog `aac-lc.ini`, published `featmgr/aac-lc/9.0.2-47608676`) | 9.0.2 + `ffmpeg-9.0.2-aac-lc-only.patch` | `-DNITRO_AAC_LC_ONLY` | AAC-LC |
| `full` | `aac` (catalog `aac.ini`) | 9.0.2, **unmodified** | default | AAC-LC, HE-AAC (SBR), HE-AAC v2 (PS) |

Both register the same CLSID and install the same file names, so they exclude each other: `aac.ini` has `Replaces=aac-lc`
(turning `aac` on turns `aac-lc` off first, then installs the full decoder; turning `aac` off removes everything), and
`aac-lc.ini` has `Conflicts=aac` (it refuses to turn on while `aac` is on). The full variant accepts audioObjectType 2, 5 and
29 only (what the Windows decoder documents; AAC Main/LTP/SSR/ER/USAC are refused); HE-AAC output is 2048 frames per input frame
at twice the core rate. The rest of this file describes the LC-only variant unless it says "full".

`nitroaacdec.dll` is a synchronous Media Foundation transform registered as `CLSID_CMSAACDecMFT`
({32D186A7-218F-4C75-8876-DD77273A8999}), the CLSID Firefox's WMF path creates for `audio/mp4a-latm`.
It decodes **AAC-LC only** with FFmpeg's native `aac` decoder (LGPL-2.1-or-later), statically linked. Nothing here is
built by the ReactOS build: the DLLs are the hosted payload of the featmgr entry `aac-lc`
(`base/applications/featmgr/catalog/aac-lc.ini`), downloaded when the user turns the feature on, with a patent notice.

## What is built

- `nitroaacdec.c`: the IMFTransform (input `MFAudioFormat_AAC`, raw or ADTS payload; output PCM 16 bit or float 32 bit, one
  1024-frame sample per AAC frame), the class factory, `DllRegisterServer` (CLSID + `MFTRegister`). Behaviour follows the
  public Microsoft documentation of the AAC decoder MFT; no Microsoft binary was read or used.
- `ffmpeg-9.0.2-aac-lc-only.patch`: the only change to FFmpeg 9.0.2. It
  1. replaces `aacsbr.c`, `aacps*.c`, `sbrdsp.c` with `aacsbr_lc.c` (channel-element allocation + entry points that return
     `AVERROR_PATCHWELCOME`) and drops SBR/PS/USAC objects from the Makefiles,
  2. removes the SBR and PS Huffman tables (`aac/aacdec_tab.c`),
  3. makes an SBR/PS extension payload in a frame an error (`aac/aacdec.c`), and
  4. refuses any AudioSpecificConfig whose audio object type is not 2 (AAC-LC) or that signals SBR/PS explicitly
     (HE-AAC, HE-AAC v2, AAC Main/LTP/SSR, ER profiles, USAC/xHE-AAC).
- FFmpeg is configured with `--disable-everything --enable-decoder=aac` (libavcodec + libavutil only, no
  libavformat/swresample, no asm, no threads).
- `build-aacdec.sh <outdir>` downloads the pinned FFmpeg tarball (SHA-256 checked), applies the patch, builds both
  architectures with mingw-w64 and writes the payload files, the licence texts and the source tarball.
  `base/applications/featmgr/tools/stage-aac-lc-payload.sh` stages them with the pins of the catalog.

## What Fedora does (and what this mirrors)

Checked 2026-11-07 against Fedora's `ffmpeg` source package (rawhide, FFmpeg 9.0.2, builds `ffmpeg-free`/`libavcodec-free`):
`ffmpeg.spec` configures `--disable-decoders --enable-decoder=<enable_decoders>` and that list has the native `aac` decoder AND
`libfdk_aac # fdk-aac-free`; its only AAC-related patch, `ffmpeg-allow-fdk-aac-free.patch`, moves `libfdk_aac` out of the
"nonfree" list in `configure`. No Fedora patch touches `libavcodec/aac*`: the native decoder in ffmpeg-free is unchanged
(SBR and PS included), and libavcodec picks it first (`allcodecs.c` registers `ff_aac_decoder` at line 424 and
`ff_libfdk_aac_decoder` at 779). The patent-motivated stripping is in `fdk-aac-free`
(Fedora's fork of the Android Fraunhofer FDK AAC tree, 2.0.3): its `README.fedora` says it "is stripped from parts with patent
concerns (i.e. HE (High Efficiency) and HEv2 profiles)", the `libSBRdec` directory is absent from the source tarball, and the
Fedora Legal team approved that fork (https://bugzilla.redhat.com/1501522). We cannot use fdk-aac (operator rule), so this
patch applies the same scope (no SBR, no PS) to FFmpeg's native decoder; it is stricter than Fedora's ffmpeg-free itself.
Sources: https://src.fedoraproject.org/rpms/ffmpeg (ffmpeg.spec, enable_decoders, ffmpeg-allow-fdk-aac-free.patch),
https://src.fedoraproject.org/rpms/fdk-aac-free (fdk-aac-free.spec), https://wtaymans.fedorapeople.org/fdk-aac-free-2.0.3.tar.gz
(SHA-256 2dc6952b70283888994ae6e551a79039781f0a64c67fb637bffd5a8f483c34c5). Full report: the ticket
`releases/2026.11/backlog/MEDIA-aac-decoder-missing.md`.

## The full variant and Fedora (re-verified 2026-11-08)

Fedora's `ffmpeg-free` ships the native `aac` decoder unmodified, SBR and PS included: rawhide `ffmpeg.spec` (FFmpeg 9.0.2,
https://src.fedoraproject.org/rpms/ffmpeg, commit b40bf995d001927f649f67775bcd6e3c21e4127b, 2026-10-30) has Source0 = the
pristine upstream tarball, `--disable-decoders` then `--enable-decoder=` the list in `enable_decoders` (line 2 `aac`, line 4
`libfdk_aac # fdk-aac-free`), and its patches (codec-choice, allow-fdk-aac-free, allow-decklink, vapoursynth-lib-rename,
openh264 flush callback, streamcopy pts, chromium) do not touch `libavcodec/aac*`. The patent-motivated stripping is only in
`fdk-aac-free` (https://src.fedoraproject.org/rpms/fdk-aac-free, commit 827a29f5cca86bb4549951b29dc7bf70c76b0810). The full
variant is therefore the same decoder Fedora ships, built from the same upstream tarball. Full report: the ticket
`releases/2026.11/backlog/MEDIA-aac-full-he-aac-addon.md`.

## Known limits

- (lc only) HE-AAC with implicit (backward-compatible) signalling carries SBR in a fill element of each frame: the frame is
  refused (`MF_E_INVALID_STREAM_DATA` from `ProcessInput`), so the player reports a decode error rather than playing the
  band-limited core at half the sample rate.
- No ICodecAPI, no `GetAttributes`, no 32-bit-float-only or 24-bit output; channel configurations 1-7 (up to 7.1).
- The registry entries are written by featmgr (`aac-lc.ini`), not by regsvr32 (which also works: `DllRegisterServer`).
