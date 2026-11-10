# featmgr (Optional Features / Addon Manager)

Feature catalog, `featmgr.exe` (CLI) and the Optional Features applet (`optfeatures.exe`); Scoop apps are installed
through `scoop.c` / `engine.c`. Roundtrip test: `tests\roundtrip.cmd` (offline, in a guest); Scoop live test: `tests\scoop-live.cmd`.

- NitroOS default for VS Code: after featmgr installs or updates the Scoop app `vscode` or `vscode-insiders`, it adds
  `"terminal.integrated.windowsUseConptyDll": false` to `<scoop>\persist\<app>\data\user-data\User\settings.json`
  when that key is absent (an existing value is never changed). One file, `scoopdefaults.c`; remove it when
  CONSOLE-condrv-device (`\Device\ConDrv`) lands. A plain `scoop install` typed in a shell does not go through featmgr.
- NitroOS default for WezTerm (`wezterm`, `wezterm-nightly`): its bundled `conpty.dll` and `OpenConsole.exe` need
  `\Device\ConDrv`, so featmgr renames them to `*.off` in each real version directory under `<scoop>\apps\<app>`
  after an install/update it runs (WezTerm then uses the system ConPTY; it has no setting for that). With no WezTerm config
  present it also writes `~\.wezterm.lua` (`default_prog` = pwsh).
- NitroOS default for Alacritty: when `%APPDATA%\alacritty` has no `alacritty.toml`/`alacritty.yml`, featmgr writes
  one with an installed font (Lucida Console) and `pwsh` (else `cmd`); Alacritty's own defaults (Consolas, powershell)
  do not exist here. These two never follow links (reparse-point checks, CREATE_NEW). Same removal rule as above.

## Hosted payloads (OS-tier packs downloaded at enable time)

An OS-tier manifest whose files are not in the image lists them in `[Download]`, one line per file:
`File<N>=<file name>|<SHA-256>|<size in bytes>`, where `<file name>` is the `[Payload]` source name. When the pack is
turned on, featmgr fetches each file that is not already staged (and verified) in `%SystemRoot%\Featmgr\Payload\<id>\`
from `<base>/<[Source] Path>/<file name>` with the component downloader (https only, retries, progress, Cancel),
refuses it unless its SHA-256 matches, then applies `[Payload]` and `[Registry]` as for a staged pack (an existing
destination file is moved aside to `.fmbak` and put back when the pack is turned off) and deletes the downloaded copies.
Nothing outside `%SystemRoot%\Featmgr` changes until every file is downloaded and verified. Every `[Payload]` file of a hosted pack must have a
`[Download]` hash (else the pack fails closed), each installed copy is re-hashed where it lands, and a download is
aborted as soon as it is larger than its pinned size. A file in use when the pack is turned off (a loaded DLL) is
renamed to a free `<name>.fmdel[N]` and deleted at reboot, so the original goes back at once; if it cannot be renamed,
the original replaces it at the next boot (a reboot-delete is never queued for the real name of a backed-up file).

- `<base>`: `HKLM\SOFTWARE\ReactOS\Nitro\Featmgr`, value `PayloadBaseUrl` (REG_SZ), when set; otherwise `[Source] BaseUrl`
  of the manifest (`lavapipe-pack`: `https://repo.nitroos.org/featmgr`). A base that still holds a `REPLACE-WITH-...`
  placeholder, or that is not `https://`, makes the pack listed as "not available yet" (no broken enable).
- `[Source] Arch=amd64`: on any other architecture the entry says so ("Only for 64-bit (amd64) NitroOS").
- `[Feature] BuiltInFile=<path>`: when the image already carries the pack (that file exists) and featmgr has no record of
  it, the entry shows Enabled, "included in this image", and cannot be turned off there.
- The hosted files of `lavapipe-pack` are produced by `tools/stage-lavapipe-payload.sh <dir>` (the six files of
  `[Download]` plus `SHA256SUMS`); they are published at `https://repo.nitroos.org/featmgr/lavapipe-pack/26.3.0-beed97f8/`. Copying them into the payload
  folder instead makes the pack installable offline (they are still verified). Offline tests: `tests\roundtrip.cmd` (H1-H29).

## AAC audio decoder (AAC-LC), opt-in add-on

Entry `aac-lc` (`catalog/aac-lc.ini`, amd64): a hosted pack (see above) that installs `nitroaacdec.dll`, an AAC-LC decoder Media
Foundation transform (`CLSID_CMSAACDecMFT`, the CLSID Firefox's WMF path creates for `audio/mp4a-latm`), into System32 and, for 32-bit
programs, SysWOW64, with the licence texts and the written source offer in `System32\aac-lc-licenses`. It is NOT in the image:
real MP4 files carry AAC audio and without a decoder Firefox refuses the whole file ("no decoder found for audio/mp4a-latm").
The decoder is FFmpeg's native `aac` decoder (LGPL-2.1-or-later) built AAC-LC only (SBR, PS and USAC removed by
`dll/3rdparty/nitro-aacdec/ffmpeg-9.0.2-aac-lc-only.patch`), the way Fedora keeps HE-AAC out of fdk-aac-free; see
`dll/3rdparty/nitro-aacdec/README.md` for what Fedora does exactly. Because AAC has a patent pool, `[Feature] Notice=` is shown before
the feature is turned on: the Optional Features GUI asks OK/Cancel, `featmgr /enable aac-lc` prints it first.

- Registration is `[Registry]` only (no regsvr32): the CLSID/InprocServer32 keys and the `MediaFoundation\Transforms` entries for the
  64-bit view and for `Classes\Wow6432Node`. New value type `REG_BINARY` (hex digits) and the pseudo-type `KEY`
  (`HKLM|subkey||KEY`: creates the key, and turning the feature off deletes it again when this enable created it and it is empty).
- Files: `tools/stage-aac-lc-payload.sh <dir>` builds them (reproducibly, `build-aacdec.sh`), checks the pins of the catalog and writes
  `SHA256SUMS` and the source tarball; the folder is published at `https://repo.nitroos.org/featmgr/aac-lc/<version>-<hash>/`.
- Tests: `tests\aaclc-live.cmd` (turn on, notice, files, both registry views, decoder via `mfplat_apitest MftAac` and `mfttest`
  against FFmpeg's own decode, HE-AAC refused, turn off removes everything, turn on again).

### Full AAC (AAC-LC, HE-AAC, HE-AAC v2): entry `aac`

Entry `aac` (`catalog/aac.ini`, amd64) is the same decoder built from the UNPATCHED FFmpeg 9.0.2 native `aac` decoder (SBR and PS
included, as in Fedora's ffmpeg-free; `AAC_VARIANT=full` in `build-aacdec.sh` / `tools/stage-aac-lc-payload.sh`): the same
`nitroaacdec.dll` names, the same CLSID and the same registry keys as `aac-lc`, licence texts in `System32\aac-licenses`, a notice that
names HE-AAC and HE-AAC v2. It is a separate feature id, not a new version of `aac-lc`: the published `aac-lc` pack (and its pins) stay
valid. Because both write the same files and keys they exclude each other, with two catalog keys in `[Feature]`:

- `Replaces=aac-lc` (in `aac.ini`): turning `aac` on first turns `aac-lc` off when it is on (its files and keys are removed, or what it
  backed up is restored), after the pack of `aac` is downloaded and verified (a failed download leaves `aac-lc` in place), then installs
  the full decoder. A removal that has to wait for a reboot (files in use) stops the upgrade with a message instead of mixing the two.
- `Conflicts=aac` (in `aac-lc.ini`): `aac-lc` refuses to turn on while `aac` is on.

Turning `aac` off removes everything; `aac-lc` stays off (it is not restored). Tests: `tests\aac-live.cmd` (A: turn on, notice, files, both
views, decoder LC/HE-AAC/HE-AAC v2, off, on again; upgrade from `aac-lc`; `aac-lc` refused while `aac` is on).

## Wine Gecko 2.47.4 (the mshtml engine), on demand

Entry `wine-gecko` (`catalog/wine-gecko.ini`, i386 and amd64; Provider=component, recipe in `catalog/components.ini`). Gecko is not
in the image: Install downloads the official packages, refuses them unless the SHA-256 (and the SHA-1) match, and runs them silently.
It is compatibility-only (an old engine for WebBrowser controls, help viewers and installers; not for browsing untrusted
sites). Licence: MPL 2.0, with the LGPL and the third-party licences of the engine's about:license page (the package's `LICENSE`
points to it); nothing is redistributed. mshtml (synced to Wine 10.0) accepts exactly Gecko 2.47.4 (`GECKO_VERSION` in `dll/win32/mshtml/nsiface.idl`), WineHQ has nothing newer.

- Two packages on a 64-bit system, as for the add-on prompt of appwiz.cpl (the same sources and SHA-1 pins; `tools\check-gecko-pins.sh`
  compares `dll\cpl\appwiz\addons.c` with `components.ini`): `[wine-gecko]` is the WineHQ 32-bit MSI (installed by the
  32-bit msiexec into SysWOW64, and the only package on i386), `[wine-gecko-x64]` the WineHQ x86_64 MSI. `Also=` in the component
  list chains them: installed one after the other, a package whose own detect rule already holds (installed by appwiz's prompt) is
  skipped, a failing second package takes the first out again, and the entry is Enabled only when every package of this build is there.
  appwiz's prompt installs only the package of its own architecture, so after it on amd64 featmgr shows Wine Gecko as not installed
  (the 32-bit programs have no engine yet) and Install adds the missing one.
- Detected by the engine's `gecko\2.47.4\wine_gecko\xul.dll` in System32 (and SysWOW64); the packages also write
  `HKLM\Software\Wine\MSHTML\2.47.4\GeckoPath`, which iexplore's check and mshtml read.
- Uninstall runs `msiexec /x` for each product (an already removed one, error 1605, counts as removed), then the list's `Cleanup=`
  line: the 32-bit and the 64-bit MSI register one component, so removing both leaves the files of one of them behind, and a stale
  32-bit `GeckoPath`. Without a recorded install (appwiz did it) the same lines are derived from the component list.
- Tests: `tests\gecko-live.cmd` (real downloads; `mshtmlrender.c` is the mshtml consumer: it builds with any Windows compiler for
  both architectures and checks title, script and layout), `tests\components-live.cmd` C25-C45 (the `Also=` rules with fixtures).

## Native installs and the RAPPS catalog (rapps.exe is gone)

NitroOS no longer builds or ships `rapps.exe` / `rapps.com` (the upstream source stays in `base/applications/rapps*`; build it
with `-DNITRO_SHIP_RAPPS=ON`). Everything it did for us is done here:

- **Provider=native** (`native.c`, `natgen.c`; the old spelling `rapps` is read as `native`): featmgr downloads the file itself
  (wininet; https, or http when the entry has a checksum), verifies SHA-256, else SHA-1 (both when both are given; an entry with
  neither is refused and not imported), then installs silently: `msiexec /i ... /qn /norestart <MsiProperties>`, Inno / NSIS
  switches (from `Installer=` or detected from the file), the entry's `SilentParameters`, or `Installer=Generate` (unpack a zip or
  cab, move the `[Generate] Files`, write the Add/Remove Programs record and the Start menu shortcut) / `Installer=ExeInZip`.
  Generate and ExeInZip run in a `featmgr /nat-install` child; archive entry names are checked (no `..`, no drive), files are
  created `CREATE_NEW`, and an existing reparse point is never written through.
- **Uninstall**: the recorded line is `featmgr /nat-uninstall <RegName|-> <name> <tag>`: it finds the program's Uninstall key
  (HKCU, HKLM, HKLM WoW64; key name = RegName or name, or DisplayName), then removes what a Generate install recorded, or runs
  `msiexec /x{key} /qn`, or the QuietUninstallString / UninstallString with the silent switches of the program's installer type
  (NSIS runs in place with `_?=` so that it finishes before featmgr looks). `[Rapps] UninstallCmd[.amd64|.x86]` still overrides.
- **Installed state**: a native entry is also `Enabled` when its Uninstall key exists (RegName / UninstallName / Name), as RAPPS saw it.
- **Local-first**: `[Rapps] LocalInstaller=` names a file in the feature's payload folder (PowerShell 7's MSI, put there by the
  image); it is used, with no download, when its hash matches `[Source] ArtifactSHA256`.
- **Catalog**: `featmgr /update-catalog` (the GUI's *Update catalog* button) downloads `https://rapps.reactos.org/rappmgr2.cab`
  (the address rapps used; the server certificate chain must end in the ISRG Root X1/X2 pins rapps had), unpacks the entries
  into `%SystemRoot%\Featmgr\RappsDb\appdb` (admin-writable, replaced only when complete) and runs `/import-rapps` on it. The
  importer keeps RAPPS rules: `[Section.<arch>]` overrides `[Section]`, the generic URL is ignored on non-x86 unless `/anyarch`,
  `NTVersion` is honoured. Dropped: entries without a checksum, and `firefox`, `firefox-esr`, `firefox28`, `firefox36` (the native
  `firefox` entry, current release, replaces the old overlay).
- `featmgr /install <name>` resolves a bare RAPPS package name to `rapps-<name>` and fetches the catalog when there is none (the Japanese
  language package, scripts). Setup installs and asks for neither Gecko nor WineVDM; both are catalog entries (`wine-gecko`; `winevdm`, i386 only: a
  `Provider=component` manifest plus its `components.ini` section), so they need no RAPPS catalog download.
- **Entry points**: Start menu "Optional Features" replaces "Applications Manager"; appwiz.cpl "Programs and Features" is its own
  list of installed programs (uninstall / change) with a "Turn features on or off" button, and has no software catalog (as in
  Windows 10); browserchooser installs Firefox with `featmgr /install firefox`; syssetup and the language page call
  `featmgr /install <package>`. `rapps://` was never registered by anything in the tree, so there is no compatibility shim;
  programs that rapps' Generate installer registered keep working: `/nat-uninstall` reads the same `RApps` record.
- `unattend.inf` keeps the old key name `RappsDownload` (existing answer files): it now allows featmgr to download the add-ons.
- Tests: `tests\roundtrip.cmd` (offline fixtures) and `tests\live-install.cmd` (a real HTTP download of a test installer, hash
  check, silent install, uninstall through the Uninstall key).
