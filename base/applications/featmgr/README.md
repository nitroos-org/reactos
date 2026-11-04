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
  of the manifest. While it holds the placeholder `REPLACE-WITH-...`, the pack is listed as "not available yet" (no
  broken enable); a base that is not `https://` is refused the same way.
- `[Source] Arch=amd64`: on any other architecture the entry says so ("Only for 64-bit (amd64) NitroOS").
- `[Feature] BuiltInFile=<path>`: when the image already carries the pack (that file exists) and featmgr has no record of
  it, the entry shows Enabled, "included in this image", and cannot be turned off there.
- The hosted files of `lavapipe-pack` are produced by `tools/stage-lavapipe-payload.sh <dir>` (the six files of
  `[Download]` plus `SHA256SUMS`); upload them to `<base>/lavapipe-pack/26.2.4-6ab3d0fe/`. Copying them into the payload
  folder instead makes the pack installable offline (they are still verified). Offline tests: `tests\roundtrip.cmd` (H1-H29).
