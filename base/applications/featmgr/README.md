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
