# featmgr (Optional Features / Addon Manager)

Feature catalog, `featmgr.exe` (CLI) and the Optional Features applet (`optfeatures.exe`); Scoop apps are installed
through `scoop.c` / `engine.c`. Roundtrip test: `tests\roundtrip.cmd` (offline, in a guest); Scoop live test: `tests\scoop-live.cmd`.

- NitroOS default for VS Code: after featmgr installs or updates the Scoop app `vscode` or `vscode-insiders`, it adds
  `"terminal.integrated.windowsUseConptyDll": false` to `<scoop>\persist\<app>\data\user-data\User\settings.json`
  when that key is absent (an existing value is never changed). One file, `scoopdefaults.c`; remove it when
  CONSOLE-condrv-device (`\Device\ConDrv`) lands. A plain `scoop install` typed in a shell does not go through featmgr.
