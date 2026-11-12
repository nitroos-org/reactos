@echo off
rem Stand-in for the Scoop installer in scoopdefaults.cmd: what featmgr's "scoop" feature leaves behind is the shim.
mkdir "%FEATMGR_SCOOP_ROOT%\shims" 2>nul
echo @echo off> "%FEATMGR_SCOOP_ROOT%\shims\scoop.cmd"
exit 0
