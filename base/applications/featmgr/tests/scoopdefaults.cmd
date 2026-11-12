@echo off
rem featmgr scoopdefaults.c (NitroOS defaults for Scoop apps), VS Code settings.json: link refusal, the seed path and
rem the JSONC fixtures that tests\roundtrip.cmd (VS1-VS22) does not cover. Offline: scoop is the stub of the
rem roundtrip test (fixtures\scoop-stub.cmd) in a fake root. Run from a directory holding fixtures\.
rem Usage: scoopdefaults.cmd [fixture-dir]     Result: %O%\sdtest.txt, last line SCOOPDEFAULTS-RESULT: PASS|FAIL n
rem Needs an NTFS or FAT volume with junction support (mklink /J); a file symbolic link (mklink) is used when the
rem volume has them (RPs2 SKIP otherwise). Nothing here writes outside %O%.
setlocal
set FX=%~dp0fixtures
if not "%1"=="" set FX=%1
set FM=%SystemRoot%\system32\featmgr.exe
set R=%SystemRoot%\Featmgr
set O=%~dp0out
mkdir %O% 2>nul
set LOG=%O%\sdtest.txt
set FAILS=0
echo scoopdefaults test> %LOG%

set FSROOT=%O%\fakescoop
set SW=%R%\Catalog\Software
set TGT=%O%\sd-target
set VICTIM=%O%\sd-victim.txt
set VSP=%FSROOT%\persist\vscode
set VSU=%VSP%\data\user-data\User
set VSJ=%VSU%\settings.json
rd /s /q %FSROOT% 2>nul
rd /s /q %SW% 2>nul
mkdir %FSROOT%\shims
mkdir %FSROOT%\buckets\main\bucket
mkdir %FSROOT%\apps\scoop\current
copy /y %FX%\scoop-stub.cmd %FSROOT%\shims\scoop.cmd >nul
set FEATMGR_SCOOP_ROOT=%FSROOT%
set FEATMGR_SCOOP_RUNNER=%FSROOT%\shims\scoop.cmd
%FM% /import-scoop vscfx /dir:%FX%\scoop-vscode /trust > %O%\imp.txt 2>&1
call :rc0 "SD0 import of the vscode test bucket"

rem ===== JSONC fixtures: expected output compared byte for byte (fc /b) =====
call :vsc nestedarr
fc /b %FX%\vscode-settings\nestedarr.expected.json %VSJ% >nul
call :rc0 "SD1 last member is a nested array: comma after the ], member added"
call :vsc escquote
fc /b %FX%\vscode-settings\escquote.expected.json %VSJ% >nul
call :rc0 "SD2 escaped quote, brace, slashes and a trailing backslash inside strings do not end the string or the object"
call :vsc closeblock
fc /b %FX%\vscode-settings\closeblock.expected.json %VSJ% >nul
call :rc0 "SD3 closing brace after a block comment on the same line: member spliced in before the brace"
call :vsc closeblock2
fc /b %FX%\vscode-settings\closeblock2.expected.json %VSJ% >nul
call :rc0 "SD4 closing brace after a block comment on its own line"
call :vsc crlfnonl
fc /b %FX%\vscode-settings\crlfnonl.expected.json %VSJ% >nul
call :rc0 "SD5 CRLF file with no trailing newline: CRLF kept, no newline added"
call :vsc mismatch
fc /b %FX%\vscode-settings\mismatch.json %VSJ% >nul
call :rc0 "SD6 an array closed by a brace and then a bracket is not a JSON object: left untouched"
call :vsc mismatch2
fc /b %FX%\vscode-settings\mismatch2.json %VSJ% >nul
call :rc0 "SD7 { closed by ]: left untouched"
call :vsc extraclose
fc /b %FX%\vscode-settings\extraclose.json %VSJ% >nul
call :rc0 "SD8 text after the closing brace: left untouched"
call :vsc utf16le-nobom
fc /b %FX%\vscode-settings\utf16le-nobom.json %VSJ% >nul
call :rc0 "SD9 UTF-16LE without a BOM: left untouched"
call :vsc utf16be-nobom
fc /b %FX%\vscode-settings\utf16be-nobom.json %VSJ% >nul
call :rc0 "SD10 UTF-16BE without a BOM: left untouched"

rem ===== a link on the path under persist is refused, nothing is written through it =====
mkdir %TGT% 2>nul
rem RP1: persist\vscode\data\user-data\User is a junction to a folder outside
call :resetvs
mkdir %VSP%\data\user-data
mklink /J %VSU% %TGT% > %O%\mk.txt 2>&1
call :rc0 "RP0 mklink /J works in the guest (the junction cases need it)"
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "RP1 install vscode with User a junction: the install itself still succeeds (first boot never fails)"
type %O%\i.txt >> %LOG%
call :ex %TGT%\settings.json 0 "RP2 nothing written through the User junction: no settings.json in the target"
call :ex %TGT%\settings.json.nitro-tmp 0 "RP3 ...and no temp file"
call :empty %TGT% "RP4 ...the target folder is still empty"
find "refused" %O%\i.txt >nul
call :rc0 "RP5 the refusal is logged"
call :rmlink %VSU%

rem RP6: a junction higher up (persist\vscode\data)
call :resetvs
mkdir %VSP%
mklink /J %VSP%\data %TGT% > %O%\mk.txt 2>&1
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "RP6 install vscode with data a junction: install succeeds"
call :ex %TGT%\user-data 0 "RP7 nothing created below the junction target"
find "refused" %O%\i.txt >nul
call :rc0 "RP8 refusal logged"
call :rmlink %VSP%\data

rem RP9: persist\vscode itself is a junction
call :resetvs
mkdir %FSROOT%\persist
mklink /J %VSP% %TGT% > %O%\mk.txt 2>&1
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "RP9 install vscode with persist\vscode a junction: install succeeds"
call :ex %TGT%\data 0 "RP10 nothing created below the junction target"
call :rmlink %VSP%

rem RP11: a junction where the temp file goes: nothing written through it, settings.json untouched
call :resetvs
mkdir %VSU%
copy /y %FX%\vscode-settings\comments.json %VSJ% >nul
mklink /J %VSJ%.nitro-tmp %TGT% > %O%\mk.txt 2>&1
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "RP11 install vscode with settings.json.nitro-tmp a junction: install succeeds"
call :empty %TGT% "RP12 nothing written into the junction target"
fc /b %FX%\vscode-settings\comments.json %VSJ% >nul
call :rc0 "RP13 settings.json left untouched"
call :rmlink %VSJ%.nitro-tmp

rem RP14: a file symbolic link where the temp file goes (planted before featmgr runs): the file it points to is not overwritten
call :resetvs
mkdir %VSU%
copy /y %FX%\vscode-settings\comments.json %VSJ% >nul
echo victim> %VICTIM%
copy /y %VICTIM% %VICTIM%.orig >nul
mklink %VSJ%.nitro-tmp %VICTIM% > %O%\mk.txt 2>&1
if errorlevel 1 goto :nosym
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "RP14 install vscode with settings.json.nitro-tmp a symbolic link: install succeeds"
type %O%\i.txt >> %LOG%
fc /b %VICTIM%.orig %VICTIM% >nul
call :rc0 "RP15 the file the link points to is not written"
fc /b %FX%\vscode-settings\comments.json %VSJ% >nul
call :rc0 "RP16 settings.json left untouched"
find "refused" %O%\i.txt >nul
call :rc0 "RP17 refusal logged"
del /q %VSJ%.nitro-tmp 2>nul
rem RP18: settings.json itself a symbolic link
del /q %VSJ%
mklink %VSJ% %VICTIM% > %O%\mk.txt 2>&1
%FM% /uninstall vscode >nul 2>&1
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "RP18 install vscode with settings.json a symbolic link: install succeeds"
type %O%\i.txt >> %LOG%
fc /b %VICTIM%.orig %VICTIM% >nul
call :rc0 "RP19 the file the link points to is not written"
find "refused" %O%\i.txt >nul
call :rc0 "RP20 refusal logged"
del /q %VSJ% 2>nul
goto :nosym_done
:nosym
echo SKIP RP14-RP20 no file symbolic links on this volume>> %LOG%
:nosym_done

rem RP21: a stale plain temp file from an interrupted run does not block the default
call :resetvs
mkdir %VSU%
copy /y %FX%\vscode-settings\comments.json %VSJ% >nul
echo stale> %VSJ%.nitro-tmp
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "RP21 install vscode with a stale plain settings.json.nitro-tmp"
find ": false" %VSJ% >nul
call :rc0 "RP22 ...the default is applied"
call :ex %VSJ%.nitro-tmp 0 "RP23 ...and no temp file is left"

rem RP24: no links: the same install still applies the default (control for the refusals above)
call :resetvs
%FM% /install vscode > %O%\i.txt 2>&1
find ": false" %VSJ% >nul
call :rc0 "RP24 no link anywhere: settings.json created with the key (control)"

rem ===== the seed path: featmgr installs Scoop itself (the catalog's scoop entry is replaced by a stand-in) =====
rem (the seed also writes Alacritty's config under %APPDATA%: pointed into %O% so nothing outside it changes)
set APPDATA=%O%\appdata
mkdir %APPDATA% 2>nul
call :resetvs
rd /s /q %FSROOT%\apps\vscode 2>nul
if exist %R%\Catalog\scoop.ini copy /y %R%\Catalog\scoop.ini %O%\scoop.ini.save >nul
copy /y %FX%\fmt-seed-scoop.ini %R%\Catalog\scoop.ini >nul
mkdir %R%\Payload\scoop 2>nul
copy /y %FX%\fmt-seed-setup.cmd %R%\Payload\scoop\ >nul
del /q %FSROOT%\shims\scoop.cmd
rem the stub is gone: Scoop is "not installed" until the stand-in installer runs; the runner variable still points at the stub path
%FM% /install scoop > %O%\i.txt 2>&1
call :rc0 "SS1 featmgr installs the (stand-in) scoop feature"
type %O%\i.txt >> %LOG%
call :ex %VSJ% 1 "SS2 seed: vscode's settings.json written before vscode is installed"
find ": false" %VSJ% >nul
call :rc0 "SS3 ...with the key"
call :ex %FSROOT%\persist\vscode-insiders\data\user-data\User\settings.json 1 "SS4 seed: vscode-insiders too"
call :ex %FSROOT%\apps\vscode 0 "SS5 vscode itself was not installed by the seed"
%FM% /uninstall scoop >> %LOG% 2>&1
rem seed with a link in the way: the other app is still seeded
rd /s /q %FSROOT%\persist 2>nul
mkdir %FSROOT%\persist\vscode-insiders
rd /s /q %TGT% 2>nul
mkdir %TGT%
mklink /J %FSROOT%\persist\vscode-insiders\data %TGT% > %O%\mk.txt 2>&1
%FM% /install scoop > %O%\i.txt 2>&1
call :rc0 "SS6 seed with persist\vscode-insiders\data a junction: the install succeeds"
type %O%\i.txt >> %LOG%
call :ex %VSJ% 1 "SS7 ...vscode is seeded"
call :ex %TGT%\user-data 0 "SS8 ...nothing written through the junction"
call :rmlink %FSROOT%\persist\vscode-insiders\data
%FM% /uninstall scoop >> %LOG% 2>&1
del /q %R%\Catalog\scoop.ini 2>nul
if exist %O%\scoop.ini.save copy /y %O%\scoop.ini.save %R%\Catalog\scoop.ini >nul
del /q %R%\Payload\scoop\*.* 2>nul
rmdir %R%\Payload\scoop 2>nul

rem ===== cleanup =====
rd /s /q %O%\appdata 2>nul
%FM% /uninstall vscode >nul 2>&1
call :rmlink %FSROOT%\persist\vscode-insiders\data
call :rmlink %VSP%\data
call :rmlink %VSU%
rd /s /q %FSROOT% 2>nul
rd /s /q %SW% 2>nul
rd /s /q %TGT% 2>nul
del /q %VICTIM% %VICTIM%.orig 2>nul
set FEATMGR_SCOOP_ROOT=
set FEATMGR_SCOOP_RUNNER=
if "%FAILS%"=="0" (echo SCOOPDEFAULTS-RESULT: PASS>> %LOG%) else (echo SCOOPDEFAULTS-RESULT: FAIL %FAILS% >> %LOG%)
goto :eof

:vsc
rem :vsc <fixture>: put vscode-settings\<fixture>.json in place as scoop's persisted settings.json, then a fresh featmgr install of vscode
call :resetvs
mkdir %VSU% 2>nul
copy /y %FX%\vscode-settings\%1.json %VSJ% >nul
%FM% /install vscode >> %LOG% 2>&1
goto :eof
:resetvs
rem no vscode, no persist data (links removed first: rd /s must not walk into a link's target)
%FM% /uninstall vscode >nul 2>&1
call :rmlink %VSU%
call :rmlink %VSP%\data
call :rmlink %VSP%
call :rmlink %FSROOT%\persist\vscode-insiders\data
rd /s /q %FSROOT%\persist 2>nul
rd /s /q %TGT% 2>nul
mkdir %TGT%
goto :eof
:rmlink
rem :rmlink <path>: remove a junction (or symlink) at path itself, not its target. rmdir fails on a real non-empty folder: harmless.
rmdir %1 2>nul
goto :eof
:empty
rem :empty <dir> <text>: no file directly in dir
set GOT=0
for %%f in (%1\*) do set GOT=1
if "%GOT%"=="0" (echo PASS %~2>> %LOG%) else (call :fail %2 "files in %1")
goto :eof
:ex
if exist %1 (set GOT=1) else (set GOT=0)
if "%GOT%"=="%2" (echo PASS %3>> %LOG%) else (call :fail %3 "exist=%GOT% want %2")
goto :eof
:rc0
if errorlevel 1 (call :fail %1 "rc nonzero") else (echo PASS %1>> %LOG%)
goto :eof
:rc1
if errorlevel 1 (echo PASS %1>> %LOG%) else (call :fail %1 "rc zero, wanted failure")
goto :eof
:fail
echo FAIL %~1 -- %~2 >> %LOG%
set /a FAILS=%FAILS%+1
goto :eof
