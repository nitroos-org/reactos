@echo off
rem FEATMGMT-01 in-guest verb/state round-trip. Run from a directory holding
rem fixtures\ (fmt-base.ini fmt-dep.ini fmt-base.txt fmt-dep.txt).  Result: %O%\fmtest.txt
rem Usage: roundtrip.cmd [fixture-dir]   (default: directory of this script)
setlocal
set FX=%~dp0fixtures
if not "%1"=="" set FX=%1
set FM=%SystemRoot%\system32\featmgr.exe
set R=%SystemRoot%\Featmgr
set O=%~dp0out
mkdir %O% 2>nul
set LOG=%O%\fmtest.txt
set FAILS=0
echo FEATMGMT roundtrip> %LOG%
rem --- install fixtures into the catalog / payload dirs
mkdir %R%\Catalog 2>nul
mkdir %R%\Payload\fmt-base 2>nul
mkdir %R%\Payload\fmt-dep 2>nul
copy /y %FX%\fmt-base.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-dep.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-base.txt %R%\Payload\fmt-base\ >nul
copy /y %FX%\fmt-dep.txt %R%\Payload\fmt-dep\ >nul

call :st fmt-base NotInstalled "1 initial base"
call :st fmt-dep NotInstalled "2 initial dep"

rem install dependent -> pulls in its dependency
%FM% /install fmt-dep >> %LOG% 2>&1
call :rc0 "3 install fmt-dep"
call :st fmt-dep Enabled "4 dep enabled"
call :st fmt-base Enabled "5 base auto-enabled by dependency"
%FM% /query fmt-base > %O%\q.txt 2>&1
find "InstalledVersion: 1.0" %O%\q.txt >nul
call :rc0 "V1 query: InstalledVersion recorded at enable (os tier)"
%FM% /list /state:enabled > %O%\l.txt 2>&1
find "INSTALLED" %O%\l.txt >nul
call :rc0 "V2 /list has the INSTALLED column"
%FM% "/list" "/search:test BASE feature" > %O%\l.txt 2>&1
find "fmt-base" %O%\l.txt >nul
call :rc0 "V3 /list /search finds the os-tier fixture by its name (case-insensitive)"
find "fmt-dep" %O%\l.txt >nul
call :rc1 "V4 ...and nothing else"
call :ex %R%\fmt-base.out 1 "6 base file placed"
call :ex %R%\fmt-dep.out 1 "7 dep file placed"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v Base >nul 2>&1
call :rc0 "8 base reg value set"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v Dep >nul 2>&1
call :rc0 "9 dep reg value set"
%FM% /query fmt-base > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "EnabledDependents: fmt-dep" %O%\q.txt >nul
call :rc0 "10 query reports enabled dependent"
%FM% /list /state:enabled > %O%\l.txt 2>&1
find "fmt-dep" %O%\l.txt >nul
call :rc0 "11 list /state:enabled shows dep"
%FM% /list /tier:software > %O%\l.txt 2>&1
find "fmt-base" %O%\l.txt >nul
call :rc1 "12 list /tier:software hides os-tier base"

rem dependency protection
%FM% /disable fmt-base >> %LOG% 2>&1
call :rc1 "13 disable base refused while dep enabled"
call :st fmt-base Enabled "14 base still enabled"
call :ex %R%\fmt-base.out 1 "15 base file still present"

rem proper order
%FM% /disable fmt-dep >> %LOG% 2>&1
call :rc0 "16 disable dep"
call :st fmt-dep Disabled "17 dep Disabled"
call :ex %R%\fmt-dep.out 0 "18 dep file removed"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v Dep >nul 2>&1
call :rc1 "19 dep reg value reverted"
call :st fmt-base Enabled "20 base untouched"
%FM% /disable fmt-base >> %LOG% 2>&1
call :rc0 "21 disable base"
call :st fmt-base Disabled "22 base Disabled"
call :ex %R%\fmt-base.out 0 "23 base file removed"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v Base >nul 2>&1
call :rc1 "24 base reg value reverted"

rem re-enable + cascade disable
%FM% /enable fmt-dep >> %LOG% 2>&1
call :rc0 "25 re-enable dep (re-enables base)"
call :st fmt-base Enabled "26 base Enabled again"
call :st fmt-dep Enabled "27 dep Enabled again"
%FM% /disable fmt-base /cascade >> %LOG% 2>&1
call :rc0 "28 cascade disable base"
call :st fmt-dep Disabled "29 dep Disabled by cascade"
call :st fmt-base Disabled "30 base Disabled by cascade"

rem uninstall -> forget
%FM% /uninstall fmt-dep >> %LOG% 2>&1
call :rc0 "31 uninstall dep"
%FM% /uninstall fmt-base >> %LOG% 2>&1
call :rc0 "32 uninstall base"
call :st fmt-dep NotInstalled "33 dep NotInstalled after uninstall"
call :st fmt-base NotInstalled "34 base NotInstalled after uninstall"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmt-base >nul 2>&1
call :rc1 "35 base state record deleted"
rem uninstall of an enabled feature = disable + forget in one step
%FM% /install fmt-base >> %LOG% 2>&1
%FM% /uninstall fmt-base >> %LOG% 2>&1
call :rc0 "36 uninstall of enabled feature"
call :st fmt-base NotInstalled "37 NotInstalled after enabled-uninstall"
call :ex %R%\fmt-base.out 0 "38 base file gone"

rem --- lavapipe-pack (GPU pack): included in an image built with the GPU stack in system32 (not removable there),
rem otherwise a hosted pack that is "not available yet" while its download location is the placeholder; amd64 only
set FMK=HKLM\SOFTWARE\ReactOS\Nitro\Featmgr
reg delete %FMK% /v PayloadBaseUrl /f >nul 2>&1
if exist %FX%\lavapipe-pack.ini copy /y %FX%\lavapipe-pack.ini %R%\Catalog\ >nul
if not exist %R%\Catalog\lavapipe-pack.ini goto lvp_done
%FM% /query lavapipe-pack > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" goto lvp_x86
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\lavapipe-pack >nul 2>&1
if not errorlevel 1 goto lvp_done
if not exist %SystemRoot%\System32\vulkan_lvp.dll goto lvp_hosted
find /i "included in this image" %O%\q.txt >nul
call :rc0 "39 lavapipe-pack: included in this image (vulkan_lvp.dll in system32, no record)"
call :st lavapipe-pack Enabled "40 ...shown Enabled"
%FM% /disable lavapipe-pack > %O%\b.txt 2>&1
call :rc1 "41 disable lavapipe-pack refused"
find "base component" %O%\b.txt >nul
call :rc0 "42 ...with the base-component error"
%FM% /uninstall lavapipe-pack > %O%\b.txt 2>&1
call :rc1 "43 uninstall lavapipe-pack refused"
call :ex %SystemRoot%\System32\vulkan_lvp.dll 1 "44 ...and the in-box files stay"
goto lvp_done
:lvp_hosted
find /i "not available yet" %O%\q.txt >nul
call :rc0 "39h lavapipe-pack (image without the GPU stack): not available yet with the placeholder URL"
%FM% /install lavapipe-pack > %O%\b.txt 2>&1
call :rc1 "40h install refused"
call :st lavapipe-pack NotInstalled "41h ...left NotInstalled"
goto lvp_done
:lvp_x86
find "64-bit (amd64)" %O%\q.txt >nul
call :rc0 "39x lavapipe-pack on x86: amd64 only"
%FM% /install lavapipe-pack > %O%\b.txt 2>&1
call :rc1 "40x install refused on x86"
find "64-bit" %O%\b.txt >nul
call :rc0 "41x ...with the amd64-only message"
:lvp_done

rem --- hosted pack ([Download]) offline checks: placeholder, non-https base, arch, pre-staged payload
copy /y %FX%\fmt-hosted.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-hostedarch.ini %R%\Catalog\ >nul
rmdir /s /q %R%\Payload\fmt-hosted 2>nul
%FM% /query fmt-hosted > %O%\q.txt 2>&1
find /i "not available yet" %O%\q.txt >nul
call :rc0 "H1 hosted pack with the placeholder base: not available yet"
%FM% /list > %O%\l.txt 2>&1
find "fmt-hosted " %O%\l.txt | find "*" >nul
call :rc0 "H2 /list marks it '*'"
%FM% /install fmt-hosted > %O%\b.txt 2>&1
call :rc1 "H3 install refused with the placeholder"
type %O%\b.txt >> %LOG%
find /i "not available yet" %O%\b.txt >nul
call :rc0 "H4 ...with the not-available-yet message"
call :st fmt-hosted NotInstalled "H5 ...left NotInstalled"
call :ex %R%\fmt-hosted.out 0 "H6 ...nothing installed"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmt-hosted >nul 2>&1
call :rc1 "H7 ...no state record"
reg add %FMK% /v PayloadBaseUrl /t REG_SZ /d http://127.0.0.1/featmgr /f >nul
%FM% /query fmt-hosted > %O%\q.txt 2>&1
find "https" %O%\q.txt >nul
call :rc0 "H8 PayloadBaseUrl override that is not https: not available (names https)"
%FM% /install fmt-hosted > %O%\b.txt 2>&1
call :rc1 "H9 ...install refused"
reg add %FMK% /v PayloadBaseUrl /t REG_SZ /d https://127.0.0.1:1/featmgr /f >nul
%FM% /query fmt-hosted > %O%\q.txt 2>&1
find "downloaded at enable" %O%\q.txt >nul
call :rc0 "H10 https PayloadBaseUrl override: the pack can be turned on (downloaded at enable)"
%FM% /install fmt-hosted > %O%\b.txt 2>&1
call :rc1 "H11 unreachable server: install fails"
type %O%\b.txt >> %LOG%
find /i "nothing was changed" %O%\b.txt >nul
call :rc0 "H12 ...and nothing was changed"
call :ex %R%\fmt-hosted.out 0 "H13 ...nothing installed"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmt-hosted >nul 2>&1
call :rc1 "H14 ...no state record"
reg delete %FMK% /v PayloadBaseUrl /f >nul 2>&1
mkdir %R%\Payload\fmt-hosted 2>nul
echo wrong> %R%\Payload\fmt-hosted\fmt-hosted.txt
%FM% /install fmt-hosted > %O%\b.txt 2>&1
call :rc1 "H15 pre-staged file with a wrong SHA-256 (placeholder base): refused"
call :ex %R%\fmt-hosted.out 0 "H16 ...nothing installed"
copy /y %FX%\fmt-hosted.txt %R%\Payload\fmt-hosted\ >nul
%FM% /install fmt-hosted > %O%\b.txt 2>&1
call :rc0 "H17 pre-staged verified payload installs offline (placeholder base)"
type %O%\b.txt >> %LOG%
call :st fmt-hosted Enabled "H18 ...Enabled"
call :ex %R%\fmt-hosted.out 1 "H19 ...payload file placed"
call :ex %R%\Payload\fmt-hosted\fmt-hosted.txt 1 "H20 ...a pre-staged (not downloaded) copy is kept"
%FM% /uninstall fmt-hosted > %O%\b.txt 2>&1
call :rc0 "H21 uninstall"
call :ex %R%\fmt-hosted.out 0 "H22 ...payload file removed"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v Hosted >nul 2>&1
call :rc1 "H23 ...registry value reverted"
%FM% /query fmt-hostedarch > %O%\q.txt 2>&1
find /i "architecture" %O%\q.txt >nul
call :rc0 "H24 [Source] Arch without this architecture: not available on this architecture"
%FM% /install fmt-hostedarch > %O%\b.txt 2>&1
call :rc1 "H25 ...install refused"
copy /y %FX%\fmt-hostednohash.ini %R%\Catalog\ >nul
mkdir %R%\Payload\fmt-hostednohash 2>nul
copy /y %FX%\fmt-hosted.txt %R%\Payload\fmt-hostednohash\ >nul
copy /y %FX%\fmt-base.txt %R%\Payload\fmt-hostednohash\ >nul
%FM% /install fmt-hostednohash > %O%\b.txt 2>&1
call :rc1 "H26 hosted pack with a [Payload] file that has no [Download] hash: refused (fail closed)"
type %O%\b.txt >> %LOG%
find /i "no [Download] hash" %O%\b.txt >nul
call :rc0 "H27 ...naming the missing hash"
call :ex %R%\fmt-hostednohash.out 0 "H28 ...nothing installed"
call :ex %R%\fmt-hostednohash2.out 0 "H29 ...not even the unhashed file"
del /q %R%\Catalog\fmt-hostednohash.ini 2>nul
rmdir /s /q %R%\Payload\fmt-hostednohash 2>nul
del /q %R%\Catalog\fmt-hosted.ini %R%\Catalog\fmt-hostedarch.ini 2>nul
rmdir /s /q %R%\Payload\fmt-hosted 2>nul
mkdir %R%\Payload\fmt-sys 2>nul
mkdir %R%\Payload\fmt-sysdep 2>nul
copy /y %FX%\fmt-sys.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-sysdep.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-sys.txt %R%\Payload\fmt-sys\ >nul
copy /y %FX%\fmt-sysdep.txt %R%\Payload\fmt-sysdep\ >nul
%FM% /install fmt-sysdep >> %LOG% 2>&1
call :rc0 "43 install dependent of base component"
call :st fmt-sys Enabled "44 base component enabled"
rem Removable guard wins over the dependency guard
%FM% /disable fmt-sys > %O%\b.txt 2>&1
call :rc1 "45 disable base component refused (dependent present)"
find "base component" %O%\b.txt >nul
call :rc0 "46 ...base-component error takes precedence over dependents"
%FM% /disable fmt-sysdep >> %LOG% 2>&1
call :rc0 "47 disable dependent"
%FM% /disable fmt-sys > %O%\b.txt 2>&1
call :rc1 "48 disable base component refused (no dependents)"
find "base component" %O%\b.txt >nul
call :rc0 "49 ...base-component error"
%FM% /uninstall fmt-sys > %O%\b.txt 2>&1
call :rc1 "50 uninstall base component refused"
call :st fmt-sys Enabled "51 base component still Enabled"
call :ex %R%\fmt-sys.out 1 "52 base component file still present"
rem the fixture is force-removed by hand (the engine rightly will not)
%FM% /uninstall fmt-sysdep >> %LOG% 2>&1
reg delete HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmt-sys /f >nul 2>&1
del /q %R%\fmt-sys.out 2>nul
del /q %R%\Catalog\fmt-sys.ini %R%\Catalog\fmt-sysdep.ini 2>nul
del /q %R%\Payload\fmt-sys\fmt-sys.txt %R%\Payload\fmt-sysdep\fmt-sysdep.txt 2>nul
rmdir %R%\Payload\fmt-sys 2>nul
rmdir %R%\Payload\fmt-sysdep 2>nul

rem ===== SOFTWARE TIER (FEATMGMT-01 software slice) =====
rem --- A. /import-rapps: RAPPS appdb -> Tier=software catalog entries
set SW=%R%\Catalog\Software
rd /s /q %SW% 2>nul
%FM% /import-rapps %FX%\sw-appdb /anyarch > %O%\imp.txt 2>&1
call :rc0 "53 import-rapps rc0"
type %O%\imp.txt >> %LOG%
find "imported 5 RAPPS entries" %O%\imp.txt >nul
call :rc0 "54 imported 5 (testapp testlib depapp archapp utf16app)"
find "(2 skipped)" %O%\imp.txt >nul
call :rc0 "55 2 skipped (no URL, unusable package name)"
%FM% /list /tier:software > %O%\l.txt 2>&1
find "rapps-testapp" %O%\l.txt >nul
call :rc0 "56 imported entry listed in software tier"
%FM% /list /tier:os > %O%\l.txt 2>&1
find "rapps-testapp" %O%\l.txt >nul
call :rc1 "57 imported entry absent from os tier"
call :st rapps-testapp NotInstalled "58 imported entry NotInstalled"
%FM% /query rapps-testapp > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "Tier:         software" %O%\q.txt >nul
call :rc0 "59 query: Tier=software"
find "Provider:     rapps" %O%\q.txt >nul
call :rc0 "60 query: Provider=rapps"
find "Rapps.Pkg:    testapp" %O%\q.txt >nul
call :rc0 "61 query: Rapps.Pkg"
find "Version:      1.2.3" %O%\q.txt >nul
call :rc0 "62 query: Version mapped"
find "Source.Artifact: https://example.invalid/testapp-1.2.3.exe" %O%\q.txt >nul
call :rc0 "63 query: URLDownload -> Source.Artifact"
find "Source.ArtifactSHA1: 0123456789abcdef0123456789abcdef01234567" %O%\q.txt >nul
call :rc0 "64 query: SHA1 -> Source.ArtifactSHA1"
find "Source.License: Open Source (GPLv2)" %O%\q.txt >nul
call :rc0 "65 query: License/LicenseType -> Source.License"
find "Category:     Internet" %O%\q.txt >nul
call :rc0 "66 query: numeric Category -> name"
%FM% /query rapps-depapp > %O%\q.txt 2>&1
find "Dependencies: rapps-testlib" %O%\q.txt >nul
call :rc0 "67 RAPPS Dependencies -> catalog deps (present pkgs only)"
find "nosuchpkg" %O%\q.txt >nul
call :rc1 "68 dep absent from the DB not in the catalog graph"
%FM% /query rapps-archapp > %O%\q.txt 2>&1
find "Source.Artifact: https://example.invalid/arch-" %O%\q.txt >nul
call :rc0 "69 [Section.<arch>] URLDownload overrides generic"
%FM% /query rapps-utf16app > %O%\q.txt 2>&1
call :rc0 "70 UTF-16LE+BOM RAPPS entry imported"
%FM% /query rapps-nourl >nul 2>&1
call :rc1 "71 entry without URLDownload not imported"
rem re-run is additive/idempotent; /clean drops stale generated entries only
echo [Feature]> %SW%\rapps-stale.ini
echo Id=rapps-stale>> %SW%\rapps-stale.ini
echo Tier=software>> %SW%\rapps-stale.ini
%FM% /query rapps-stale >nul 2>&1
call :rc0 "72 hand-made stale entry visible"
%FM% /import-rapps %FX%\sw-appdb /anyarch > %O%\imp.txt 2>&1
find "imported 5 RAPPS entries" %O%\imp.txt >nul
call :rc0 "73 re-import idempotent"
%FM% /query rapps-stale >nul 2>&1
call :rc0 "74 re-import without /clean keeps other entries"
%FM% /import-rapps %FX%\sw-appdb /anyarch /clean > %O%\imp.txt 2>&1
%FM% /query rapps-stale >nul 2>&1
call :rc1 "75 /clean removes stale generated entries"
%FM% /import-rapps %R%\nonexistent-dir > %O%\imp.txt 2>&1
call :rc1 "76 import from a missing dir fails (rc 3)"

rem --- B. software-tier install semantics (command provider = controlled local installer)
mkdir %R%\Payload\fmt-sw 2>nul
mkdir %R%\Payload\fmt-swbad 2>nul
mkdir %R%\Payload\fmt-swstuck 2>nul
copy /y %FX%\fmt-sw.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-swbad.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-swstuck.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-sw-setup.cmd %R%\Payload\fmt-sw\ >nul
copy /y %FX%\fmt-sw-uninst.cmd %R%\Payload\fmt-sw\ >nul
copy /y %FX%\fmt-swbad-setup.cmd %R%\Payload\fmt-swbad\ >nul
copy /y %FX%\fmt-swstuck-setup.cmd %R%\Payload\fmt-swstuck\ >nul
copy /y %FX%\fmt-swstuck-uninst.cmd %R%\Payload\fmt-swstuck\ >nul
call :st fmt-sw NotInstalled "77 sw initial"
%FM% /install fmt-sw > %O%\i.txt 2>&1
call :rc0 "78 install runs the installer (rc0)"
find "Open a new terminal" %O%\i.txt >nul
call :rc1 "P0 an install that leaves PATH alone prints no 'open a new terminal' hint"
%FM% /query fmt-sw > %O%\q.txt 2>&1
find "InstalledVersion: 1.0" %O%\q.txt >nul
call :rc0 "V5 software tier (command provider): InstalledVersion recorded at install"
type %O%\i.txt >> %LOG%
call :st fmt-sw Enabled "79 sw Enabled after install"
call :ex %R%\fmt-sw.installed 1 "80 installer ran (side-effect file)"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v Sw >nul 2>&1
call :rc0 "81 installer side-effect registry value"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v SwReg >nul 2>&1
call :rc0 "81b software-tier [Registry] applied after install"
%FM% /list /state:enabled /tier:software > %O%\l.txt 2>&1
find "fmt-sw" %O%\l.txt >nul
call :rc0 "82 list shows installed software"
%FM% /disable fmt-sw > %O%\i.txt 2>&1
call :rc0 "83 disable runs the uninstaller (rc0)"
type %O%\i.txt >> %LOG%
call :st fmt-sw Disabled "84 sw Disabled"
call :ex %R%\fmt-sw.installed 0 "85 uninstaller removed side-effect file"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v Sw >nul 2>&1
call :rc1 "86 uninstaller removed registry value"
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v SwReg >nul 2>&1
call :rc1 "86b software-tier [Registry] reverted on disable"
%FM% /enable fmt-sw >> %LOG% 2>&1
call :rc0 "87 re-install from Disabled"
call :st fmt-sw Enabled "88 sw Enabled again"
%FM% /uninstall fmt-sw >> %LOG% 2>&1
call :rc0 "89 uninstall (uninstaller + forget)"
call :st fmt-sw NotInstalled "90 sw NotInstalled after uninstall"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmt-sw >nul 2>&1
call :rc1 "91 sw state record deleted"

rem --- C. PATH-changing install: featmgr says the shell that ran it keeps the old PATH (parent here is cmd.exe)
mkdir %R%\Payload\fmt-swpath 2>nul
copy /y %FX%\fmt-swpath.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-swpath-setup.cmd %R%\Payload\fmt-swpath\ >nul
copy /y %FX%\fmt-swpath-uninst.cmd %R%\Payload\fmt-swpath\ >nul
%FM% /install fmt-swpath > %O%\ip.txt 2>&1
call :rc0 "P1 install of a PATH-changing feature rc0"
type %O%\ip.txt >> %LOG%
reg query HKCU\Environment /v Path | find "fmtpath-test" >nul
call :rc0 "P2 the installer changed the user PATH"
find "is installed. Open a new terminal, or run this in the current one" %O%\ip.txt >nul
call :rc0 "P3 the hint is printed (parent is cmd.exe; refreshenv ships)"
find "refreshenv" %O%\ip.txt >nul
call :rc0 "P3a ...and names refreshenv"
find "Environment]::GetEnvironmentVariable" %O%\ip.txt >nul
call :rc1 "P4 the cmd flavour carries no PowerShell command"
rem --- refreshenv: bring THIS cmd window (and a pwsh started from it) up to date
call :ex %SystemRoot%\system32\refreshenv.cmd 1 "P7 refreshenv.cmd ships in system32"
call :ex %SystemRoot%\system32\refreshenv.ps1 1 "P7b refreshenv.ps1 ships in system32"
%FM% /print-path > %O%\pp.txt 2>&1
call :rc0 "P8 featmgr /print-path rc0"
find "C:\fmtpath-test;" %O%\pp.txt >nul
call :rc0 "P8a the new user PATH entry is in it"
find "C:\fmtpath-test2" %O%\pp.txt >nul
call :rc0 "P8b ...with the variable expanded"
find /i "system32" %O%\pp.txt >nul
call :rc0 "P8c ...and the system PATH is still there"
%FM% /print-path /cmd > %O%\ppc.txt 2>&1
find "PATH=C:" %O%\ppc.txt >nul
call :rc0 "P8e /cmd line carries the path"
find "set " %O%\ppc.txt >nul
call :rc0 "P8d /cmd prints a batch set line"
echo %PATH% | find "fmtpath-test2" >nul
call :rc1 "P9 this window still has the old PATH (as on Windows)"
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (
  "%ProgramFiles%\PowerShell\7\pwsh.exe" -NoProfile -Command "if ($env:Path -like '*fmtpath-test2*') { exit 1 } else { exit 0 }"
  call :rc0 "P10 a pwsh started from this window has the old PATH too"
  "%ProgramFiles%\PowerShell\7\pwsh.exe" -NoProfile -Command "refreshenv; if ($env:Path -like '*C:\fmtpath-test2*' -and $env:Path -like '*system32*') { exit 0 } else { exit 1 }"
  call :rc0 "P11 refreshenv in pwsh (the .ps1 wins over the .cmd) brings its PATH up to date"
)
call refreshenv
echo %PATH% | find "C:\fmtpath-test2" >nul
call :rc0 "P9a refreshenv.cmd: the PATH of this window has the new entry"
echo %PATH% | find /i "system32" >nul
call :rc0 "P9b ...and keeps the system entries"
%FM% /uninstall fmt-swpath >> %LOG% 2>&1
call :rc0 "P5 uninstall PATH-changing feature"
reg query HKCU\Environment /v Path >nul 2>&1
call :rc1 "P6 uninstaller removed the user PATH value"
del /q %R%\Catalog\fmt-swpath.ini %R%\Payload\fmt-swpath\fmt-swpath-setup.cmd %R%\Payload\fmt-swpath\fmt-swpath-uninst.cmd 2>nul
rmdir %R%\Payload\fmt-swpath 2>nul
call :ex %R%\fmt-sw.installed 0 "92 sw side-effect file gone"
rem failing installer: feature stays NotInstalled, no record left behind
%FM% /install fmt-swbad > %O%\i.txt 2>&1
call :rc1 "93 failing installer -> install fails (rc3)"
type %O%\i.txt >> %LOG%
call :st fmt-swbad NotInstalled "94 failed install leaves NotInstalled"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmt-swbad >nul 2>&1
call :rc1 "95 failed install leaves no state record"
rem failing uninstaller: stays Enabled unless /force
%FM% /install fmt-swstuck >> %LOG% 2>&1
call :rc0 "96 swstuck installs"
%FM% /disable fmt-swstuck > %O%\i.txt 2>&1
call :rc1 "97 failing uninstaller -> disable refused"
type %O%\i.txt >> %LOG%
call :st fmt-swstuck Enabled "98 swstuck still Enabled"
%FM% /uninstall fmt-swstuck >> %LOG% 2>&1
call :rc1 "99 uninstall refused too"
%FM% /uninstall fmt-swstuck /force >> %LOG% 2>&1
call :rc0 "100 uninstall /force forgets it"
call :st fmt-swstuck NotInstalled "101 swstuck NotInstalled after /force"
rem installer not staged -> deferred, refused
del /q %R%\Payload\fmt-sw\fmt-sw-setup.cmd
%FM% /list /tier:software > %O%\l.txt 2>&1
find "fmt-sw " %O%\l.txt | find "*" >nul
call :rc0 "102 software entry with missing installer marked deferred (*)"
%FM% /install fmt-sw >> %LOG% 2>&1
call :rc1 "103 install refused when installer not staged"
rem rapps package larger than the free space: refused up front with a clear message (not a bare exit code)
copy /y %FX%\fmt-bigdisk.ini %R%\Catalog\ >nul
%FM% /install fmt-bigdisk > %O%\i.txt 2>&1
call :rc1 "103a oversized rapps package -> install refused"
type %O%\i.txt >> %LOG%
find "not enough disk space" %O%\i.txt >nul
call :rc0 "103b ...with a 'not enough disk space' message"
find "exit code" %O%\i.txt >nul
call :rc1 "103c ...and the installer was never started"
call :st fmt-bigdisk NotInstalled "103d refused install leaves NotInstalled"
del /q %R%\Catalog\fmt-bigdisk.ini 2>nul

rem ===== RAPPS-provider /S no-hang (RAPPS-S-dialog-hang fix) =====
rem rapps.exe is only present in a full image. A failing silent download must return
rem PROMPTLY with a non-zero code and no modal dialog; before the fix it popped a modal
rem MessageBox on the (headless) worker thread and blocked featmgr up to the 60-min watchdog.
rem The .invalid URLDownload fails fast whether or not the VM has network.
if exist %SystemRoot%\system32\rapps.exe (
  mkdir "%LOCALAPPDATA%\RApps\appdb" 2>nul
  copy /y %FX%\nohang-appdb\fmnohang.txt "%LOCALAPPDATA%\RApps\appdb\" >nul
  %FM% /import-rapps "%LOCALAPPDATA%\RApps\appdb" /clean /anyarch > %O%\nohang-imp.txt 2>&1
  call :rc0 "104 import nohang rapps entry"
  echo NOHANG-START %time% >> %LOG%
  %FM% /install rapps-fmnohang > %O%\nohang.txt 2>&1
  call :rc1 "105 rapps /S download failure returns non-zero (no modal hang)"
  echo NOHANG-END %time% >> %LOG%
  type %O%\nohang.txt >> %LOG%
  rem control returned to the script => proven not hung
  echo NOHANG-RETURNED ok >> %LOG%
  call :st rapps-fmnohang NotInstalled "106 failed live install leaves NotInstalled"
  reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\rapps-fmnohang >nul 2>&1
  call :rc1 "107 failed live install leaves no state record"
  del "%LOCALAPPDATA%\RApps\appdb\fmnohang.txt" 2>nul
  rd /s /q %SW% 2>nul
) else (
  echo SKIP 104-107 rapps.exe not present ^(module-only test image^) >> %LOG%
)

rem ===== SCOOP (SCOOP-FEATMGR-01): bucket import, Provider=scoop install/uninstall/state =====
rem Offline: the bucket is a fixture directory and "scoop" is a stub (fixtures\scoop-stub.cmd) in a fake
rem root (FEATMGR_SCOOP_ROOT). The real thing is tests\scoop-live.cmd. FMT_FAT=1 = run on a FAT volume.
set FXS=%FX%\scoop-bucket
set FSROOT=%O%\fakescoop
set FEATMGR_SCOOP_ROOT=
set FEATMGR_SCOOP_RUNNER=
rd /s /q %SW% 2>nul
rd /s /q %FSROOT% 2>nul
%FM% /query scoop > %O%\q.txt 2>&1
if errorlevel 1 goto :scoop_x86
type %O%\q.txt >> %LOG%
find "Provider:     command" %O%\q.txt >nul
call :rc0 "108 scoop feature in the catalog (amd64): command provider"
find "Dependencies: powershell-7" %O%\q.txt >nul
call :rc0 "109 scoop depends on powershell-7"
find "Source:       command" %O%\q.txt >nul
call :rc0 "110 scoop source = command"
if "%FMT_FAT%"=="1" goto :scoop_fat

rem --- import from a fixture bucket
%FM% /import-scoop fmfix /dir:%FXS% > %O%\imp.txt 2>&1
call :rc1 "111 unofficial bucket refused without /trust"
find "not an official Scoop bucket" %O%\imp.txt >nul
call :rc0 "112 ...with the consent message"
%FM% /query fmsc-plain >nul 2>&1
call :rc1 "113 nothing imported by the refused run"
%FM% /import-scoop fmfix /dir:%FXS% /trust > %O%\imp.txt 2>&1
call :rc0 "114 import with /trust rc0"
type %O%\imp.txt >> %LOG%
find "imported 7 Scoop app(s) (5 skipped: 1 without hash, 1 without a download for this machine, 3 invalid)" %O%\imp.txt >nul
call :rc0 "115 imported 7, skipped 5 (nohash, arm64-only, 3 unusable/malformed)"
%FM% /list /tier:software /source:scoop > %O%\l.txt 2>&1
find "fmsc-plain" %O%\l.txt >nul
call :rc0 "116 /list /source:scoop shows the entry"
%FM% /list /tier:software /source:scoop/fmfix > %O%\l.txt 2>&1
find "fmsc-arch" %O%\l.txt >nul
call :rc0 "117 /list /source:scoop/fmfix shows the bucket"
%FM% /list /tier:software /source:rapps > %O%\l.txt 2>&1
find "fmsc-plain" %O%\l.txt >nul
call :rc1 "118 /list /source:rapps hides scoop entries"
%FM% /list /tier:os > %O%\l.txt 2>&1
find "fmsc-plain" %O%\l.txt >nul
call :rc1 "119 scoop entries are not os tier"
call :st fmsc-plain NotInstalled "120 imported entry NotInstalled"
%FM% /query fmsc-plain > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "Tier:         software" %O%\q.txt >nul
call :rc0 "121 query: Tier=software"
find "Provider:     scoop" %O%\q.txt >nul
call :rc0 "122 query: Provider=scoop"
find "Source:       scoop/fmfix" %O%\q.txt >nul
call :rc0 "123 query: Source=scoop/fmfix"
find "Version:      1.2.3" %O%\q.txt >nul
call :rc0 "124 query: Version"
find "Dependencies: scoop" %O%\q.txt >nul
call :rc0 "125 query: Dependencies=scoop"
find "Scoop.App: fmsc-plain" %O%\q.txt >nul
call :rc0 "126 query: Scoop.App"
find "Scoop.Homepage: https://example.invalid/fmsc-plain" %O%\q.txt >nul
call :rc0 "127 query: homepage"
find "Scoop.License: MIT" %O%\q.txt >nul
call :rc0 "128 query: license string"
find "Scoop.Verified: 1" %O%\q.txt >nul
call :rc0 "129 query: verified (manifest has a hash)"
%FM% /query fmsc-arch > %O%\q.txt 2>&1
find "Scoop.License: Apache-2.0" %O%\q.txt >nul
call :rc0 "130 license object -> identifier"
find "quoted" %O%\q.txt >nul
call :rc0 "131 JSON escapes decoded in the description"
%FM% /query fmsc-nodesc > %O%\q.txt 2>&1
call :rc0 "132 hash only in architecture.64bit imported"
find "Scoop app from the fmfix bucket" %O%\q.txt >nul
call :rc0 "133 missing description gets a placeholder"
%FM% /query fmsc-arr >nul 2>&1
call :rc0 "134 url/hash arrays imported"
%FM% /query fmsc-deep >nul 2>&1
call :rc0 "135 manifest with scripts/braces in strings imported"
%FM% /query fmsc-nohash >nul 2>&1
call :rc1 "136 manifest without hash not imported"
%FM% /query fmsc-arm >nul 2>&1
call :rc1 "137 arm64-only manifest not imported"
%FM% /query fmsc-broken >nul 2>&1
call :rc1 "138 malformed JSON not imported"
%FM% /query fmfix-fmt-base > %O%\q.txt 2>&1
call :rc0 "139 id collision with fmt-base -> fmfix-fmt-base"
find "Scoop.App: fmt-base" %O%\q.txt >nul
call :rc0 "140 ...still installs the app name fmt-base"
%FM% /query fmt-base > %O%\q.txt 2>&1
find "Tier:         os" %O%\q.txt >nul
call :rc0 "141 original fmt-base catalog entry untouched"
%FM% /import-scoop fmfix /dir:%FXS% /trust /unverified /clean > %O%\imp.txt 2>&1
call :rc0 "142 /unverified import rc0"
find "imported 8 Scoop app(s)" %O%\imp.txt >nul
call :rc0 "143 /unverified adds the no-hash manifest"
%FM% /query fmsc-nohash > %O%\q.txt 2>&1
find "Scoop.Verified: 0" %O%\q.txt >nul
call :rc0 "144 unverified entry flagged Verified=0"
find "No hash in the manifest" %O%\q.txt >nul
call :rc0 "145 ...and labelled in the description"
%FM% /import-scoop fmfix /dir:%FXS% /trust /clean /limit:1 > %O%\imp.txt 2>&1
find "imported 1 Scoop app(s)" %O%\imp.txt >nul
call :rc0 "146 /limit:1 caps the import"
%FM% /query fmsc-nohash >nul 2>&1
call :rc1 "147 /clean dropped the bucket's earlier entries"
%FM% /import-scoop "bad bucket" /dir:%FXS% /trust > %O%\imp.txt 2>&1
call :rc1 "148 invalid bucket name refused"
%FM% /import-scoop fmfix /dir:%FXS%\nonexistent /trust > %O%\imp.txt 2>&1
call :rc1 "149 missing manifest dir fails"
%FM% /import-scoop fmfix /dir:%FXS% /trust /clean >> %LOG% 2>&1

rem --- official buckets from the Scoop root (fake root with a main bucket, a stub scoop)
mkdir %FSROOT%\shims
mkdir %FSROOT%\buckets\main\bucket
mkdir %FSROOT%\apps\scoop\current
copy /y %FX%\scoop-stub.cmd %FSROOT%\shims\scoop.cmd >nul
copy /y %FXS%\fmsc-plain.json %FSROOT%\buckets\main\bucket\ >nul
copy /y %FXS%\fmsc-nohash.json %FSROOT%\buckets\main\bucket\ >nul
set FEATMGR_SCOOP_ROOT=%FSROOT%
set FEATMGR_SCOOP_RUNNER=%FSROOT%\shims\scoop.cmd
%FM% /scoop-buckets > %O%\b.txt 2>&1
call :rc0 "150 /scoop-buckets rc0"
type %O%\b.txt >> %LOG%
find "main" %O%\b.txt >nul
call :rc0 "151 /scoop-buckets lists main"
%FM% /import-scoop > %O%\imp.txt 2>&1
call :rc0 "152 /import-scoop (all official buckets present) rc0"
type %O%\imp.txt >> %LOG%
find "bucket 'main': 1 imported" %O%\imp.txt >nul
call :rc0 "153 main bucket read from the Scoop root, 1 imported (no-hash skipped)"
%FM% /query main-fmsc-plain > %O%\q.txt 2>&1
call :rc0 "154 same app in two buckets: second one prefixed (main-fmsc-plain)"
find "Source:       scoop/main" %O%\q.txt >nul
call :rc0 "155 ...Source=scoop/main"
%FM% /import-scoop extras > %O%\imp.txt 2>&1
call :rc1 "156 bucket that Scoop does not have: import fails"
type %O%\imp.txt >> %LOG%
find "scoop bucket add extras" %O%\imp.txt >nul
call :rc0 "157 ...and says how to add it (never adds one itself)"

rem --- install / uninstall / state through the stub scoop (scoop itself is detected as installed)
call :st scoop Enabled "158 scoop feature detected as installed (shim present)"
call :st fmsc-plain NotInstalled "159 app not installed before"
%FM% /install fmsc-plain > %O%\i.txt 2>&1
call :rc0 "160 install fmsc-plain runs 'scoop install' (rc0)"
type %O%\i.txt >> %LOG%
find "install fmfix/fmsc-plain" %FSROOT%\calls.txt >nul
call :rc0 "161 scoop was called with the bucket-qualified name"
call :st fmsc-plain Enabled "162 Enabled after install"
call :ex %FSROOT%\apps\fmsc-plain\current 1 "163 stub left apps\<app>\current"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmsc-plain /v Uninstall >nul 2>&1
call :rc0 "164 uninstall command recorded in the state"
%FM% /disable scoop > %O%\i.txt 2>&1
call :rc1 "165 scoop cannot be disabled while a Scoop app is installed"
find "fmsc-plain" %O%\i.txt >nul
call :rc0 "166 ...naming the dependent"
call :st scoop Enabled "167 scoop untouched"
%FM% /list /state:enabled /tier:software > %O%\l.txt 2>&1
find "fmsc-plain" %O%\l.txt >nul
call :rc0 "168 list shows the installed Scoop app"
rem an app installed with the scoop CLI is seen without a featmgr record
mkdir %FSROOT%\apps\fmsc-deep\current
call :st fmsc-deep Enabled "169 externally installed app detected as Enabled"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmsc-deep >nul 2>&1
call :rc1 "170 ...without any featmgr record"
%FM% /disable fmsc-deep > %O%\i.txt 2>&1
call :rc0 "171 disable of an externally installed app runs 'scoop uninstall'"
type %O%\i.txt >> %LOG%
find "uninstall fmfix/fmsc-deep" %FSROOT%\calls.txt >nul
call :rc0 "172 scoop was called to uninstall it"
call :ex %FSROOT%\apps\fmsc-deep 0 "173 app directory gone"
%FM% /uninstall fmsc-deep >> %LOG% 2>&1
call :rc0 "174 uninstall forgets it"
call :st fmsc-deep NotInstalled "175 NotInstalled again"
rem removed outside featmgr: the stale record does not claim Enabled
rd /s /q %FSROOT%\apps\fmsc-plain
call :st fmsc-plain NotInstalled "176 app removed outside featmgr -> NotInstalled (probe beats the stale record)"
%FM% /uninstall fmsc-plain >> %LOG% 2>&1
call :rc0 "177 uninstall clears the stale record"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmsc-plain >nul 2>&1
call :rc1 "178 stale record deleted"
rem normal uninstall
%FM% /install fmsc-plain >> %LOG% 2>&1
%FM% /uninstall fmsc-plain > %O%\i.txt 2>&1
call :rc0 "179 uninstall of an installed app (scoop uninstall + forget)"
find "uninstall fmfix/fmsc-plain" %FSROOT%\calls.txt >nul
call :rc0 "180 scoop was called to uninstall it"
call :ex %FSROOT%\apps\fmsc-plain 0 "181 app directory gone"
call :st fmsc-plain NotInstalled "182 NotInstalled"
rem Scoop's own failure is surfaced and leaves nothing behind
%FM% /install fmsc-fail > %O%\i.txt 2>&1
call :rc1 "183 failing scoop install -> rc3"
type %O%\i.txt >> %LOG%
find "Hash check failed" %O%\i.txt >nul
call :rc0 "184 Scoop's own output is shown (hash check failed)"
find "exit code 7" %O%\i.txt >nul
call :rc0 "185 ...with its exit code"
call :st fmsc-fail NotInstalled "186 failed install leaves NotInstalled"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmsc-fail >nul 2>&1
call :rc1 "187 failed install leaves no record"
rem ===== SCOOP M2: per-bucket index file, installed version, update, search, bucket add, scale =====
rem --- the import writes ONE index file per bucket, not one ini per app
call :ex %SW%\scoop-fmfix.idx 1 "M1 index file for bucket fmfix"
call :ex %SW%\scoop-main.idx 1 "M2 index file for bucket main (imported from the Scoop root)"
call :ex %SW%\fmsc-plain.ini 0 "M3 no per-app ini written"
find "#featmgr-scoop-index" %SW%\scoop-fmfix.idx >nul
call :rc0 "M4 index header present"
find "bucket=fmfix" %SW%\scoop-fmfix.idx >nul
call :rc0 "M5 header names the bucket"
find "fmsc-plain" %SW%\scoop-fmfix.idx >nul
call :rc0 "M6 index holds the entries"
rem per-app ini files of an M1 import: still read; replaced by the index when their bucket is imported again
> %SW%\fmsc-legacy.ini echo [Feature]
>> %SW%\fmsc-legacy.ini echo Id=fmsc-legacy
>> %SW%\fmsc-legacy.ini echo Name=fmsc-legacy
>> %SW%\fmsc-legacy.ini echo Description=M1-style per-app entry
>> %SW%\fmsc-legacy.ini echo Version=3.1
>> %SW%\fmsc-legacy.ini echo Tier=software
>> %SW%\fmsc-legacy.ini echo Dependencies=scoop
>> %SW%\fmsc-legacy.ini echo [Install]
>> %SW%\fmsc-legacy.ini echo Provider=scoop
>> %SW%\fmsc-legacy.ini echo [Scoop]
>> %SW%\fmsc-legacy.ini echo App=fmsc-legacy
>> %SW%\fmsc-legacy.ini echo Bucket=fmlegacy
> %SW%\fmsc-plain.ini echo [Feature]
>> %SW%\fmsc-plain.ini echo Id=fmsc-plain
>> %SW%\fmsc-plain.ini echo Name=fmsc-plain
>> %SW%\fmsc-plain.ini echo Version=0.0.1
>> %SW%\fmsc-plain.ini echo Tier=software
>> %SW%\fmsc-plain.ini echo Dependencies=scoop
>> %SW%\fmsc-plain.ini echo [Install]
>> %SW%\fmsc-plain.ini echo Provider=scoop
>> %SW%\fmsc-plain.ini echo [Scoop]
>> %SW%\fmsc-plain.ini echo App=fmsc-plain
>> %SW%\fmsc-plain.ini echo Bucket=fmfix
%FM% /query fmsc-legacy > %O%\q.txt 2>&1
call :rc0 "M7 per-app ini of an older import still readable"
find "Source:       scoop/fmlegacy" %O%\q.txt >nul
call :rc0 "M8 ...with its source"
%FM% /import-scoop fmfix /dir:%FXS% /trust > %O%\imp.txt 2>&1
call :rc0 "M9 re-import of fmfix"
call :ex %SW%\fmsc-plain.ini 0 "M10 the older per-app ini of the re-imported bucket is gone"
call :ex %SW%\fmsc-legacy.ini 1 "M11 other buckets' per-app ini untouched"
%FM% /query fmsc-plain > %O%\q.txt 2>&1
find "Version:      1.2.3" %O%\q.txt >nul
call :rc0 "M12 the entry now comes from the index (version 1.2.3, not the stale ini's 0.0.1)"
del /q %SW%\fmsc-legacy.ini

rem --- search: name and description, case-insensitive
%FM% /list /search:FMSC-PLAIN > %O%\l.txt 2>&1
find "fmsc-plain" %O%\l.txt >nul
call :rc0 "S1 /list /search matches the name, case-insensitively"
find "fmsc-arch" %O%\l.txt >nul
call :rc1 "S2 ...and hides the others"
%FM% "/list" "/search:Plain Scoop TEST" > %O%\l.txt 2>&1
find "fmsc-plain" %O%\l.txt >nul
call :rc0 "S3 /list /search matches the description"
%FM% /list /search:CAF > %O%\l.txt 2>&1
find "fmsc-arch" %O%\l.txt >nul
call :rc0 "S4 description match (Caf in the description of fmsc-arch, not in its name)"
%FM% /list /search:zzznomatchzzz > %O%\l.txt 2>&1
find "0 feature(s)" %O%\l.txt >nul
call :rc0 "S5 no match lists nothing"
%FM% /list /tier:software /search:fmsc /source:scoop/fmfix > %O%\l.txt 2>&1
find "fmsc-plain" %O%\l.txt >nul
call :rc0 "S6 /search combines with /tier and /source"

rem --- installed version and update (the stub keeps the bucket manifest as apps\<app>\current\manifest.json)
mkdir %FSROOT%\pending 2>nul
mkdir %FSROOT%\bucketsrc 2>nul
copy /y %FX%\scoop-upd\v1\fmsc-upd.json %FSROOT%\buckets\main\bucket\ >nul
copy /y %FX%\scoop-upd\v1\fmsc-failupd.json %FSROOT%\buckets\main\bucket\ >nul
%FM% /import-scoop > %O%\imp.txt 2>&1
call :rc0 "U1 import of the official buckets with the update fixture (1.0.0)"
%FM% /query fmsc-upd > %O%\q.txt 2>&1
find "Version:      1.0.0" %O%\q.txt >nul
call :rc0 "U2 catalog version 1.0.0"
find "InstalledVersion: (not installed)" %O%\q.txt >nul
call :rc0 "U3 not installed: no installed version"
%FM% /install fmsc-upd > %O%\i.txt 2>&1
call :rc0 "U4 install fmsc-upd"
call :ex %FSROOT%\apps\fmsc-upd\current\manifest.json 1 "U5 stub left current\manifest.json"
%FM% /query fmsc-upd > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "InstalledVersion: 1.0.0" %O%\q.txt >nul
call :rc0 "U6 installed version read from current\manifest.json"
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "U7 no update while the catalog matches"
%FM% /list /state:enabled /tier:software > %O%\l.txt 2>&1
find "INSTALLED" %O%\l.txt >nul
call :rc0 "U8 /list has the INSTALLED column"
findstr /b "fmsc-upd" %O%\l.txt | find "1.0.0" >nul
call :rc0 "U9 /list shows the installed version of fmsc-upd"
rem "scoop update" pulled a newer manifest into the bucket: the catalog still has the old one until it is re-imported
copy /y %FX%\scoop-upd\v2\fmsc-upd.json %FSROOT%\buckets\main\bucket\ >nul
%FM% /query fmsc-upd > %O%\q.txt 2>&1
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "U10 catalog not refreshed yet: no update shown"
%FM% /import-scoop > %O%\imp.txt 2>&1
call :rc0 "U11 re-import after the bucket changed"
%FM% /query fmsc-upd > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "Version:      1.1.0" %O%\q.txt >nul
call :rc0 "U12 catalog version now 1.1.0"
find "InstalledVersion: 1.0.0" %O%\q.txt >nul
call :rc0 "U13 installed version still 1.0.0"
find "UpdateAvailable: Yes (1.0.0 -> 1.1.0)" %O%\q.txt >nul
call :rc0 "U14 update available 1.0.0 -> 1.1.0"
%FM% /list /state:enabled /tier:software > %O%\l.txt 2>&1
find "[update available]" %O%\l.txt >nul
call :rc0 "U15 /list marks the update"
%FM% /update fmsc-upd > %O%\u.txt 2>&1
call :rc0 "U16 featmgr /update fmsc-upd rc0"
type %O%\u.txt >> %LOG%
findstr /x /c:"update fmsc-upd" %FSROOT%\calls.txt >nul
call :rc0 "U17 scoop was called: update fmsc-upd"
find "updated: 1.0.0 -> 1.1.0" %O%\u.txt >nul
call :rc0 "U18 the report says 1.0.0 -> 1.1.0"
%FM% /query fmsc-upd > %O%\q.txt 2>&1
find "InstalledVersion: 1.1.0" %O%\q.txt >nul
call :rc0 "U19 installed version is 1.1.0"
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "U20 no update pending after the update"
%FM% /update fmsc-upd > %O%\u.txt 2>&1
call :rc0 "U21 update when already current: rc0"
find "latest version Scoop has" %O%\u.txt >nul
call :rc0 "U22 ...says so"
rem /update /all: scoop update (pulls the bucket), re-import, scoop update *
copy /y %FX%\scoop-upd\v3\fmsc-upd.json %FSROOT%\pending\ >nul
%FM% /update /all > %O%\u.txt 2>&1
call :rc0 "U23 featmgr /update /all rc0"
type %O%\u.txt >> %LOG%
findstr /x /c:"update" %FSROOT%\calls.txt >nul
call :rc0 "U24 scoop was called: update (Scoop and buckets)"
findstr /x /c:"update *" %FSROOT%\calls.txt >nul
call :rc0 "U25 scoop was called: update * (apps)"
%FM% /query fmsc-upd > %O%\q.txt 2>&1
find "Version:      1.2.0" %O%\q.txt >nul
call :rc0 "U26 catalog refreshed from the pulled bucket (1.2.0)"
find "InstalledVersion: 1.2.0" %O%\q.txt >nul
call :rc0 "U27 app updated to 1.2.0"
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "U28 nothing pending"
%FM% /update fmsc-nohash > %O%\u.txt 2>&1
call :rc1 "U29 /update of an app that is not in the catalog"
%FM% /update fmsc-plain > %O%\u.txt 2>&1
call :rc1 "U30 /update of an app that is not installed"
find "not installed" %O%\u.txt >nul
call :rc0 "U31 ...says it is not installed"
%FM% /update fmt-sw > %O%\u.txt 2>&1
call :rc1 "U32 /update of a non-Scoop entry refused"
find "only Scoop apps" %O%\u.txt >nul
call :rc0 "U33 ...says only Scoop apps have an updater"
%FM% /update > %O%\u.txt 2>&1
call :rc1 "U34 /update without an argument is a usage error"
%FM% /install fmsc-failupd > %O%\i.txt 2>&1
call :rc0 "U35 install fmsc-failupd"
%FM% /update fmsc-failupd > %O%\u.txt 2>&1
call :rc1 "U36 a failing scoop update fails"
type %O%\u.txt >> %LOG%
find "download failed" %O%\u.txt >nul
call :rc0 "U37 Scoop's own output is shown"
find "exit code 7" %O%\u.txt >nul
call :rc0 "U38 ...with its exit code"
%FM% /uninstall fmsc-failupd >> %LOG% 2>&1
%FM% /uninstall fmsc-upd >> %LOG% 2>&1

rem --- add bucket: Scoop's known buckets by name, anything else needs /trust and an https URL
copy /y %FXS%\fmsc-arch.json %FSROOT%\bucketsrc\ >nul
%FM% /scoop-buckets > %O%\b.txt 2>&1
type %O%\b.txt >> %LOG%
find "Known buckets" %O%\b.txt >nul
call :rc0 "B1 /scoop-buckets lists Scoop's known buckets"
find "versions" %O%\b.txt >nul
call :rc0 "B2 ...built-in names when Scoop's buckets.json is absent"
%FM% /add-bucket versions > %O%\ab.txt 2>&1
call :rc0 "B3 /add-bucket versions (known) rc0"
type %O%\ab.txt >> %LOG%
findstr /x /c:"bucket add versions" %FSROOT%\calls.txt >nul
call :rc0 "B4 scoop was called: bucket add versions"
call :ex %SW%\scoop-versions.idx 1 "B5 the bucket was imported (index file)"
%FM% /query versions-fmsc-arch > %O%\q.txt 2>&1
call :rc0 "B6 imported entry (id prefixed: fmsc-arch is taken by another bucket's index)"
find "Source:       scoop/versions" %O%\q.txt >nul
call :rc0 "B7 ...Source=scoop/versions"
%FM% /add-bucket versions > %O%\ab.txt 2>&1
call :rc0 "B8 adding a bucket twice is harmless"
find "already added" %O%\ab.txt >nul
call :rc0 "B9 ...says it is already added"
%FM% /add-bucket nosuchbucket > %O%\ab.txt 2>&1
call :rc1 "B10 unknown bucket refused without a URL"
find "not one of Scoop's known buckets" %O%\ab.txt >nul
call :rc0 "B11 ...with the reason"
%FM% /add-bucket fmthird https://example.invalid/fmthird > %O%\ab.txt 2>&1
call :rc1 "B12 arbitrary URL refused without /trust"
find "explicit consent" %O%\ab.txt >nul
call :rc0 "B13 ...asks for consent"
%FM% /add-bucket versions https://example.invalid/other > %O%\ab.txt 2>&1
call :rc1 "B14 a known name with a different URL also needs /trust"
%FM% /add-bucket fmthird "https://example.invalid/a&b" /trust > %O%\ab.txt 2>&1
call :rc1 "B15 URL with a shell metacharacter refused even with /trust"
%FM% /add-bucket fmthird http://example.invalid/fmthird /trust > %O%\ab.txt 2>&1
call :rc1 "B16 plain http URL refused"
%FM% /add-bucket fmthird /trust > %O%\ab.txt 2>&1
call :rc1 "B17 unknown bucket without URL refused even with /trust"
%FM% /add-bucket bad/name /trust > %O%\ab.txt 2>&1
call :rc1 "B18 invalid bucket name refused"
find "fmthird" %FSROOT%\calls.txt >nul
call :rc1 "B19 scoop was never called for any refused request"
%FM% /add-bucket fmthird https://example.invalid/fmthird /trust > %O%\ab.txt 2>&1
call :rc0 "B20 /add-bucket <name> <https-url> /trust rc0"
type %O%\ab.txt >> %LOG%
findstr /x /c:"bucket add fmthird https://example.invalid/fmthird" %FSROOT%\calls.txt >nul
call :rc0 "B21 scoop was called with the URL"
%FM% /query fmthird-fmsc-arch > %O%\q.txt 2>&1
call :rc0 "B22 third-party bucket imported"
find "trust=1" %SW%\scoop-fmthird.idx >nul
call :rc0 "B23 the index records that the import had /trust"
rem Scoop's own list (buckets.json) decides what is known
> %FSROOT%\apps\scoop\current\buckets.json echo {"fmknown": "https://example.invalid/fmknown", "main": "https://example.invalid/main"}
%FM% /scoop-buckets > %O%\b.txt 2>&1
find "fmknown" %O%\b.txt >nul
call :rc0 "B24 /scoop-buckets reads Scoop's buckets.json"
find "https://example.invalid/fmknown" %O%\b.txt >nul
call :rc0 "B25 ...with the URL"
%FM% /add-bucket fmknown > %O%\ab.txt 2>&1
call :rc0 "B26 a bucket from buckets.json is known"
%FM% /add-bucket nirsoft > %O%\ab.txt 2>&1
call :rc1 "B27 a built-in name that buckets.json does not list is not known"
rem a refresh keeps the consent of the original import and never widens it
%FM% /update /all > %O%\u.txt 2>&1
call :rc0 "B28 /update /all refreshes added buckets too"
find "trust=1" %SW%\scoop-fmthird.idx >nul
call :rc0 "B29 fmthird keeps its recorded flags"
del /q %FSROOT%\apps\scoop\current\buckets.json

rem --- scale: 4000 manifests in one bucket
set PERF=%O%\perfbucket
rd /s /q %PERF% 2>nul
mkdir %PERF%
for /l %%i in (1,1,4000) do @echo {"version":"1.0.%%i","description":"Perf app %%i","homepage":"https://example.invalid/p%%i","license":"MIT","url":"https://example.invalid/p%%i.zip","hash":"0123456789abcdef"}> %PERF%\perf-%%i.json
dir /b %PERF%\*.json | find /c ".json" > %O%\pc.txt
type %O%\pc.txt >> %LOG%
find "4000" %O%\pc.txt >nul
call :rc0 "P1 4000 fixture manifests generated"
%FM% /import-scoop fmperf /dir:%PERF% /trust /timing > %O%\imp.txt 2>&1
call :rc0 "P2 import of 4000 manifests rc0"
find "imported 4000 Scoop app(s)" %O%\imp.txt >nul
call :rc0 "P3 4000 imported"
findstr /b "timing:" %O%\imp.txt >> %LOG%
set IMS=999999
for /f "tokens=3" %%a in ('findstr /b "timing:" %O%\imp.txt') do set IMS=%%a
echo import of 4000 manifests: %IMS% ms>> %LOG%
if %IMS% LSS 30000 (echo PASS P4 import of 4000 manifests under 30 s>> %LOG%) else (call :fail "P4 import of 4000 manifests under 30 s" "%IMS% ms")
call :ex %SW%\scoop-fmperf.idx 1 "P5 one index file for the bucket"
%FM% /list /tier:software /timing > %O%\l.txt 2>&1
call :rc0 "P6 /list over 4000+ entries rc0"
findstr /b "timing:" %O%\l.txt >> %LOG%
set LMS=999999
for /f "tokens=3" %%a in ('findstr /b "timing:" %O%\l.txt') do set LMS=%%a
echo list of 4000+ entries: %LMS% ms>> %LOG%
if %LMS% LSS 5000 (echo PASS P7 /list enumerates 4000+ entries in under 5 s>> %LOG%) else (call :fail "P7 /list enumerates 4000+ entries in under 5 s" "%LMS% ms")
find "perf-4000" %O%\l.txt >nul
call :rc0 "P8 the last entry is listed"
%FM% "/list" "/search:Perf app 3999" > %O%\l.txt 2>&1
find "perf-3999" %O%\l.txt >nul
call :rc0 "P9 search finds one of 4000 by description"
find "1 feature(s)" %O%\l.txt >nul
call :rc0 "P10 ...and only that one"
%FM% /query perf-2500 > %O%\q.txt 2>&1
find "Version:      1.0.2500" %O%\q.txt >nul
call :rc0 "P11 /query of one entry out of 4000+"
rd /s /q %PERF% 2>nul

rem ===== NitroOS default for VS Code (SCOOP-vscode-default-conpty-dll-false): after featmgr installs or updates
rem vscode it adds "terminal.integrated.windowsUseConptyDll": false to scoop's persisted settings.json, only when
rem that key is absent. TODO CONSOLE-condrv-device: remove together with scoopdefaults.c.
set FEATMGR_SCOOP_ROOT=%FSROOT%
set FEATMGR_SCOOP_RUNNER=%FSROOT%\shims\scoop.cmd
set VSU=%FSROOT%\persist\vscode\data\user-data\User
set VSJ=%VSU%\settings.json
%FM% /import-scoop vscfx /dir:%FX%\scoop-vscode /trust > %O%\imp.txt 2>&1
call :rc0 "VS0 import of the vscode test bucket"
rd /s /q %FSROOT%\persist 2>nul
%FM% /install vscode > %O%\i.txt 2>&1
call :rc0 "VS1 install vscode (no settings.json yet)"
type %O%\i.txt >> %LOG%
call :ex %VSJ% 1 "VS2 settings.json created under persist\vscode\data\user-data\User"
find ": false" %VSJ% >nul
call :rc0 "VS3 ...with the key false"
find "CONSOLE-condrv-device" %VSJ% >nul
call :rc0 "VS4 ...and the TODO note (a comment)"
call :vsc true
fc /b %FX%\vscode-settings\true.json %VSJ% >nul
call :rc0 "VS5 an existing true: file byte for byte as it was (no false added)"
fc /b %FX%\vscode-settings\false.json %VSJ% >nul
call :rc1 "VS6 (self-check) fc /b reports a difference between two different files"
call :vsc false
fc /b %FX%\vscode-settings\false.json %VSJ% >nul
call :rc0 "VS7 an existing false: file untouched"
call :vsc tricky
fc /b %FX%\vscode-settings\tricky.expected.json %VSJ% >nul
call :rc0 "VS8 a commented-out or nested key does not count; slashes and a brace inside a string are not comments or braces; top-level key added after a new comma"
call :vsc comments
fc /b %FX%\vscode-settings\comments.expected.json %VSJ% >nul
call :rc0 "VS9 leading, member-trailing, block and trailing comments kept; comma added after the last member"
call :vsc trailing-comma
fc /b %FX%\vscode-settings\trailing-comma.expected.json %VSJ% >nul
call :rc0 "VS10 trailing comma, CRLF kept"
call :vsc oneline
fc /b %FX%\vscode-settings\oneline.expected.json %VSJ% >nul
call :rc0 "VS11 one-line object: member spliced in on the same line"
call :vsc emptyobj
fc /b %FX%\vscode-settings\emptyobj.expected.json %VSJ% >nul
call :rc0 "VS12 empty object"
call :vsc empty
fc /b %FX%\vscode-settings\empty.expected.json %VSJ% >nul
call :rc0 "VS13 empty file: object written"
call :vsc commentonly
fc /b %FX%\vscode-settings\commentonly.expected.json %VSJ% >nul
call :rc0 "VS14 comment-only file: comment kept, object added"
call :vsc bom
fc /b %FX%\vscode-settings\bom.expected.json %VSJ% >nul
call :rc0 "VS15 UTF-8 BOM kept, CRLF kept"
call :vsc broken
fc /b %FX%\vscode-settings\broken.json %VSJ% >nul
call :rc0 "VS16 malformed file left untouched"
call :vsc array
fc /b %FX%\vscode-settings\array.json %VSJ% >nul
call :rc0 "VS17 non-object file left untouched"
rem the hook runs after an update as well
copy /y %FX%\vscode-settings\comments.json %VSJ% >nul
%FM% /update vscode > %O%\i.txt 2>&1
type %O%\i.txt >> %LOG%
find ": false" %VSJ% >nul
call :rc0 "VS18 /update vscode adds the key when absent"
copy /y %FX%\vscode-settings\true.json %VSJ% >nul
%FM% /update /all >> %LOG% 2>&1
fc /b %FX%\vscode-settings\true.json %VSJ% >nul
call :rc0 "VS19 /update /all keeps the user's true"
copy /y %FX%\vscode-settings\comments.json %VSJ% >nul
%FM% /update /all >> %LOG% 2>&1
find ": false" %VSJ% >nul
call :rc0 "VS20 /update /all adds the key when absent"
rem vscode-insiders has its own persist dir; other apps get nothing
%FM% /install vscode-insiders >> %LOG% 2>&1
find ": false" %FSROOT%\persist\vscode-insiders\data\user-data\User\settings.json >nul
call :rc0 "VS21 vscode-insiders gets the default in its own persist dir"
%FM% /install fmsc-plain >> %LOG% 2>&1
call :ex %FSROOT%\persist\fmsc-plain 0 "VS22 other Scoop apps get no persist data from featmgr"
%FM% /uninstall fmsc-plain >> %LOG% 2>&1
%FM% /uninstall vscode-insiders >> %LOG% 2>&1
%FM% /uninstall vscode >> %LOG% 2>&1
rd /s /q %FSROOT%\persist 2>nul

rem the install of a feature that is available only with scoop present
set FEATMGR_SCOOP_ROOT=
set FEATMGR_SCOOP_RUNNER=
goto :scoop_done

:scoop_fat
rem FAT volume: Scoop and every Scoop app must be refused up front, nothing downloaded.
%FM% /install scoop > %O%\i.txt 2>&1
call :rc1 "F1 install scoop refused on FAT"
type %O%\i.txt >> %LOG%
find "NTFS" %O%\i.txt >nul
call :rc0 "F2 ...with a message naming NTFS"
call :st scoop NotInstalled "F3 scoop NotInstalled"
call :st powershell-7 NotInstalled "F4 powershell-7 was not pulled in (refused before the dependency)"
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (call :fail "F5 nothing downloaded or installed" "pwsh present") else (echo PASS F5 nothing downloaded or installed>> %LOG%)
%FM% /import-scoop fmfix /dir:%FXS% /trust > %O%\imp.txt 2>&1
%FM% /install fmsc-plain > %O%\i.txt 2>&1
call :rc1 "F6 a Scoop app is refused on FAT too"
find "NTFS" %O%\i.txt >nul
call :rc0 "F7 ...with the NTFS message"
goto :scoop_done

:scoop_x86
rem No PowerShell 7 x86: the scoop feature is not in the catalog and the import refuses cleanly.
echo scoop feature absent from this catalog (x86 image)>> %LOG%
%FM% /list > %O%\l.txt 2>&1
find "scoop" %O%\l.txt >nul
call :rc1 "X1 scoop hidden from /list on x86"
%FM% /import-scoop fmfix /dir:%FXS% /trust > %O%\imp.txt 2>&1
call :rc1 "X2 /import-scoop refused on x86"
type %O%\imp.txt >> %LOG%
find "not available on this architecture" %O%\imp.txt >nul
call :rc0 "X3 ...with a clear message"
%FM% /import-scoop > %O%\imp.txt 2>&1
call :rc1 "X4 /import-scoop (no args) refused on x86"
%FM% /query fmsc-plain >nul 2>&1
call :rc1 "X5 nothing imported on x86"
%FM% /update /all > %O%\u.txt 2>&1
call :rc1 "X6 /update /all refused on x86"
find "not available on this architecture" %O%\u.txt >nul
call :rc0 "X7 ...with a clear message"
%FM% /add-bucket versions > %O%\u.txt 2>&1
call :rc1 "X8 /add-bucket refused on x86"

:scoop_done
set FEATMGR_SCOOP_ROOT=
set FEATMGR_SCOOP_RUNNER=
rd /s /q %FSROOT% 2>nul
rd /s /q %SW% 2>nul

rem --- software-tier cleanup
del /q %R%\Catalog\fmt-sw.ini %R%\Catalog\fmt-swbad.ini %R%\Catalog\fmt-swstuck.ini 2>nul
del /q %R%\Payload\fmt-sw\*.* %R%\Payload\fmt-swbad\*.* %R%\Payload\fmt-swstuck\*.* 2>nul
rmdir %R%\Payload\fmt-sw 2>nul
rmdir %R%\Payload\fmt-swbad 2>nul
rmdir %R%\Payload\fmt-swstuck 2>nul
rd /s /q %SW% 2>nul

rem --- shell defaults (shelldefaults.c): the desktop / Start shortcuts follow what is installed. Dummy pwsh.exe / firefox.exe
rem     files stand in for the programs (the check is "the file exists"); skipped when the real ones are installed.
set PD=%ProgramFiles%\PowerShell\7
set FD=%ProgramFiles%\Mozilla Firefox
set CD=%PUBLIC%\Desktop
set PM=%ProgramData%\Microsoft\Windows\Start Menu\Programs
if exist "%FD%\firefox.exe" goto :sd_done
if exist "%PD%\pwsh.exe" goto :sd_pw
%FM% /shell-defaults > %O%\sd0.txt 2>&1
call :rc0 "SD1 /shell-defaults with nothing installed"
type %O%\sd0.txt >> %LOG%
call :ex "%CD%\PowerShell.lnk" 0 "SD2 no PowerShell shortcut while pwsh is absent"
call :ex "%CD%\Firefox.lnk" 0 "SD3 no Firefox shortcut while Firefox is absent"
call :wslnk 1 "SD4 Command Prompt is under Start/Windows System"
call :cmdlnk 1 "SD5 a Command Prompt shortcut is on the desktop"
mkdir "%PD%" 2>nul
copy /y %SystemRoot%\system32\cmd.exe "%PD%\pwsh.exe" >nul
mkdir "%FD%" 2>nul
copy /y %SystemRoot%\system32\cmd.exe "%FD%\firefox.exe" >nul
%FM% /shell-defaults > %O%\sd1.txt 2>&1
call :rc0 "SD6 /shell-defaults with pwsh and Firefox present"
type %O%\sd1.txt >> %LOG%
call :ex "%CD%\PowerShell.lnk" 1 "SD7 PowerShell shortcut on the desktop"
call :ex "%PM%\PowerShell.lnk" 1 "SD8 PowerShell shortcut in the Start menu"
call :cmdlnk 0 "SD9 the Command Prompt shortcut left the desktop"
call :wslnk 1 "SD10 Command Prompt stays under Start/Windows System"
call :ex "%CD%\Firefox.lnk" 1 "SD11 Firefox shortcut on the desktop"
call :ex "%PM%\Firefox.lnk" 1 "SD12 Firefox shortcut in the Start menu"
call :ex "%FD%\distribution\policies.json" 1 "SD13 Firefox policies.json written"
find "DontCheckDefaultBrowser" "%FD%\distribution\policies.json" >nul
call :rc0 "SD14 ...with DontCheckDefaultBrowser"
call :ielnk 0 "SD15 the Internet Explorer entry left the Start menu"
%FM% /shell-defaults > %O%\sd2.txt 2>&1
call :rc0 "SD16 /shell-defaults a second time (idempotent)"
call :ex "%CD%\PowerShell.lnk" 1 "SD17 still one PowerShell shortcut"
del /q "%PD%\pwsh.exe" "%FD%\firefox.exe" 2>nul
%FM% /shell-defaults > %O%\sd3.txt 2>&1
call :rc0 "SD18 /shell-defaults after pwsh and Firefox are gone"
type %O%\sd3.txt >> %LOG%
call :ex "%CD%\PowerShell.lnk" 0 "SD19 PowerShell shortcut removed"
call :ex "%CD%\Firefox.lnk" 0 "SD20 Firefox shortcut removed"
call :cmdlnk 1 "SD21 Command Prompt is back on the desktop"
call :ielnk 0 "SD22 no Internet Explorer entry comes back, iexplore opens the default browser as on Windows 11"
rd /s /q "%FD%" 2>nul
rd /s /q "%ProgramFiles%\PowerShell" 2>nul
goto :sd_done
:sd_pw
rem the image carries the real pwsh (build-time preinstall): PowerShell is the desktop shell already, Firefox is not installed yet
%FM% /shell-defaults > %O%\sp0.txt 2>&1
call :rc0 "SP1 /shell-defaults with the preinstalled pwsh"
type %O%\sp0.txt >> %LOG%
call :ex "%CD%\PowerShell.lnk" 1 "SP2 PowerShell shortcut on the desktop"
call :ex "%PM%\PowerShell.lnk" 1 "SP3 PowerShell shortcut in the Start menu"
call :cmdlnk 0 "SP4 no Command Prompt shortcut on the desktop"
call :wslnk 1 "SP5 Command Prompt is under Start/Windows System"
call :ex "%CD%\Firefox.lnk" 0 "SP6 no Firefox shortcut while Firefox is absent"
call :ielnk 0 "SP7 no Internet Explorer entry in the Start menu, as on Windows 11"
mkdir "%FD%" 2>nul
copy /y %SystemRoot%\system32\cmd.exe "%FD%\firefox.exe" >nul
%FM% /shell-defaults > %O%\sp1.txt 2>&1
call :rc0 "SP8 /shell-defaults with pwsh and a Firefox stand-in"
call :ex "%CD%\Firefox.lnk" 1 "SP9 Firefox shortcut on the desktop"
call :ielnk 0 "SP10 the Internet Explorer entry left the Start menu"
call :ex "%CD%\PowerShell.lnk" 1 "SP11 PowerShell shortcut stays"
del /q "%FD%\firefox.exe" 2>nul
%FM% /shell-defaults > %O%\sp2.txt 2>&1
call :rc0 "SP12 /shell-defaults after the Firefox stand-in is gone"
call :ex "%CD%\Firefox.lnk" 0 "SP13 Firefox shortcut removed"
call :ielnk 0 "SP14 no Internet Explorer entry comes back, iexplore opens the default browser"
call :ex "%CD%\PowerShell.lnk" 1 "SP15 PowerShell shortcut still on the desktop"
call :cmdlnk 0 "SP16 still no Command Prompt shortcut on the desktop"
rd /s /q "%FD%" 2>nul
:sd_done

rem --- leftover plain Internet Explorer shortcuts are removed once (RemoveIeLinksOnce, flag IeShortcutsRemoved): a plain
rem     one the user makes afterwards stays, one with arguments is never removed. WScript.Shell makes the shortcuts.
set IEX=%ProgramFiles%\Internet Explorer\iexplore.exe
set IEL=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Wine Internet Explorer.lnk
set IEA=%APPDATA%\Microsoft\Windows\Start Menu\Programs\IE with arguments.lnk
set IEK=HKCU\SOFTWARE\ReactOS\Nitro\Featmgr
echo Set l = CreateObject("WScript.Shell").CreateShortcut(WScript.Arguments(0))> %O%\mklnk.vbs
echo l.TargetPath = WScript.Arguments(1)>> %O%\mklnk.vbs
echo If WScript.Arguments.Count ^> 2 Then l.Arguments = WScript.Arguments(2)>> %O%\mklnk.vbs
echo l.Save>> %O%\mklnk.vbs
%FM% /shell-defaults > %O%\ie0.txt 2>&1
reg query %IEK% /v IeShortcutsRemoved >nul 2>&1
call :rc0 "IE1 the per-user IE shortcut flag is set once shell defaults ran"
cscript //nologo %O%\mklnk.vbs "%IEL%" "%IEX%" >> %LOG% 2>&1
cscript //nologo %O%\mklnk.vbs "%IEA%" "%IEX%" "https://example.com" >> %LOG% 2>&1
call :ex "%IEL%" 1 "IE2 a plain IE shortcut made by the user"
call :ex "%IEA%" 1 "IE3 an IE shortcut with arguments made by the user"
%FM% /shell-defaults > %O%\ie1.txt 2>&1
call :ex "%IEL%" 1 "IE4 the user's plain IE shortcut survives the next run, the flag is set"
reg delete %IEK% /v IeShortcutsRemoved /f >nul 2>&1
%FM% /shell-defaults > %O%\ie2.txt 2>&1
type %O%\ie2.txt >> %LOG%
call :ex "%IEL%" 0 "IE5 with the flag cleared the plain IE shortcut is removed, once"
call :ex "%IEA%" 1 "IE6 the IE shortcut with arguments is never removed"
reg query %IEK% /v IeShortcutsRemoved >nul 2>&1
call :rc0 "IE7 the flag is set again"
cscript //nologo %O%\mklnk.vbs "%IEL%" "%IEX%" >> %LOG% 2>&1
%FM% /shell-defaults > %O%\ie3.txt 2>&1
call :ex "%IEL%" 1 "IE8 a plain IE shortcut re-created afterwards stays"
del /q "%IEL%" "%IEA%" %O%\mklnk.vbs 2>nul

rem --- cleanup fixtures
del /q %R%\Catalog\fmt-base.ini %R%\Catalog\fmt-dep.ini 2>nul
del /q %R%\Payload\fmt-base\fmt-base.txt %R%\Payload\fmt-dep\fmt-dep.txt 2>nul
rmdir %R%\Payload\fmt-base 2>nul
rmdir %R%\Payload\fmt-dep 2>nul
reg delete HKLM\SOFTWARE\ReactOS\Nitro\FmTest /f >nul 2>&1

if "%FAILS%"=="0" (echo ROUNDTRIP-RESULT: PASS>> %LOG%) else (echo ROUNDTRIP-RESULT: FAIL %FAILS% >> %LOG%)
goto :eof

:st
%FM% /state %1 > %O%\s.txt 2>&1
find "%2" %O%\s.txt >nul
if errorlevel 1 (call :fail %3 "state != %2") else (echo PASS %3>> %LOG%)
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
echo FAIL %~1 -- %~2>> %LOG%
set /a FAILS=%FAILS%+1
goto :eof

:cmdlnk
rem :cmdlnk <1|0> <name>: is there a Command Prompt shortcut on the common or the user's desktop?
set GOT=0
if exist "%CD%\Command Prompt.lnk" set GOT=1
if exist "%USERPROFILE%\Desktop\Command Prompt.lnk" set GOT=1
if "%GOT%"=="%1" (echo PASS %~2>> %LOG%) else (call :fail %2 "cmd shortcut=%GOT% want %1")
goto :eof
:wslnk
set GOT=0
if exist "%PM%\Windows System\Command Prompt.lnk" set GOT=1
if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Windows System\Command Prompt.lnk" set GOT=1
if "%GOT%"=="%1" (echo PASS %~2>> %LOG%) else (call :fail %2 "Windows System cmd=%GOT% want %1")
goto :eof
:ielnk
set GOT=0
if exist "%PM%\Wine Internet Explorer.lnk" set GOT=1
if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Wine Internet Explorer.lnk" set GOT=1
if "%GOT%"=="%1" (echo PASS %~2>> %LOG%) else (call :fail %2 "IE entry=%GOT% want %1")
goto :eof
:vsc
rem :vsc <fixture>: put vscode-settings\<fixture>.json in place as scoop's persisted settings.json, then a fresh
rem featmgr install of vscode through the stub
%FM% /uninstall vscode >nul 2>&1
mkdir %VSU% 2>nul
copy /y %FX%\vscode-settings\%1.json %VSJ% >nul
%FM% /install vscode >> %LOG% 2>&1
goto :eof
