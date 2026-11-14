@echo off
rem Downgrade guard of featmgr (fmt-lvpold = an "old Mesa pack" staged offline, catalog keys PackFileTime/GuardFiles/GuardMinSize).
rem Run in the guest on an image whose System32 carries the in-tree 26.3.0-dc2 Mesa DLLs. Result: %O%\lvpguard.txt
rem   FIXED : "already newer, skipped" in the output, the DLLs are byte-for-byte the same, exit code 0
rem   BASE  : the stand-in files replace the DLLs (a downgrade)
rem Usage: lavapipe-guard.cmd [fixture-dir]
setlocal
set FX=%~dp0fixtures
if not "%1"=="" set FX=%1
set FM=%SystemRoot%\system32\featmgr.exe
set R=%SystemRoot%\Featmgr
set O=%~dp0out
mkdir %O% 2>nul
set LOG=%O%\lvpguard.txt
echo LVPGUARD> %LOG%
mkdir %R%\Catalog 2>nul
mkdir %R%\Payload\fmt-lvpold 2>nul
copy /y %FX%\fmt-lvpold.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-lvpold-vulkan_lvp.dll.txt %R%\Payload\fmt-lvpold\vulkan_lvp.dll >nul
copy /y %FX%\fmt-lvpold-libgallium_wgl.dll.txt %R%\Payload\fmt-lvpold\libgallium_wgl.dll >nul

dir /-c /tw %SystemRoot%\System32\vulkan_lvp.dll %SystemRoot%\System32\libgallium_wgl.dll %SystemRoot%\SysWOW64\libgallium_wgl.dll > %O%\lvp-before.txt 2>&1
echo --- before>> %LOG%
type %O%\lvp-before.txt >> %LOG%
%FM% /install fmt-lvpold > %O%\lvp-install.txt 2>&1
echo --- featmgr /install fmt-lvpold: exit %ERRORLEVEL%>> %LOG%
type %O%\lvp-install.txt >> %LOG%
dir /-c /tw %SystemRoot%\System32\vulkan_lvp.dll %SystemRoot%\System32\libgallium_wgl.dll %SystemRoot%\SysWOW64\libgallium_wgl.dll > %O%\lvp-after.txt 2>&1
echo --- after>> %LOG%
type %O%\lvp-after.txt >> %LOG%

find "already newer, skipped" %O%\lvp-install.txt >nul
if errorlevel 1 (echo RESULT message-not-shown>> %LOG%) else (echo RESULT message-shown>> %LOG%)
rem the "bytes free" line of dir changes by itself: compare only the file lines
type %O%\lvp-before.txt | find ".dll" > %O%\lvp-b.txt
type %O%\lvp-after.txt | find ".dll" > %O%\lvp-a.txt
fc %O%\lvp-b.txt %O%\lvp-a.txt >nul
if errorlevel 1 (echo RESULT dlls-changed>> %LOG%) else (echo RESULT dlls-unchanged>> %LOG%)
if exist %SystemRoot%\System32\vulkan_lvp.dll.fmbak (echo RESULT backup-made>> %LOG%) else (echo RESULT no-backup>> %LOG%)

rem put the system back for a rerun (base: restores the originals from .fmbak)
%FM% /disable fmt-lvpold >nul 2>&1
echo LVPGUARD done>> %LOG%
