@echo off
rem Wine Gecko through the feature manager (catalog entry wine-gecko, components.ini [wine-gecko] + [wine-gecko-x64]): a real
rem download of the official MSI packages (needs internet), SHA-256 check, silent install into System32 (and SysWOW64 on a 64-bit
rem system), an mshtml consumer that renders afterwards, the uninstall, and the two-way visibility with the appwiz.cpl add-on path.
rem Run from a directory holding mshtmlrender32.exe (and mshtmlrender64.exe on amd64); for the appwiz step also gm\wine_gecko-2.40-<arch>.msi
rem (not in git: the harness stages it). Result: %O%\geckolive.txt, last line GECKOLIVE-RESULT: PASS|FAIL n
setlocal
set H=%~dp0
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set LOG=%O%\geckolive.txt
set FAILS=0
set WOW=0
if exist "%SystemRoot%\SysWOW64\kernel32.dll" set WOW=1
set G64=%SystemRoot%\System32\gecko\2.40\wine_gecko\xul.dll
set G32=%SystemRoot%\System32\gecko\2.40\wine_gecko\xul.dll
if "%WOW%"=="1" set G32=%SystemRoot%\SysWOW64\gecko\2.40\wine_gecko\xul.dll
mkdir %O% 2>nul
echo Wine Gecko featmgr live test %date% %time% (WOW=%WOW%)> %LOG%

set N=0
:netwait
ping -n 1 -w 1000 10.0.2.2 2>&1 | find "Reply from" >nul
if not errorlevel 1 goto netup
set /a N+=1
if %N% GEQ 90 goto netup
ping -n 3 127.0.0.1 >nul
goto netwait
:netup
echo network wait: %N% tries>> %LOG%

%FM% /query wine-gecko > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "Provider:     component" %O%\q.txt >nul
call :rc0 "G1 /query: component entry"
call :st wine-gecko NotInstalled "G2 NotInstalled before"
call :renderall 1 "G3 mshtml cannot render without Gecko"

%FM% /install wine-gecko > %O%\i.txt 2>&1
call :rc0 "G4 featmgr install of Wine Gecko"
type %O%\i.txt >> %LOG%
call :st wine-gecko Enabled "G5 Enabled after the install"
call :ex %G32% 1 "G6 the 32-bit engine is in place (xul.dll)"
if "%WOW%"=="1" call :ex %G64% 1 "G7 the 64-bit engine is in place (xul.dll)"
%SystemRoot%\system32\reg.exe query HKLM\Software\Wine\MSHTML\2.40 /v GeckoPath > %O%\reg64.txt 2>&1
type %O%\reg64.txt >> %LOG%
find "GeckoPath" %O%\reg64.txt >nul
call :rc0 "G8 GeckoPath is registered (native registry view)"
if exist "%SystemRoot%\SysWOW64\reg.exe" (
  %SystemRoot%\SysWOW64\reg.exe query HKLM\Software\Wine\MSHTML\2.40 /v GeckoPath > %O%\reg32.txt 2>&1
  type %O%\reg32.txt >> %LOG%
  find "GeckoPath" %O%\reg32.txt >nul
  call :rc0 "G9 GeckoPath is registered (32-bit registry view)"
)
call :renderall 0 "G10 mshtml renders a page and runs its script"
dir /b "%SystemRoot%\Featmgr\Downloads\wine_gecko*" > %O%\dl.txt 2>&1
find "wine_gecko" %O%\dl.txt >nul
call :rc1 "G11 the downloaded MSI files are removed after the install"
%FM% /install wine-gecko > %O%\i2.txt 2>&1
call :rc0 "G12 a second install is a no-op"
type %O%\i2.txt >> %LOG%

%FM% /uninstall wine-gecko > %O%\u.txt 2>&1
call :rc0 "G13 featmgr uninstall of Wine Gecko"
type %O%\u.txt >> %LOG%
call :st wine-gecko NotInstalled "G14 NotInstalled after the uninstall"
call :ex %G32% 0 "G15 the 32-bit engine is gone"
if "%WOW%"=="1" call :ex %G64% 0 "G16 the 64-bit engine is gone"
%SystemRoot%\system32\reg.exe query HKLM\Software\Wine\MSHTML\2.40 /v GeckoPath > %O%\reg64b.txt 2>&1
find "GeckoPath" %O%\reg64b.txt >nul
call :rc1 "G17 GeckoPath is gone"
if exist "%SystemRoot%\SysWOW64\reg.exe" (
  %SystemRoot%\SysWOW64\reg.exe query HKLM\Software\Wine\MSHTML\2.40 /v GeckoPath > %O%\reg32b.txt 2>&1
  find "GeckoPath" %O%\reg32b.txt >nul
  call :rc1 "G17b GeckoPath is gone (32-bit registry view)"
)
call :ex %SystemRoot%\System32\gecko\2.40 0 "G17c the 64-bit engine folder is gone"
if "%WOW%"=="1" call :ex %SystemRoot%\SysWOW64\gecko\2.40 0 "G17d the 32-bit engine folder is gone"
call :renderall 1 "G18 mshtml cannot render again"

rem ----- the other way: the appwiz.cpl add-on path (GeckoCabDir points at the staged MSI, no dialog) installs, featmgr sees it -----
if not exist "%H%gm" goto noappwiz
set GKEY=HKCU\Software\Wine\MSHTML
reg add %GKEY% /v GeckoCabDir /t REG_SZ /d "%H%gm" /f >nul
start /wait rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl,,install_gecko
reg delete %GKEY% /v GeckoCabDir /f >nul 2>&1
if "%WOW%"=="1" goto appwiz64
call :st wine-gecko Enabled "G19 installed by appwiz.cpl: featmgr sees it Enabled (i386)"
call :renderall 0 "G20 mshtml renders after the appwiz install"
%FM% /uninstall wine-gecko > %O%\u2.txt 2>&1
call :rc0 "G21 featmgr removes what appwiz installed (no record: lines derived from the list)"
type %O%\u2.txt >> %LOG%
call :st wine-gecko NotInstalled "G22 NotInstalled after that"
call :ex %G32% 0 "G23 the engine is gone"
goto appwizdone
:appwiz64
call :ex %G64% 1 "G19 appwiz.cpl installed the 64-bit engine"
call :ex %G32% 0 "G20 ...and not the 32-bit one"
call :st wine-gecko NotInstalled "G21 only the 64-bit engine there: featmgr says not installed (the 32-bit programs have none)"
%FM% /install wine-gecko > %O%\i3.txt 2>&1
call :rc0 "G22 featmgr install completes the missing 32-bit package"
type %O%\i3.txt >> %LOG%
find "skipping its package" %O%\i3.txt >nul
call :rc0 "G23 ...and skips the package appwiz installed"
call :st wine-gecko Enabled "G24 Enabled"
call :renderall 0 "G25 both mshtml flavours render"
%FM% /uninstall wine-gecko > %O%\u2.txt 2>&1
call :rc0 "G26 featmgr uninstall removes both"
type %O%\u2.txt >> %LOG%
call :ex %G32% 0 "G27 the 32-bit engine is gone"
call :ex %G64% 0 "G28 the 64-bit engine is gone"
call :st wine-gecko NotInstalled "G29 NotInstalled"
:appwizdone
goto done
:noappwiz
echo SKIP appwiz step: no gm\ folder with the staged MSI>> %LOG%
:done
if "%FAILS%"=="0" (echo GECKOLIVE-RESULT: PASS>> %LOG%) else (echo GECKOLIVE-RESULT: FAIL %FAILS%>> %LOG%)
goto :eof

:renderall
rem :renderall <want-fail 1|0> <label>: the 32-bit renderer, and on a 64-bit system the 64-bit one too
set LBL=%~2
if exist "%H%mshtmlrender32.exe" (
  "%H%mshtmlrender32.exe" %O%\r32.txt
  call :judge %1 32
)
if "%WOW%"=="1" (
  "%H%mshtmlrender64.exe" %O%\r64.txt
  call :judge %1 64
)
goto :eof
:judge
set RC=%errorlevel%
type %O%\r%2.txt >> %LOG%
if "%1"=="0" (if "%RC%"=="0" (echo PASS %LBL% [x%2]>> %LOG%) else (call :fail "%LBL% [x%2]" "renderer rc=%RC%"))
if "%1"=="1" (if "%RC%"=="0" (call :fail "%LBL% [x%2]" "rendered without Gecko") else (echo PASS %LBL% [x%2]>> %LOG%))
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
