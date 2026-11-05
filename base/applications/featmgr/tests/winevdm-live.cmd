@echo off
rem WineVDM through the feature manager (catalog entry winevdm, components.ini [winevdm], i386 only): a real download of the
rem official installer (needs internet), SHA-256 check, silent install into Program Files\otvdm, detection, the uninstall, and
rem that the RAPPS import does not list a second copy. Setup itself neither installs nor asks for it (checked by the attended
rem install test, not here). Result: %O%\winevdmlive.txt, last line WINEVDMLIVE-RESULT: PASS|FAIL n
setlocal
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set LOG=%O%\winevdmlive.txt
set FAILS=0
set VD=%ProgramFiles%\otvdm
mkdir %O% 2>nul
echo WineVDM featmgr live test %date% %time%> %LOG%

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

%FM% /query winevdm > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "Provider:     component" %O%\q.txt >nul
call :rc0 "V1 /query: component entry"
call :st winevdm NotInstalled "V2 NotInstalled before"
call :ex "%VD%\otvdm.exe" 0 "V3 not on disk before"

%FM% /install winevdm > %O%\i.txt 2>&1
call :rc0 "V4 featmgr install of WineVDM"
type %O%\i.txt >> %LOG%
call :st winevdm Enabled "V5 Enabled after the install"
call :ex "%VD%\otvdm.exe" 1 "V6 otvdm.exe is in place"
call :ex "%VD%\unins000.exe" 1 "V7 the uninstaller is in place"
dir /b "%SystemRoot%\Featmgr\Downloads\winevdm*" > %O%\dl.txt 2>&1
find "winevdm" %O%\dl.txt >nul
call :rc1 "V8 the downloaded installer is removed after the install"
%FM% /install winevdm > %O%\i2.txt 2>&1
call :rc0 "V9 a second install is a no-op"
type %O%\i2.txt >> %LOG%

rem the RAPPS catalog has a winevdm package too: the import hides it (this entry replaces it)
%FM% /update-catalog > %O%\uc.txt 2>&1
type %O%\uc.txt >> %LOG%
%FM% /query rapps-winevdm > %O%\qr.txt 2>&1
call :rc1 "V10 no second rapps-winevdm entry after Update catalog"

%FM% /uninstall winevdm > %O%\u.txt 2>&1
call :rc0 "V11 featmgr uninstall of WineVDM"
type %O%\u.txt >> %LOG%
call :st winevdm NotInstalled "V12 NotInstalled after the uninstall"
call :ex "%VD%\otvdm.exe" 0 "V13 otvdm.exe is gone"

%FM% /install winevdm > %O%\i3.txt 2>&1
call :rc0 "V14 installs again after an uninstall"
call :st winevdm Enabled "V15 Enabled again"
%FM% /uninstall winevdm > %O%\u2.txt 2>&1
call :rc0 "V16 final uninstall"
call :st winevdm NotInstalled "V17 NotInstalled at the end"

if "%FAILS%"=="0" (echo WINEVDMLIVE-RESULT: PASS>> %LOG%) else (echo WINEVDMLIVE-RESULT: FAIL %FAILS%>> %LOG%)
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
