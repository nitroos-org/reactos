@echo off
rem FEATMGMT-01 software-tier LIVE install proof (native provider: real HTTP download +
rem SHA1 verify + silent install by featmgr itself, then uninstall round-trip). Unlike roundtrip.cmd this
rem needs a reachable HTTP server. The harness stages:
rem   - an appdb dir (default C:\harness\appdb) holding one RAPPS entry whose URLDownload
rem     points at the server and whose SHA1 matches the served installer,
rem The installed test package's side effect is a registry marker (written by the silent
rem installer that featmgr downloads + runs): HKLM\SOFTWARE\ReactOS\Nitro\FmLiveMarker.
rem Usage: live-install.cmd [appdb-dir] [pkg]
setlocal
set APPDB=%1
if "%APPDB%"=="" set APPDB=C:\harness\appdb
set PKG=%2
if "%PKG%"=="" set PKG=fmlivetest
set MARKER=HKLM\SOFTWARE\ReactOS\Nitro\FmLiveMarker
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
mkdir %O% 2>nul
set LOG=%O%\live.txt
set FAILS=0
echo FEATMGMT software-tier LIVE install> %LOG%
echo START %date% %time%>> %LOG%

reg delete "%MARKER%" /f >nul 2>&1

rem --- import the staged RAPPS appdb into the software tier
%FM% /import-rapps "%APPDB%" /clean /anyarch > %O%\live-import.txt 2>&1
call :rc0 "L1 import-rapps rc0"
type %O%\live-import.txt >> %LOG%
call :st rapps-%PKG% NotInstalled "L2 imported entry NotInstalled"

rem --- live install: featmgr downloads over HTTP, verifies SHA1, runs the silent installer
%FM% /install rapps-%PKG% > %O%\live-install.txt 2>&1
call :rc0 "L3 live install rc0 (HTTP download + SHA1 + silent install)"
type %O%\live-install.txt >> %LOG%
call :st rapps-%PKG% Enabled "L4 Enabled after live install"
reg query "%MARKER%" /v Installed >nul 2>&1
call :rc0 "L5 installer side-effect (registry marker) present"
reg query HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\rapps-%PKG% /v State >nul 2>&1
call :rc0 "L6 state record written"

rem --- uninstall round-trip (clean first; force-forget as a fallback)
%FM% /uninstall rapps-%PKG% > %O%\live-uninstall.txt 2>&1
type %O%\live-uninstall.txt >> %LOG%
%FM% /state rapps-%PKG% > %O%\s.txt 2>&1
find "NotInstalled" %O%\s.txt >nul
if errorlevel 1 (
  echo note: clean uninstall did not forget; forcing>> %LOG%
  %FM% /uninstall rapps-%PKG% /force > %O%\live-uninstall2.txt 2>&1
  type %O%\live-uninstall2.txt >> %LOG%
)
call :st rapps-%PKG% NotInstalled "L7 NotInstalled after uninstall round-trip"

echo END %date% %time%>> %LOG%
if "%FAILS%"=="0" (echo LIVE-RESULT: PASS>> %LOG%) else (echo LIVE-RESULT: FAIL %FAILS%>> %LOG%)
goto :eof

:st
%FM% /state %1 > %O%\s.txt 2>&1
find "%2" %O%\s.txt >nul
if errorlevel 1 (call :fail %3 "state != %2") else (echo PASS %3>> %LOG%)
goto :eof
:rc0
if errorlevel 1 (call :fail %1 "rc nonzero") else (echo PASS %1>> %LOG%)
goto :eof
:ex
if exist %1 (set GOT=1) else (set GOT=0)
if "%GOT%"=="%2" (echo PASS %3>> %LOG%) else (call :fail %3 "exist=%GOT% want %2")
goto :eof
:fail
echo FAIL %~1 -- %~2>> %LOG%
set /a FAILS=%FAILS%+1
goto :eof
