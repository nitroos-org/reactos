@echo off
rem Component provider (Provider=component, catalog\components.ini): download over https, SHA-256 check, detect rule,
rem install line, uninstall line. Needs internet (a small pinned GitHub file). Run from a directory holding fixtures\fmt-comp*.
rem Result: %O%\complive.txt, last line COMPLIVE-RESULT: PASS|FAIL n
setlocal
set FX=%~dp0fixtures
set FM=%SystemRoot%\system32\featmgr.exe
set R=%SystemRoot%\Featmgr
set O=C:\harness\out
set LOG=%O%\complive.txt
set FAILS=0
mkdir %O% 2>nul
echo component provider live test %date% %time%> %LOG%

rem the guest needs its DHCP lease before the first download
set N=0
:netwait
ping -n 1 -w 1000 raw.githubusercontent.com 2>&1 | find "Reply from" >nul
if not errorlevel 1 goto netup
set /a N+=1
if %N% GEQ 120 goto netup
ping -n 3 127.0.0.1 >nul
goto netwait
:netup
echo network wait: %N% tries>> %LOG%

for %%i in (fmt-comp fmt-compbad fmt-comphttp fmt-compnosha fmt-compreg fmt-compchain fmt-compchainbad) do copy /y %FX%\%%i.ini %R%\Catalog\ >nul
set FEATMGR_COMPONENTS=%FX%\fmt-comp.components.ini

%FM% /query fmt-comp > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "Provider:     component" %O%\q.txt >nul
call :rc0 "C1 /query shows Provider component"
find "Source.ArtifactSHA256: 94f983b1" %O%\q.txt >nul
call :rc0 "C2 /query shows the SHA-256 of the component list"
call :st fmt-comp NotInstalled "C3 NotInstalled before"

%FM% /install fmt-comp > %O%\i.txt 2>&1
call :rc0 "C4 install of the component (download, verify, install line)"
type %O%\i.txt >> %LOG%
call :st fmt-comp Enabled "C5 Enabled after the install"
call :ex %R%\fmt-comp.out 1 "C6 the install line ran with the downloaded file"
call :ex %R%\Downloads\fmt-comp.ps1 0 "C7 the download is removed after a successful install"
call :ex %R%\Downloads\fmt-comp.ps1.part 0 "C8 no partial file"

%FM% /uninstall fmt-comp > %O%\u.txt 2>&1
call :rc0 "C9 uninstall runs the Uninstall line"
call :ex %R%\fmt-comp.out 0 "C10 the uninstall line removed the file"
call :st fmt-comp NotInstalled "C11 NotInstalled after the uninstall"

%FM% /install fmt-compbad > %O%\bad.txt 2>&1
call :rc1 "C12 a wrong SHA-256 is refused"
type %O%\bad.txt >> %LOG%
find "checksum" %O%\bad.txt >nul
call :rc0 "C13 the message names the checksum"
call :ex %R%\fmt-compbad.out 0 "C14 the install line did not run"
call :ex %R%\Downloads\fmt-compbad.ps1 0 "C15 the mismatching file was deleted"
call :ex %R%\Downloads\fmt-compbad.ps1.part 0 "C16 no partial file"
call :st fmt-compbad NotInstalled "C17 left NotInstalled"

%FM% /install fmt-comphttp > %O%\http.txt 2>&1
call :rc1 "C18 a plain http address is refused"
find "https" %O%\http.txt >nul
call :rc0 "C19 the message says https"
%FM% /install fmt-compnosha > %O%\nosha.txt 2>&1
call :rc1 "C20 a component without a SHA-256 is refused"
call :st fmt-compnosha NotInstalled "C21 left NotInstalled"

call :st fmt-compreg NotInstalled "C22 detect rule not met: NotInstalled"
reg add HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v CompDetect /t REG_DWORD /d 7 /f >nul
call :st fmt-compreg Enabled "C23 detect rule met (DWORD 7 >= 5): Enabled without a record"
reg add HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v CompDetect /t REG_DWORD /d 3 /f >nul
call :st fmt-compreg NotInstalled "C24 detect rule not met again (3 < 5)"
reg delete HKLM\SOFTWARE\ReactOS\Nitro\FmTest /f >nul 2>&1

rem ===== multi-package component (Also=): every package installs, a package already there is kept, a failing later package rolls back =====
call :st fmt-compchain NotInstalled "C25 chain: NotInstalled before"
%FM% /install fmt-compchain > %O%\ch1.txt 2>&1
call :rc0 "C26 chain: install of both packages"
type %O%\ch1.txt >> %LOG%
call :ex %R%\fmt-chainA.out 1 "C27 chain: package A installed"
call :ex %R%\fmt-chainB.out 1 "C28 chain: package B installed"
call :st fmt-compchain Enabled "C29 chain: Enabled when both are there"
%FM% /uninstall fmt-compchain > %O%\ch2.txt 2>&1
call :rc0 "C30 chain: uninstall runs both uninstall lines"
call :ex %R%\fmt-chainA.out 0 "C31 chain: package A removed"
call :ex %R%\fmt-chainB.out 0 "C32 chain: package B removed"
call :st fmt-compchain NotInstalled "C33 chain: NotInstalled after the uninstall"
echo keep> %R%\fmt-chainA.out
call :st fmt-compchain NotInstalled "C34 chain: only package A there is not installed"
%FM% /install fmt-compchain > %O%\ch3.txt 2>&1
call :rc0 "C35 chain: install completes the missing package"
type %O%\ch3.txt >> %LOG%
call :ex %R%\fmt-chainB.out 1 "C36 chain: package B installed"
find "keep" %R%\fmt-chainA.out >nul
call :rc0 "C37 chain: the package that was already there was not installed again"
call :st fmt-compchain Enabled "C38 chain: Enabled"
reg delete "HKLM\SOFTWARE\ReactOS\Nitro\OptionalFeatures\fmt-compchain" /f >nul 2>&1
%FM% /uninstall fmt-compchain > %O%\ch4.txt 2>&1
call :rc0 "C39 chain: uninstall without a recorded line derives both from the list"
call :ex %R%\fmt-chainA.out 0 "C40 chain: package A removed (derived line)"
call :ex %R%\fmt-chainB.out 0 "C41 chain: package B removed (derived line)"
%FM% /install fmt-compchainbad > %O%\chb.txt 2>&1
call :rc1 "C42 chain: a failing second package fails the install"
type %O%\chb.txt >> %LOG%
call :ex %R%\fmt-chainbadA.out 0 "C43 chain: the first package was rolled back"
call :ex %R%\fmt-chainbadB.out 0 "C44 chain: the failing package did not install"
call :st fmt-compchainbad NotInstalled "C45 chain: left NotInstalled"

set FEATMGR_COMPONENTS=
for %%i in (fmt-comp fmt-compbad fmt-comphttp fmt-compnosha fmt-compreg fmt-compchain fmt-compchainbad) do del /q %R%\Catalog\%%i.ini 2>nul
if "%FAILS%"=="0" (echo COMPLIVE-RESULT: PASS>> %LOG%) else (echo COMPLIVE-RESULT: FAIL %FAILS%>> %LOG%)
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
