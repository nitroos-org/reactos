@echo off
rem FEATMGMT software tier: .NET Framework 4.8 live proof (i386 and amd64; needs internet).
rem   dotnet48-live.cmd install     negative checksum test, then install dotnet-framework-4.8 and check it
rem   dotnet48-live.cmd run [DIR]   run the managed test programs in DIR (default %~dp0managed): hello32.exe, helloany.exe,
rem                                 wf32.exe, hello.cs (compiled with the Framework's csc) and on amd64 hello64.exe, wf64.exe
rem   dotnet48-live.cmd uninstall   uninstall dotnet-framework-4.8 and check it is gone
rem Run from a directory holding fixtures\fmt-net48bad.ini (default: this script's
rem directory). The programs are small C# programs built with the Framework's csc (hello: prints, exits 42; wf: a WinForms
rem form that closes itself and exits 7; both write their progress to the file named on the command line).
rem Result: %O%\net48live.txt, last line NET48LIVE-RESULT: PASS|FAIL n
setlocal
set FX=%~dp0fixtures
set FM=%SystemRoot%\system32\featmgr.exe
set R=%SystemRoot%\Featmgr
set O=C:\harness\out
set NDPKEY=HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
set FW=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319
set LOG=%O%\net48live.txt
set FAILS=0
mkdir %O% 2>nul
echo .NET Framework 4.8 live test %1 %date% %time%>> %LOG%

if /i "%1"=="run" goto :runprogs
if /i "%1"=="uninstall" goto :uninst

rem the guest needs its DHCP lease before the first download
set N=0
:netwait
ping -n 1 -w 1000 download.microsoft.com 2>&1 | find "Reply from" >nul
if not errorlevel 1 goto netup
set /a N+=1
if %N% GEQ 120 goto netup
ping -n 3 127.0.0.1 >nul
goto netwait
:netup
echo network wait: %N% tries>> %LOG%

%FM% /list > %O%\l.txt 2>&1
find "dotnet-framework-4.8" %O%\l.txt >nul
call :rc0 "I1 dotnet-framework-4.8 listed by /list"
%FM% /query dotnet-framework-4.8 > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "ArtifactSHA256: " %O%\q.txt >nul
call :rc0 "I2 manifest pins a SHA-256"
find "Dependencies: ." %O%\q.txt >nul
call :rc1 "I3 manifest has no dependencies"
call :st dotnet-framework-4.8 NotInstalled "I4 NotInstalled before the install"
reg query "%NDPKEY%" /v Release >nul 2>&1
call :rc1 "I5 no .NET 4.x Release key before the install"

rem --- wrong SHA-256 must be refused after the download: nothing installed, no record
copy /y %FX%\fmt-net48bad.ini %R%\Catalog\ >nul
%FM% /install fmt-net48bad > %O%\bad.txt 2>&1
call :rc1 "I6 install with a wrong SHA-256 fails"
type %O%\bad.txt >> %LOG%
reg query "%NDPKEY%" /v Release >nul 2>&1
call :rc1 "I7 nothing installed after the checksum failure"
call :st fmt-net48bad NotInstalled "I8 wrong-hash entry left NotInstalled"
del /q %R%\Catalog\fmt-net48bad.ini 2>nul

rem --- the real install (the installer is given the Windows 7 SP1 answer by the compatibility database; no layer is set here)
set __COMPAT_LAYER=
echo install start %time%>> %LOG%
%FM% /install dotnet-framework-4.8 > %O%\install.txt 2>&1
set IRC=%errorlevel%
echo install end %time% rc=%IRC%>> %LOG%
type %O%\install.txt >> %LOG%
if "%IRC%"=="0" (call :pass "I9 featmgr /install dotnet-framework-4.8 rc0") else (call :fail "I9 featmgr /install dotnet-framework-4.8 rc0")
call :st dotnet-framework-4.8 Enabled "I10 Enabled after install"
set REL=
for /f "tokens=3" %%a in ('reg query "%NDPKEY%" /v Release 2^>nul ^| find "Release"') do set REL=%%a
echo Release=%REL%>> %LOG%
if "%REL%"=="" (call :fail "I11 Release key present") else (call :relchk)
if exist %FW%\csc.exe (call :pass "I12 csc.exe installed") else (call :fail "I12 csc.exe installed")
if exist %FW%\clr.dll (call :pass "I13 clr.dll installed") else (call :fail "I13 clr.dll installed")
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
  if exist %SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\clr.dll (call :pass "I14 64-bit clr.dll installed") else (call :fail "I14 64-bit clr.dll installed")
)
goto :end

:relchk
set /a RELN=%REL%
if %RELN% GEQ 528040 (call :pass "I11 Release key %REL% is 4.8 or later") else (call :fail "I11 Release key %REL% is 4.8 or later")
goto :eof

:runprogs
set D=%2
if "%D%"=="" set D=%~dp0managed
cd /d %D%
set RT=%D%\runto32.exe
%RT% %O%\h32.rt.txt 90 %D%\hello32.exe %O%\h32.out.txt > %O%\h32.stdout.txt 2>&1
call :rcis 42 "R1 hello32 exits 42"
type %O%\h32.stdout.txt >> %LOG%
%RT% %O%\hany.rt.txt 90 %D%\helloany.exe %O%\hany.out.txt > %O%\hany.stdout.txt 2>&1
call :rcis 42 "R2 helloany exits 42"
%RT% %O%\wf32.rt.txt 120 %D%\wf32.exe %O%\wf32.out.txt > %O%\wf32.stdout.txt 2>&1
call :rcis 7 "R3 WinForms (32-bit) shows its form and exits 7"
type %O%\wf32.out.txt >> %LOG%
%RT% %O%\csc.rt.txt 180 %FW%\csc.exe /nologo /out:%O%\h2.exe %D%\hello.cs > %O%\csc.stdout.txt 2>&1
call :rcis 0 "R4 csc.exe compiles hello.cs"
type %O%\csc.stdout.txt >> %LOG%
%RT% %O%\h2.rt.txt 90 %O%\h2.exe %O%\h2.out.txt > %O%\h2.stdout.txt 2>&1
call :rcis 42 "R5 the program csc built runs and exits 42"
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
  %RT% %O%\h64.rt.txt 90 %D%\hello64.exe %O%\h64.out.txt > %O%\h64.stdout.txt 2>&1
  call :rcis 42 "R6 hello64 (native x64) exits 42"
  %RT% %O%\wf64.rt.txt 120 %D%\wf64.exe %O%\wf64.out.txt > %O%\wf64.stdout.txt 2>&1
  call :rcis 7 "R7 WinForms (native x64) shows its form and exits 7"
)
goto :end

:uninst
set __COMPAT_LAYER=
%FM% /uninstall dotnet-framework-4.8 > %O%\un.txt 2>&1
call :rc0 "U1 featmgr /uninstall dotnet-framework-4.8 rc0"
type %O%\un.txt >> %LOG%
call :st dotnet-framework-4.8 NotInstalled "U2 NotInstalled after uninstall"
reg query "%NDPKEY%" /v Release >nul 2>&1
call :rc1 "U3 Release key removed"
if exist %FW%\csc.exe (call :fail "U4 csc.exe removed") else (call :pass "U4 csc.exe removed")
goto :end

:end
if "%FAILS%"=="0" (echo NET48LIVE-RESULT: PASS>> %LOG%) else (echo NET48LIVE-RESULT: FAIL %FAILS%>> %LOG%)
goto :eof

:st
%FM% /state %1 > %O%\s.txt 2>&1
find "%2" %O%\s.txt >nul
if errorlevel 1 (call :fail %3) else (call :pass %3)
goto :eof

:rcis
set RC=%errorlevel%
if "%RC%"=="%1" (call :pass %2) else (call :fail "%~2 (got %RC%)")
goto :eof

:rc0
if errorlevel 1 (call :fail %1) else (call :pass %1)
goto :eof

:rc1
if errorlevel 1 (call :pass %1) else (call :fail %1)
goto :eof

:pass
echo PASS %~1 >> %LOG%
goto :eof

:fail
echo FAIL %~1 >> %LOG%
set /a FAILS+=1
goto :eof
