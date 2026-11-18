@echo off
rem [Service] account + [Hooks] Enable/Disable + [Source] HideOnOtherArch (in-guest, offline fixtures). Result: %O%\hooktest.txt
rem Usage: hooks.cmd [fixture-dir]   (default: directory of this script)
setlocal
set FX=%~dp0fixtures
if not "%1"=="" set FX=%1
set FM=%SystemRoot%\system32\featmgr.exe
set R=%SystemRoot%\Featmgr
set O=%~dp0out
mkdir %O% 2>nul
set LOG=%O%\hooktest.txt
set FAILS=0
echo FEATMGMT hooks> %LOG%
mkdir %R%\Catalog 2>nul
mkdir %R%\Payload\fmt-hook 2>nul
mkdir %R%\Payload\fmt-hookfail 2>nul
copy /y %FX%\fmt-hook.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-hookfail.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-hide.ini %R%\Catalog\ >nul
copy /y %FX%\fmt-hook.cmd %R%\Payload\fmt-hook\ >nul
copy /y %FX%\fmt-hook.cmd %R%\Payload\fmt-hookfail\ >nul
del %R%\fmt-hook.log %R%\fmt-hookfail.log 2>nul

rem --- a service with an account, and the Enable hook
%FM% /enable fmt-hook >> %LOG% 2>&1
call :rc0 "H1 enable fmt-hook: a service with an account and hooks"
find "enable" %R%\fmt-hook.log >nul
call :rc0 "H2 the Enable hook ran, after the payload file was placed"
sc qc FmtHookSvc > %O%\qc.txt 2>&1
type %O%\qc.txt >> %LOG%
find "LocalService" %O%\qc.txt >nul
call :rc0 "H3 the service runs as NT AUTHORITY\LocalService"
find "DEMAND_START" %O%\qc.txt >nul
call :rc0 "H4 and is demand start: nothing started it"
%FM% /state fmt-hook > %O%\s.txt 2>&1
find "Enabled" %O%\s.txt >nul
call :rc0 "H5 state Enabled"
%FM% /disable fmt-hook >> %LOG% 2>&1
call :rc0 "H6 disable fmt-hook"
find "disable" %R%\fmt-hook.log >nul
call :rc0 "H7 the Disable hook ran"
rem the SCM keeps a deleted service queryable for minutes (plain "sc delete" does the same, not featmgr's doing): check what featmgr did
find "service: deleting FmtHookSvc" %LOG% >nul
call :rc0 "H8 disable deleted the service it created"
if exist %R%\fmt-hook.cmd (call :fail "H9 payload file removed" "still there") else (echo PASS H9 payload file removed>> %LOG%)

rem --- a failing Enable hook rolls everything back and runs Disable once
%FM% /enable fmt-hookfail >> %LOG% 2>&1
call :rc1 "H10 enable fails when the Enable hook exits with 3"
%FM% /state fmt-hookfail > %O%\s.txt 2>&1
find "Enabled" %O%\s.txt >nul
call :rc1 "H11 the feature is not enabled"
find "service: deleting FmtHookFail" %LOG% >nul
call :rc0 "H12 the rollback deleted its service"
if exist %R%\fmt-hookfail.out (call :fail "H13 payload file rolled back" "still there") else (echo PASS H13 payload file rolled back>> %LOG%)
reg query HKLM\SOFTWARE\ReactOS\Nitro\FmTest /v HookFail >nul 2>&1
call :rc1 "H14 its registry value was rolled back"
if exist %R%\fmt-hookfail.log (echo PASS H15 the Disable hook ran once for the rollback>> %LOG%) else (call :fail "H15 Disable hook on rollback" "log missing")

rem --- HideOnOtherArch: an x86-only entry is listed on x86 and not listed elsewhere
%FM% /list > %O%\l.txt 2>&1
find "fmt-hide" %O%\l.txt >nul
if /i "%PROCESSOR_ARCHITECTURE%"=="x86" (if not defined PROCESSOR_ARCHITEW6432 (call :rc0 "H16 x86: the x86-only entry is listed" & goto :hidden))
call :rc1 "H16 not x86: the x86-only entry is hidden from /list"
:hidden

rem cleanup
%FM% /disable fmt-hook >nul 2>&1
del %R%\Catalog\fmt-hook.ini %R%\Catalog\fmt-hookfail.ini %R%\Catalog\fmt-hide.ini 2>nul
rmdir /s /q %R%\Payload\fmt-hook %R%\Payload\fmt-hookfail 2>nul
echo DONE hooks fails=%FAILS% >> %LOG%
exit /b %FAILS%

:rc0
if errorlevel 1 (call :fail %1 "rc nonzero") else (echo PASS %~1 >> %LOG%)
goto :eof
:rc1
if errorlevel 1 (echo PASS %~1 >> %LOG%) else (call :fail %1 "rc zero, wanted failure")
goto :eof
:gone
rem :gone <service> <label>: the SCM removes a deleted service a little later; wait up to 60 s for it to disappear (the SCM drops a deleted service only after a while)
set /a TRIES=0
:gone1
sc qc %1 >nul 2>&1
if errorlevel 1 (echo PASS %~2 >> %LOG% & goto :eof)
set /a TRIES=%TRIES%+1
if %TRIES% geq 60 (call :fail %2 "still registered after 60 s" & goto :eof)
ping -n 2 127.0.0.1 >nul
goto :gone1
:fail
echo FAIL %~1 -- %~2>> %LOG%
set /a FAILS=%FAILS%+1
goto :eof
