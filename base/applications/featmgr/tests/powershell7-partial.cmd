@echo off
rem A half PowerShell 7 (the MSI cut in the middle: pwsh.exe on the disk, the product not registered) is not "enabled".
rem amd64 only (the catalog entry is). Two cases:
rem - PowerShell 7 is installed (the default amd64 image): its Uninstall key is moved away and back, pwsh.exe renamed and back;
rem - it is not installed: pwsh.exe and the Uninstall entry "PowerShell 7-x64" are made up here.
rem Rows: installed -> Enabled; pwsh.exe without the registered product -> NotInstalled; with it -> Enabled; the registered
rem product without pwsh.exe -> NotInstalled. Everything changed here is put back.
rem Result: %O%\ps7partial.txt, last line PS7PARTIAL-RESULT: PASS|FAIL n
setlocal
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set LOG=%O%\ps7partial.txt
set FAILS=0
set D=%ProgramFiles%\PowerShell\7
set UNINST=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
set K=%UNINST%\RosPs7PartialTest
set SAVE=HKLM\SOFTWARE\RosPs7PartialSave
set REAL=0
if exist "%D%\pwsh.exe" set REAL=1
mkdir %O% 2>nul
echo PowerShell 7 partial install detection %date% %time% (installed: %REAL%)> %LOG%

if "%REAL%"=="1" goto :real

call :clean
call :st NotInstalled "P1 nothing installed"
mkdir "%D%" 2>nul
echo x> "%D%\pwsh.exe"
call :st NotInstalled "P2 pwsh.exe without the registered product"
reg add %K% /v DisplayName /d "PowerShell 7-x64" /f > nul
call :st Enabled "P3 pwsh.exe and the registered product"
del "%D%\pwsh.exe"
call :st NotInstalled "P4 the registered product without pwsh.exe"
call :clean
goto :done

:real
set PK=
for /f "delims=" %%k in ('reg query %UNINST% 2^>nul') do call :chk "%%k"
if "%PK%"=="" (echo FAIL R0 no Uninstall key with DisplayName "PowerShell 7-x64">> %LOG% & set /a FAILS+=1 & goto :done)
call :st Enabled "R1 installed and registered"
reg copy "%PK%" %SAVE% /s /f > nul
reg delete "%PK%" /f > nul
call :st NotInstalled "R2 pwsh.exe without the registered product"
reg copy %SAVE% "%PK%" /s /f > nul
reg delete %SAVE% /f > nul
call :st Enabled "R3 registered again"
ren "%D%\pwsh.exe" pwsh.exe.save
call :st NotInstalled "R4 the registered product without pwsh.exe"
ren "%D%\pwsh.exe.save" pwsh.exe
call :st Enabled "R5 pwsh.exe back"

:done
echo.>> %LOG%
if "%FAILS%"=="0" (echo PS7PARTIAL-RESULT: PASS>> %LOG%) else (echo PS7PARTIAL-RESULT: FAIL %FAILS% >> %LOG%)
type %LOG%
exit /b %FAILS%

:chk
reg query %1 /v DisplayName 2>nul | find /i "PowerShell 7-x64" > nul
if not errorlevel 1 set PK=%~1
exit /b 0

:clean
reg delete %K% /f > nul 2>&1
del "%D%\pwsh.exe" > nul 2>&1
rmdir "%D%" > nul 2>&1
rmdir "%ProgramFiles%\PowerShell" > nul 2>&1
exit /b 0

:st
set S=
for /f "delims=" %%a in ('%FM% /state powershell-7 2^>^&1') do set S=%%a
if /i "%S%"=="%~1" (echo PASS %~2 [%S%]>> %LOG%) else (echo FAIL %~2: expected %~1, got [%S%]>> %LOG% & set /a FAILS+=1)
exit /b 0
