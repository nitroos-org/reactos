@echo off
rem FEATMGMT software tier: OpenSSH Client live proof (i386 and amd64; needs internet and a NIC).
rem   openssh-live.cmd install     install openssh-client, check files, PATH, ssh -V, nothing of the server
rem   openssh-live.cmd uninstall   uninstall it and check that exactly that is gone (a user file in the folder survives)
rem Result: %O%\sshlive.txt, last line SSHLIVE-RESULT: PASS|FAIL n.
rem The PATH before the install is saved in %O%\path-before.txt and compared after the uninstall.
setlocal
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set D=%SystemRoot%\System32\OpenSSH
set ENVKEY=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
set LOG=%O%\sshlive.txt
set FAILS=0
mkdir %O% 2>nul
echo OpenSSH client live test %1 %date% %time%>> %LOG%

rem the guest needs its DHCP lease before the download
set N=0
:netwait
ping -n 1 -w 1000 github.com 2>&1 | find "Reply from" >nul
if not errorlevel 1 goto netup
set /a N+=1
if %N% GEQ 120 goto netup
ping -n 3 127.0.0.1 >nul
goto netwait
:netup
echo network wait: %N% tries>> %LOG%

if /i "%1"=="uninstall" goto :uninst

%FM% /list > %O%\l.txt 2>&1
find "openssh-client" %O%\l.txt >nul
call :rc0 "I1 openssh-client listed by /list"
call :st openssh-client NotInstalled "I2 NotInstalled before the install"
if exist "%D%" (call :fail "I3 no OpenSSH folder before the install") else (call :pass "I3 no OpenSSH folder before the install")
reg query "%ENVKEY%" /v Path > %O%\path-before.txt 2>&1

%FM% /install openssh-client > %O%\install.txt 2>&1
call :rc0 "I4 featmgr /install openssh-client rc0"
type %O%\install.txt >> %LOG%
call :st openssh-client Enabled "I5 Enabled after the install"
for %%F in (ssh.exe scp.exe sftp.exe ssh-keygen.exe ssh-add.exe ssh-agent.exe ssh-keyscan.exe ssh-pkcs11-helper.exe ssh-sk-helper.exe libcrypto.dll LICENSE.txt NOTICE.txt) do (
  if exist "%D%\%%F" (call :pass "I6 %%F installed") else (call :fail "I6 %%F installed")
)
for %%F in (sshd.exe sshd-session.exe sshd-auth.exe sftp-server.exe ssh-shellhost.exe install-sshd.ps1 moduli) do (
  if exist "%D%\%%F" (call :fail "I7 %%F must not be installed") else (call :pass "I7 %%F not installed")
)
reg query "%ENVKEY%" /v Path | find "OpenSSH" >nul
call :rc0 "I8 the machine PATH has the OpenSSH folder"
sc query ssh-agent 2>&1 | find "SERVICE_NAME" >nul
call :rc1 "I9 no ssh-agent service registered"
sc query sshd 2>&1 | find "SERVICE_NAME" >nul
call :rc1 "I10 no sshd service registered"
"%D%\ssh.exe" -V > %O%\ver.txt 2>&1
type %O%\ver.txt >> %LOG%
find "OpenSSH_" %O%\ver.txt >nul
call :rc0 "I11 ssh -V reports OpenSSH"
rem a new process finds ssh through the PATH: featmgr /print-path is what a new process would get
%FM% /print-path > %O%\pp.txt 2>&1
find /i "OpenSSH" %O%\pp.txt >nul
call :rc0 "I12 a new process would have the folder on its PATH"

rem a second install is refused or a no-op, and nothing is replaced
%FM% /install openssh-client > %O%\install2.txt 2>&1
type %O%\install2.txt >> %LOG%
"%D%\ssh.exe" -V >nul 2>&1
call :rc0 "I13 ssh still runs after a repeated install"
rem a file of the user's in the folder must survive the uninstall
echo keep> "%D%\mine.txt"
goto :end

:uninst
%FM% /uninstall openssh-client > %O%\un.txt 2>&1
call :rc0 "U1 featmgr /uninstall openssh-client rc0"
type %O%\un.txt >> %LOG%
call :st openssh-client NotInstalled "U2 NotInstalled after the uninstall"
for %%F in (ssh.exe scp.exe sftp.exe ssh-keygen.exe ssh-add.exe ssh-agent.exe ssh-keyscan.exe ssh-pkcs11-helper.exe ssh-sk-helper.exe libcrypto.dll LICENSE.txt NOTICE.txt) do (
  if exist "%D%\%%F" (call :fail "U3 %%F removed") else (call :pass "U3 %%F removed")
)
if exist "%D%\mine.txt" (call :pass "U4 a user file in the folder survived (and so did the folder)") else (call :fail "U4 a user file in the folder survived")
del /q "%D%\mine.txt" 2>nul
rd "%D%" 2>nul
if exist "%D%" (call :fail "U5 the folder is removed once empty") else (call :pass "U5 the folder is removed once empty")
reg query "%ENVKEY%" /v Path > %O%\path-after.txt 2>&1
fc %O%\path-before.txt %O%\path-after.txt >nul
call :rc0 "U6 the machine PATH is exactly what it was before the install"
reg query "HKLM\SOFTWARE\ReactOS\Nitro\Featmgr\Zip\openssh-client" >nul 2>&1
call :rc1 "U7 the install record is gone"
goto :end

:end
if "%FAILS%"=="0" (echo SSHLIVE-RESULT: PASS>> %LOG%) else (echo SSHLIVE-RESULT: FAIL %FAILS%>> %LOG%)
goto :eof

:st
%FM% /state %1 > %O%\s.txt 2>&1
find "%2" %O%\s.txt >nul
if errorlevel 1 (call :fail %3) else (call :pass %3)
goto :eof

:rc0
if errorlevel 1 (call :fail %1) else (call :pass %1)
goto :eof

:rc1
if errorlevel 1 (call :pass %1) else (call :fail %1)
goto :eof

:pass
echo PASS %~1>> %LOG%
goto :eof

:fail
echo FAIL %~1>> %LOG%
set /a FAILS+=1
goto :eof
