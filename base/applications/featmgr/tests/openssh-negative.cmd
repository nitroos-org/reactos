@echo off
rem featmgr /zip-install and /zip-uninstall (zipinst.c): the refusals and the rollbacks. Offline apart from one download of the 64-bit
rem OpenSSH zip when %ZIP% is not given (the zip is only the test input; it is checked against the pinned SHA-256).
rem Usage: openssh-negative.cmd [path of OpenSSH-Win64.zip or OpenSSH-Win32.zip]
rem Run it on an image where openssh-client is NOT installed. Result: %O%\sshneg.txt, last line SSHNEG-RESULT: PASS|FAIL n
setlocal enabledelayedexpansion
set ZIP=%1
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set D=%SystemRoot%\System32\OpenSSH
set ENVKEY=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
set REC=HKLM\SOFTWARE\ReactOS\Nitro\Featmgr\Zip\fmzt
set LOG=%O%\sshneg.txt
set FAILS=0
mkdir %O% 2>nul
echo zip-install negative tests %date% %time%> %LOG%
if "%ZIP%"=="" goto :nozip
goto :haszip
:nozip
echo no zip given: the tests need one (the official OpenSSH-Win64.zip or OpenSSH-Win32.zip)>> %LOG%
call :fail "N0 a zip was given"
goto :end
:haszip
rem a component list of its own (FEATMGR_COMPONENTS), sections fmzt (good), fmzt-missing, fmzt-baddir, fmzt-root
set FEATMGR_COMPONENTS=%O%\fmz-components.ini
rem the lists hold "|": delayed expansion, so that the batch parser never sees a pipe (%var% is expanded before the pipe is parsed, as on Windows)
set "LIST3=ssh.exe|scp.exe|libcrypto.dll"
set "LISTM=ssh.exe|scp.exe|nosuchfile.exe"
> %FEATMGR_COMPONENTS% echo [fmzt]
>> %FEATMGR_COMPONENTS% echo ZipDir=%%SystemRoot%%\System32\OpenSSH
>> %FEATMGR_COMPONENTS% echo ZipFiles=!LIST3!
>> %FEATMGR_COMPONENTS% echo ZipPath=1
>> %FEATMGR_COMPONENTS% echo [fmzt-missing]
>> %FEATMGR_COMPONENTS% echo ZipDir=%%SystemRoot%%\System32\OpenSSH
>> %FEATMGR_COMPONENTS% echo ZipFiles=!LISTM!
>> %FEATMGR_COMPONENTS% echo ZipPath=1
>> %FEATMGR_COMPONENTS% echo [fmzt-baddir]
>> %FEATMGR_COMPONENTS% echo ZipDir=%%SystemRoot%%\System32
>> %FEATMGR_COMPONENTS% echo ZipFiles=ssh.exe
>> %FEATMGR_COMPONENTS% echo [fmzt-dots]
>> %FEATMGR_COMPONENTS% echo ZipDir=%%SystemRoot%%\System32\..\FmzDots
>> %FEATMGR_COMPONENTS% echo ZipFiles=ssh.exe
>> %FEATMGR_COMPONENTS% echo [fmzt-nested]
>> %FEATMGR_COMPONENTS% echo ZipDir=%%SystemRoot%%\System32\OpenSSH\inner
>> %FEATMGR_COMPONENTS% echo ZipFiles=ssh.exe
>> %FEATMGR_COMPONENTS% echo [fmzt-name]
>> %FEATMGR_COMPONENTS% echo ZipDir=%%SystemRoot%%\System32\OpenSSH
>> %FEATMGR_COMPONENTS% echo ZipFiles=..\evil.exe
reg query "%ENVKEY%" /v Path > %O%\neg-path0.txt 2>&1
if exist "%D%" (call :fail "N1 no OpenSSH folder before the tests") else (call :pass "N1 no OpenSSH folder before the tests")

rem N2: a target file that exists is never replaced, nothing else is written
mkdir "%D%"
echo precious> "%D%\scp.exe"
%FM% /zip-install fmzt "%ZIP%" >> %LOG% 2>&1
call :rc1 "N2 install refuses when scp.exe already exists"
if exist "%D%\ssh.exe" (call :fail "N2b nothing else was written") else (call :pass "N2b nothing else was written")
find "precious" "%D%\scp.exe" >nul
call :rc0 "N2c the existing file is untouched"
reg query "%REC%" >nul 2>&1
call :rc1 "N2d no record was written"
call :pathsame "N2e the PATH is unchanged"
del /q "%D%\scp.exe"
rd "%D%"

rem N3: not a zip
echo this is not a zip> %O%\notzip.bin
%FM% /zip-install fmzt %O%\notzip.bin >> %LOG% 2>&1
call :rc1 "N3 a file that is not a zip is refused"
if exist "%D%" (call :fail "N3b no folder left behind") else (call :pass "N3b no folder left behind")
call :pathsame "N3c the PATH is unchanged"

rem N4: a listed file that the archive does not hold: everything written so far is taken out again
%FM% /zip-install fmzt-missing "%ZIP%" >> %LOG% 2>&1
call :rc1 "N4 install fails when the archive lacks a listed file"
if exist "%D%" (call :fail "N4b rolled back: no folder left") else (call :pass "N4b rolled back: no folder left")
call :pathsame "N4c the PATH is unchanged"
reg query "%REC%" >nul 2>&1
call :rc1 "N4d no record"

rem N5: folders that are not a folder of their own directly below System32 / Program Files
%FM% /zip-install fmzt-baddir "%ZIP%" >> %LOG% 2>&1
call :rc1 "N5 ZipDir = System32 itself is refused"
%FM% /zip-install fmzt-dots "%ZIP%" >> %LOG% 2>&1
call :rc1 "N5b ZipDir with .. is not accepted as a new folder of System32"
if exist "%SystemRoot%\FmzDots" (call :fail "N5c nothing was created for it") else (call :pass "N5c nothing was created for it")
%FM% /zip-install fmzt-nested "%ZIP%" >> %LOG% 2>&1
call :rc1 "N5d ZipDir two levels below System32 is refused"
%FM% /zip-install fmzt-name "%ZIP%" >> %LOG% 2>&1
call :rc1 "N5e a file name that climbs out is refused"
if exist "%SystemRoot%\System32\evil.exe" (call :fail "N5f nothing was written outside") else (call :pass "N5f nothing was written outside")

rem N6: a good install, run twice (the second one must refuse: the files exist), then uninstall twice
%FM% /zip-install fmzt "%ZIP%" >> %LOG% 2>&1
call :rc0 "N6 install of the three files"
reg query "%ENVKEY%" /v Path | find "OpenSSH" >nul
call :rc0 "N6b PATH has the folder"
%FM% /zip-install fmzt "%ZIP%" >> %LOG% 2>&1
call :rc1 "N6c a second install refuses (files exist)"
reg query "%ENVKEY%" /v Path > %O%\neg-path1.txt 2>&1
find "OpenSSH;%%SystemRoot%%\System32\OpenSSH" %O%\neg-path1.txt >nul
call :rc1 "N6d the folder is on the PATH once (no second entry after the refused install)"
echo mine> "%D%\mine.txt"
%FM% /zip-uninstall fmzt >> %LOG% 2>&1
call :rc0 "N7 uninstall"
for %%F in (ssh.exe scp.exe libcrypto.dll) do (if exist "%D%\%%F" (call :fail "N7 %%F removed") else (call :pass "N7 %%F removed"))
if exist "%D%\mine.txt" (call :pass "N7b a user file stays, so does the folder") else (call :fail "N7b a user file stays, so does the folder")
call :pathsame "N7c the PATH is what it was"
%FM% /zip-uninstall fmzt >> %LOG% 2>&1
call :rc0 "N8 a second uninstall with no record removes nothing and succeeds"
if exist "%D%\mine.txt" (call :pass "N8b the user file is still there") else (call :fail "N8b the user file is still there")
del /q "%D%\mine.txt"
rd "%D%"

rem N9: the folder is already on the PATH when the install runs (a stale entry: the files were deleted by hand): no second entry,
rem and the record says the entry is not ours, so uninstall leaves it. The record is then set by hand so the last uninstall takes it out.
%FM% /zip-install fmzt "%ZIP%" >> %LOG% 2>&1
call :rc0 "N9 install (adds the folder to the PATH)"
reg query "%ENVKEY%" /v Path > %O%\neg-path2.txt 2>&1
del /q "%D%\ssh.exe" "%D%\scp.exe" "%D%\libcrypto.dll"
rd "%D%"
%FM% /zip-install fmzt "%ZIP%" >> %LOG% 2>&1
call :rc0 "N9b install again with the folder already on the PATH"
reg query "%ENVKEY%" /v Path > %O%\neg-path3.txt 2>&1
fc %O%\neg-path2.txt %O%\neg-path3.txt >nul
call :rc0 "N9c the PATH is unchanged (no second entry)"
%FM% /zip-uninstall fmzt >> %LOG% 2>&1
call :rc0 "N9d uninstall"
reg query "%ENVKEY%" /v Path > %O%\neg-path4.txt 2>&1
fc %O%\neg-path2.txt %O%\neg-path4.txt >nul
call :rc0 "N9e the entry that was not added by this install is still there"
%FM% /zip-install fmzt "%ZIP%" >> %LOG% 2>&1
reg add "HKLM\SOFTWARE\ReactOS\Nitro\Featmgr\Zip\fmzt" /v PathAdded /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\ReactOS\Nitro\Featmgr\Zip\fmzt" /v PathEntry /t REG_SZ /d "%%SystemRoot%%\System32\OpenSSH" /f >nul
%FM% /zip-uninstall fmzt >> %LOG% 2>&1
call :rc0 "N9f uninstall with the record naming the entry"
call :pathsame "N9g the PATH is back as it was before the tests"
if exist "%D%" (call :fail "N9h the folder is gone") else (call :pass "N9h the folder is gone")

:end
set FEATMGR_COMPONENTS=
if "%FAILS%"=="0" (echo SSHNEG-RESULT: PASS>> %LOG%) else (echo SSHNEG-RESULT: FAIL %FAILS%>> %LOG%)
goto :eof

:pathsame
reg query "%ENVKEY%" /v Path > %O%\neg-pathN.txt 2>&1
fc %O%\neg-path0.txt %O%\neg-pathN.txt >nul
if errorlevel 1 (call :fail %1) else (call :pass %1)
goto :eof

:rc0
if errorlevel 1 (call :fail %1) else (call :pass %1)
goto :eof

:rc1
if errorlevel 1 (call :pass %1) else (call :fail %1)
goto :eof

:pass
echo PASS %~1>> %LOG%
echo PASS %~1>COM2 2>nul
goto :eof

:fail
echo FAIL %~1>> %LOG%
echo FAIL %~1>COM2 2>nul
set /a FAILS+=1
goto :eof
