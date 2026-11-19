@echo off
rem Tests of nitrodiag.exe: every case runs one of the ndt test programs under the tool and checks that the VERDICT line
rem names the right cause. Run it in the folder that holds the ndt programs (the rostests bin folder); it prints PASS/FAIL per case.
rem   nitrodiag_tests.cmd [output folder]
setlocal
set ND=%SystemRoot%\system32\nitrodiag.exe
set OUT=%1
if "%OUT%"=="" set OUT=%TEMP%\ndt-out
mkdir "%OUT%" 2>nul
set FAILS=0

call :case av "ndt.exe av" "crashed: access violation (writing 0x8) in ndt.exe"
call :case avread "ndt.exe avread" "crashed: access violation (reading 0x10) in ndt.exe"
call :case div0 "ndt.exe div0" "crashed: integer divide by zero"
call :case stackoverflow "ndt.exe stackoverflow" "crashed: stack overflow"
call :case cppexc "ndt_cpp.exe" "exited with code 3"
call :case abort "ndt.exe abort" "exited with code 3"
call :case childcrash "ndt.exe child" "a child process (ndt.exe) crashed: access violation"
call :case hang "/timeout 4 ndt.exe hang" "still running after 4 s"
taskkill /f /im ndt.exe >nul 2>&1
call :case exit0 "ndt.exe exit 0" "exited normally with code 0"
call :case exit7 "ndt.exe exit 7" "exited normally with code 7"
call :case dbgcheck "ndt.exe dbgcheck" "exited normally with code 77"
call :case dbgcheck2 "ndt.exe dbgcheck" "asked whether a debugger is attached"
rem (a Debug build prints its own debug text after the program's, so only the exit code is asserted here; the text is in the timeline)
call :case debugstr "ndt.exe debugstr" "exited normally with code 5"
call :case stub "ndt.exe stub" "kernel32.dll!CheckForReadOnlyResource"
call :case stub2 "ndt.exe stub2" "kernel32.dll!CheckElevationEnabled (2 times)"
call :case gui "ndt_gui.exe" "exited normally with code 0"
call :case missingexe "this_program_is_not_here.exe" "did not start"
call :case okimports "ndt_missing.exe" "exited normally with code 0"

rem missing DLL: the dependency is renamed
ren ndt_full.dll ndt_full.gone
call :case missdll "/timeout 8 ndt_missing.exe" "did not start: missing DLL ndt_full.dll needed by ndt_missing.exe"
taskkill /f /im ndt_missing.exe >nul 2>&1
ren ndt_full.gone ndt_full.dll

rem missing import: a DLL of the same name without one export
copy /y ndt_full.dll ndt_full.orig >nul
copy /y ndt_short.dll ndt_full.dll >nul
call :case missimp "/timeout 8 ndt_missing.exe" "did not start: missing function NdFuncB in ndt_full.dll needed by ndt_missing.exe"
taskkill /f /im ndt_missing.exe >nul 2>&1
copy /y ndt_full.orig ndt_full.dll >nul
del ndt_full.orig

rem bad image: a DLL of the wrong 32/64-bit type in its place (ndt_full32.dll is the 32-bit build, when present)
if exist ndt_full32.dll (
copy /y ndt_full.dll ndt_full.orig >nul
copy /y ndt_full32.dll ndt_full.dll >nul
call :case badimage "/timeout 8 ndt_missing.exe" "bad image"
taskkill /f /im ndt_missing.exe >nul 2>&1
copy /y ndt_full.orig ndt_full.dll >nul
del ndt_full.orig
)

rem a shortcut as the program: it is resolved to its target (cmd.exe) and run with its arguments
ndt.exe mklnk "%OUT%\ndt.lnk" "%CD%\ndt.exe" "exit 9"
call :case lnk """%OUT%\ndt.lnk""" "exited normally with code 9"

rem arguments with spaces and quotes arrive as typed
"%ND%" /quiet /zip "%OUT%\echo.zip" ndt.exe echo "a b" "c d" e"f" > "%OUT%\echo.out" 2>&1
findstr /l /c:"ARG1=[a b]" "%OUT%\echo.out" >nul && findstr /l /c:"ARG2=[c d]" "%OUT%\echo.out" >nul && findstr /l /c:"ARG3=[ef]" "%OUT%\echo.out" >nul && (echo PASS echo) || (echo FAIL echo & set /a FAILS+=1)

rem a 32-bit program on a 64-bit system (ndt32.exe is the 32-bit build of ndt.exe, when present)
if exist ndt32.exe call :case wow64av "ndt32.exe av" "crashed: access violation (writing 0x8) in ndt32.exe"
if exist ndt32.exe call :case wow64ok "ndt32.exe exit 3" "exited"

echo DONE fails=%FAILS%
exit /b %FAILS%

:case
rem :case name "command" "text that must be in the output"
"%ND%" /quiet /zip "%OUT%\%~1.zip" %~2 > "%OUT%\%~1.out" 2>&1
findstr /l /c:%3 "%OUT%\%~1.out" >nul
if errorlevel 1 (echo FAIL %~1 & set /a FAILS+=1) else (echo PASS %~1)
goto :eof
