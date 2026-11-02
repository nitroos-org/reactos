@echo off
rem refreshenv - re-read PATH (registry machine + user) into THIS cmd window, e.g. after "featmgr /install scoop".
rem A program cannot change its parent shell's environment, but a batch file runs inside cmd.exe itself, so it can.
rem The value comes from "featmgr /print-path /cmd", which prints one line:  set "PATH=..."
set "FM_REFRESHENV=%TEMP%\featmgr-refreshenv.cmd"
"%SystemRoot%\system32\featmgr.exe" /print-path /cmd > "%FM_REFRESHENV%"
if errorlevel 1 (
    echo refreshenv: could not read the PATH from the registry.
    del "%FM_REFRESHENV%" 2>nul
    set "FM_REFRESHENV="
    goto :eof
)
call "%FM_REFRESHENV%"
del "%FM_REFRESHENV%" 2>nul
set "FM_REFRESHENV="
