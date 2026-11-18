@echo off
rem fixture of hooks.cmd: every hook call appends its argument to fmt-hook.log
echo %1>> %SystemRoot%\Featmgr\fmt-hook.log
exit /b 0
