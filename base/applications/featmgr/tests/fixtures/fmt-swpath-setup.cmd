@echo off
rem guest-only fixture: the test guest has no user PATH value of its own; the uninstaller deletes it again
reg add HKCU\Environment /v Path /t REG_EXPAND_SZ /d "C:\fmtpath-test;%%SystemDrive%%\fmtpath-test2" /f >nul
exit 0
