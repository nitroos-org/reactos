@echo off
reg delete HKCU\Environment /v Path /f >nul
exit 0
