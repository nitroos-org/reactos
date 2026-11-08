@echo off
rem AAC audio decoder (AAC-LC) feature through the feature manager (catalog entry aac-lc, dll/3rdparty/nitro-aacdec): turn on (the pack is
rem downloaded over https from PayloadBaseUrl, or staged offline in %SystemRoot%\Featmgr\Payload\aac-lc), check files, registry (64-bit and
rem 32-bit view), the patent notice, the decoder (mfplat_apitest MftAac, mfttest against a reference), turn off (everything removed again),
rem turn on again. Run in a guest from a directory holding mfplat_apitest.exe, mfttest64.exe, mfttest32.exe, lc-st.aac, he-sbr.aac.
rem Result: %O%\aaclc.txt, last line AACLC-RESULT: PASS|FAIL n
setlocal
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set LOG=%O%\aaclc.txt
set FAILS=0
set CLS={32D186A7-218F-4C75-8876-DD77273A8999}
set MFG=32d186a7-218f-4c75-8876-dd77273a8999
set CAT=9ea73fb4-ef7a-4559-8d5d-719d8f0426c7
mkdir %O% 2>nul
echo AAC-LC featmgr live test %date% %time%> %LOG%

%FM% /query aac-lc > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
call :st aac-lc NotInstalled "A1 NotInstalled before"
call :gone "A2 nothing registered or installed before"
call :apit skip "A3 mfplat_apitest: registration part passes, decoder part skipped (feature off)"

%FM% /enable aac-lc > %O%\en.txt 2>&1
call :rc0 "A4 featmgr /enable aac-lc"
type %O%\en.txt >> %LOG%
find "NOTICE (AAC audio decoder (AAC-LC))" %O%\en.txt >nul
call :rc0 "A5 the patent notice is printed before enabling"
find "no patent licence" %O%\en.txt >nul
call :rc0 "A6 ...and says no patent licence is granted"
call :st aac-lc Enabled "A7 Enabled"
call :present "A8 files and registry present (both views)"
call :apit run "A9 mfplat_apitest: registration and decoder parts pass (feature on)"
call :mft mfttest64.exe %SystemRoot%\System32\nitroaacdec.dll lc-st.aac adts "A10 x64 decoder: ADTS stream"
call :mft mfttest64.exe - lc-st.aac raw "A11 x64 through CoCreateInstance (registry), raw frames + AudioSpecificConfig"
call :mft mfttest32.exe - lc-st.aac raw "A12 x86 through CoCreateInstance (32-bit registry view), raw frames"
call :hefail mfttest64.exe "A13 x64 HE-AAC stream is refused (no crash)"
call :hefail mfttest32.exe "A14 x86 HE-AAC stream is refused (no crash)"

%FM% /disable aac-lc > %O%\dis.txt 2>&1
call :rc0 "A15 featmgr /disable aac-lc"
call :st aac-lc Disabled "A16 Disabled"
call :gone "A17 files and registry entries removed again (both views)"
call :apit skip "A18 mfplat_apitest: decoder part skipped again"
%O%\..\mfttest64.exe - lc-st.aac %O%\x.raw raw float > %O%\x.txt 2>&1
find "createfail" %O%\x.txt >nul
call :rc0 "A19 CoCreateInstance of the decoder fails cleanly while off"

%FM% /enable aac-lc > %O%\en2.txt 2>&1
call :rc0 "A20 re-enable"
call :present "A21 files and registry present again"
call :apit run "A22 mfplat_apitest passes again"
call :mft mfttest32.exe - lc-st.aac raw "A23 x86 decoder after re-enable"

echo.>> %LOG%
if "%FAILS%"=="0" (echo AACLC-RESULT: PASS>> %LOG%) else (echo AACLC-RESULT: FAIL %FAILS%>> %LOG%)
type %LOG% | find "AACLC-RESULT"
exit /b %FAILS%

:rc0
if errorlevel 1 (echo FAIL %~1>> %LOG% & set /a FAILS+=1) else (echo PASS %~1>> %LOG%)
exit /b 0

:st
%FM% /state %1 > %O%\s.txt 2>&1
find "%2" %O%\s.txt >nul
call :rc0 %3
exit /b 0

:present
set P=0
for %%F in (%SystemRoot%\System32\nitroaacdec.dll %SystemRoot%\SysWOW64\nitroaacdec.dll %SystemRoot%\System32\aac-lc-licenses\aac-lc-licenses.txt %SystemRoot%\System32\aac-lc-licenses\aac-lc-source-offer.txt %SystemRoot%\System32\aac-lc-licenses\aac-lc-patent-notice.txt) do if not exist %%F set /a P+=1
reg query "HKLM\SOFTWARE\Classes\CLSID\%CLS%\InprocServer32" >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\%CLS%\InprocServer32" >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\%MFG%" /v InputTypes >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\%MFG%" /v InputTypes >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 || set /a P+=1
if "%P%"=="0" (echo PASS %~1>> %LOG%) else (echo FAIL %~1 (%P% missing)>> %LOG% & set /a FAILS+=1)
exit /b 0

:gone
set P=0
for %%F in (%SystemRoot%\System32\nitroaacdec.dll %SystemRoot%\SysWOW64\nitroaacdec.dll %SystemRoot%\System32\aac-lc-licenses) do if exist %%F set /a P+=1
reg query "HKLM\SOFTWARE\Classes\CLSID\%CLS%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\%CLS%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\%MFG%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\%MFG%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 && set /a P+=1
if "%P%"=="0" (echo PASS %~1>> %LOG%) else (echo FAIL %~1 (%P% left)>> %LOG% & set /a FAILS+=1)
exit /b 0

:apit
mfplat_apitest.exe MftAac > %O%\apit.txt 2>&1
type %O%\apit.txt >> %LOG%
if "%1"=="skip" (find "CLSID_CMSAACDecMFT is not registered" %O%\apit.txt >nul) else (find "skipped" %O%\apit.txt | find "not registered" >nul && exit /b 1)
set RC=%ERRORLEVEL%
find "0 failed" %O%\apit.txt >nul || set RC=1
if "%RC%"=="0" (echo PASS %~1>> %LOG%) else (echo FAIL %~1>> %LOG% & set /a FAILS+=1)
exit /b 0

:mft
%~1 %~2 %~3 %O%\m.raw %~4 float > %O%\m.txt 2>&1
type %O%\m.txt >> %LOG%
find "firsterr=0x00000000 setinput=0x00000000" %O%\m.txt | find "in=470 out=470" >nul
call :rc0 %5
exit /b 0

:hefail
%~1 - he-sbr.aac %O%\he.raw adts float > %O%\he.txt 2>&1
type %O%\he.txt >> %LOG%
find "firsterr=0xc00d36cb" %O%\he.txt >nul
call :rc0 %2
exit /b 0
