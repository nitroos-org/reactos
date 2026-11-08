@echo off
rem AAC audio decoder features through the feature manager: "aac" (AAC-LC + HE-AAC + HE-AAC v2, catalog aac.ini) and its relation to
rem "aac-lc" (AAC-LC only, catalog aac-lc.ini): turn on (the packs are downloaded over https from PayloadBaseUrl, or staged offline in
rem %SystemRoot%\Featmgr\Payload\<id>), check files, registry (64-bit and 32-bit view), the patent notice, the decoder (mfplat_apitest
rem MftAac, mfttest), turn off (everything removed again), turn on again, then the aac-lc -> aac upgrade (Replaces=) and the refusal of
rem aac-lc while aac is on (Conflicts=). Run in a guest from a directory holding mfplat_apitest.exe, mfttest64.exe, mfttest32.exe,
rem cmpf32.exe, lc-st.aac, he-sbr.aac, he-ps.aac and the FFmpeg decodes lc-st.ref.f32, he-sbr.ref.f32, he-ps.ref.f32 (raw float32).
rem Result: %O%\aac.txt, last line AAC-RESULT: PASS|FAIL n
setlocal
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set LOG=%O%\aac.txt
set FAILS=0
set CLS={32D186A7-218F-4C75-8876-DD77273A8999}
set MFG=32d186a7-218f-4c75-8876-dd77273a8999
set CAT=9ea73fb4-ef7a-4559-8d5d-719d8f0426c7
rem pinned SHA-256 of the x64 DLLs of the two packs (catalog [Download] File0)
set SHA_LC=4ce425d0f1a8f879277fb26cc9f81439b48fd84cff8bd3ee16d7928ed171548b
set SHA_FULL=bdd8a373f28f3f21094f40b20d07bce459075b04278ba3cdd06f19652af31b59
mkdir %O% 2>nul
echo AAC (full) featmgr live test %date% %time%> %LOG%

rem ---- both features off, clean system (a state record left by an earlier run is removed first)
%FM% /uninstall aac > nul 2>&1
%FM% /uninstall aac-lc > nul 2>&1
%FM% /state aac > %O%\s.txt 2>&1
call :st aac NotInstalled "B1 aac NotInstalled before"
call :st aac-lc NotInstalled "B2 aac-lc NotInstalled before"
call :gone aac-licenses "B3 nothing registered or installed before"
call :apit skip "B4 mfplat_apitest: registration part passes, decoder part skipped , feature off"

rem ---- turn aac on
%FM% /enable aac > %O%\en.txt 2>&1
call :rc0 "C1 featmgr /enable aac"
type %O%\en.txt >> %LOG%
find "NOTICE (AAC audio decoder (AAC-LC, HE-AAC, HE-AAC v2))" %O%\en.txt >nul
call :rc0 "C2 the patent notice is printed before enabling"
find "HE-AAC v2 (PS)" %O%\en.txt >nul
call :rc0 "C3 ...and names HE-AAC and HE-AAC v2"
find "no patent licence" %O%\en.txt >nul
call :rc0 "C4 ...and says no patent licence is granted"
call :st aac Enabled "C5 aac Enabled"
call :present aac-licenses aac "C6 files and registry present , both views"
call :sha %SHA_FULL% "C7 System32\nitroaacdec.dll is the full-AAC build , pinned SHA-256"
call :apit run "C8 mfplat_apitest: registration and decoder parts pass , feature on; HE-AAC types accepted"
call :mftcmp mfttest64.exe %SystemRoot%\System32\nitroaacdec.dll lc-st.aac adts lc-st.ref.f32 - "C9 x64 AAC-LC stream ADTS equals FFmpeg's decode"
call :mftcmp mfttest64.exe - lc-st.aac raw lc-st.ref.f32 - "C10 x64 AAC-LC through CoCreateInstance registry, raw frames + AudioSpecificConfig"
call :mftcmp mfttest32.exe - lc-st.aac raw lc-st.ref.f32 - "C11 x86 AAC-LC through CoCreateInstance 32-bit registry view"
call :mftcmp mfttest64.exe %SystemRoot%\System32\nitroaacdec.dll he-sbr.aac adts he-sbr.ref.f32 - "C12 x64 HE-AAC SBR stream equals FFmpeg's decode"
call :mftcmp mfttest32.exe - he-sbr.aac adts he-sbr.ref.f32 - "C13 x86 HE-AAC SBR stream equals FFmpeg's decode"
call :mftcmp mfttest64.exe - he-sbr.aac raw he-sbr.ref.f32 131056e598 "C14 x64 HE-AAC with the explicit AudioSpecificConfig of an MP4"
call :mftcmp mfttest32.exe - he-sbr.aac raw he-sbr.ref.f32 131056e598 "C15 x86 HE-AAC with the explicit AudioSpecificConfig of an MP4"
call :mftcmp mfttest64.exe - he-ps.aac adts he-ps.ref.f32 - "C16 x64 HE-AAC v2 PS stream equals FFmpeg's decode"
call :mftcmp mfttest32.exe - he-ps.aac adts he-ps.ref.f32 - "C17 x86 HE-AAC v2 PS stream equals FFmpeg's decode"
call :mftcmp mfttest64.exe - he-ps.aac raw he-ps.ref.f32 140006040000000056e5a8 "C18 x64 HE-AAC v2 with the AudioSpecificConfig of an MP4"
call :mftcmp mfttest32.exe - he-ps.aac raw he-ps.ref.f32 140006040000000056e5a8 "C19 x86 HE-AAC v2 with the AudioSpecificConfig of an MP4"

rem ---- turn aac-lc on while aac is on: refused
%FM% /enable aac-lc > %O%\en-lc.txt 2>&1
if errorlevel 1 (echo PASS C20 aac-lc refuses to turn on while aac is on>> %LOG%) else (echo FAIL C20 aac-lc turned on while aac is on>> %LOG% & set /a FAILS+=1)
type %O%\en-lc.txt >> %LOG%
call :st aac-lc NotInstalled "C21 aac-lc still NotInstalled"
call :st aac Enabled "C22 aac still Enabled, its files untouched"
call :sha %SHA_FULL% "C23 System32\nitroaacdec.dll still the full build"

rem ---- turn off: everything removed
%FM% /disable aac > %O%\dis.txt 2>&1
call :rc0 "D1 featmgr /disable aac"
call :st aac Disabled "D2 aac Disabled"
call :gone aac-licenses "D3 files and registry entries removed again , both views"
call :apit skip "D4 mfplat_apitest: decoder part skipped again"
mfttest64.exe - lc-st.aac %O%\x.raw raw float > %O%\x.txt 2>&1
find "createfail" %O%\x.txt >nul
call :rc0 "D5 CoCreateInstance of the decoder fails cleanly while off"

rem ---- turn on again
%FM% /enable aac > %O%\en2.txt 2>&1
call :rc0 "E1 re-enable aac"
call :present aac-licenses aac "E2 files and registry present again"
call :apit run "E3 mfplat_apitest passes again"
call :mftcmp mfttest32.exe - he-ps.aac adts he-ps.ref.f32 - "E4 x86 HE-AAC v2 after re-enable equals FFmpeg's decode"
%FM% /disable aac > %O%\dis2.txt 2>&1
call :rc0 "E5 disable aac"
call :gone aac-licenses "E6 clean again"

rem ---- upgrade: aac-lc on, then aac replaces it
%FM% /enable aac-lc > %O%\en-lc2.txt 2>&1
call :rc0 "F1 featmgr /enable aac-lc , the published LC-only pack"
call :st aac-lc Enabled "F2 aac-lc Enabled"
call :present aac-lc-licenses aac-lc "F3 aac-lc files and registry present"
call :sha %SHA_LC% "F4 System32\nitroaacdec.dll is the LC-only build"
call :apit run "F5 mfplat_apitest against the LC-only decoder , HE-AAC refused"
call :hefail mfttest64.exe "F6 x64 LC-only: HE-AAC stream refused , no crash"
%FM% /enable aac > %O%\up.txt 2>&1
call :rc0 "G1 featmgr /enable aac with aac-lc on , upgrade"
type %O%\up.txt >> %LOG%
find "replacing 'aac-lc'" %O%\up.txt >nul
call :rc0 "G2 the log says aac-lc is replaced"
call :st aac Enabled "G3 aac Enabled"
call :st aac-lc Disabled "G4 aac-lc Disabled , replaced"
call :sha %SHA_FULL% "G5 System32\nitroaacdec.dll is now the full build"
if exist %SystemRoot%\System32\aac-lc-licenses (echo FAIL G6 aac-lc-licenses folder left behind>> %LOG% & set /a FAILS+=1) else (echo PASS G6 aac-lc-licenses folder removed>> %LOG%)
call :present aac-licenses aac "G7 aac files and registry present, both views"
call :apit run "G8 mfplat_apitest against the full decoder after the upgrade"
call :mftcmp mfttest64.exe - he-sbr.aac adts he-sbr.ref.f32 - "G9 x64 HE-AAC equals FFmpeg's decode after the upgrade"
call :mftcmp mfttest32.exe - he-ps.aac adts he-ps.ref.f32 - "G10 x86 HE-AAC v2 equals FFmpeg's decode after the upgrade"
%FM% /disable aac > %O%\dis3.txt 2>&1
call :rc0 "H1 disable aac after the upgrade"
call :gone aac-licenses "H2 everything removed , nothing of aac-lc or aac left, both views"
call :st aac-lc Disabled "H3 aac-lc stays Disabled , not restored"
call :apit skip "H4 mfplat_apitest: decoder part skipped"

echo.>> %LOG%
if "%FAILS%"=="0" (echo AAC-RESULT: PASS>> %LOG%) else (echo AAC-RESULT: FAIL %FAILS%>> %LOG%)
type %LOG% | find "AAC-RESULT"
exit /b %FAILS%

:rc0
if errorlevel 1 (echo FAIL %~1>> %LOG% & set /a FAILS+=1) else (echo PASS %~1>> %LOG%)
exit /b 0

:st
%FM% /state %1 > %O%\s.txt 2>&1
find "%2" %O%\s.txt >nul
call :rc0 %3
exit /b 0

:sha
set GOT=
"%ProgramFiles%\PowerShell\7\pwsh.exe" -NoProfile -Command "(Get-FileHash %SystemRoot%\System32\nitroaacdec.dll -Algorithm SHA256).Hash" > %O%\h.txt 2>&1
set /p GOT=<%O%\h.txt
if /i "%GOT%"=="%~1" (echo PASS %~2>> %LOG%) else (echo FAIL %~2: got %GOT%>> %LOG% & set /a FAILS+=1)
exit /b 0

:present
set P=0
set LD=%SystemRoot%\System32\%~1
set LP=%~2
for %%F in (%SystemRoot%\System32\nitroaacdec.dll %SystemRoot%\SysWOW64\nitroaacdec.dll %LD%\%LP%-licenses.txt %LD%\%LP%-source-offer.txt %LD%\%LP%-patent-notice.txt) do if not exist %%F set /a P+=1
reg query "HKLM\SOFTWARE\Classes\CLSID\%CLS%\InprocServer32" >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\%CLS%\InprocServer32" >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\%MFG%" /v InputTypes >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\%MFG%" /v InputTypes >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 || set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 || set /a P+=1
if "%P%"=="0" (echo PASS %~3>> %LOG%) else (echo FAIL %~3: %P% missing>> %LOG% & set /a FAILS+=1)
exit /b 0

:gone
set P=0
for %%F in (%SystemRoot%\System32\nitroaacdec.dll %SystemRoot%\SysWOW64\nitroaacdec.dll %SystemRoot%\System32\aac-lc-licenses %SystemRoot%\System32\aac-licenses) do if exist %%F set /a P+=1
reg query "HKLM\SOFTWARE\Classes\CLSID\%CLS%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\CLSID\%CLS%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\%MFG%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\%MFG%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 && set /a P+=1
reg query "HKLM\SOFTWARE\Classes\Wow6432Node\MediaFoundation\Transforms\Categories\%CAT%\%MFG%" >nul 2>&1 && set /a P+=1
if "%P%"=="0" (echo PASS %~2>> %LOG%) else (echo FAIL %~2: %P% left>> %LOG% & set /a FAILS+=1)
exit /b 0

:apit
mfplat_apitest.exe MftAac > %O%\apit.txt 2>&1
type %O%\apit.txt >> %LOG%
set RC=0
find "is not registered" %O%\apit.txt >nul
if "%1"=="skip" (if errorlevel 1 set RC=1) else (if not errorlevel 1 set RC=1)
find ", 0 failures)" %O%\apit.txt >nul
if errorlevel 1 set RC=1
if "%RC%"=="0" (echo PASS %~2>> %LOG%) else (echo FAIL %~2>> %LOG% & set /a FAILS+=1)
exit /b 0

:mftcmp
set AS=
if not "%~6"=="-" set AS=asc=%~6
%~1 %~2 %~3 %O%\m.raw %~4 float - %AS% > %O%\m.txt 2>&1
type %O%\m.txt >> %LOG%
find "firsterr=0x00000000 setinput=0x00000000" %O%\m.txt >nul
if errorlevel 1 (echo FAIL %~7: the decoder reported an error>> %LOG% & set /a FAILS+=1 & exit /b 0)
cmpf32.exe %O%\m.raw %~5 > %O%\c.txt 2>&1
type %O%\c.txt >> %LOG%
find "CMPRESULT PASS" %O%\c.txt >nul
call :rc0 %7
exit /b 0

:hefail
%~1 - he-sbr.aac %O%\he.raw adts float > %O%\he.txt 2>&1
type %O%\he.txt >> %LOG%
find "firsterr=0xc00d36cb" %O%\he.txt >nul
call :rc0 %2
exit /b 0
