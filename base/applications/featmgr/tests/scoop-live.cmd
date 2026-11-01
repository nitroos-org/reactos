@echo off
rem SCOOP-FEATMGR-01 live proof (amd64, NTFS, needs internet). Run inside the guest:
rem   scoop-live.cmd [extras]
rem Steps: featmgr /install scoop (pulls in powershell-7 when missing) -> /import-scoop main (timed) -> search ->
rem /install 7zip -> installed version (checked against Scoop's version directory) -> a REAL update with a local bucket
rem (fm7z = 7-Zip 24.09, bucket manifest then replaced by the current one, re-import, /update fm7z) -> catalog edited so
rem a newer 7zip is "available", /update 7zip -> /uninstall scoop refused while 7zip is installed -> /uninstall 7zip ->
rem /uninstall scoop. "extras" adds: /install git, featmgr /add-bucket extras (a known bucket), /list timings over main+extras,
rem main re-added as a git clone, /update /all (real scoop update).
rem Result: %O%\scooplive.txt, last line SCOOPLIVE-RESULT: PASS|FAIL n
setlocal
set FM=%SystemRoot%\system32\featmgr.exe
set O=C:\harness\out
set SROOT=C:\scoop
set PSDIR=C:\Program Files\PowerShell\7
set ENVKEY=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
set LOG=%O%\scooplive.txt
set FX=%~dp0fixtures
set FEATMGR_TIMING_FILE=%O%\gui-timing.txt
set FAILS=0
mkdir %O% 2>nul
echo Scoop live test %date% %time%> %LOG%

rem the guest needs its DHCP lease before the first download
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

%FM% /list /tier:software > %O%\l.txt 2>&1
find "scoop" %O%\l.txt >nul
call :rc0 "L1 scoop listed by featmgr /list"
call :st scoop NotInstalled "L2 scoop NotInstalled at start"
if exist "%SROOT%" (call :fail "L3 no C:\scoop at start") else (call :pass "L3 no C:\scoop at start")
call :stq powershell-7

rem --- install scoop (installs powershell-7 first when it is missing)
%FM% /install scoop > %O%\install-scoop.txt 2>&1
call :rc0 "L4 featmgr /install scoop rc0"
type %O%\install-scoop.txt >> %LOG%
call :st scoop Enabled "L5 scoop Enabled"
call :st powershell-7 Enabled "L6 powershell-7 Enabled (dependency)"
if exist "%PSDIR%\pwsh.exe" (call :pass "L7 pwsh.exe installed") else (call :fail "L7 pwsh.exe installed")
if exist "%SROOT%\shims\scoop.cmd" (call :pass "L8 scoop shim present") else (call :fail "L8 scoop shim present")
if exist "%SROOT%\apps\scoop\current\bin\scoop.ps1" (call :pass "L9 scoop core present") else (call :fail "L9 scoop core present")
if exist "%SROOT%\buckets\main\bucket" (call :pass "L10 main bucket present") else (call :fail "L10 main bucket present")
reg query "%ENVKEY%" /v SCOOP | find "C:\scoop" >nul
call :rc0 "L11 machine SCOOP variable set"
reg query "%ENVKEY%" /v Path | find "C:\scoop\shims" >nul
call :rc0 "L12 machine PATH has C:\scoop\shims"
findstr /c:"scoop-install: ACL on" /c:"WARNING" %O%\install-scoop.txt >> %LOG%
find "inheritance off" %O%\install-scoop.txt >nul
call :rc0 "L12a C:\scoop ACL: inheritance from C:\ disabled (see ACL lines above)"
"%PSDIR%\pwsh.exe" -NoProfile -Command "foreach($p in 'C:\scoop','C:\scoop\shims','C:\scoop\shims\scoop.cmd','C:\scoop\apps\scoop\current\bin\scoop.ps1'){ '{0}: protected={1}' -f $p,(Get-Acl $p).AreAccessRulesProtected; foreach($a in (Get-Acl $p).Access){ '   {0} {1} inherited={2}' -f $a.IdentityReference,$a.FileSystemRights,$a.IsInherited } }" > %O%\acl.txt 2>&1
type %O%\acl.txt >> %LOG%
find "BUILTIN\Users" %O%\acl.txt | find "Modify" >nul
call :rc1 "L12b Users have no Modify/Write on C:\scoop"
find "Authenticated Users" %O%\acl.txt | find "Modify" >nul
call :rc1 "L12c Authenticated Users have no Modify on C:\scoop"
rem the installing account must keep its own ACE: programs that drop the Administrators group from their token (PostgreSQL initdb) need it
"%PSDIR%\pwsh.exe" -NoProfile -Command "$me=[Security.Principal.WindowsIdentity]::GetCurrent().Name; $ok=@((Get-Acl 'C:\scoop').Access | Where-Object { $_.IdentityReference.Value -eq $me -and $_.FileSystemRights -eq 'FullControl' }).Count; if ($ok -ge 1) { exit 0 } else { exit 1 }"
call :rc0 "L12d the installing user has its own FullControl ACE on C:\scoop (restricted-token programs)"
set SCOOP=%SROOT%
set PATH=%SROOT%\shims;%PSDIR%;%PATH%
call scoop --version > %O%\ver.txt 2>&1
type %O%\ver.txt >> %LOG%
find "Current Scoop version" %O%\ver.txt >nul
call :rc0 "L13 scoop --version runs from cmd"

rem --- import the main bucket
%FM% /import-scoop main /timing > %O%\import.txt 2>&1
call :rc0 "L14 featmgr /import-scoop main rc0"
findstr /b "timing:" %O%\import.txt | find "import" > %O%\t1.txt
for /f "tokens=*" %%a in (%O%\t1.txt) do echo TIMING /import-scoop main: %%a>> %LOG%
if exist "%SystemRoot%\Featmgr\Catalog\Software\scoop-main.idx" (call :pass "M1 one index file for the main bucket") else (call :fail "M1 one index file for the main bucket")
dir "%SystemRoot%\Featmgr\Catalog\Software" | find "scoop-main.idx" >> %LOG%
find "imported" %O%\import.txt | find "Scoop app(s)" >nul
call :rc0 "L15 import summary printed"
type %O%\import.txt | find "imported" >> %LOG%
%FM% /query 7zip > %O%\q.txt 2>&1
type %O%\q.txt >> %LOG%
find "Source:       scoop/main" %O%\q.txt >nul
call :rc0 "L16 7zip entry from scoop/main"
find "Scoop.Verified: 1" %O%\q.txt >nul
call :rc0 "L17 7zip manifest carries a hash"
%FM% /list /tier:software /source:scoop/main > %O%\l.txt 2>&1
find "git " %O%\l.txt >nul
call :rc0 "L18 git is listed too"
call :st 7zip NotInstalled "L19 7zip NotInstalled"
%FM% /list /tier:software /timing > %O%\l-all.txt 2>&1
call :rc0 "M2 /list over the main bucket rc0"
findstr /b "timing:" %O%\l-all.txt > %O%\t1.txt
for /f "tokens=*" %%a in (%O%\t1.txt) do echo TIMING /list main: %%a>> %LOG%
%FM% /list /search:7ZIP > %O%\l.txt 2>&1
find "7zip" %O%\l.txt >nul
call :rc0 "M3 /list /search:7ZIP finds 7zip (case-insensitive)"
%FM% "/list" "/search:archiver" > %O%\l.txt 2>&1
find "7zip" %O%\l.txt >nul
call :rc0 "M4 /list /search:archiver finds 7zip through its description"
%FM% /list /search:zzznomatchzzz > %O%\l.txt 2>&1
find "0 feature(s)" %O%\l.txt >nul
call :rc0 "M5 a search without a match lists nothing"
%FM% /query 7zip > %O%\q.txt 2>&1
find "InstalledVersion: (not installed)" %O%\q.txt >nul
call :rc0 "M6 7zip not installed: no installed version"

rem --- install 7zip through featmgr, then run it
%FM% /install 7zip > %O%\install-7zip.txt 2>&1
call :rc0 "L20 featmgr /install 7zip rc0"
type %O%\install-7zip.txt >> %LOG%
call :st 7zip Enabled "L21 7zip Enabled"
%FM% /query 7zip > %O%\q.txt 2>&1
type %O%\q.txt | find "Version" >> %LOG%
set IV=
for /f "tokens=2" %%a in ('findstr /b "InstalledVersion:" %O%\q.txt') do set IV=%%a
echo installed version reported by featmgr: %IV%>> %LOG%
dir /b /ad "%SROOT%\apps\7zip" > %O%\vd.txt 2>&1
type %O%\vd.txt >> %LOG%
find "%IV%" %O%\vd.txt >nul
call :rc0 "M7 InstalledVersion equals the version directory Scoop created (apps\7zip\%IV%)"
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "M8 a fresh install has no update pending"
%FM% /list /state:enabled /tier:software > %O%\l.txt 2>&1
findstr /b "7zip" %O%\l.txt | find "%IV%" >nul
call :rc0 "M9 /list shows the installed version"
if exist "%SROOT%\apps\7zip\current\7z.exe" (call :pass "L22 7z.exe in apps\7zip\current") else (call :fail "L22 7z.exe in apps\7zip\current")
if exist "%SROOT%\shims\7z.exe" (call :pass "L23 7z shim created") else (call :fail "L23 7z shim created")
"%SROOT%\shims\7z.exe" > %O%\7z.txt 2>&1
type %O%\7z.txt | find "7-Zip" >> %LOG%
find "7-Zip" %O%\7z.txt >nul
call :rc0 "L24 7z runs (banner)"
mkdir %O%\z7 2>nul
echo scoop-featmgr-7z-payload> %O%\z7\in.txt
"%SROOT%\shims\7z.exe" a -y %O%\z7\t.7z %O%\z7\in.txt > %O%\7za.txt 2>&1
call :rc0 "L25 7z a (create archive) rc0"
"%SROOT%\shims\7z.exe" e -y -o%O%\z7\out %O%\z7\t.7z > %O%\7ze.txt 2>&1
call :rc0 "L26 7z e (extract) rc0"
find "scoop-featmgr-7z-payload" %O%\z7\out\in.txt >nul
call :rc0 "L27 extracted content matches"
rd /s /q %O%\z7 2>nul

rem --- ACLs of what Scoop created after the lock-down (new items must not be writable by users either)
"%PSDIR%\pwsh.exe" -NoProfile -Command "foreach($p in 'C:\scoop\shims\7z.exe','C:\scoop\apps\7zip','C:\scoop\apps\7zip\current\7z.exe'){ '{0}:' -f $p; foreach($a in (Get-Acl $p).Access){ '   {0} {1}' -f $a.IdentityReference,$a.FileSystemRights } }" > %O%\acl2.txt 2>&1
type %O%\acl2.txt >> %LOG%
find "Authenticated Users" %O%\acl2.txt | find "Modify" >nul
call :rc1 "L27a items created later: Authenticated Users have no Modify"
rem informational: does nitro enforce a file ACL at all? (Deny read to Administrators, then read as admin)
"%PSDIR%\pwsh.exe" -NoProfile -Command "$f='C:\aclprobe.txt'; 'x' | Set-Content $f; $s=New-Object System.Security.AccessControl.FileSecurity; $s.SetAccessRuleProtection($true,$false); $a=[System.Security.AccessControl.FileSystemAccessRule]; $adm=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'); $sys=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18'); $s.AddAccessRule((New-Object $a($adm,'ReadData','Deny'))); $s.AddAccessRule((New-Object $a($sys,'FullControl','Allow'))); Set-Acl $f $s; try { Get-Content $f -ErrorAction Stop | Out-Null; 'ACL-ENFORCEMENT: NOT enforced (admin read a file with Deny ReadData for Administrators)' } catch { 'ACL-ENFORCEMENT: enforced (' + $_.Exception.GetType().Name + ')' }; Remove-Item $f -Force -ErrorAction SilentlyContinue" > %O%\aclenf.txt 2>&1
type %O%\aclenf.txt >> %LOG%
del /f /q C:\aclprobe.txt >nul 2>&1

rem --- a REAL update through Scoop: a local bucket "fmlive" whose app fm7z (7-Zip under another name) is first 24.09,
rem then gets the newer manifest (what "scoop update" does when it pulls a bucket); featmgr re-imports and updates.
"%PSDIR%\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File "%FX%\live-mkbucket.ps1" old > %O%\mk-old.txt 2>&1
type %O%\mk-old.txt >> %LOG%
%FM% /import-scoop fmlive /trust > %O%\imp-live.txt 2>&1
call :rc0 "Y1 /import-scoop fmlive /trust (local bucket, fm7z 24.09)"
find "imported 1 Scoop app(s)" %O%\imp-live.txt >nul
call :rc0 "Y2 ...one app imported"
%FM% /install fm7z > %O%\install-fm7z.txt 2>&1
call :rc0 "Y3 featmgr /install fm7z (real scoop install of 7-Zip 24.09)"
type %O%\install-fm7z.txt >> %LOG%
%FM% /query fm7z > %O%\q.txt 2>&1
type %O%\q.txt | find "Version" >> %LOG%
find "InstalledVersion: 24.09" %O%\q.txt >nul
call :rc0 "Y4 installed version 24.09"
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "Y5 no update while the bucket has 24.09"
call fm7z > %O%\fm7z-old.txt 2>&1
find "7-Zip 24.09" %O%\fm7z-old.txt >nul
call :rc0 "Y6 fm7z runs: 7-Zip 24.09"
"%PSDIR%\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File "%FX%\live-mkbucket.ps1" new > %O%\mk-new.txt 2>&1
type %O%\mk-new.txt >> %LOG%
%FM% /import-scoop fmlive /trust > %O%\imp-live.txt 2>&1
call :rc0 "Y7 re-import of fmlive after its manifest got newer"
%FM% /query fm7z > %O%\q.txt 2>&1
type %O%\q.txt | find "Version" >> %LOG%
find "UpdateAvailable: Yes (24.09 ->" %O%\q.txt >nul
call :rc0 "Y8 update available (24.09 to the new version)"
if not defined SHOT goto :noshotY
del /q %O%\gui-timing.txt 2>nul
start "" %SystemRoot%\system32\optfeatures.exe /software /search:fm7z /select:fm7z
ping -n 15 127.0.0.1 >nul
echo SCOOPLIVE:SHOT1>COM2
ping -n 20 127.0.0.1 >nul
taskkill /f /im optfeatures.exe >nul 2>&1
:noshotY
%FM% /update fm7z > %O%\upd-fm7z.txt 2>&1
call :rc0 "Y9 featmgr /update fm7z rc0 (real scoop update: download, hash check, extract, relink)"
type %O%\upd-fm7z.txt >> %LOG%
%FM% /query fm7z > %O%\q.txt 2>&1
type %O%\q.txt | find "Version" >> %LOG%
find "InstalledVersion: 24.09" %O%\q.txt >nul
call :rc1 "Y10 installed version moved off 24.09"
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "Y11 no update pending afterwards"
call fm7z > %O%\fm7z-new.txt 2>&1
type %O%\fm7z-new.txt | find "7-Zip" >> %LOG%
find "7-Zip 24.09" %O%\fm7z-new.txt >nul
call :rc1 "Y12 fm7z is no longer 24.09"
find "7-Zip" %O%\fm7z-new.txt >nul
call :rc0 "Y13 fm7z runs (the new version)"
%FM% /uninstall fm7z > %O%\un-fm7z.txt 2>&1
call :rc0 "Y14 featmgr /uninstall fm7z rc0"

rem --- the imported catalog gets a newer 7zip than the installed one (stands in for "scoop update" having pulled it)
"%PSDIR%\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File "%FX%\live-setver.ps1" "%SystemRoot%\Featmgr\Catalog\Software\scoop-main.idx" 7zip 99.99.99 > %O%\setver.txt 2>&1
type %O%\setver.txt >> %LOG%
find "1 line(s) changed" %O%\setver.txt >nul
call :rc0 "M10 catalog edited: 7zip 99.99.99 available"
%FM% /query 7zip > %O%\q.txt 2>&1
type %O%\q.txt | find "Version" >> %LOG%
find "UpdateAvailable: Yes (%IV% -> 99.99.99)" %O%\q.txt >nul
call :rc0 "M11 query: update available (installed version to 99.99.99)"
%FM% /list /state:enabled /tier:software > %O%\l.txt 2>&1
find "[update available]" %O%\l.txt >nul
call :rc0 "M12 /list marks the update"

rem --- optional (SHOT=1, VM harness): the Optional Features GUI on the Software tab, for screenshots
if not defined SHOT goto :noshot
del /q %O%\gui-timing.txt 2>nul
start "" %SystemRoot%\system32\optfeatures.exe /software
ping -n 15 127.0.0.1 >nul
echo SCOOPLIVE:SHOT2>COM2
ping -n 20 127.0.0.1 >nul
taskkill /f /im optfeatures.exe >nul 2>&1
type %O%\gui-timing.txt >> %LOG%
:noshot

rem --- featmgr /update 7zip: real "scoop update 7zip" (nothing newer exists on the Scoop side), then the bucket is re-read
%FM% /update 7zip > %O%\upd.txt 2>&1
call :rc0 "M13 featmgr /update 7zip rc0 (real scoop update)"
type %O%\upd.txt >> %LOG%
%FM% /query 7zip > %O%\q.txt 2>&1
find "99.99.99" %O%\q.txt >nul
call :rc1 "M14 the refresh re-read the bucket: the made-up 99.99.99 is gone"
find "UpdateAvailable" %O%\q.txt >nul
call :rc1 "M15 no update pending after the refresh"
find "InstalledVersion: %IV%" %O%\q.txt >nul
call :rc0 "M16 7zip still installed at %IV%"

rem --- dependency protection, then uninstall in order
%FM% /uninstall scoop > %O%\un-early.txt 2>&1
call :rc1 "L28 /uninstall scoop refused while 7zip is installed"
find "7zip" %O%\un-early.txt >nul
call :rc0 "L29 ...naming 7zip"
if exist "%SROOT%\shims\scoop.cmd" (call :pass "L30 scoop still there") else (call :fail "L30 scoop still there")

if /i not "%1"=="extras" goto :uninst
rem --- optional: extras bucket (needs git, itself a Scoop app)
%FM% /import-scoop extras > %O%\imp-x0.txt 2>&1
call :rc1 "E1 /import-scoop extras refused before the bucket is added"
find "featmgr /add-bucket extras" %O%\imp-x0.txt >nul
call :rc0 "E2 ...with the command to run (featmgr /add-bucket extras)"
%FM% /add-bucket nosuchbucketxyz > %O%\ab0.txt 2>&1
call :rc1 "E2a /add-bucket of a name Scoop does not know is refused"
%FM% /add-bucket extras https://example.invalid/extras > %O%\ab0.txt 2>&1
call :rc1 "E2b ...and so is a known name with a URL, without /trust"
%FM% /install git > %O%\install-git.txt 2>&1
call :rc0 "E3 featmgr /install git rc0"
rem --- postgresql: initdb re-runs itself with a restricted token (no Administrators) and chmods its data dir
call scoop install postgresql > %O%\install-pg.txt 2>&1
type %O%\install-pg.txt >> %LOG%
find "could not change permissions" %O%\install-pg.txt >nul
call :rc1 "E3a scoop install postgresql: initdb does not fail with 'could not change permissions'"
find "Success. You can now start the database server" %O%\install-pg.txt >nul
call :rc0 "E3b initdb initialised the cluster"
%FM% /uninstall postgresql > %O%\uninstall-pg.txt 2>&1
call :rc0 "E3c featmgr /uninstall postgresql rc0 (so the later /uninstall scoop is not blocked by a dependent)"
type %O%\install-git.txt >> %LOG%
%FM% /add-bucket extras > %O%\bucket.txt 2>&1
call :rc0 "E4 featmgr /add-bucket extras (known bucket, added through Scoop, imported) rc0"
type %O%\bucket.txt >> %LOG%
if exist "%SROOT%\buckets\extras\bucket" (call :pass "E4a Scoop has the extras bucket") else (call :fail "E4a Scoop has the extras bucket")
if exist "%SystemRoot%\Featmgr\Catalog\Software\scoop-extras.idx" (call :pass "E4b extras imported into its own index file") else (call :fail "E4b extras imported into its own index file")
%FM% /add-bucket extras > %O%\bucket2.txt 2>&1
call :rc0 "E4c adding it again is harmless"
find "already added" %O%\bucket2.txt >nul
call :rc0 "E4d ...and says so"
call scoop bucket known > %O%\known.txt 2>&1
type %O%\known.txt >> %LOG%
%FM% /scoop-buckets > %O%\b.txt 2>&1
type %O%\b.txt >> %LOG%
find "Known buckets" %O%\b.txt >nul
call :rc0 "E5 /scoop-buckets lists the known buckets"
call :knownchk main
call :knownchk extras
call :knownchk versions
%FM% /import-scoop extras /timing > %O%\imp-x.txt 2>&1
call :rc0 "E6 featmgr /import-scoop extras (re-import) rc0"
type %O%\imp-x.txt | find "imported" >> %LOG%
findstr /b "timing:" %O%\imp-x.txt > %O%\t1.txt
for /f "tokens=*" %%a in (%O%\t1.txt) do echo TIMING /import-scoop extras: %%a>> %LOG%
%FM% /list /tier:software /timing > %O%\l-all2.txt 2>&1
call :rc0 "E7 /list over main + extras rc0"
findstr /b "timing:" %O%\l-all2.txt > %O%\t1.txt
for /f "tokens=*" %%a in (%O%\t1.txt) do echo TIMING /list main+extras: %%a>> %LOG%
find "feature(s)" %O%\l-all2.txt >> %LOG%
%FM% /list /tier:software /timing /search:git > %O%\l.txt 2>&1
find "git " %O%\l.txt >nul
call :rc0 "E8 /list /search:git over main + extras"
findstr /b "timing:" %O%\l.txt > %O%\t1.txt
for /f "tokens=*" %%a in (%O%\t1.txt) do echo TIMING /list /search:git: %%a>> %LOG%
%FM% /query git > %O%\q.txt 2>&1
find "InstalledVersion:" %O%\q.txt | find "(not installed)" >nul
call :rc1 "E9 git (installed above as the bucket-add prerequisite) shows an installed version"
type %O%\q.txt | find "Version" >> %LOG%
%FM% /list /tier:software /source:scoop/extras > %O%\l.txt 2>&1
find "feature(s)" %O%\l.txt >> %LOG%
if not defined SHOT goto :noshot3
del /q %O%\gui-timing.txt 2>nul
start "" %SystemRoot%\system32\optfeatures.exe /software /search:distributed /select:git
ping -n 30 127.0.0.1 >nul
echo SCOOPLIVE:SHOT3>COM2
ping -n 20 127.0.0.1 >nul
taskkill /f /im optfeatures.exe >nul 2>&1
type %O%\gui-timing.txt >> %LOG%
del /q %O%\gui-timing.txt 2>nul
start "" %SystemRoot%\system32\optfeatures.exe /addbucket
ping -n 20 127.0.0.1 >nul
echo SCOOPLIVE:SHOT4>COM2
ping -n 10 127.0.0.1 >nul
taskkill /f /im optfeatures.exe >nul 2>&1
echo GUI open with every Scoop entry listed (no search, no filter):>> %LOG%
type %O%\gui-timing.txt >> %LOG%
:noshot3
rem --- a real update. Scoop installed from the zip has no git, so "main" is a plain folder and Scoop cannot find older
rem versions in it or pull it. Now that git is here, main is re-added as a git clone (featmgr /add-bucket main: a known bucket
rem added through featmgr), then featmgr /update /all runs the real scoop update (git pull of the buckets).
call scoop bucket rm main > %O%\rmmain.txt 2>&1
type %O%\rmmain.txt >> %LOG%
%FM% /add-bucket main > %O%\addmain.txt 2>&1
call :rc0 "R0 featmgr /add-bucket main (known bucket, re-added as a git clone) rc0"
type %O%\addmain.txt | find "imported" >> %LOG%
if exist "%SROOT%\buckets\main\.git" (call :pass "R0a main is a git repository now") else (call :fail "R0a main is a git repository now")
%FM% /update /all > %O%\updall.txt 2>&1
call :rc0 "R8 featmgr /update /all rc0 (real scoop update, re-import, scoop update *)"
type %O%\updall.txt >> %LOG%
%FM% /uninstall git >> %LOG% 2>&1
call :rc0 "E10 featmgr /uninstall git rc0"

:uninst
%FM% /uninstall 7zip > %O%\un-7zip.txt 2>&1
call :rc0 "U1 featmgr /uninstall 7zip rc0"
type %O%\un-7zip.txt >> %LOG%
call :st 7zip NotInstalled "U2 7zip NotInstalled"
if exist "%SROOT%\apps\7zip" (call :fail "U3 apps\7zip removed") else (call :pass "U3 apps\7zip removed")
if exist "%SROOT%\shims\7z.exe" (call :fail "U4 7z shim removed") else (call :pass "U4 7z shim removed")

%FM% /uninstall scoop > %O%\un-scoop.txt 2>&1
call :rc0 "U5 featmgr /uninstall scoop rc0"
type %O%\un-scoop.txt >> %LOG%
call :st scoop NotInstalled "U6 scoop NotInstalled"
if exist "%SROOT%" (call :fail "U7 C:\scoop removed") else (call :pass "U7 C:\scoop removed")
reg query "%ENVKEY%" /v SCOOP >nul 2>&1
call :rc1 "U8 machine SCOOP variable removed"
reg query "%ENVKEY%" /v Path | find "C:\scoop" >nul
call :rc1 "U9 machine PATH no longer has C:\scoop"
call :st powershell-7 Enabled "U10 powershell-7 left in place (not Scoop's to remove)"

if "%FAILS%"=="0" (echo SCOOPLIVE-RESULT: PASS>> %LOG%) else (echo SCOOPLIVE-RESULT: FAIL %FAILS% >> %LOG%)
goto :eof

:knownchk
find "%~1" %O%\known.txt >nul
if errorlevel 1 goto :knownbad
find "%~1" %O%\b.txt >nul
if errorlevel 1 goto :knownbad
call :pass "E5 known bucket %~1: in scoop bucket known and in featmgr /scoop-buckets"
goto :eof
:knownbad
call :fail "E5 known bucket %~1 missing from scoop bucket known or featmgr /scoop-buckets"
goto :eof

:stq
%FM% /state %1 > %O%\s.txt 2>&1
echo %1 state at start: >> %LOG%
type %O%\s.txt >> %LOG%
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
