<#
.SYNOPSIS
    featmgr "scoop" feature: install Scoop headless, machine-wide (SCOOP-FEATMGR-01).
.DESCRIPTION
    Run by featmgr with PowerShell 7 (pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File).
    1. Adopts an existing Scoop in the root (exit 0), refuses a non-empty foreign directory.
    2. Downloads the upstream installer from a COMMIT-PINNED URL (not the moving get.scoop.sh) and
       refuses to run it unless its SHA-256 equals $InstallerSha256.
    3. Runs it with -ScoopDir <root> -RunAsAdmin (nitro's account is an administrator).
    4. Makes Scoop machine-wide: machine SCOOP variable + <root>\shims on the machine PATH.
    Exit 0 = Scoop is installed and usable; anything else = failure (message on stdout).

    What the pin covers: this script. The pinned installer itself downloads Scoop and the Main bucket
    as .../archive/master.zip (its own "TODO: Use a specific version"), or git-clones them if git is
    on PATH; those cannot be hashed from outside. Every app download is later verified by Scoop
    against the hash in its manifest.

    Bumping the pin (manual, reviewed, then re-run tests\scoop-live.cmd):
      git ls-remote https://github.com/ScoopInstaller/Install master        -> new commit
      curl -L https://raw.githubusercontent.com/ScoopInstaller/Install/<commit>/install.ps1 | sha256sum
    and change $InstallerCommit / $InstallerSha256 here and Artifact / ArtifactSHA256 in scoop.ini.
#>
param([string] $Root)

$ErrorActionPreference = 'Stop'
$InstallerCommit = '1e2f334083d609986d8c8bc9e31ae8e87c39fab4'
$InstallerSha256 = '94f983b190438311e006b957db7c8422709e0ba62a6c2ac04e278164108f2512'
$InstallerUrl    = "https://raw.githubusercontent.com/ScoopInstaller/Install/$InstallerCommit/install.ps1"

function Say($m) { Write-Output ("scoop-install: " + $m) }
function Die($m) { Write-Output ("scoop-install: ERROR: " + $m); exit 1 }

function New-ScoopAcl($isDir) {
    $fs = [System.Security.AccessControl.FileSystemRights]
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    if ($isDir) {
        $sec = New-Object System.Security.AccessControl.DirectorySecurity
        $inh = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    } else {
        $sec = New-Object System.Security.AccessControl.FileSecurity
        $inh = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $sec.SetAccessRuleProtection($true, $false)                # nothing inherited from the parent
    $grants = @(@('S-1-5-18', $fs::FullControl), @('S-1-5-32-544', $fs::FullControl),
                @('S-1-5-32-545', $fs::ReadAndExecute), @('S-1-5-11', $fs::ReadAndExecute))
    # The installing account's own SID too. Administrators alone is not enough: a program that drops the
    # Administrators group from its token (PostgreSQL's initdb and pg_ctl re-run themselves with
    # CreateRestrictedToken, Administrators deny-only) is left with Users / Authenticated Users, i.e.
    # read-only, and its chmod of the data directory fails with "Permission denied". Windows does the same
    # with the same ACL (measured on Windows 10 22H2); an ACE for the user's own SID lets it through.
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($me -and $me.Value -ne 'S-1-5-18') { $grants += ,@($me.Value, $fs::FullControl) }
    foreach ($g in $grants) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($g[0])
        $sec.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sid, $g[1], $inh, $none, $allow)))
    }
    return $sec
}

function Lock-ScoopRoot($dir) {
    # The shims dir is on the MACHINE PATH, so a user who could write into it could plant a program that
    # administrators then run. Folders created under C:\ normally inherit "Authenticated Users: Modify".
    # Cut that inheritance and grant SYSTEM and Administrators full control, Users and Authenticated Users
    # read and execute only (well-known SIDs: independent of the display language). Measured on nitro: an
    # ACL set on the root is NOT pushed down to the files that already exist, so every existing item gets
    # the ACL explicitly (junctions are not followed); items created later inherit from their parent.
    # Best effort: where the file system cannot hold or apply ACLs, say so and carry on.
    try {
        Set-Acl -LiteralPath $dir -AclObject (New-ScoopAcl $true)
        $n = 0; $bad = 0
        Get-ChildItem -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } |
            ForEach-Object {
                try { Set-Acl -LiteralPath $_.FullName -AclObject (New-ScoopAcl $_.PSIsContainer); $n++ } catch { $bad++ }
            }
        $back = Get-Acl -LiteralPath $dir
        Say ("ACL on ${dir}: inheritance " + $(if ($back.AreAccessRulesProtected) { 'off' } else { 'STILL ON' }) + "; $n existing items locked, $bad failed")
        foreach ($a in $back.Access) { Say ("  " + $a.IdentityReference + " " + $a.FileSystemRights + " " + $a.AccessControlType) }
    } catch {
        Say ("WARNING: could not restrict the ACL of ${dir}: " + $_.Exception.Message)
    }
}

try {
    if (-not $Root) {
        $Root = [Environment]::GetEnvironmentVariable('SCOOP', 'Machine')
        if (-not $Root) { $Root = Join-Path $env:SystemDrive 'scoop' }
    }
    $shim = Join-Path $Root 'shims\scoop.cmd'
    $core = Join-Path $Root 'apps\scoop\current\bin\scoop.ps1'
    $env:SCOOP = $Root

    if ((Test-Path $core) -and -not (Test-Path $shim)) {
        # The Scoop installer creates its shim last: core without shim is what a failed or cancelled install
        # leaves behind (a retry used to "adopt" it and stop at "scoop.cmd is missing"). When the root holds
        # nothing but that (no other app, no persisted data), clear it and install again; anything else in
        # it is the user's and is not touched.
        $apps = @(Get-ChildItem -LiteralPath (Join-Path $Root 'apps') -Force -ErrorAction SilentlyContinue)
        $bkts = @(Get-ChildItem -LiteralPath (Join-Path $Root 'buckets') -Force -ErrorAction SilentlyContinue)
        $top  = @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction SilentlyContinue)
        $onlyScoop = (-not ($apps | Where-Object { $_.Name -ne 'scoop' })) -and
                     (-not ($bkts | Where-Object { $_.Name -ne 'main' })) -and
                     (-not ($top  | Where-Object { @('apps', 'buckets', 'shims', 'cache') -notcontains $_.Name }))
        if (-not $onlyScoop) { Die "Scoop in $Root is damaged ($shim is missing) and the folder holds other data; repair or remove it first" }
        Say "found a half-finished Scoop install in $Root ($shim is missing); removing it and starting over"
        # junctions (apps\<app>\current) first, without following them
        Get-ChildItem -LiteralPath (Join-Path $Root 'apps') -Force -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
                ForEach-Object { cmd.exe /c rmdir "$($_.FullName)" 2>&1 | Out-Null }
        }
        Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path $Root) { Die "cannot remove the half-finished Scoop install in $Root" }
    }

    if (Test-Path $core) {
        Say "Scoop already present in $Root; adopting it"
    } else {
        if ((Test-Path $Root) -and (Get-ChildItem -Force $Root -ErrorAction SilentlyContinue)) {
            Die "$Root exists and is not empty (and holds no Scoop); move it away first"
        }
        # --- fetch + verify the pinned installer
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("scoop-install-" + [Guid]::NewGuid().ToString('N') + '.ps1')
        $ok = $false
        for ($try = 1; $try -le 3 -and -not $ok; $try++) {
            try {
                Say "downloading $InstallerUrl (attempt $try)"
                Invoke-WebRequest -Uri $InstallerUrl -UseBasicParsing -OutFile $tmp -TimeoutSec 120
                $ok = $true
            } catch {
                Say ("download failed: " + $_.Exception.Message)
                if ($try -lt 3) { Start-Sleep -Seconds 3 }
            }
        }
        if (-not $ok) { Die "cannot download the Scoop installer (check the network connection): $InstallerUrl" }
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant()
        if ($got -ne $InstallerSha256) {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
            Die "SHA-256 of the downloaded installer is $got, expected $InstallerSha256; refusing to run it"
        }
        Say "installer SHA-256 verified; running it (root $Root)"
        $global:LASTEXITCODE = 0
        try {
            & $tmp -ScoopDir $Root -RunAsAdmin
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
        if ($LASTEXITCODE -ne 0) { Die "the Scoop installer exited with code $LASTEXITCODE" }
    }

    if (-not (Test-Path $shim)) { Die "Scoop installer finished but $shim is missing" }

    # --- machine-wide: SCOOP + shims on the machine PATH (the installer only touched the user's)
    [Environment]::SetEnvironmentVariable('SCOOP', $Root, 'Machine')
    $shims = Join-Path $Root 'shims'
    $mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    if (-not (($mp -split ';') -contains $shims)) {
        [Environment]::SetEnvironmentVariable('Path', ($shims + ';' + $mp), 'Machine')
    }
    Lock-ScoopRoot $Root
    Say "Scoop is installed in $Root"
    exit 0
} catch {
    Die ($_.Exception.Message)
}
