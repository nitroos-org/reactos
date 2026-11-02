<#
.SYNOPSIS
    featmgr "scoop" feature: remove Scoop, every app installed with it, and the environment entries.
.DESCRIPTION
    Runs Scoop's own uninstaller (bin\uninstall.ps1 with purge; its confirmation prompt is answered
    on stdin), then removes the machine/user SCOOP variable and shims PATH entries. If Scoop's
    uninstaller leaves the directory behind, junctions are removed first (without following them) and
    the tree is deleted. Exit 0 = Scoop is gone.
#>
param([string] $Root)

$ErrorActionPreference = 'Continue'
function Say($m) { Write-Output ("scoop-uninstall: " + $m) }

if (-not $Root) {
    $Root = [Environment]::GetEnvironmentVariable('SCOOP', 'Machine')
    if (-not $Root) { $Root = Join-Path $env:SystemDrive 'scoop' }
}
$shims = Join-Path $Root 'shims'
$env:SCOOP = $Root
$env:PATH = "$shims;$env:PATH"

$uninst = Join-Path $Root 'apps\scoop\current\bin\uninstall.ps1'
if (Test-Path $uninst) {
    Say "running Scoop's uninstaller"
    $pwsh = (Get-Process -Id $PID).Path
    # uninstall.ps1 takes [bool] parameters and asks 'Are you sure? (yN)': feed it 'y' on stdin.
    'y' | & $pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "& '$uninst' `$false `$true"
    Say "Scoop's uninstaller exited with $LASTEXITCODE"
}

if (Test-Path $Root) {
    Say "directory still present; removing junctions, then the tree"
    Get-ChildItem -Path (Join-Path $Root 'apps'), (Join-Path $Root 'persist') -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
                ForEach-Object { cmd.exe /c rmdir "$($_.FullName)" 2>&1 | Out-Null }
        }
    Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue
}

# --- environment: machine + user SCOOP variable and the shims PATH entry
foreach ($scope in 'Machine', 'User') {
    # [NullString]::Value, not $null: PowerShell 7 turns a bare $null into "" here and .NET then stores an
    # EMPTY variable instead of deleting it (scoop-live U8). Unconditional, so an empty value that an older
    # uninstall left behind is removed too (deleting an absent variable is a no-op).
    [Environment]::SetEnvironmentVariable('SCOOP', [NullString]::Value, $scope)
    $p = [Environment]::GetEnvironmentVariable('Path', $scope)
    if ($p) {
        $keep = ($p -split ';') | Where-Object { $_ -and ($_.TrimEnd('\') -ne $shims.TrimEnd('\')) }
        $new = $keep -join ';'
        if ($new -ne $p) { [Environment]::SetEnvironmentVariable('Path', $new, $scope) }
    }
}

if (Test-Path $Root) { Say "ERROR: $Root could not be removed"; exit 1 }
Say "Scoop removed"
exit 0
