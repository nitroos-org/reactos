# Start-NitroDiag: a thin wrapper over nitrodiag.exe (all the work is done by the native tool; nothing is uploaded).
function Start-NitroDiag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)] [string] $FilePath,
        [Parameter(Position = 1)] [string[]] $ArgumentList,
        [string] $OutDirectory,
        [int] $Timeout
    )
    $tool = Join-Path $env:SystemRoot 'system32\nitrodiag.exe'
    $a = @('/quiet')
    if ($OutDirectory) { $a += '/out', $OutDirectory }
    if ($Timeout -gt 0) { $a += '/timeout', "$Timeout" }
    $a += '--', $FilePath
    if ($ArgumentList) { $a += $ArgumentList }
    $out = @(& $tool @a)
    $path = $out | ForEach-Object { if ($_ -match '^Report saved to (.+)$') { $Matches[1].Trim() } } | Select-Object -Last 1
    if (-not $path) { $out; throw 'nitrodiag.exe did not report a saved file' }
    $out | Select-Object -First 1 | Write-Host
    $path
}
Export-ModuleMember -Function Start-NitroDiag
