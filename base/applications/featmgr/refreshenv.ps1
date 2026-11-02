# refreshenv - re-read PATH (registry machine + user) into THIS PowerShell session, e.g. after
# "featmgr /install scoop". A program cannot change its parent shell's environment, but a script that the
# shell itself runs can ($env:Path is process-wide). Entries the session has that the registry does not are kept.
# Ships in system32 (on PATH); no profile is touched. In PowerShell this .ps1 wins over refreshenv.cmd.
$new = New-Object System.Collections.Generic.List[string]
$seen = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
$all = @([Environment]::GetEnvironmentVariable('Path', 'Machine'),
         [Environment]::GetEnvironmentVariable('Path', 'User'),
         $env:Path)
foreach ($list in $all) {
    if (-not $list) { continue }
    foreach ($e in [Environment]::ExpandEnvironmentVariables($list).Split(';')) {
        $t = $e.Trim()
        if ($t -and $seen.Add($t.TrimEnd('\'))) { $new.Add($t) }
    }
}
$env:Path = $new -join ';'
