# Pester 4 tests of the ScheduledTasks module (Get-/Register-/Unregister-/Start-/Stop-/Enable-/Disable-ScheduledTask,
# Get-ScheduledTaskInfo, New-ScheduledTask{Action,Trigger,Principal,SettingsSet}) for the nitro guest.
# The expectations are the shapes measured on the Windows 10 reference machine (PowerShell 7.4.22, the Windows module):
# type-name chains, property sets and their order, value types, defaults, the default table, error ids and texts.
# The round trip registers throw-away tasks named NitroPester-* in the root folder and a temp file; it needs a running
# Schedule service (the nitro guest) and is skipped when SCHT_NOROUNDTRIP=1.
Import-Module ScheduledTasks -Force -ErrorAction Stop
$skipRt = ($env:SCHT_NOROUNDTRIP -eq '1')

$CI = 'Microsoft.Management.Infrastructure.CimInstance'
$NS = "$CI#Root/Microsoft/Windows/TaskScheduler"
$NSU = "$CI#ROOT/Microsoft/Windows/TaskScheduler"
$EnumNs = 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask'
$trigBase = 'Enabled', 'EndBoundary', 'ExecutionTimeLimit', 'Id', 'Repetition', 'StartBoundary'

function Err([scriptblock]$sb) {
    $ErrorActionPreference = 'Continue'
    try { @(& $sb 2>&1 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) } catch { @($_) }
}
function Ok([scriptblock]$sb) { @(& $sb 2>$null) }
function Names($o) { @($o.psobject.Properties.Name) }
function Chain($cls, $parents) {
    @("$NS/$cls") + @($parents | ForEach-Object { "$NSU/$_" }) + @("$CI#$cls") + @($parents | ForEach-Object { "$CI#$_" }) + @($CI, 'System.Object')
}
function HeaderTokens($o) {
    $lines = @(($o | Format-Table | Out-String -Width 250) -split "`r?`n" | Where-Object { $_.Trim() })
    @($lines[0].Trim() -split '\s+')
}
function Wait-Until([scriptblock]$Cond, [int]$Seconds = 60) {
    $end = [datetime]::Now.AddSeconds($Seconds)
    while ([datetime]::Now -lt $end) { if (& $Cond) { return $true }; Start-Sleep -Milliseconds 500 }
    $false
}

$script:Created = [System.Collections.Generic.List[string]]::new()
function New-TestName { $n = 'NitroPester-' + [guid]::NewGuid().ToString('N').Substring(0, 8); $script:Created.Add($n); $n }
function Remove-TestTasks { foreach ($n in $script:Created) { Unregister-ScheduledTask -TaskName $n -Confirm:$false -ErrorAction SilentlyContinue } }

Describe 'module surface' {
    It 'imports without output or errors' {
        $out = @(Import-Module ScheduledTasks -Force -ErrorAction Stop *>&1)
        $out.Count | Should -Be 0
    }
    It 'is ScheduledTasks 1.0.0.0' { (Get-Module ScheduledTasks).Version.ToString() | Should -Be '1.0.0.0' }
    It 'exports <Name> from ScheduledTasks' -TestCases @(
        'Get-ScheduledTask', 'Get-ScheduledTaskInfo', 'Register-ScheduledTask', 'Unregister-ScheduledTask', 'Start-ScheduledTask', 'Stop-ScheduledTask',
        'Enable-ScheduledTask', 'Disable-ScheduledTask', 'New-ScheduledTask', 'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger',
        'New-ScheduledTaskPrincipal', 'New-ScheduledTaskSettingsSet' | ForEach-Object { @{ Name = $_ } }) {
        param($Name)
        (Get-Command $Name).Source | Should -Be 'ScheduledTasks'
        (Get-Command $Name).CommandType | Should -Be 'Function'
    }
    It 'has the default parameter set <Set> on <Name>' -TestCases @(
        @{ Name = 'Get-ScheduledTask'; Set = 'ByPath' }, @{ Name = 'Register-ScheduledTask'; Set = 'User' },
        @{ Name = 'Unregister-ScheduledTask'; Set = 'ByPath' }, @{ Name = 'Start-ScheduledTask'; Set = 'Path' },
        @{ Name = 'Stop-ScheduledTask'; Set = 'Path' }, @{ Name = 'New-ScheduledTaskTrigger'; Set = 'Once' },
        @{ Name = 'New-ScheduledTaskPrincipal'; Set = 'User' }) {
        param($Name, $Set)
        (Get-Command $Name).DefaultParameterSet | Should -Be $Set
    }
    It '<Name> -<Param> has set <Set>, position <Pos>, mandatory <Mand>' -TestCases @(
        @{ Name = 'Get-ScheduledTask'; Param = 'TaskName'; Set = 'ByPath'; Pos = 0; Mand = $false }
        @{ Name = 'Get-ScheduledTask'; Param = 'TaskPath'; Set = 'ByPath'; Pos = 1; Mand = $false }
        @{ Name = 'Get-ScheduledTaskInfo'; Param = 'TaskName'; Set = 'Name'; Pos = 0; Mand = $true }
        @{ Name = 'Get-ScheduledTaskInfo'; Param = 'TaskPath'; Set = 'Name'; Pos = 1; Mand = $false }
        @{ Name = 'Get-ScheduledTaskInfo'; Param = 'InputObject'; Set = 'Object'; Pos = 0; Mand = $true }
        @{ Name = 'Register-ScheduledTask'; Param = 'TaskName'; Set = 'User'; Pos = 0; Mand = $true }
        @{ Name = 'Register-ScheduledTask'; Param = 'TaskPath'; Set = 'User'; Pos = 1; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'Action'; Set = 'User'; Pos = 2; Mand = $true }
        @{ Name = 'Register-ScheduledTask'; Param = 'Trigger'; Set = 'User'; Pos = 3; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'Settings'; Set = 'User'; Pos = 4; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'User'; Set = 'User'; Pos = 5; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'Password'; Set = 'User'; Pos = 6; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'RunLevel'; Set = 'User'; Pos = 7; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'Description'; Set = 'User'; Pos = 8; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'Xml'; Set = 'Xml'; Pos = 2; Mand = $true }
        @{ Name = 'Register-ScheduledTask'; Param = 'Principal'; Set = 'Principal'; Pos = 5; Mand = $false }
        @{ Name = 'Register-ScheduledTask'; Param = 'InputObject'; Set = 'Object'; Pos = 2; Mand = $true }
        @{ Name = 'Start-ScheduledTask'; Param = 'TaskName'; Set = 'Path'; Pos = 0; Mand = $true }
        @{ Name = 'Start-ScheduledTask'; Param = 'InputObject'; Set = 'Object'; Pos = 1; Mand = $true }
        @{ Name = 'Enable-ScheduledTask'; Param = 'TaskName'; Set = 'Name'; Pos = 0; Mand = $true }
        @{ Name = 'Enable-ScheduledTask'; Param = 'InputObject'; Set = 'Object'; Pos = 0; Mand = $true }
        @{ Name = 'New-ScheduledTaskAction'; Param = 'Execute'; Set = 'Exec'; Pos = 0; Mand = $true }
        @{ Name = 'New-ScheduledTaskAction'; Param = 'Argument'; Set = 'Exec'; Pos = 1; Mand = $false }
        @{ Name = 'New-ScheduledTaskAction'; Param = 'WorkingDirectory'; Set = 'Exec'; Pos = 2; Mand = $false }
        @{ Name = 'New-ScheduledTaskTrigger'; Param = 'Once'; Set = 'Once'; Pos = 0; Mand = $true }
        @{ Name = 'New-ScheduledTaskTrigger'; Param = 'At'; Set = 'Once'; Pos = -2147483648; Mand = $true }
        @{ Name = 'New-ScheduledTaskTrigger'; Param = 'Daily'; Set = 'Daily'; Pos = 0; Mand = $true }
        @{ Name = 'New-ScheduledTaskTrigger'; Param = 'AtStartup'; Set = 'Startup'; Pos = 0; Mand = $true }
        @{ Name = 'New-ScheduledTaskTrigger'; Param = 'AtLogOn'; Set = 'Logon'; Pos = 0; Mand = $true }
        @{ Name = 'New-ScheduledTaskPrincipal'; Param = 'UserId'; Set = 'User'; Pos = 0; Mand = $true }
        @{ Name = 'New-ScheduledTaskPrincipal'; Param = 'LogonType'; Set = 'User'; Pos = 1; Mand = $false }
        @{ Name = 'New-ScheduledTaskPrincipal'; Param = 'RunLevel'; Set = 'User'; Pos = 2; Mand = $false }
        @{ Name = 'New-ScheduledTaskPrincipal'; Param = 'GroupId'; Set = 'Group'; Pos = 0; Mand = $true }
    ) {
        param($Name, $Param, $Set, $Pos, $Mand)
        $a = (Get-Command $Name).Parameters[$Param].ParameterSets[$Set]
        $a | Should -Not -BeNullOrEmpty
        $a.Position | Should -Be $Pos
        $a.IsMandatory | Should -Be $Mand
    }
    It 'Unregister-ScheduledTask supports ShouldProcess with ConfirmImpact High' {
        $m = [System.Management.Automation.CommandMetadata]::new((Get-Command Unregister-ScheduledTask))
        $m.SupportsShouldProcess | Should -BeTrue
        $m.ConfirmImpact | Should -Be 'High'
    }
    It 'defines the Windows enum types in the Cmdletization namespace' {
        $e = @{ StateEnum = 'Unknown,Disabled,Queued,Ready,Running'; RunLevelEnum = 'Limited,Highest'
                LogonTypeEnum = 'None,Password,S4U,Interactive,Group,ServiceAccount,InteractiveOrPassword'
                MultipleInstancesEnum = 'Parallel,Queue,IgnoreNew'; CompatibilityEnum = 'At,V1,Vista,Win7,Win8'
                ProcessTokenSidTypeEnum = 'None,Unrestricted,Default' }
        foreach ($k in $e.Keys) {
            $t = "$EnumNs.$k" -as [type]
            $t | Should -Not -BeNullOrEmpty
            ([enum]::GetNames($t) -join ',') | Should -Be $e[$k]
        }
    }
    It 'loads in a fresh pwsh by name without errors' {
        $pwsh = (Get-Process -Id $PID).Path
        $r = & $pwsh -NoLogo -NoProfile -NonInteractive -Command '$e = $Error.Count; (Get-Module -ListAvailable ScheduledTasks | Measure-Object).Count; (Get-Command New-ScheduledTaskAction).Source; "errors=$($Error.Count - $e)"' 2>&1
        @($r) | Should -Contain '1'
        @($r) | Should -Contain 'ScheduledTasks'
        @($r) | Should -Contain 'errors=0'
    }
}

Describe 'New-ScheduledTaskAction' {
    It 'has the MSFT_TaskExecAction type chain and the measured properties' {
        $a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo hi' -WorkingDirectory 'C:\Windows'
        $a.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskExecAction' @('MSFT_TaskAction'))
        (Names $a) | Should -Be @('Id', 'Arguments', 'Execute', 'WorkingDirectory', 'PSComputerName')
        $a.Execute | Should -Be 'cmd.exe'; $a.Arguments | Should -Be '/c echo hi'; $a.WorkingDirectory | Should -Be 'C:\Windows'
        $a.Id | Should -BeNullOrEmpty
    }
    It 'leaves Arguments, WorkingDirectory and Id null when not given' {
        $a = New-ScheduledTaskAction -Execute 'cmd.exe'
        $null -eq $a.Arguments | Should -BeTrue; $null -eq $a.WorkingDirectory | Should -BeTrue; $null -eq $a.Id | Should -BeTrue
    }
    It 'rejects an empty Execute' {
        $e = @(Err { New-ScheduledTaskAction -Execute '' })
        $e[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentValidationError,New-ScheduledTaskAction'
    }
    It 'takes Execute and Argument by position' {
        $a = New-ScheduledTaskAction 'a.exe' '-x'
        $a.Execute | Should -Be 'a.exe'; $a.Arguments | Should -Be '-x'
    }
}

Describe 'New-ScheduledTaskTrigger' {
    It 'Once: MSFT_TaskTimeTrigger, property set, UTC start boundary' {
        $at = [datetime]'2030-01-02 11:04:05'
        $t = New-ScheduledTaskTrigger -Once -At $at
        $t.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskTimeTrigger' @('MSFT_TaskTrigger'))
        (Names $t) | Should -Be ($trigBase + @('RandomDelay', 'PSComputerName'))
        $t.StartBoundary | Should -Be ($at.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
        $t.Enabled | Should -BeTrue
        $null -eq $t.Repetition | Should -BeTrue; $null -eq $t.RandomDelay | Should -BeTrue
        $null -eq $t.EndBoundary | Should -BeTrue; $null -eq $t.Id | Should -BeTrue
    }
    It 'a string and a UTC DateTime are accepted for -At' {
        (New-ScheduledTaskTrigger -Once -At '2030-01-02 03:04:00').StartBoundary | Should -Be (([datetime]'2030-01-02 03:04:00').ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
        (New-ScheduledTaskTrigger -Once -At ([datetime]::SpecifyKind([datetime]'2030-01-02 03:04:05', 'Utc'))).StartBoundary | Should -Be '2030-01-02T03:04:05Z'
    }
    It 'Once with repetition: MSFT_TaskRepetitionPattern, StopAtDurationEnd true' {
        $t = New-ScheduledTaskTrigger -Once -At '2030-01-02 03:04:05' -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 1)
        $t.Repetition.PSObject.TypeNames | Should -Be @("$NS/MSFT_TaskRepetitionPattern", "$CI#MSFT_TaskRepetitionPattern", $CI, 'System.Object')
        (Names $t.Repetition) | Should -Be @('Duration', 'Interval', 'StopAtDurationEnd', 'PSComputerName')
        $t.Repetition.Interval | Should -Be 'PT10M'; $t.Repetition.Duration | Should -Be 'P1D'; $t.Repetition.StopAtDurationEnd | Should -BeTrue
    }
    It 'Once with only an interval or only a duration fills just that field' {
        $i = New-ScheduledTaskTrigger -Once -At '2030-01-02 03:04:05' -RepetitionInterval (New-TimeSpan -Minutes 10)
        $i.Repetition.Interval | Should -Be 'PT10M'; $null -eq $i.Repetition.Duration | Should -BeTrue; $i.Repetition.StopAtDurationEnd | Should -BeTrue
        $d = New-ScheduledTaskTrigger -Once -At '2030-01-02 03:04:05' -RepetitionDuration (New-TimeSpan -Days 1)
        $d.Repetition.Duration | Should -Be 'P1D'; $null -eq $d.Repetition.Interval | Should -BeTrue
    }
    It 'RandomDelay is an ISO 8601 duration' {
        (New-ScheduledTaskTrigger -Once -At '2030-01-02 03:04:05' -RandomDelay (New-TimeSpan -Minutes 5)).RandomDelay | Should -Be 'PT5M'
    }
    It 'Daily: MSFT_TaskDailyTrigger, DaysInterval is Int16 and defaults to 1' {
        $t = New-ScheduledTaskTrigger -Daily -At '2030-01-02 03:04:05'
        $t.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskDailyTrigger' @('MSFT_TaskTrigger'))
        (Names $t) | Should -Be ($trigBase + @('DaysInterval', 'RandomDelay', 'PSComputerName'))
        $t.DaysInterval | Should -Be 1
        $t.DaysInterval.GetType().FullName | Should -Be 'System.Int16'
        (New-ScheduledTaskTrigger -Daily -At '2030-01-02 03:04:05' -DaysInterval 2).DaysInterval | Should -Be 2
    }
    It 'AtStartup: MSFT_TaskBootTrigger with a null Delay (RandomDelay ignored)' {
        $t = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 1)
        $t.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskBootTrigger' @('MSFT_TaskTrigger'))
        (Names $t) | Should -Be ($trigBase + @('Delay', 'PSComputerName'))
        $null -eq $t.Delay | Should -BeTrue; $null -eq $t.StartBoundary | Should -BeTrue
    }
    It 'AtLogOn: MSFT_TaskLogonTrigger with the user' {
        $t = New-ScheduledTaskTrigger -AtLogOn -User 'DOMAIN\bob'
        $t.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskLogonTrigger' @('MSFT_TaskTrigger'))
        (Names $t) | Should -Be ($trigBase + @('Delay', 'UserId', 'PSComputerName'))
        $t.UserId | Should -Be 'DOMAIN\bob'
        $null -eq (New-ScheduledTaskTrigger -AtLogOn).UserId | Should -BeTrue
    }
    It 'Once and Daily need -At' {
        (Err { New-ScheduledTaskTrigger -Once })[0].FullyQualifiedErrorId | Should -Be 'MissingMandatoryParameter,New-ScheduledTaskTrigger'
        (Err { New-ScheduledTaskTrigger -Daily })[0].FullyQualifiedErrorId | Should -Be 'MissingMandatoryParameter,New-ScheduledTaskTrigger'
    }
    It '-Once with -User is an ambiguous parameter set' {
        (Err { New-ScheduledTaskTrigger -Once -At '2030-01-02' -User x })[0].FullyQualifiedErrorId | Should -Be 'AmbiguousParameterSet,New-ScheduledTaskTrigger'
    }
    It 'refuses a weekly trigger (phase-1 limit: the service never fires it)' {
        $e = @(Err { New-ScheduledTaskTrigger -Weekly -At '2030-01-02 03:04:05' -DaysOfWeek Monday })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be 'TriggerTypeNotSupported,New-ScheduledTaskTrigger'
        $e[0].CategoryInfo.Category | Should -Be 'NotImplemented'
    }
}

Describe 'New-ScheduledTaskPrincipal' {
    It 'user only: MSFT_TaskPrincipal2, Interactive, Limited, Default token SID' {
        $p = New-ScheduledTaskPrincipal -UserId 'DOMAIN\bob'
        $p.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskPrincipal2' @('MSFT_TaskPrincipal'))
        (Names $p) | Should -Be @('RunLevel', 'LogonType', 'ProcessTokenSidType', 'DisplayName', 'GroupId', 'Id', 'UserId', 'RequiredPrivilege', 'PSComputerName')
        $p.UserId | Should -Be 'DOMAIN\bob'
        [string]$p.RunLevel | Should -Be 'Limited'; [string]$p.LogonType | Should -Be 'Interactive'; [string]$p.ProcessTokenSidType | Should -Be 'Default'
        $p.RunLevel.GetType().FullName | Should -Be "$EnumNs.RunLevelEnum"
        $p.LogonType.GetType().FullName | Should -Be "$EnumNs.LogonTypeEnum"
        $p.ProcessTokenSidType.GetType().FullName | Should -Be "$EnumNs.ProcessTokenSidTypeEnum"
        $null -eq $p.Id | Should -BeTrue; $null -eq $p.GroupId | Should -BeTrue
    }
    It 'SYSTEM, ServiceAccount, Highest' {
        $p = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
        [string]$p.RunLevel | Should -Be 'Highest'; [string]$p.LogonType | Should -Be 'ServiceAccount'; $p.UserId | Should -Be 'SYSTEM'
    }
    It 'full set: S4U, Unrestricted, Id and privileges' {
        $p = New-ScheduledTaskPrincipal -UserId 'DOMAIN\bob' -LogonType S4U -ProcessTokenSidType Unrestricted -Id X1 -RequiredPrivilege SeBackupPrivilege, SeRestorePrivilege
        [string]$p.LogonType | Should -Be 'S4U'; [string]$p.ProcessTokenSidType | Should -Be 'Unrestricted'; $p.Id | Should -Be 'X1'
        $p.RequiredPrivilege | Should -Be @('SeBackupPrivilege', 'SeRestorePrivilege')
    }
    It 'group: the domain is stripped, LogonType Group, UserId null' {
        $p = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Users'
        $p.GroupId | Should -Be 'Users'; [string]$p.LogonType | Should -Be 'Group'; $null -eq $p.UserId | Should -BeTrue
    }
    It 'enum values can be set as strings and numbers' {
        $p = New-ScheduledTaskPrincipal -UserId x
        $p.RunLevel = 'Highest'; [string]$p.RunLevel | Should -Be 'Highest'
        $p.LogonType = 5; [string]$p.LogonType | Should -Be 'ServiceAccount'
    }
}

Describe 'New-ScheduledTaskSettingsSet' {
    It 'defaults: MSFT_TaskSettings3 with the measured values and types' {
        $s = New-ScheduledTaskSettingsSet
        $s.PSObject.TypeNames | Should -Be @("$NS/MSFT_TaskSettings3", "$NSU/MSFT_TaskSettings2", "$NSU/MSFT_TaskSettings", "$CI#MSFT_TaskSettings3", "$CI#MSFT_TaskSettings2", "$CI#MSFT_TaskSettings", $CI, 'System.Object')
        (Names $s) | Should -Be @('MultipleInstances', 'Compatibility', 'AllowDemandStart', 'AllowHardTerminate', 'DeleteExpiredTaskAfter', 'DisallowStartIfOnBatteries',
            'Enabled', 'ExecutionTimeLimit', 'Hidden', 'IdleSettings', 'NetworkSettings', 'Priority', 'RestartCount', 'RestartInterval', 'RunOnlyIfIdle',
            'RunOnlyIfNetworkAvailable', 'StartWhenAvailable', 'StopIfGoingOnBatteries', 'WakeToRun', 'DisallowStartOnRemoteAppSession',
            'UseUnifiedSchedulingEngine', 'MaintenanceSettings', 'volatile', 'PSComputerName')
        [string]$s.MultipleInstances | Should -Be 'IgnoreNew'; [string]$s.Compatibility | Should -Be 'Win7'
        $s.AllowDemandStart | Should -BeTrue; $s.AllowHardTerminate | Should -BeTrue; $s.DisallowStartIfOnBatteries | Should -BeTrue
        $s.StopIfGoingOnBatteries | Should -BeTrue; $s.Enabled | Should -BeTrue; $s.Hidden | Should -BeFalse
        $s.ExecutionTimeLimit | Should -Be 'PT72H'
        $s.Priority | Should -Be 7; $s.Priority.GetType().FullName | Should -Be 'System.UInt32'
        $s.RestartCount | Should -Be 0; $s.RestartCount.GetType().FullName | Should -Be 'System.UInt32'
        $s.StartWhenAvailable | Should -BeFalse; $s.UseUnifiedSchedulingEngine | Should -BeTrue; $s.volatile | Should -BeFalse
        $null -eq $s.DeleteExpiredTaskAfter | Should -BeTrue; $null -eq $s.RestartInterval | Should -BeTrue; $null -eq $s.MaintenanceSettings | Should -BeTrue
        $s.MultipleInstances.GetType().FullName | Should -Be "$EnumNs.MultipleInstancesEnum"
        $s.Compatibility.GetType().FullName | Should -Be "$EnumNs.CompatibilityEnum"
    }
    It 'idle and network settings objects' {
        $s = New-ScheduledTaskSettingsSet
        $s.IdleSettings.PSObject.TypeNames | Should -Be @("$NS/MSFT_TaskIdleSettings", "$CI#MSFT_TaskIdleSettings", $CI, 'System.Object')
        (Names $s.IdleSettings) | Should -Be @('IdleDuration', 'RestartOnIdle', 'StopOnIdleEnd', 'WaitTimeout', 'PSComputerName')
        $s.IdleSettings.IdleDuration | Should -Be 'PT10M'; $s.IdleSettings.WaitTimeout | Should -Be 'PT1H'
        $s.IdleSettings.StopOnIdleEnd | Should -BeTrue; $s.IdleSettings.RestartOnIdle | Should -BeFalse
        $s.NetworkSettings.PSObject.TypeNames | Should -Be @("$NS/MSFT_TaskNetworkSettings", "$CI#MSFT_TaskNetworkSettings", $CI, 'System.Object')
        (Names $s.NetworkSettings) | Should -Be @('Id', 'Name', 'PSComputerName')
    }
    It 'switches and values change the matching properties' {
        $s = New-ScheduledTaskSettingsSet -DisallowDemandStart -DisallowHardTerminate -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Disable -Hidden `
            -StartWhenAvailable -WakeToRun -RunOnlyIfNetworkAvailable -MultipleInstances Parallel -Compatibility Win8 `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -DeleteExpiredTaskAfter (New-TimeSpan -Days 1) -Priority 3 -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
        $s.AllowDemandStart | Should -BeFalse; $s.AllowHardTerminate | Should -BeFalse; $s.DisallowStartIfOnBatteries | Should -BeFalse
        $s.StopIfGoingOnBatteries | Should -BeFalse; $s.Enabled | Should -BeFalse; $s.Hidden | Should -BeTrue
        $s.StartWhenAvailable | Should -BeTrue; $s.WakeToRun | Should -BeTrue; $s.RunOnlyIfNetworkAvailable | Should -BeTrue
        [string]$s.MultipleInstances | Should -Be 'Parallel'; [string]$s.Compatibility | Should -Be 'Win8'
        $s.ExecutionTimeLimit | Should -Be 'PT30M'; $s.DeleteExpiredTaskAfter | Should -Be 'P1D'
        $s.Priority | Should -Be 3; $s.RestartCount | Should -Be 3; $s.RestartInterval | Should -Be 'PT5M'
    }
    It 'idle parameters fill IdleSettings' {
        $s = New-ScheduledTaskSettingsSet -RunOnlyIfIdle -IdleDuration (New-TimeSpan -Minutes 20) -IdleWaitTimeout (New-TimeSpan -Hours 1) -RestartOnIdle -DontStopOnIdleEnd
        $s.RunOnlyIfIdle | Should -BeTrue
        $s.IdleSettings.IdleDuration | Should -Be 'PT20M'; $s.IdleSettings.WaitTimeout | Should -Be 'PT1H'
        $s.IdleSettings.RestartOnIdle | Should -BeTrue; $s.IdleSettings.StopOnIdleEnd | Should -BeFalse
    }
    It '-Priority 11 fails with HRESULT 0x80070057' {
        $e = @(Err { New-ScheduledTaskSettingsSet -Priority 11 })
        $e[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x80070057,New-ScheduledTaskSettingsSet'
        $e[0].Exception.GetType().FullName | Should -Be 'Microsoft.Management.Infrastructure.CimException'
        $e[0].Exception.Message | Should -Match '^The parameter is incorrect\.'
    }
}

Describe 'New-ScheduledTask' {
    It 'builds an unregistered MSFT_ScheduledTask' {
        $t = New-ScheduledTask -Action (New-ScheduledTaskAction -Execute cmd.exe) -Trigger (New-ScheduledTaskTrigger -Once -At '2030-01-02') -Settings (New-ScheduledTaskSettingsSet) -Description d
        $t.PSObject.TypeNames | Should -Be @("$NS/MSFT_ScheduledTask", "$CI#MSFT_ScheduledTask", $CI, 'System.Object')
        (Names $t) | Should -Be @('State', 'Actions', 'Author', 'Date', 'Description', 'Documentation', 'Principal', 'SecurityDescriptor', 'Settings', 'Source', 'TaskName', 'TaskPath', 'Triggers', 'URI', 'Version', 'PSComputerName')
        $t.Description | Should -Be 'd'
        @($t.Actions).Count | Should -Be 1; @($t.Triggers).Count | Should -Be 1
        $null -eq $t.Principal | Should -BeTrue; $null -eq $t.State | Should -BeTrue
    }
}

Describe 'Get-ScheduledTask / Get-ScheduledTaskInfo errors' {
    It 'an unknown exact TaskName writes CmdletizationQuery_NotFound_TaskName' {
        $e = @(Err { Get-ScheduledTask -TaskName nosuchtask_zz })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound_TaskName,Get-ScheduledTask'
        $e[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
        $e[0].CategoryInfo.Reason | Should -Be 'CimJobException'
        $e[0].Exception.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.Cim.CimJobException'
        $e[0].TargetObject | Should -Be 'nosuchtask_zz'
        $e[0].CategoryInfo.TargetName | Should -Be 'nosuchtask_zz'
        $e[0].Exception.Message | Should -Be "No MSFT_ScheduledTask objects found with property 'TaskName' equal to 'nosuchtask_zz'.  Verify the value of the property and retry."
    }
    It 'a wildcard TaskName without a match is silent' {
        @(Err { Get-ScheduledTask -TaskName 'nosuch*_zz' }).Count | Should -Be 0
        @(Ok { Get-ScheduledTask -TaskName 'nosuch*_zz' }).Count | Should -Be 0
    }
    It 'an unknown exact TaskPath writes CmdletizationQuery_NotFound_TaskPath' {
        $e = @(Err { Get-ScheduledTask -TaskPath '\nosuchfolder\' })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound_TaskPath,Get-ScheduledTask'
        $e[0].Exception.Message | Should -Be "No MSFT_ScheduledTask objects found with property 'TaskPath' equal to '\nosuchfolder\'.  Verify the value of the property and retry."
    }
    It 'a name with a path that match nothing writes CmdletizationQuery_NotFound with the query' {
        $e = @(Err { Get-ScheduledTask -TaskName nosuchtask_zz -TaskPath '\' })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound,Get-ScheduledTask'
        $e[0].TargetObject | Should -Be 'MSFT_ScheduledTask'
        $e[0].Exception.Message | Should -Be "No matching MSFT_ScheduledTask objects found by CIM query for instances of the Root/Microsoft/Windows/TaskScheduler/MSFT_ScheduledTask class on the  CIM server: SELECT * FROM MSFT_ScheduledTask  WHERE ((TaskName LIKE 'nosuchtask_zz')) AND ((TaskPath LIKE '\\')). Verify query parameters and retry."
    }
    It 'a wildcard name with an exact path also gives the query error, a wildcard path does not' {
        (Err { Get-ScheduledTask -TaskName 'nosuch*' -TaskPath '\' })[0].Exception.Message | Should -Match "TaskName LIKE 'nosuch%'"
        @(Err { Get-ScheduledTask -TaskName nosuchtask_zz -TaskPath '\nosuch*' }).Count | Should -Be 1
        @(Err { Get-ScheduledTask -TaskName 'nosuch*' -TaskPath '\nosuch*' }).Count | Should -Be 0
    }
    It 'a null TaskName is a binding error' {
        (Err { Get-ScheduledTask -TaskName $null })[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentValidationError,Get-ScheduledTask'
    }
    It 'an empty TaskName is not found' {
        (Err { Get-ScheduledTask -TaskName '' })[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound_TaskName,Get-ScheduledTask'
    }
    It '<Cmd> on an unknown task fails with HRESULT 0x80070002' -TestCases @(
        @{ Cmd = 'Get-ScheduledTaskInfo' }, @{ Cmd = 'Start-ScheduledTask' }, @{ Cmd = 'Stop-ScheduledTask' }, @{ Cmd = 'Enable-ScheduledTask' }, @{ Cmd = 'Disable-ScheduledTask' }) {
        param($Cmd)
        $e = @(Err ([scriptblock]::Create("$Cmd -TaskName nosuchtask_zz")))
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be "HRESULT 0x80070002,$Cmd"
        $e[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
        $e[0].CategoryInfo.Reason | Should -Be 'CimException'
        $e[0].Exception.GetType().FullName | Should -Be 'Microsoft.Management.Infrastructure.CimException'
        $e[0].Exception.Message | Should -Match '^The system cannot find the file specified\.'
        $e[0].CategoryInfo.TargetName | Should -Be 'PS_ScheduledTask'
    }
    It 'Get-ScheduledTaskInfo on a missing folder, a wildcard name and a subfolder task without a path fail the same way' {
        (Err { Get-ScheduledTaskInfo -TaskName x -TaskPath '\nosuchfolder\' })[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x80070002,Get-ScheduledTaskInfo'
        (Err { Get-ScheduledTaskInfo -TaskName 'nosuch*' })[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x80070002,Get-ScheduledTaskInfo'
    }
    It 'Get-ScheduledTaskInfo without arguments cannot resolve a parameter set' {
        (Err { Get-ScheduledTaskInfo })[0].FullyQualifiedErrorId | Should -Match '^(AmbiguousParameterSet|MissingMandatoryParameter),Get-ScheduledTaskInfo$'
    }
    It 'Get-ScheduledTaskInfo -TaskName "" is a validation error' {
        (Err { Get-ScheduledTaskInfo -TaskName '' })[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentValidationError,Get-ScheduledTaskInfo'
    }
    It 'Start-ScheduledTask without a name misses the mandatory parameter' {
        (Err { Start-ScheduledTask })[0].FullyQualifiedErrorId | Should -Be 'MissingMandatoryParameter,Start-ScheduledTask'
    }
    It 'Unregister-ScheduledTask of an unknown name writes the not-found error and -WhatIf the delete text for a real one' {
        $e = @(Err { Unregister-ScheduledTask -TaskName nosuchtask_zz -Confirm:$false })
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound_TaskName,Unregister-ScheduledTask'
    }
}

Describe 'refusals (phase-1 limits of the task service)' {
    BeforeAll {
        $script:xmlHead = '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Triggers>'
        $script:xmlTail = '</Triggers><Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals><Actions Context="Author"><Exec><Command>cmd.exe</Command></Exec></Actions></Task>'
    }
    It 'Register-ScheduledTask -Xml refuses <What> and registers nothing' -TestCases @(
        @{ What = 'a weekly trigger'; Body = '<CalendarTrigger><StartBoundary>2030-01-02T11:04:05Z</StartBoundary><ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><Monday/></DaysOfWeek></ScheduleByWeek></CalendarTrigger>' }
        @{ What = 'a monthly trigger'; Body = '<CalendarTrigger><StartBoundary>2030-01-02T11:04:05Z</StartBoundary><ScheduleByMonth><DaysOfMonth><Day>1</Day></DaysOfMonth><Months><January/></Months></ScheduleByMonth></CalendarTrigger>' }
        @{ What = 'an idle trigger'; Body = '<IdleTrigger/>' }
        @{ What = 'an event trigger'; Body = '<EventTrigger><Subscription>x</Subscription></EventTrigger>' }
        @{ What = 'a session state change trigger'; Body = '<SessionStateChangeTrigger><StateChange>SessionLock</StateChange></SessionStateChangeTrigger>' }
    ) {
        param($What, $Body)
        $n = New-TestName
        $e = @(Err { Register-ScheduledTask -TaskName $n -Xml ($script:xmlHead + $Body + $script:xmlTail) })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be 'TriggerTypeNotSupported,Register-ScheduledTask'
        $e[0].CategoryInfo.Category | Should -Be 'NotImplemented'
        $e[0].Exception.Message | Should -Match $What
        @(Err { Get-ScheduledTask -TaskName $n }).Count | Should -Be 1
        @(Ok { Get-ScheduledTask -TaskName $n }).Count | Should -Be 0
    }
    It 'Register-ScheduledTask refuses a trigger object of an unsupported kind' {
        $n = New-TestName
        $w = [pscustomobject]@{ Enabled = $true }
        $w.PSObject.TypeNames.Insert(0, "$NS/MSFT_TaskWeeklyTrigger")
        $e = @(Err { Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe) -Trigger $w })
        $e[0].FullyQualifiedErrorId | Should -Be 'TriggerTypeNotSupported,Register-ScheduledTask'
        @(Ok { Get-ScheduledTask -TaskName $n }).Count | Should -Be 0
    }
}

Describe 'registration, read-back and the task life cycle' {
    BeforeAll {
        $script:tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('nitro-sched-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
        $script:rt = New-TestName
        $script:action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c echo nitro-round-trip> `"$($script:tmp)`"" -WorkingDirectory ([System.IO.Path]::GetTempPath().TrimEnd('\'))
        $script:when = [datetime]::Now.AddDays(1)
        $script:trigger = New-ScheduledTaskTrigger -Once -At $script:when
    }
    AfterAll { Remove-TestTasks; Remove-Item $script:tmp -ErrorAction SilentlyContinue }

    It 'registers a task and returns the MSFT_ScheduledTask' -Skip:$skipRt {
        $t = Register-ScheduledTask -TaskName $script:rt -Action $script:action -Trigger $script:trigger -Description 'nitro pester round trip'
        $t.PSObject.TypeNames | Should -Be @("$NS/MSFT_ScheduledTask", "$CI#MSFT_ScheduledTask", $CI, 'System.Object')
        (Names $t) | Should -Be @('State', 'Actions', 'Author', 'Date', 'Description', 'Documentation', 'Principal', 'SecurityDescriptor', 'Settings', 'Source', 'TaskName', 'TaskPath', 'Triggers', 'URI', 'Version', 'PSComputerName')
        $t.TaskName | Should -Be $script:rt; $t.TaskPath | Should -Be '\'; $t.URI | Should -Be "\$($script:rt)"
        $t.Description | Should -Be 'nitro pester round trip'
        [string]$t.State | Should -Be 'Ready'
        $t.State.GetType().FullName | Should -Be "$EnumNs.StateEnum"
    }
    It 'registering the same name again fails with 0x800700b7, -Force updates it' -Skip:$skipRt {
        $e = @(Err { Register-ScheduledTask -TaskName $script:rt -Action $script:action })
        $e[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x800700b7,Register-ScheduledTask'
        $e[0].CategoryInfo.Category | Should -Be 'ResourceExists'
        $e[0].Exception.Message | Should -Match '^Cannot create a file when that file already exists\.'
        $u = Register-ScheduledTask -TaskName $script:rt -Action $script:action -Trigger $script:trigger -Description 'nitro pester round trip' -Force
        $u.TaskName | Should -Be $script:rt
    }
    It 'Get-ScheduledTask finds it by name, wildcard, path and pipeline' -Skip:$skipRt {
        @(Get-ScheduledTask -TaskName $script:rt).Count | Should -Be 1
        @(Get-ScheduledTask -TaskName ($script:rt.Substring(0, 12) + '*')).Count | Should -Be 1
        @(Get-ScheduledTask -TaskName $script:rt.ToUpper()).Count | Should -Be 1
        @(Get-ScheduledTask -TaskName $script:rt -TaskPath '\').Count | Should -Be 1
        @(Get-ScheduledTask -TaskPath '\' | Where-Object TaskName -eq $script:rt).Count | Should -Be 1
        @(Get-ScheduledTask -TaskName $script:rt -TaskPath '\*').Count | Should -Be 1
        @(Get-ScheduledTask -TaskName $script:rt | Get-ScheduledTask).Count | Should -Be 1
        @(Get-ScheduledTask).Count | Should -BeGreaterThan 0
    }
    It 'the task has the measured nested objects' -Skip:$skipRt {
        $t = Get-ScheduledTask -TaskName $script:rt
        @($t.Actions).Count | Should -Be 1
        $a = $t.Actions[0]
        $a.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskExecAction' @('MSFT_TaskAction'))
        $a.Execute | Should -Be 'cmd.exe'; $a.Arguments | Should -Match 'nitro-round-trip'
        @($t.Triggers).Count | Should -Be 1
        $tr = $t.Triggers[0]
        $tr.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskTimeTrigger' @('MSFT_TaskTrigger'))
        (Names $tr) | Should -Be ($trigBase + @('RandomDelay', 'PSComputerName'))
        $tr.Repetition.PSObject.TypeNames[0] | Should -Be "$NS/MSFT_TaskRepetitionPattern"
        $tr.Enabled | Should -BeTrue
        $tr.StartBoundary | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d'
        $t.Principal.PSObject.TypeNames | Should -Be (Chain 'MSFT_TaskPrincipal2' @('MSFT_TaskPrincipal'))
        (Names $t.Principal) | Should -Be @('RunLevel', 'LogonType', 'ProcessTokenSidType', 'DisplayName', 'GroupId', 'Id', 'UserId', 'RequiredPrivilege', 'PSComputerName')
        [string]$t.Principal.LogonType | Should -Be 'Interactive'; [string]$t.Principal.RunLevel | Should -Be 'Limited'
        $t.Principal.UserId | Should -Be "$([Environment]::UserDomainName)\$([Environment]::UserName)"
        $t.Principal.Id | Should -Be 'Author'
        $t.Settings.PSObject.TypeNames[0] | Should -Be "$NS/MSFT_TaskSettings3"
        $t.Settings.IdleSettings.PSObject.TypeNames[0] | Should -Be "$NS/MSFT_TaskIdleSettings"
        $t.Settings.NetworkSettings.PSObject.TypeNames[0] | Should -Be "$NS/MSFT_TaskNetworkSettings"
        $t.Settings.Priority.GetType().FullName | Should -Be 'System.UInt32'
        $t.Settings.ExecutionTimeLimit | Should -Be 'PT72H'
        $t.Settings.Enabled | Should -BeTrue
        $t.SecurityDescriptor | Should -Be ''
        $t.Author | Should -Be "$([Environment]::UserDomainName)\$([Environment]::UserName)"
    }
    It 'the default table has TaskPath, TaskName and State' -Skip:$skipRt {
        $t = Get-ScheduledTask -TaskName $script:rt
        (HeaderTokens $t) | Should -Be @('TaskPath', 'TaskName', 'State')
        $text = $t | Format-Table | Out-String -Width 200
        $text | Should -Match ([regex]::Escape($script:rt) + '\s+Ready')
    }
    It 'Format-List shows the nested objects as class names and State among the properties' -Skip:$skipRt {
        $text = (Get-ScheduledTask -TaskName $script:rt | Format-List | Out-String -Width 200)
        $text | Should -Match 'Actions\s+: \{MSFT_TaskExecAction\}'
        $text | Should -Match 'Principal\s+: MSFT_TaskPrincipal2'
        $text | Should -Match 'Settings\s+: MSFT_TaskSettings3'
        $text | Should -Match 'Triggers\s+: \{MSFT_TaskTimeTrigger\}'
        $text | Should -Match 'URI\s+: \\'
    }
    It 'Get-ScheduledTaskInfo of a task that never ran' -Skip:$skipRt {
        $i = Get-ScheduledTaskInfo -TaskName $script:rt
        $i.PSObject.TypeNames | Should -Be @("$NS/MSFT_TaskDynamicInfo", "$CI#MSFT_TaskDynamicInfo", $CI, 'System.Object')
        (Names $i) | Should -Be @('LastRunTime', 'LastTaskResult', 'NextRunTime', 'NumberOfMissedRuns', 'TaskName', 'TaskPath', 'PSComputerName')
        $i.TaskName | Should -Be $script:rt; $i.TaskPath | Should -Be '\'
        $i.LastRunTime | Should -Be ([datetime]'1999-11-30')
        $i.LastRunTime.GetType().FullName | Should -Be 'System.DateTime'
        $i.LastTaskResult | Should -Be 267011
        $i.LastTaskResult.GetType().FullName | Should -Be 'System.UInt32'
        $i.NextRunTime | Should -Not -BeNullOrEmpty
        $i.NumberOfMissedRuns.GetType().FullName | Should -Be 'System.UInt32'
        (Get-ScheduledTask -TaskName $script:rt | Get-ScheduledTaskInfo).TaskName | Should -Be $script:rt
        (Get-ScheduledTaskInfo $script:rt '\').TaskPath | Should -Be '\'
    }
    It 'Start-ScheduledTask runs it: the file is written and LastTaskResult is 0' -Skip:$skipRt {
        Remove-Item $script:tmp -ErrorAction SilentlyContinue
        @(Start-ScheduledTask -TaskName $script:rt).Count | Should -Be 0
        (Wait-Until { (Test-Path $script:tmp) -and ((Get-ScheduledTaskInfo -TaskName $script:rt).LastTaskResult -eq 0) } 90) | Should -BeTrue
        (Get-Content $script:tmp -Raw).Trim() | Should -Be 'nitro-round-trip'
        $i = Get-ScheduledTaskInfo -TaskName $script:rt
        $i.LastTaskResult | Should -Be 0
        $i.LastRunTime.Year | Should -BeGreaterThan 2000
        $i.LastRunTime | Should -BeGreaterThan ([datetime]::Now.AddMinutes(-10))
    }
    It 'Stop-ScheduledTask on a task that is not running is not an error' -Skip:$skipRt {
        @(Err { Stop-ScheduledTask -TaskName $script:rt }).Count | Should -Be 0
    }
    It 'Disable-ScheduledTask and Enable-ScheduledTask return the task with the new State' -Skip:$skipRt {
        $d = Disable-ScheduledTask -TaskName $script:rt
        $d.PSObject.TypeNames[0] | Should -Be "$NS/MSFT_ScheduledTask"
        [string]$d.State | Should -Be 'Disabled'
        [string](Get-ScheduledTask -TaskName $script:rt).State | Should -Be 'Disabled'
        (Get-ScheduledTask -TaskName $script:rt).Settings.Enabled | Should -BeFalse
        $null -eq (Get-ScheduledTaskInfo -TaskName $script:rt).NextRunTime | Should -BeTrue
        $e = Get-ScheduledTask -TaskName $script:rt | Enable-ScheduledTask
        [string]$e.State | Should -Be 'Ready'
        (Get-ScheduledTask -TaskName $script:rt).Settings.Enabled | Should -BeTrue
        (Get-ScheduledTaskInfo -TaskName $script:rt).NextRunTime | Should -Not -BeNullOrEmpty
    }
    It 'Unregister-ScheduledTask -WhatIf names the target and keeps the task' -Skip:$skipRt {
        $pwsh = (Get-Process -Id $PID).Path
        $w = (& $pwsh -NoLogo -NoProfile -NonInteractive -Command "Unregister-ScheduledTask -TaskName '$($script:rt)' -WhatIf" 2>&1 | Out-String)
        $w | Should -Match ([regex]::Escape("What if: Performing operation 'Delete' on Target '\$($script:rt)'."))
        @(Get-ScheduledTask -TaskName $script:rt).Count | Should -Be 1
    }
    It 'Unregister-ScheduledTask -PassThru deletes the task and returns it' -Skip:$skipRt {
        $r = Unregister-ScheduledTask -TaskName $script:rt -Confirm:$false -PassThru
        $r.TaskName | Should -Be $script:rt
        @(Ok { Get-ScheduledTask -TaskName $script:rt }).Count | Should -Be 0
        (Err { Get-ScheduledTask -TaskName $script:rt })[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound_TaskName,Get-ScheduledTask'
        (Err { Get-ScheduledTaskInfo -TaskName $script:rt })[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x80070002,Get-ScheduledTaskInfo'
    }
}

Describe 'a running task can be stopped' {
    AfterAll { Remove-TestTasks }
    It 'Start makes it Running, Stop returns it to Ready' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c ping -n 40 127.0.0.1 > nul') -Trigger (New-ScheduledTaskTrigger -Once -At ([datetime]::Now.AddDays(1)))
        Start-ScheduledTask -TaskName $n
        (Wait-Until { [string](Get-ScheduledTask -TaskName $n).State -eq 'Running' } 30) | Should -BeTrue
        Stop-ScheduledTask -TaskName $n
        (Wait-Until { [string](Get-ScheduledTask -TaskName $n).State -eq 'Ready' } 30) | Should -BeTrue
        Unregister-ScheduledTask -TaskName $n -Confirm:$false
    }
}

Describe 'principals, XML registration and folders' {
    AfterAll {
        Remove-TestTasks
        try { $s = New-Object -ComObject Schedule.Service; $s.Connect(); $s.GetFolder('\').DeleteFolder('NitroPesterDir', 0) } catch { }
    }
    It 'registers a SYSTEM task through -Principal and reads the principal back' -Skip:$skipRt {
        $n = New-TestName
        $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $t = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit 0') -Principal $p
        $t.Principal.UserId | Should -Be 'SYSTEM'
        [string]$t.Principal.LogonType | Should -Be 'ServiceAccount'
        [string]$t.Principal.RunLevel | Should -Be 'Highest'
        @($t.Triggers).Count | Should -Be 0
        Unregister-ScheduledTask -TaskName $n -Confirm:$false
    }
    It 'registers with -User SYSTEM as a service account task' -Skip:$skipRt {
        $n = New-TestName
        $t = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe) -User SYSTEM -RunLevel Highest
        [string]$t.Principal.LogonType | Should -Be 'ServiceAccount'
        Unregister-ScheduledTask -TaskName $n -Confirm:$false
    }
    It 'registers a task from -Xml in a subfolder and finds it by path' -Skip:$skipRt {
        $n = New-TestName
        $xml = '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><RegistrationInfo><Description>xml task</Description></RegistrationInfo>' +
            '<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>' +
            '<Principals><Principal id="Author"><UserId>SYSTEM</UserId><LogonType>ServiceAccount</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>' +
            '<Settings><Enabled>true</Enabled></Settings><Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c exit 0</Arguments></Exec></Actions></Task>'
        $t = Register-ScheduledTask -TaskName $n -TaskPath '\NitroPesterDir' -Xml $xml
        $t.TaskPath | Should -Be '\NitroPesterDir\'
        $t.URI | Should -Be "\NitroPesterDir\$n"
        @($t.Triggers | ForEach-Object { $_.PSObject.TypeNames[0] -replace '^.*/' }) | Should -Be @('MSFT_TaskBootTrigger', 'MSFT_TaskLogonTrigger')
        $t.Description | Should -Be 'xml task'
        @(Get-ScheduledTask -TaskPath '\NitroPesterDir\').Count | Should -Be 1
        @(Get-ScheduledTask -TaskName $n -TaskPath '\NitroPesterDir\').Count | Should -Be 1
        (Get-ScheduledTaskInfo -TaskName $n -TaskPath '\NitroPesterDir\').TaskPath | Should -Be '\NitroPesterDir\'
        (Get-ScheduledTaskInfo -TaskName $n -TaskPath '\NitroPesterDir').TaskPath | Should -Be '\NitroPesterDir'
        @(Err { Get-ScheduledTaskInfo -TaskName $n }).Count | Should -Be 1
        Unregister-ScheduledTask -TaskName $n -TaskPath '\NitroPesterDir\' -Confirm:$false
        @(Ok { Get-ScheduledTask -TaskName $n }).Count | Should -Be 0
    }
    It 'registers Daily, AtStartup and AtLogOn triggers and reads their kinds back' -Skip:$skipRt {
        $n = New-TestName
        $t = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe) -Trigger @(
            (New-ScheduledTaskTrigger -Daily -At '2030-01-02 03:04:05' -DaysInterval 2), (New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
        @($t.Triggers | ForEach-Object { $_.PSObject.TypeNames[0] -replace '^.*/' }) | Should -Be @('MSFT_TaskDailyTrigger', 'MSFT_TaskBootTrigger', 'MSFT_TaskLogonTrigger')
        $t.Triggers[0].DaysInterval | Should -Be 2
        $t.Triggers[0].DaysInterval.GetType().FullName | Should -Be 'System.Int16'
        Unregister-ScheduledTask -TaskName $n -Confirm:$false
    }
    It 'copies a task through the Object parameter set' -Skip:$skipRt {
        $n = New-TestName; $n2 = New-TestName
        $t = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit 0') -Trigger (New-ScheduledTaskTrigger -Once -At ([datetime]::Now.AddDays(2)))
        $c = Register-ScheduledTask -TaskName $n2 -InputObject $t
        $c.TaskName | Should -Be $n2
        $c.Actions[0].Arguments | Should -Be '/c exit 0'
        @($c.Triggers).Count | Should -Be 1
        Unregister-ScheduledTask -TaskName $n, $n2 -Confirm:$false
    }
    It 'Unregister-ScheduledTask takes a list of names and reports the unknown one' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe)
        $e = @(Err { Unregister-ScheduledTask -TaskName $n, nosuchtask_zz -Confirm:$false })
        $e.Count | Should -Be 1
        $e[0].TargetObject | Should -Be 'nosuchtask_zz'
        @(Ok { Get-ScheduledTask -TaskName $n }).Count | Should -Be 0
    }
}

Describe 'schtasks.exe sees the tasks of the module' {
    It 'a registered task shows up in schtasks /query' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe)
        $q = (& schtasks.exe /query /tn $n 2>&1) -join "`n"
        $q | Should -Match ([regex]::Escape($n))
        Unregister-ScheduledTask -TaskName $n -Confirm:$false
        Remove-TestTasks
    }
}

# ======================================================================================== Set-/Export-ScheduledTask
# Surface and error rows were measured read-only on the Windows 10 reference machine (parameter sets, positions, mandatory flags,
# the HRESULT errors of Export-ScheduledTask, the binding errors of Set-ScheduledTask). The round trip rows need the nitro guest.
function PI($cmd, $param, $set) { (Get-Command $cmd).Parameters[$param].ParameterSets[$set] }

Describe 'Set-ScheduledTask and Export-ScheduledTask surface' {
    It 'exports both commands from ScheduledTasks as functions' {
        foreach ($n in 'Set-ScheduledTask', 'Export-ScheduledTask') { (Get-Command $n).Source | Should -Be 'ScheduledTasks'; (Get-Command $n).CommandType | Should -Be 'Function' }
    }
    It 'Set-ScheduledTask has the sets User (default), Principal and Object' {
        $c = Get-Command Set-ScheduledTask
        $c.DefaultParameterSet | Should -Be 'User'
        @($c.ParameterSets.Name | Sort-Object) | Should -Be @('Object', 'Principal', 'User')
        $c.OutputType.Name | Should -Contain 'Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask'
    }
    It 'Set-ScheduledTask positions and mandatory flags match Windows: <Param> in <Set>' -TestCases @(
        @{ Param = 'TaskName'; Set = 'User'; Pos = 0; Mand = $true }, @{ Param = 'TaskPath'; Set = 'User'; Pos = 1; Mand = $false },
        @{ Param = 'Action'; Set = 'User'; Pos = 2; Mand = $false }, @{ Param = 'Trigger'; Set = 'User'; Pos = 3; Mand = $false },
        @{ Param = 'Settings'; Set = 'User'; Pos = 4; Mand = $false }, @{ Param = 'User'; Set = 'User'; Pos = 5; Mand = $false },
        @{ Param = 'Password'; Set = 'User'; Pos = 6; Mand = $false }, @{ Param = 'TaskName'; Set = 'Principal'; Pos = 0; Mand = $true },
        @{ Param = 'Principal'; Set = 'Principal'; Pos = 5; Mand = $false }, @{ Param = 'Action'; Set = 'Principal'; Pos = 2; Mand = $false },
        @{ Param = 'InputObject'; Set = 'Object'; Pos = 0; Mand = $true }, @{ Param = 'Password'; Set = 'Object'; Pos = 1; Mand = $false },
        @{ Param = 'User'; Set = 'Object'; Pos = 2; Mand = $false }) {
        param($Param, $Set, $Pos, $Mand)
        $i = PI Set-ScheduledTask $Param $Set
        $i.Position | Should -Be $Pos
        $i.IsMandatory | Should -Be $Mand
    }
    It 'Set-ScheduledTask: InputObject comes from the pipeline, Principal exists only in its own set, AsJob and CimSession are accepted' {
        (PI Set-ScheduledTask InputObject Object).ValueFromPipeline | Should -BeTrue
        (Get-Command Set-ScheduledTask).Parameters['Principal'].ParameterSets.Keys | Should -Be @('Principal')
        (Get-Command Set-ScheduledTask).Parameters['Action'].ParameterType.FullName | Should -BeIn @('System.Object[]', 'Microsoft.Management.Infrastructure.CimInstance[]')
        (Get-Command Set-ScheduledTask).Parameters.Keys | Should -Contain 'AsJob'
        (Get-Command Set-ScheduledTask).Parameters['CimSession'].Aliases | Should -Contain 'Session'
        (Get-Command Set-ScheduledTask).Parameters.Keys | Should -Not -Contain 'WhatIf'
    }
    It 'Export-ScheduledTask has the sets Name (TaskName 0, TaskPath 1, none mandatory) and Object (InputObject 0, mandatory, pipeline); outputs a string' {
        $c = Get-Command Export-ScheduledTask
        @($c.ParameterSets.Name | Sort-Object) | Should -Be @('Name', 'Object')
        (PI Export-ScheduledTask TaskName Name).Position | Should -Be 0
        (PI Export-ScheduledTask TaskName Name).IsMandatory | Should -BeFalse
        (PI Export-ScheduledTask TaskPath Name).Position | Should -Be 1
        (PI Export-ScheduledTask InputObject Object).IsMandatory | Should -BeTrue
        (PI Export-ScheduledTask InputObject Object).ValueFromPipeline | Should -BeTrue
        $c.OutputType.Type.FullName | Should -Contain 'System.String'
    }
    It 'Set-ScheduledTask without a name is a missing-mandatory-parameter error' {
        $e = @(Err { Set-ScheduledTask })
        $e[0].FullyQualifiedErrorId | Should -Be 'MissingMandatoryParameter,Set-ScheduledTask'
        $e[0].Exception.Message | Should -Match 'missing mandatory parameters: TaskName'
    }
    It 'Set-ScheduledTask -User with -Principal is an ambiguous parameter set' {
        $e = @(Err { Set-ScheduledTask -TaskName x -User a -Principal (New-ScheduledTaskPrincipal -UserId a) })
        $e[0].FullyQualifiedErrorId | Should -Be 'AmbiguousParameterSet,Set-ScheduledTask'
    }
    It 'Export-ScheduledTask with no name, or only a path, is HRESULT 0x80070057 (CimException, InvalidArgument)' {
        foreach ($sb in { Export-ScheduledTask }, { Export-ScheduledTask -TaskPath '\nosuch-nitro\' }) {
            $e = @(Err $sb)
            $e.Count | Should -Be 1
            $e[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x80070057,Export-ScheduledTask'
            [string]$e[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
            $e[0].Exception.GetType().FullName | Should -Be 'Microsoft.Management.Infrastructure.CimException'
            $e[0].TargetObject | Should -Be 'PS_ScheduledTask'
            $e[0].Exception.Message.Trim() | Should -Be 'The parameter is incorrect.'
        }
    }
    It 'Export-ScheduledTask of an unknown task or folder is HRESULT 0x80070002; a wildcard name is not expanded' {
        foreach ($sb in { Export-ScheduledTask -TaskName nosuchtask-nitro }, { Export-ScheduledTask -TaskName nosuchtask-nitro -TaskPath '\nosuch-nitro\' }, { Export-ScheduledTask -TaskName 'nosuch*' }) {
            $e = @(Err $sb)
            $e.Count | Should -Be 1
            $e[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x80070002,Export-ScheduledTask'
            [string]$e[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
            $e[0].Exception.Message.Trim() | Should -Be 'The system cannot find the file specified.'
        }
    }
}

Describe 'Set-ScheduledTask and Export-ScheduledTask round trip' {
    AfterAll { Remove-TestTasks }
    It 'Set-ScheduledTask -Action replaces the action; Get-ScheduledTask and schtasks /query /xml show it; the rest of the task is kept' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c echo one') -Description 'first desc'
        $before = Get-ScheduledTask -TaskName $n
        $r = Set-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c echo two')
        $r.psobject.TypeNames[0] | Should -Be "$NS/MSFT_ScheduledTask"
        $r.TaskName | Should -Be $n
        $t = Get-ScheduledTask -TaskName $n
        @($t.Actions).Count | Should -Be 1
        $t.Actions[0].Arguments | Should -Be '/c echo two'
        $t.Description | Should -Be 'first desc'
        $t.Author | Should -Be $before.Author
        $t.Date | Should -Be $before.Date
        ((& schtasks.exe /query /tn $n /xml) -join "`n") | Should -Match '<Arguments>/c echo two</Arguments>'
    }
    It 'Set-ScheduledTask -Trigger / -Settings / -User / -Principal change just that part (checked in the stored XML)' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit 0')
        $null = Set-ScheduledTask -TaskName $n -Trigger (New-ScheduledTaskTrigger -Daily -At '2031-05-06 03:30:00' -DaysInterval 3)
        $t = Get-ScheduledTask -TaskName $n
        @($t.Triggers).Count | Should -Be 1
        $t.Triggers[0].PSObject.TypeNames[0] | Should -Be "$NS/MSFT_TaskDailyTrigger"
        $t.Triggers[0].DaysInterval | Should -Be 3
        $t.Actions[0].Arguments | Should -Be '/c exit 0'
        $null = Set-ScheduledTask -TaskName $n -Settings (New-ScheduledTaskSettingsSet -Hidden -Priority 5 -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2))
        $t = Get-ScheduledTask -TaskName $n
        $t.Settings.Hidden | Should -BeTrue
        $t.Settings.Priority | Should -Be 5
        $t.Settings.DisallowStartIfOnBatteries | Should -BeFalse
        $t.Settings.ExecutionTimeLimit | Should -Be 'PT2H'
        @($t.Triggers).Count | Should -Be 1
        $null = Set-ScheduledTask -TaskName $n -User SYSTEM
        $t = Get-ScheduledTask -TaskName $n
        $t.Principal.UserId | Should -Be 'SYSTEM'
        [string]$t.Principal.LogonType | Should -Be 'ServiceAccount'
        $null = Set-ScheduledTask -TaskName $n -Principal (New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest -LogonType ServiceAccount)
        $t = Get-ScheduledTask -TaskName $n
        [string]$t.Principal.RunLevel | Should -Be 'Highest'
        $x = (& schtasks.exe /query /tn $n /xml) -join "`n"
        $x | Should -Match '<RunLevel>HighestAvailable</RunLevel>'
        $x | Should -Match '<Hidden>true</Hidden>'
        $x | Should -Match '<DaysInterval>3</DaysInterval>'
    }
    It 'Set-ScheduledTask -InputObject writes the whole edited definition back (also by pipeline)' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c echo one') -Description 'before'
        $t = Get-ScheduledTask -TaskName $n
        $t.Description = 'after'
        $t.Actions[0].Arguments = '/c echo three'
        $r = $t | Set-ScheduledTask
        $r.Description | Should -Be 'after'
        $g = Get-ScheduledTask -TaskName $n
        $g.Description | Should -Be 'after'
        $g.Actions[0].Arguments | Should -Be '/c echo three'
        $g.Settings.Enabled | Should -BeTrue
    }
    It 'Set-ScheduledTask keeps what the module cannot write: a weekly trigger made by schtasks.exe survives -Action, -Settings and -User' -Skip:$skipRt {
        $n = New-TestName
        $null = & schtasks.exe /create /tn $n /tr 'cmd /c exit 0' /sc weekly /d MON /st 03:00 /f
        $LASTEXITCODE | Should -Be 0
        $null = Set-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit 7')
        $null = Set-ScheduledTask -TaskName $n -Settings (New-ScheduledTaskSettingsSet -Hidden)
        $null = Set-ScheduledTask -TaskName $n -User SYSTEM
        $x = (& schtasks.exe /query /tn $n /xml) -join "`n"
        $x | Should -Match '<ScheduleByWeek>'
        $x | Should -Match '<Monday\s*/>'
        $x | Should -Match '<Arguments>/c exit 7</Arguments>'
        $x | Should -Match '<Hidden>true</Hidden>'
        $x | Should -Match '<UserId>(NT AUTHORITY\\)?SYSTEM</UserId>'
        $t = Get-ScheduledTask -TaskName $n
        @($t.Triggers).Count | Should -Be 1
        $t.Triggers[0].PSObject.TypeNames[0] | Should -Be "$NS/MSFT_TaskWeeklyTrigger"
        [int]$t.Triggers[0].DaysOfWeek | Should -Be 2
        # the object set writes the definition from the object, which cannot carry a weekly trigger back: refused, nothing changes
        $e = @(Err { $t | Set-ScheduledTask })
        $e[0].FullyQualifiedErrorId | Should -Be 'TriggerTypeNotSupported,Set-ScheduledTask'
        ((& schtasks.exe /query /tn $n /xml) -join "`n") | Should -Match '<ScheduleByWeek>'
    }
    It 'Set-ScheduledTask of an unknown task is HRESULT 0x80070002 and registers nothing' -Skip:$skipRt {
        $e = @(Err { Set-ScheduledTask -TaskName nosuchtask-nitro -Action (New-ScheduledTaskAction -Execute cmd.exe) })
        $e[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x80070002,Set-ScheduledTask'
        @(Ok { Get-ScheduledTask -TaskName nosuchtask-nitro }).Count | Should -Be 0
    }
    It 'Set-ScheduledTask keeps the Enabled state set by Disable-/Enable-ScheduledTask' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe)
        $null = Disable-ScheduledTask -TaskName $n
        $t = Get-ScheduledTask -TaskName $n
        $t.Settings.Enabled = $false
        $null = $t | Set-ScheduledTask
        [string](Get-ScheduledTask -TaskName $n).State | Should -Be 'Disabled'
        $null = Enable-ScheduledTask -TaskName $n
        [string](Get-ScheduledTask -TaskName $n).State | Should -Be 'Ready'
    }
    It 'Export-ScheduledTask -TaskName is the stored definition: the text schtasks /query /xml prints' -Skip:$skipRt {
        $n = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit 0') -Description 'to export'
        $x = Export-ScheduledTask -TaskName $n
        $x | Should -BeOfType [string]
        @($x).Count | Should -Be 1
        $x | Should -Match '<Description>to export</Description>'
        $q = ((& schtasks.exe /query /tn $n /xml) -join "`n").Trim()
        ($x -replace "`r`n", "`n").Trim() | Should -Be ($q -replace "`r`n", "`n")
        (Export-ScheduledTask -TaskName $n -TaskPath '\') | Should -Be $x
        $e = @(Err { Export-ScheduledTask -TaskName $n -TaskPath '\\' })
        $e[0].FullyQualifiedErrorId | Should -Be 'HRESULT 0x8007007B,Export-ScheduledTask'
    }
    It 'Export-ScheduledTask -InputObject writes the object as indented UTF-16 task XML (also by pipeline) that Register-ScheduledTask -Xml accepts' -Skip:$skipRt {
        $n = New-TestName; $n2 = New-TestName
        $null = Register-ScheduledTask -TaskName $n -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c exit 0') -Description 'object export' `
            -Trigger (New-ScheduledTaskTrigger -Daily -At '2031-05-06 03:30:00')
        $t = Get-ScheduledTask -TaskName $n
        $x = Export-ScheduledTask -InputObject $t
        $x | Should -Be ($t | Export-ScheduledTask)
        $x.StartsWith("<?xml version=`"1.0`" encoding=`"UTF-16`"?>`r`n<Task version=`"1.3`" xmlns=`"http://schemas.microsoft.com/windows/2004/02/mit/task`">`r`n  <RegistrationInfo>") | Should -BeTrue
        $x | Should -Match '<URI>\\NitroPester-[0-9a-f]{8}</URI>\r\n    <SecurityDescriptor></SecurityDescriptor>\r\n  </RegistrationInfo>'
        $x | Should -Match '<Triggers>\r\n    <CalendarTrigger>'
        $x | Should -Not -Match '<Actions Context='
        $x.EndsWith('</Task>') | Should -BeTrue
        $x | Should -Match '<Command>cmd.exe</Command>\r\n      <Arguments>/c exit 0</Arguments>'
        $null = Register-ScheduledTask -TaskName $n2 -Xml $x
        $c = Get-ScheduledTask -TaskName $n2
        $c.Actions[0].Arguments | Should -Be '/c exit 0'
        $c.Description | Should -Be 'object export'
        @($c.Triggers).Count | Should -Be 1
    }
    It 'Export-ScheduledTask -InputObject of a Win8-level task writes version 1.4 and of a Vista/Win7 task 1.3 (measured)' {
        $s = New-ScheduledTaskSettingsSet -Compatibility Win8
        ([xml](Export-ScheduledTask -InputObject (New-ScheduledTask -Action (New-ScheduledTaskAction -Execute cmd.exe) -Settings $s -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount)))).Task.version | Should -Be '1.4'
        $s = New-ScheduledTaskSettingsSet -Compatibility Vista
        ([xml](Export-ScheduledTask -InputObject (New-ScheduledTask -Action (New-ScheduledTaskAction -Execute cmd.exe) -Settings $s -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount)))).Task.version | Should -Be '1.3'
    }
}
