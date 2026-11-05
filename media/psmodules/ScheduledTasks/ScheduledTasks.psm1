# ScheduledTasks for ReactOS-Nitro: a clean-room PowerShell 7 script module with the module, cmdlet and parameter names and the
# object shapes of the Windows ScheduledTasks module. It is a plain script over the Schedule.Service COM object (taskschd.dll);
# nothing is compiled. Registration goes through the task XML (RegisterTask), reads parse the task XML and the IRegisteredTask
# properties. The output objects carry the Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/
# MSFT_* type names, the properties in the order Windows reports them and the same value types.
#
# Limits of the nitro task service: idle, event and session-state triggers are stored exactly but never fired (weekly, monthly and
# monthly day-of-week triggers are fired); this module refuses the three never-fired kinds (an error) instead of registering a
# task that would never run.

Set-StrictMode -Version 2.0

$script:CimBase = 'Microsoft.Management.Infrastructure.CimInstance'
$script:TsPath = 'Microsoft/Windows/TaskScheduler'
$script:EnumNs = 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask'
$script:TaskXmlNs = 'http://schemas.microsoft.com/windows/2004/02/mit/task'
$script:TSSvc = $null
# Trigger kinds the module writes (the service fires them); idle, event and session-state triggers are stored but never fired
$script:WritableKinds = 'Time', 'Daily', 'Weekly', 'Monthly', 'MonthlyDOW', 'Boot', 'Logon', 'Registration'
$script:ServiceAccounts = @('SYSTEM', 'NT AUTHORITY\SYSTEM', 'LOCAL SERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'LOCALSERVICE',
    'NETWORK SERVICE', 'NT AUTHORITY\NETWORK SERVICE', 'NETWORKSERVICE', 'NT AUTHORITY\LOCALSERVICE', 'NT AUTHORITY\NETWORKSERVICE')

#region objects ------------------------------------------------------------------------------------------------------------

function TSEnum {
    param([string]$Name, $Value)
    [System.Enum]::ToObject(("$script:EnumNs.$Name" -as [type]), [int]$Value)
}

# An object that looks like the CimInstance Windows returns: CimInstance type-name chain, ScriptProperty enums first (Windows
# keeps those as ETS members), then the CIM properties in class order. The base is a plain System.Object so Select-Object and
# friends pass the object through instead of copying it.
function New-TSObject {
    param([string]$Class, [string[]]$Parents, [System.Collections.IDictionary]$Props)
    $o = [psobject]::new([object]::new())
    $names = $o.PSObject.TypeNames
    $names.Clear()
    $names.Add("$script:CimBase#Root/$script:TsPath/$Class")
    foreach ($p in $Parents) { $names.Add("$script:CimBase#ROOT/$script:TsPath/$p") }
    $names.Add("$script:CimBase#$Class")
    foreach ($p in $Parents) { $names.Add("$script:CimBase#$p") }
    $names.Add($script:CimBase)
    $names.Add('System.Object')
    foreach ($k in $Props.Keys) {
        $v = $Props[$k]
        if ($v -is [System.Enum]) {
            $store = @{ V = $v }
            $et = $v.GetType()
            $get = { $store.V }.GetNewClosure()
            $set = { param($x) $store.V = if ($x -is [string]) { [System.Enum]::Parse($et, $x, $true) } else { [System.Enum]::ToObject($et, $x) } }.GetNewClosure()
            $o.PSObject.Properties.Add([System.Management.Automation.PSScriptProperty]::new($k, $get, $set))
        } else {
            $o.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new($k, $v))
        }
    }
    $o.PSObject.Members.Add([System.Management.Automation.PSScriptMethod]::new('ToString', [scriptblock]::Create("'$Class'")))
    $o
}

function New-TSRepetition {
    param($Duration, $Interval, [bool]$StopAtDurationEnd)
    New-TSObject 'MSFT_TaskRepetitionPattern' @() ([ordered]@{
        Duration = $Duration; Interval = $Interval; StopAtDurationEnd = $StopAtDurationEnd; PSComputerName = $null })
}

function New-TSIdle {
    param($IdleDuration, [bool]$RestartOnIdle, [bool]$StopOnIdleEnd, $WaitTimeout)
    New-TSObject 'MSFT_TaskIdleSettings' @() ([ordered]@{
        IdleDuration = $IdleDuration; RestartOnIdle = $RestartOnIdle; StopOnIdleEnd = $StopOnIdleEnd; WaitTimeout = $WaitTimeout; PSComputerName = $null })
}

function New-TSNetwork {
    param($Id, $Name)
    New-TSObject 'MSFT_TaskNetworkSettings' @() ([ordered]@{ Id = $Id; Name = $Name; PSComputerName = $null })
}

function New-TSExecAction {
    param($Id, $Arguments, $Execute, $WorkingDirectory)
    New-TSObject 'MSFT_TaskExecAction' @('MSFT_TaskAction') ([ordered]@{
        Id = $Id; Arguments = $Arguments; Execute = $Execute; WorkingDirectory = $WorkingDirectory; PSComputerName = $null })
}

function New-TSComAction {
    param($Id, $ClassId, $Data)
    New-TSObject 'MSFT_TaskComHandlerAction' @('MSFT_TaskAction') ([ordered]@{ Id = $Id; ClassId = $ClassId; Data = $Data; PSComputerName = $null })
}

$script:TriggerClass = @{
    Time = 'MSFT_TaskTimeTrigger'; Daily = 'MSFT_TaskDailyTrigger'; Weekly = 'MSFT_TaskWeeklyTrigger'; Boot = 'MSFT_TaskBootTrigger'
    Logon = 'MSFT_TaskLogonTrigger'; Idle = 'MSFT_TaskIdleTrigger'; Registration = 'MSFT_TaskRegistrationTrigger'
    Event = 'MSFT_TaskEventTrigger'; SessionStateChange = 'MSFT_TaskSessionStateChangeTrigger'
    Monthly = 'MSFT_TaskMonthlyTrigger'; MonthlyDOW = 'MSFT_TaskMonthlyDOWTrigger'
}

function New-TSTrigger {
    param([string]$Kind, [bool]$Enabled = $true, $EndBoundary, $ExecutionTimeLimit, $Id,
        $Repetition, $StartBoundary, [System.Collections.IDictionary]$Extra)
    $p = [ordered]@{
        Enabled = $Enabled; EndBoundary = $EndBoundary; ExecutionTimeLimit = $ExecutionTimeLimit; Id = $Id
        Repetition = $Repetition; StartBoundary = $StartBoundary }
    if ($Extra) { foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] } }
    $p['PSComputerName'] = $null
    New-TSObject $script:TriggerClass[$Kind] @('MSFT_TaskTrigger') $p
}

function New-TSPrincipal {
    param($RunLevel, $LogonType, $ProcessTokenSidType, $DisplayName, $GroupId, $Id, $UserId, $RequiredPrivilege)
    New-TSObject 'MSFT_TaskPrincipal2' @('MSFT_TaskPrincipal') ([ordered]@{
        RunLevel = $RunLevel; LogonType = $LogonType; ProcessTokenSidType = $ProcessTokenSidType
        DisplayName = $DisplayName; GroupId = $GroupId; Id = $Id; UserId = $UserId
        RequiredPrivilege = $(if ($RequiredPrivilege) { [string[]]$RequiredPrivilege } else { $null }); PSComputerName = $null })
}

function New-TSSettings {
    param([hashtable]$S)
    New-TSObject 'MSFT_TaskSettings3' @('MSFT_TaskSettings2', 'MSFT_TaskSettings') ([ordered]@{
        MultipleInstances = $S.MultipleInstances; Compatibility = $S.Compatibility
        AllowDemandStart = [bool]$S.AllowDemandStart; AllowHardTerminate = [bool]$S.AllowHardTerminate
        DeleteExpiredTaskAfter = $S.DeleteExpiredTaskAfter; DisallowStartIfOnBatteries = [bool]$S.DisallowStartIfOnBatteries
        Enabled = [bool]$S.Enabled; ExecutionTimeLimit = $S.ExecutionTimeLimit; Hidden = [bool]$S.Hidden
        IdleSettings = $S.IdleSettings; NetworkSettings = $S.NetworkSettings
        Priority = [uint32]$S.Priority; RestartCount = [uint32]$S.RestartCount; RestartInterval = $S.RestartInterval
        RunOnlyIfIdle = [bool]$S.RunOnlyIfIdle; RunOnlyIfNetworkAvailable = [bool]$S.RunOnlyIfNetworkAvailable
        StartWhenAvailable = [bool]$S.StartWhenAvailable; StopIfGoingOnBatteries = [bool]$S.StopIfGoingOnBatteries
        WakeToRun = [bool]$S.WakeToRun; DisallowStartOnRemoteAppSession = [bool]$S.DisallowStartOnRemoteAppSession
        UseUnifiedSchedulingEngine = [bool]$S.UseUnifiedSchedulingEngine; MaintenanceSettings = $null; volatile = $false
        PSComputerName = $null })
}

function New-TSDefaultSettings {
    New-TSSettings @{
        MultipleInstances = (TSEnum 'MultipleInstancesEnum' 2); Compatibility = (TSEnum 'CompatibilityEnum' 3)
        AllowDemandStart = $true; AllowHardTerminate = $true; DeleteExpiredTaskAfter = $null; DisallowStartIfOnBatteries = $true
        Enabled = $true; ExecutionTimeLimit = 'PT72H'; Hidden = $false
        IdleSettings = (New-TSIdle 'PT10M' $false $true 'PT1H'); NetworkSettings = (New-TSNetwork $null $null)
        Priority = 7; RestartCount = 0; RestartInterval = $null; RunOnlyIfIdle = $false; RunOnlyIfNetworkAvailable = $false
        StartWhenAvailable = $false; StopIfGoingOnBatteries = $true; WakeToRun = $false; DisallowStartOnRemoteAppSession = $false
        UseUnifiedSchedulingEngine = $true }
}

function New-TSTask {
    param($State, $Actions, $Author, $Date, $Description, $Documentation, $Principal,
        $SecurityDescriptor, $Settings, $Source, $TaskName, $TaskPath, $Triggers, $URI, $Version)
    New-TSObject 'MSFT_ScheduledTask' @() ([ordered]@{
        State = $State; Actions = $Actions; Author = $Author; Date = $Date; Description = $Description; Documentation = $Documentation
        Principal = $Principal; SecurityDescriptor = $SecurityDescriptor; Settings = $Settings; Source = $Source
        TaskName = $TaskName; TaskPath = $TaskPath; Triggers = $Triggers; URI = $URI; Version = $Version; PSComputerName = $null })
}

#endregion

#region errors ------------------------------------------------------------------------------------------------------------

# Windows throws Microsoft.PowerShell.Cmdletization.Cim.CimJobException; it is built through its internal factory so
# Exception.GetType() and CategoryInfo.Reason read the same. Falls back to a plain exception.
function New-TSCimJobException {
    param([string]$Message, [string]$ErrorId, [System.Management.Automation.ErrorCategory]$Category)
    try {
        $t = [type]::GetType('Microsoft.PowerShell.Cmdletization.Cim.CimJobException, Microsoft.PowerShell.Commands.Management')
        $m = $t.GetMethod('CreateWithoutJobContext', [System.Reflection.BindingFlags]'NonPublic,Static')
        $m.Invoke($null, @($Message, $ErrorId, $Category, $null))
    } catch { [System.InvalidOperationException]::new($Message) }
}

function New-TSCimException {
    param([string]$Message)
    try { [Microsoft.Management.Infrastructure.CimException]::new($Message) } catch { [System.InvalidOperationException]::new($Message) }
}

function Get-TSHResult {
    param($Exception)
    $e = $Exception
    while ($null -ne $e) {
        if ($e -is [System.Runtime.InteropServices.COMException]) { return [int]$e.HResult }
        $e = $e.InnerException
    }
    [int]$Exception.HResult
}

function New-TSHresultError {
    param([int]$HResult, [string]$Message)
    $u = [uint32]($HResult -band 0xFFFFFFFFL)
    $hex = '0x{0:x8}' -f $u
    if (($u -band 0xFFFF0000L) -eq 0x80070000L) { $Message = [System.ComponentModel.Win32Exception]::new([int]($u -band 0xFFFFL)).Message }
    $cat = switch ($u) {
        { $_ -in 0x80070002L, 0x80070003L } { 'ObjectNotFound'; break }
        0x80070005L { 'PermissionDenied'; break }
        0x800700B7L { 'ResourceExists'; break }
        0x80070057L { 'InvalidArgument'; break }
        default { 'NotSpecified' }
    }
    $ex = New-TSCimException ($Message + "`r`n")
    [System.Management.Automation.ErrorRecord]::new($ex, "HRESULT $hex", $cat, 'PS_ScheduledTask')
}

function Write-TSComError {
    param($Cmdlet, $ErrorRecord)
    $hr = Get-TSHResult $ErrorRecord.Exception
    $msg = $ErrorRecord.Exception.Message
    $Cmdlet.WriteError((New-TSHresultError $hr $msg))
}

function Test-TSAsJob {
    param($Cmdlet, [bool]$AsJob)
    if ($AsJob) {
        $Cmdlet.WriteError([System.Management.Automation.ErrorRecord]::new([System.NotSupportedException]::new('The -AsJob parameter is not supported by this implementation.'), 'AsJobNotSupported', 'NotImplemented', $null))
    }
    $AsJob
}

function Stop-TSUnsupported {
    param($Cmdlet, [string]$What)
    $msg = "$What is not supported: the Task Scheduler of this system does not implement it and would never start the task."
    $Cmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([System.NotSupportedException]::new($msg), 'TriggerTypeNotSupported', 'NotImplemented', $What))
}

#endregion

#region Task Scheduler COM and XML ----------------------------------------------------------------------------------------

function Get-TSService {
    if ($null -eq $script:TSSvc) {
        $s = New-Object -ComObject Schedule.Service
        $s.Connect()
        $script:TSSvc = $s
    }
    $script:TSSvc
}

# '\a\b\' or '\a\b' or 'a' -> '\a\b' ('\' for the root), the form GetFolder takes
function Format-TSFolder {
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return '\' }
    $t = $Path.Trim().TrimEnd('\')
    if ($t -eq '') { return '\' }
    if (-not $t.StartsWith('\')) { $t = '\' + $t }
    $t
}

# '\a\b' -> '\a\b\' (the TaskPath form)
function Format-TSTaskPath {
    param([string]$Path)
    $f = Format-TSFolder $Path
    if ($f -eq '\') { '\' } else { $f + '\' }
}

function Add-TSFolderTasks {
    param($Folder, [System.Collections.Generic.List[object]]$Out)
    $tasks = @(foreach ($t in $Folder.GetTasks(1)) {
        $p = [string]$t.Path
        [pscustomobject]@{ Name = [string]$t.Name; TaskPath = $p.Substring(0, $p.LastIndexOf('\') + 1); Com = $t }
    })
    foreach ($t in ($tasks | Sort-Object -Property Name)) { $Out.Add($t) }
    $folders = @(foreach ($f in $Folder.GetFolders(0)) { $f })
    foreach ($f in ($folders | Sort-Object -Property Path)) { Add-TSFolderTasks $f $Out }
}

function Get-TSAllTasks {
    $out = [System.Collections.Generic.List[object]]::new()
    Add-TSFolderTasks ((Get-TSService).GetFolder('\')) $out
    , $out
}

function Get-TSXmlNode {
    param($Node, [string[]]$Path)
    foreach ($seg in $Path) {
        if ($null -eq $Node) { return $null }
        $Node = $Node.SelectSingleNode("*[local-name()='$seg']")
    }
    $Node
}

function Get-TSXmlText {
    param($Node, [string[]]$Path)
    $n = Get-TSXmlNode $Node $Path
    if ($null -eq $n) { return $null }
    $t = $n.InnerText
    if ([string]::IsNullOrEmpty($t)) { $null } else { $t }
}

function Get-TSXmlBool {
    param($Node, [string[]]$Path, [bool]$Default)
    $t = Get-TSXmlText $Node $Path
    if ($null -eq $t) { $Default } else { $t.Trim() -in 'true', '1' }
}

function Get-TSXmlAttr {
    param($Node, [string]$Name)
    if ($null -eq $Node -or -not $Node.HasAttribute($Name)) { return $null }
    $v = $Node.GetAttribute($Name)
    if ([string]::IsNullOrEmpty($v)) { $null } else { $v }
}

function Get-TSXmlChildren {
    param($Node)
    if ($null -eq $Node) { return @() }
    @($Node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
}

$script:LogonFromXml = @{ Password = 1; S4U = 2; InteractiveToken = 3; Group = 4; ServiceAccount = 5; InteractiveTokenOrPassword = 6 }
$script:DayBits = [ordered]@{ Sunday = 1; Monday = 2; Tuesday = 4; Wednesday = 8; Thursday = 16; Friday = 32; Saturday = 64 }
$script:MonthBits = [ordered]@{ January = 1; February = 2; March = 4; April = 8; May = 16; June = 32; July = 64; August = 128; September = 256; October = 512; November = 1024; December = 2048 }
$script:WeekBits = [ordered]@{ '1' = 1; '2' = 2; '3' = 4; '4' = 8 }

function Read-TSMask {
    param($Parent, [System.Collections.IDictionary]$Bits)
    $mask = 0
    foreach ($d in (Get-TSXmlChildren $Parent)) { if ($Bits.Contains($d.LocalName)) { $mask += $Bits[$d.LocalName] } }
    $mask
}

function Read-TSRepetition {
    param($Node)
    $rep = Get-TSXmlNode $Node @('Repetition')
    New-TSRepetition (Get-TSXmlText $rep @('Duration')) (Get-TSXmlText $rep @('Interval')) (Get-TSXmlBool $rep @('StopAtDurationEnd') $false)
}

function Read-TSTrigger {
    param($Node)
    $name = $Node.LocalName
    $common = @{
        Enabled = (Get-TSXmlBool $Node @('Enabled') $true); EndBoundary = (Get-TSXmlText $Node @('EndBoundary'))
        ExecutionTimeLimit = (Get-TSXmlText $Node @('ExecutionTimeLimit')); Id = (Get-TSXmlAttr $Node 'id')
        Repetition = (Read-TSRepetition $Node); StartBoundary = (Get-TSXmlText $Node @('StartBoundary')) }
    $kind = $null; $extra = [ordered]@{}
    switch ($name) {
        'TimeTrigger' { $kind = 'Time'; $extra['RandomDelay'] = Get-TSXmlText $Node @('RandomDelay') }
        'CalendarTrigger' {
            $rd = Get-TSXmlText $Node @('RandomDelay')
            if (Get-TSXmlNode $Node @('ScheduleByDay')) {
                $kind = 'Daily'
                $di = Get-TSXmlText $Node @('ScheduleByDay', 'DaysInterval')
                $extra['DaysInterval'] = [int16]$(if ($di) { $di } else { 1 })
                $extra['RandomDelay'] = $rd
            } elseif (Get-TSXmlNode $Node @('ScheduleByWeek')) {
                $kind = 'Weekly'
                $mask = 0
                $mask = Read-TSMask (Get-TSXmlNode $Node @('ScheduleByWeek', 'DaysOfWeek')) $script:DayBits
                $wi = Get-TSXmlText $Node @('ScheduleByWeek', 'WeeksInterval')
                $extra['DaysOfWeek'] = [uint16]$mask
                $extra['RandomDelay'] = $rd
                $extra['WeeksInterval'] = [uint16]$(if ($wi) { $wi } else { 1 })
            } elseif (Get-TSXmlNode $Node @('ScheduleByMonthDayOfWeek')) {
                $kind = 'MonthlyDOW'
                $sch = Get-TSXmlNode $Node @('ScheduleByMonthDayOfWeek')
                $wm = 0; $lastWeek = $false
                foreach ($w in (Get-TSXmlChildren (Get-TSXmlNode $sch @('Weeks')))) {
                    $wt = ([string]$w.InnerText).Trim()
                    if ($wt -eq 'Last') { $lastWeek = $true } elseif ($script:WeekBits.Contains($wt)) { $wm += $script:WeekBits[$wt] }
                }
                $extra['DaysOfWeek'] = [uint16](Read-TSMask (Get-TSXmlNode $sch @('DaysOfWeek')) $script:DayBits)
                $extra['MonthsOfYear'] = [uint16](Read-TSMask (Get-TSXmlNode $sch @('Months')) $script:MonthBits)
                $extra['RandomDelay'] = $rd
                $extra['RunOnLastWeekOfMonth'] = $lastWeek
                $extra['WeeksOfMonth'] = [uint16]$wm
            } else {
                $kind = 'Monthly'
                $sch = Get-TSXmlNode $Node @('ScheduleByMonth')
                $dm = [uint32]0; $lastDay = $false
                foreach ($d in (Get-TSXmlChildren (Get-TSXmlNode $sch @('DaysOfMonth')))) {
                    $dt = ([string]$d.InnerText).Trim()
                    $n = 0
                    if ($dt -eq 'Last') { $lastDay = $true } elseif ([int]::TryParse($dt, [ref]$n) -and $n -ge 1 -and $n -le 31) { $dm = $dm -bor [uint32][math]::Pow(2, $n - 1) }
                }
                $extra['DaysOfMonth'] = $dm
                $extra['MonthsOfYear'] = [uint16](Read-TSMask (Get-TSXmlNode $sch @('Months')) $script:MonthBits)
                $extra['RandomDelay'] = $rd
                $extra['RunOnLastDayOfMonth'] = $lastDay
            }
        }
        'BootTrigger' { $kind = 'Boot'; $extra['Delay'] = Get-TSXmlText $Node @('Delay') }
        'LogonTrigger' { $kind = 'Logon'; $extra['Delay'] = Get-TSXmlText $Node @('Delay'); $extra['UserId'] = Get-TSXmlText $Node @('UserId') }
        'IdleTrigger' { $kind = 'Idle' }
        'RegistrationTrigger' { $kind = 'Registration'; $extra['Delay'] = Get-TSXmlText $Node @('Delay') }
        'EventTrigger' {
            $kind = 'Event'; $extra['Delay'] = Get-TSXmlText $Node @('Delay'); $extra['Subscription'] = Get-TSXmlText $Node @('Subscription'); $extra['ValueQueries'] = $null
        }
        'SessionStateChangeTrigger' {
            $kind = 'SessionStateChange'; $extra['Delay'] = Get-TSXmlText $Node @('Delay')
            $sct = Get-TSXmlText $Node @('StateChange')
            $sc = if ($sct) { @{ ConsoleConnect = 1; ConsoleDisconnect = 2; RemoteConnect = 3; RemoteDisconnect = 4; SessionLock = 7; SessionUnlock = 8 }[$sct] }
            $extra['StateChange'] = [uint32]$(if ($sc) { $sc } else { 0 }); $extra['UserId'] = Get-TSXmlText $Node @('UserId')
        }
    }
    if ($null -eq $kind) { return $null }
    New-TSTrigger -Kind $kind -Enabled $common.Enabled -EndBoundary $common.EndBoundary -ExecutionTimeLimit $common.ExecutionTimeLimit `
        -Id $common.Id -Repetition $common.Repetition -StartBoundary $common.StartBoundary -Extra $extra
}

# Task XML -> the Windows-shaped parts (Actions, Triggers, Principal, Settings and the registration info)
function ConvertFrom-TSTaskXml {
    param([string]$Xml)
    $doc = [System.Xml.XmlDocument]::new()
    $doc.LoadXml($Xml)
    $root = $doc.DocumentElement
    $reg = Get-TSXmlNode $root @('RegistrationInfo')
    $ver = Get-TSXmlAttr $root 'version'
    $compat = switch ($ver) { '1.1' { 1 } '1.2' { 2 } '1.3' { 3 } default { if ($ver -and [version]$ver -gt [version]'1.3') { 4 } else { 2 } } }

    $triggers = [System.Collections.Generic.List[object]]::new()
    foreach ($n in (Get-TSXmlChildren (Get-TSXmlNode $root @('Triggers')))) { $t = Read-TSTrigger $n; if ($null -ne $t) { $triggers.Add($t) } }
    $actions = [System.Collections.Generic.List[object]]::new()
    foreach ($n in (Get-TSXmlChildren (Get-TSXmlNode $root @('Actions')))) {
        if ($n.LocalName -eq 'Exec') {
            $actions.Add((New-TSExecAction (Get-TSXmlAttr $n 'id') (Get-TSXmlText $n @('Arguments')) (Get-TSXmlText $n @('Command')) (Get-TSXmlText $n @('WorkingDirectory'))))
        } elseif ($n.LocalName -eq 'ComHandler') {
            $actions.Add((New-TSComAction (Get-TSXmlAttr $n 'id') (Get-TSXmlText $n @('ClassId')) (Get-TSXmlText $n @('Data'))))
        }
    }

    $pn = Get-TSXmlNode $root @('Principals', 'Principal')
    $lt = Get-TSXmlText $pn @('LogonType')
    if (-not $lt -and (Get-TSXmlText $pn @('GroupId'))) { $lt = 'Group' }
    $rl = Get-TSXmlText $pn @('RunLevel')
    $pts = Get-TSXmlText $pn @('ProcessTokenSidType')
    $priv = @(Get-TSXmlChildren (Get-TSXmlNode $pn @('RequiredPrivileges')) | ForEach-Object { $_.InnerText })
    $principal = New-TSPrincipal `
        -RunLevel (TSEnum 'RunLevelEnum' $(if ($rl -eq 'HighestAvailable') { 1 } else { 0 })) `
        -LogonType (TSEnum 'LogonTypeEnum' $(if ($lt -and $script:LogonFromXml.ContainsKey($lt)) { $script:LogonFromXml[$lt] } else { 0 })) `
        -ProcessTokenSidType (TSEnum 'ProcessTokenSidTypeEnum' $(switch ($pts) { 'None' { 0 } 'Unrestricted' { 1 } default { 2 } })) `
        -DisplayName (Get-TSXmlText $pn @('DisplayName')) -GroupId (Get-TSXmlText $pn @('GroupId')) -Id (Get-TSXmlAttr $pn 'id') `
        -UserId (Get-TSXmlText $pn @('UserId')) -RequiredPrivilege $priv

    $st = Get-TSXmlNode $root @('Settings')
    $idle = Get-TSXmlNode $st @('IdleSettings')
    $net = Get-TSXmlNode $st @('NetworkSettings')
    $mip = Get-TSXmlText $st @('MultipleInstancesPolicy')
    $pri = Get-TSXmlText $st @('Priority')
    $rc = Get-TSXmlText $st @('RestartOnFailure', 'Count')
    $settings = New-TSSettings @{
        MultipleInstances = (TSEnum 'MultipleInstancesEnum' $(switch ($mip) { 'Parallel' { 0 } 'Queue' { 1 } default { 2 } }))
        Compatibility = (TSEnum 'CompatibilityEnum' $compat)
        AllowDemandStart = (Get-TSXmlBool $st @('AllowStartOnDemand') $true); AllowHardTerminate = (Get-TSXmlBool $st @('AllowHardTerminate') $true)
        DeleteExpiredTaskAfter = (Get-TSXmlText $st @('DeleteExpiredTaskAfter'))
        DisallowStartIfOnBatteries = (Get-TSXmlBool $st @('DisallowStartIfOnBatteries') $true)
        Enabled = (Get-TSXmlBool $st @('Enabled') $true); ExecutionTimeLimit = $(if ($st) { Get-TSXmlText $st @('ExecutionTimeLimit') } else { 'PT72H' })
        Hidden = (Get-TSXmlBool $st @('Hidden') $false)
        IdleSettings = (New-TSIdle (Get-TSXmlText $idle @('Duration')) (Get-TSXmlBool $idle @('RestartOnIdle') $false) (Get-TSXmlBool $idle @('StopOnIdleEnd') $true) (Get-TSXmlText $idle @('WaitTimeout')))
        NetworkSettings = (New-TSNetwork (Get-TSXmlText $net @('Id')) (Get-TSXmlText $net @('Name')))
        Priority = $(if ($pri) { [int]$pri } else { 7 }); RestartCount = $(if ($rc) { [int]$rc } else { 0 })
        RestartInterval = (Get-TSXmlText $st @('RestartOnFailure', 'Interval'))
        RunOnlyIfIdle = (Get-TSXmlBool $st @('RunOnlyIfIdle') $false); RunOnlyIfNetworkAvailable = (Get-TSXmlBool $st @('RunOnlyIfNetworkAvailable') $false)
        StartWhenAvailable = (Get-TSXmlBool $st @('StartWhenAvailable') $false); StopIfGoingOnBatteries = (Get-TSXmlBool $st @('StopIfGoingOnBatteries') $true)
        WakeToRun = (Get-TSXmlBool $st @('WakeToRun') $false)
        DisallowStartOnRemoteAppSession = (Get-TSXmlBool $st @('DisallowStartOnRemoteAppSession') $false)
        UseUnifiedSchedulingEngine = (Get-TSXmlBool $st @('UseUnifiedSchedulingEngine') $false) }

    $sd = Get-TSXmlText $reg @('SecurityDescriptor')
    @{
        Actions = $actions; Triggers = $triggers; Principal = $principal; Settings = $settings
        Author = (Get-TSXmlText $reg @('Author')); Date = (Get-TSXmlText $reg @('Date')); Description = (Get-TSXmlText $reg @('Description'))
        Documentation = (Get-TSXmlText $reg @('Documentation')); Source = (Get-TSXmlText $reg @('Source')); Version = (Get-TSXmlText $reg @('Version'))
        SecurityDescriptor = $(if ($null -eq $sd) { '' } else { $sd })
    }
}

function ConvertTo-TSTaskObject {
    param($Com, [string]$TaskPath)
    $p = [string]$Com.Path
    $parts = ConvertFrom-TSTaskXml ([string]$Com.Xml)
    New-TSTask -State (TSEnum 'StateEnum' ([int]$Com.State)) -Actions ([object[]]$parts.Actions) -Author $parts.Author -Date $parts.Date `
        -Description $parts.Description -Documentation $parts.Documentation -Principal $parts.Principal -SecurityDescriptor $parts.SecurityDescriptor `
        -Settings $parts.Settings -Source $parts.Source -TaskName ([string]$Com.Name) -TaskPath $TaskPath `
        -Triggers ([object[]]$parts.Triggers) -URI $p -Version $parts.Version
}

function ConvertTo-TSInfoObject {
    param($Com, [string]$TaskName, [string]$TaskPath)
    $never = [datetime]::new(1999, 11, 30, 0, 0, 0, [System.DateTimeKind]::Local)
    $state = [int]$Com.State
    $last = [datetime]$Com.LastRunTime
    $res = [uint32](([int64]$Com.LastTaskResult) -band 0xFFFFFFFFL)
    if ($last.Year -lt 1980) { $last = $never; if ($res -eq 0) { $res = [uint32]267011 } } else { $last = [datetime]::SpecifyKind($last, [System.DateTimeKind]::Local) }
    $next = $null
    if ($state -ne 1) {
        $n = [datetime]$Com.NextRunTime
        if ($n.Year -ge 1980) { $next = [datetime]::SpecifyKind($n, [System.DateTimeKind]::Local) }
    }
    New-TSObject 'MSFT_TaskDynamicInfo' @() ([ordered]@{
        LastRunTime = $last; LastTaskResult = $res; NextRunTime = $next; NumberOfMissedRuns = [uint32]$Com.NumberOfMissedRuns
        TaskName = $TaskName; TaskPath = $TaskPath; PSComputerName = $null })
}

function Get-TSTriggerKind {
    param($Trigger)
    foreach ($n in $Trigger.PSObject.TypeNames) { if ($n -match '#Root/.*/MSFT_Task(\w+)Trigger$') { return $Matches[1] } }
    $null
}

function ConvertTo-IsoDuration {
    param([timespan]$Span)
    $s = 'P'
    if ($Span.Days) { $s += "$($Span.Days)D" }
    $t = ''
    if ($Span.Hours) { $t += "$($Span.Hours)H" }
    if ($Span.Minutes) { $t += "$($Span.Minutes)M" }
    if ($Span.Seconds) { $t += "$($Span.Seconds)S" }
    if ($t) { $s += "T$t" }
    if ($s -eq 'P') { 'PT0S' } else { $s }
}

function ConvertTo-TSTime {
    param([datetime]$At)
    $At.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

$script:UnsupportedXml = @{
    IdleTrigger = 'an idle trigger'; EventTrigger = 'an event trigger'; SessionStateChangeTrigger = 'a session state change trigger' }

# Names of the unsupported trigger kinds a task XML uses
function Find-TSUnsupportedXml {
    param([string]$Xml)
    try {
        $doc = [System.Xml.XmlDocument]::new()
        $doc.LoadXml($Xml)
    } catch { return @() }
    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($n in (Get-TSXmlChildren (Get-TSXmlNode $doc.DocumentElement @('Triggers')))) {
        if ($script:UnsupportedXml.ContainsKey($n.LocalName)) { $found.Add($script:UnsupportedXml[$n.LocalName]) }
        elseif ($n.LocalName -eq 'CalendarTrigger') {
            foreach ($c in (Get-TSXmlChildren $n)) { if ($script:UnsupportedXml.ContainsKey($c.LocalName)) { $found.Add($script:UnsupportedXml[$c.LocalName]) } }
        }
    }
    $found.ToArray()
}

function Add-TSElement {
    param($Doc, $Parent, [string]$Name, $Text)
    $e = $Doc.CreateElement($Name, $script:TaskXmlNs)
    if ($null -ne $Text) { $e.InnerText = if ($Text -is [bool]) { ([string]$Text).ToLowerInvariant() } else { [string]$Text } }
    $null = $Parent.AppendChild($e)
    $e
}

function Add-TSOptional {
    param($Doc, $Parent, [string]$Name, $Text)
    if (-not [string]::IsNullOrEmpty([string]$Text)) { $null = Add-TSElement $Doc $Parent $Name $Text }
}

# The task XML of Actions/Triggers/Principal/Settings objects (Windows-shaped objects, built by this module or read back)
function ConvertTo-TSTaskXml {
    param($Actions, $Triggers, $Principal, $Settings, [string]$Description, [string]$Author, [string]$Uri, [string]$Source, [string]$Documentation,
        [string]$Date, [string]$Version, [string]$SecurityDescriptor, [switch]$Export)
    if ($null -eq $Settings) { $Settings = New-TSDefaultSettings }
    $doc = [System.Xml.XmlDocument]::new()
    $null = $doc.AppendChild($doc.CreateXmlDeclaration('1.0', 'UTF-16', $null))
    $ver = switch ([int]$Settings.Compatibility) { 1 { '1.1' } 2 { '1.2' } 3 { '1.3' } 4 { '1.4' } default { '1.2' } }
    # Export-ScheduledTask of a task object: Windows writes 1.3 for the Vista and Win7 levels and 1.4 for Win8 (measured)
    if ($Export) { $ver = if ([int]$Settings.Compatibility -ge 4) { '1.4' } else { '1.3' } }
    $task = Add-TSElement $doc $doc 'Task'
    $task.SetAttribute('version', $ver)

    $ri = Add-TSElement $doc $task 'RegistrationInfo'
    if ($Export) {
        # the order Export-ScheduledTask uses for an object (measured on 75 tasks): Source, Author, Version, Description, URI, SecurityDescriptor
        Add-TSOptional $doc $ri 'Source' $Source
        Add-TSOptional $doc $ri 'Date' $Date
        Add-TSOptional $doc $ri 'Author' $Author
        Add-TSOptional $doc $ri 'Version' $Version
        Add-TSOptional $doc $ri 'Description' $Description
        Add-TSOptional $doc $ri 'Documentation' $Documentation
        Add-TSOptional $doc $ri 'URI' $Uri
        $sd = Add-TSElement $doc $ri 'SecurityDescriptor' $SecurityDescriptor
        $sd.IsEmpty = $false    # Windows writes <SecurityDescriptor></SecurityDescriptor>
    } else {
        Add-TSOptional $doc $ri 'Author' $Author
        Add-TSOptional $doc $ri 'Date' $(if ($Date) { $Date } else { [datetime]::Now.ToString("yyyy-MM-dd'T'HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture) })
        Add-TSOptional $doc $ri 'Description' $Description
        Add-TSOptional $doc $ri 'Source' $Source
        Add-TSOptional $doc $ri 'Documentation' $Documentation
        Add-TSOptional $doc $ri 'URI' $Uri
    }

    $trigList = @(@($Triggers) | Where-Object { $null -ne $_ })
    $actList = @(@($Actions) | Where-Object { $null -ne $_ })
    if ($trigList.Count -gt 0) {
        $tr = Add-TSElement $doc $task 'Triggers'
        foreach ($t in $trigList) {
            $kind = Get-TSTriggerKind $t
            $e = switch ($kind) {
                'Time' { Add-TSElement $doc $tr 'TimeTrigger' }
                { $_ -in 'Daily', 'Weekly', 'Monthly', 'MonthlyDOW' } { Add-TSElement $doc $tr 'CalendarTrigger' }
                'Boot' { Add-TSElement $doc $tr 'BootTrigger' }
                'Logon' { Add-TSElement $doc $tr 'LogonTrigger' }
                'Registration' { Add-TSElement $doc $tr 'RegistrationTrigger' }
                default { throw [System.NotSupportedException]::new("Trigger kind '$kind' is not supported.") }
            }
            if ($t.Id) { $e.SetAttribute('id', [string]$t.Id) }
            $rep = $t.Repetition
            if ($rep -and ($rep.Interval -or $rep.Duration)) {
                $r = Add-TSElement $doc $e 'Repetition'
                Add-TSOptional $doc $r 'Interval' $rep.Interval
                Add-TSOptional $doc $r 'Duration' $rep.Duration
                $null = Add-TSElement $doc $r 'StopAtDurationEnd' ([bool]$rep.StopAtDurationEnd)
            }
            Add-TSOptional $doc $e 'StartBoundary' $t.StartBoundary
            Add-TSOptional $doc $e 'EndBoundary' $t.EndBoundary
            $null = Add-TSElement $doc $e 'Enabled' ([bool]$t.Enabled)
            Add-TSOptional $doc $e 'ExecutionTimeLimit' $t.ExecutionTimeLimit
            switch ($kind) {
                'Time' { Add-TSOptional $doc $e 'RandomDelay' $t.RandomDelay }
                'Daily' {
                    Add-TSOptional $doc $e 'RandomDelay' $t.RandomDelay
                    $d = Add-TSElement $doc $e 'ScheduleByDay'
                    $null = Add-TSElement $doc $d 'DaysInterval' ([int]$t.DaysInterval)
                }
                'Weekly' {
                    Add-TSOptional $doc $e 'RandomDelay' $t.RandomDelay
                    $w = Add-TSElement $doc $e 'ScheduleByWeek'
                    $dw = Add-TSElement $doc $w 'DaysOfWeek'
                    foreach ($k in $script:DayBits.Keys) { if ([int]$t.DaysOfWeek -band $script:DayBits[$k]) { $null = Add-TSElement $doc $dw $k } }
                    $null = Add-TSElement $doc $w 'WeeksInterval' ([int]$t.WeeksInterval)
                }
                'Monthly' {
                    Add-TSOptional $doc $e 'RandomDelay' $t.RandomDelay
                    $m = Add-TSElement $doc $e 'ScheduleByMonth'
                    $dm = Add-TSElement $doc $m 'DaysOfMonth'
                    for ($i = 1; $i -le 31; $i++) { if (([uint32]$t.DaysOfMonth -band [uint32][math]::Pow(2, $i - 1)) -ne 0) { $null = Add-TSElement $doc $dm 'Day' $i } }
                    if ([bool]$t.RunOnLastDayOfMonth) { $null = Add-TSElement $doc $dm 'Day' 'Last' }
                    $mo = Add-TSElement $doc $m 'Months'
                    foreach ($k in $script:MonthBits.Keys) { if ([int]$t.MonthsOfYear -band $script:MonthBits[$k]) { $null = Add-TSElement $doc $mo $k } }
                }
                'MonthlyDOW' {
                    Add-TSOptional $doc $e 'RandomDelay' $t.RandomDelay
                    $m = Add-TSElement $doc $e 'ScheduleByMonthDayOfWeek'
                    $wk = Add-TSElement $doc $m 'Weeks'
                    foreach ($k in $script:WeekBits.Keys) { if ([int]$t.WeeksOfMonth -band $script:WeekBits[$k]) { $null = Add-TSElement $doc $wk 'Week' $k } }
                    if ([bool]$t.RunOnLastWeekOfMonth) { $null = Add-TSElement $doc $wk 'Week' 'Last' }
                    $dw = Add-TSElement $doc $m 'DaysOfWeek'
                    foreach ($k in $script:DayBits.Keys) { if ([int]$t.DaysOfWeek -band $script:DayBits[$k]) { $null = Add-TSElement $doc $dw $k } }
                    $mo = Add-TSElement $doc $m 'Months'
                    foreach ($k in $script:MonthBits.Keys) { if ([int]$t.MonthsOfYear -band $script:MonthBits[$k]) { $null = Add-TSElement $doc $mo $k } }
                }
                'Boot' { Add-TSOptional $doc $e 'Delay' $t.Delay }
                'Logon' { Add-TSOptional $doc $e 'UserId' $t.UserId; Add-TSOptional $doc $e 'Delay' $t.Delay }
                'Registration' { Add-TSOptional $doc $e 'Delay' $t.Delay }
            }
        }
    }

    $pid_ = 'Author'
    if ($null -eq $Principal) { $Principal = New-TSPrincipal (TSEnum 'RunLevelEnum' 0) (TSEnum 'LogonTypeEnum' 3) (TSEnum 'ProcessTokenSidTypeEnum' 2) $null $null $null ("$([Environment]::UserDomainName)\$([Environment]::UserName)") $null }
    if ($Principal.Id) { $pid_ = [string]$Principal.Id }
    $ps = Add-TSElement $doc $task 'Principals'
    $p = Add-TSElement $doc $ps 'Principal'
    $p.SetAttribute('id', $pid_)
    Add-TSOptional $doc $p 'UserId' $Principal.UserId
    Add-TSOptional $doc $p 'GroupId' $Principal.GroupId
    Add-TSOptional $doc $p 'DisplayName' $Principal.DisplayName
    $ltName = @{ 1 = 'Password'; 2 = 'S4U'; 3 = 'InteractiveToken'; 4 = 'Group'; 5 = 'ServiceAccount'; 6 = 'InteractiveTokenOrPassword' }[[int]$Principal.LogonType]
    Add-TSOptional $doc $p 'LogonType' $ltName
    $null = Add-TSElement $doc $p 'RunLevel' $(if ([int]$Principal.RunLevel -eq 1) { 'HighestAvailable' } else { 'LeastPrivilege' })
    if ([int]$Principal.ProcessTokenSidType -ne 2) { $null = Add-TSElement $doc $p 'ProcessTokenSidType' ([string]$Principal.ProcessTokenSidType) }
    if ($Principal.RequiredPrivilege) {
        $rp = Add-TSElement $doc $p 'RequiredPrivileges'
        foreach ($x in $Principal.RequiredPrivilege) { $null = Add-TSElement $doc $rp 'Privilege' $x }
    }

    $s = Add-TSElement $doc $task 'Settings'
    $null = Add-TSElement $doc $s 'MultipleInstancesPolicy' ([string]$Settings.MultipleInstances)
    $null = Add-TSElement $doc $s 'DisallowStartIfOnBatteries' ([bool]$Settings.DisallowStartIfOnBatteries)
    $null = Add-TSElement $doc $s 'StopIfGoingOnBatteries' ([bool]$Settings.StopIfGoingOnBatteries)
    $null = Add-TSElement $doc $s 'AllowHardTerminate' ([bool]$Settings.AllowHardTerminate)
    $null = Add-TSElement $doc $s 'StartWhenAvailable' ([bool]$Settings.StartWhenAvailable)
    $null = Add-TSElement $doc $s 'RunOnlyIfNetworkAvailable' ([bool]$Settings.RunOnlyIfNetworkAvailable)
    $idle = $Settings.IdleSettings
    if ($idle) {
        $i = Add-TSElement $doc $s 'IdleSettings'
        Add-TSOptional $doc $i 'Duration' $idle.IdleDuration
        Add-TSOptional $doc $i 'WaitTimeout' $idle.WaitTimeout
        $null = Add-TSElement $doc $i 'StopOnIdleEnd' ([bool]$idle.StopOnIdleEnd)
        $null = Add-TSElement $doc $i 'RestartOnIdle' ([bool]$idle.RestartOnIdle)
    }
    $null = Add-TSElement $doc $s 'AllowStartOnDemand' ([bool]$Settings.AllowDemandStart)
    $null = Add-TSElement $doc $s 'Enabled' ([bool]$Settings.Enabled)
    $null = Add-TSElement $doc $s 'Hidden' ([bool]$Settings.Hidden)
    $null = Add-TSElement $doc $s 'RunOnlyIfIdle' ([bool]$Settings.RunOnlyIfIdle)
    if ($Export) {
        $null = Add-TSElement $doc $s 'DisallowStartOnRemoteAppSession' ([bool]$Settings.DisallowStartOnRemoteAppSession)
        $null = Add-TSElement $doc $s 'UseUnifiedSchedulingEngine' ([bool]$Settings.UseUnifiedSchedulingEngine)
    }
    $null = Add-TSElement $doc $s 'WakeToRun' ([bool]$Settings.WakeToRun)
    Add-TSOptional $doc $s 'ExecutionTimeLimit' $Settings.ExecutionTimeLimit
    $null = Add-TSElement $doc $s 'Priority' ([int]$Settings.Priority)
    Add-TSOptional $doc $s 'DeleteExpiredTaskAfter' $Settings.DeleteExpiredTaskAfter
    if ($Settings.RestartInterval -or [int]$Settings.RestartCount -gt 0) {
        $rf = Add-TSElement $doc $s 'RestartOnFailure'
        Add-TSOptional $doc $rf 'Interval' $Settings.RestartInterval
        $null = Add-TSElement $doc $rf 'Count' ([int]$Settings.RestartCount)
    }
    $net = $Settings.NetworkSettings
    if ($net -and ($net.Name -or $net.Id)) {
        $n = Add-TSElement $doc $s 'NetworkSettings'
        Add-TSOptional $doc $n 'Name' $net.Name
        Add-TSOptional $doc $n 'Id' $net.Id
    }
    if (-not $Export) {
        $null = Add-TSElement $doc $s 'DisallowStartOnRemoteAppSession' ([bool]$Settings.DisallowStartOnRemoteAppSession)
        $null = Add-TSElement $doc $s 'UseUnifiedSchedulingEngine' ([bool]$Settings.UseUnifiedSchedulingEngine)
    }

    $as = Add-TSElement $doc $task 'Actions'
    if (-not $Export) { $as.SetAttribute('Context', $pid_) }
    foreach ($a in $actList) {
        if ($null -ne ($a.PSObject.Properties['Execute'])) {
            $e = Add-TSElement $doc $as 'Exec'
            if ($a.Id) { $e.SetAttribute('id', [string]$a.Id) }
            $null = Add-TSElement $doc $e 'Command' $a.Execute
            Add-TSOptional $doc $e 'Arguments' $a.Arguments
            Add-TSOptional $doc $e 'WorkingDirectory' $a.WorkingDirectory
        } elseif ($null -ne ($a.PSObject.Properties['ClassId'])) {
            $e = Add-TSElement $doc $as 'ComHandler'
            if ($a.Id) { $e.SetAttribute('id', [string]$a.Id) }
            $null = Add-TSElement $doc $e 'ClassId' $a.ClassId
            Add-TSOptional $doc $e 'Data' $a.Data
        }
    }
    if ($Export) {
        # the text Windows hands out: indented two spaces, CRLF line ends, UTF-16 declaration, no trailing newline
        $sw = [System.IO.StringWriter]::new()
        $ws = [System.Xml.XmlWriterSettings]::new()
        $ws.Indent = $true; $ws.IndentChars = '  '; $ws.NewLineChars = "`r`n"; $ws.NewLineHandling = 'Replace'; $ws.OmitXmlDeclaration = $true
        $xw = [System.Xml.XmlWriter]::Create($sw, $ws)
        $doc.DocumentElement.WriteTo($xw)
        $xw.Flush(); $xw.Close()
        return '<?xml version="1.0" encoding="UTF-16"?>' + "`r`n" + $sw.ToString()
    }
    $doc.OuterXml
}

# Task lookup shared by Get-/Unregister-ScheduledTask: matching tasks plus the not-found error records Windows writes
function Find-TSTasks {
    param([string]$ClassName, [string[]]$Name, [string[]]$Path, [bool]$HaveName, [bool]$HavePath)
    $all = (Get-TSAllTasks)
    $nameRx = @(if ($HaveName) { $Name | ForEach-Object { [System.Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') } })
    $pathRx = @(if ($HavePath) { $Path | ForEach-Object { [System.Management.Automation.WildcardPattern]::new($_, 'IgnoreCase') } })
    $hit = [System.Collections.Generic.List[object]]::new()
    $nameHit = @{}; $pathHit = @{}
    foreach ($t in $all) {
        $nm = $true; $pm = $true
        if ($HaveName) { $nm = $false; for ($i = 0; $i -lt $nameRx.Count; $i++) { if ($nameRx[$i].IsMatch($t.Name)) { $nm = $true; $nameHit[$i] = 1 } } }
        if ($HavePath) { $pm = $false; for ($i = 0; $i -lt $pathRx.Count; $i++) { if ($pathRx[$i].IsMatch($t.TaskPath)) { $pm = $true; $pathHit[$i] = 1 } } }
        if ($nm -and $pm) { $hit.Add($t) }
    }
    $errors = [System.Collections.Generic.List[object]]::new()
    $wild = { param($s) [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($s) }
    if ($HaveName -xor $HavePath) {
        $prop, $vals, $hits = if ($HaveName) { 'TaskName', $Name, $nameHit } else { 'TaskPath', $Path, $pathHit }
        for ($i = 0; $i -lt @($vals).Count; $i++) {
            $v = @($vals)[$i]
            if ((-not (& $wild $v)) -and -not $hits.ContainsKey($i)) {
                $id = "CmdletizationQuery_NotFound_$prop"
                $msg = "No $ClassName objects found with property '$prop' equal to '$v'.  Verify the value of the property and retry."
                $errors.Add([System.Management.Automation.ErrorRecord]::new((New-TSCimJobException $msg $id ObjectNotFound), $id, 'ObjectNotFound', $v))
            }
        }
    } elseif ($HaveName -and $HavePath -and $hit.Count -eq 0) {
        $anyExact = @(@($Name) + @($Path) | Where-Object { -not (& $wild $_) }).Count -gt 0
        if ($anyExact) {
            $like = {
                param($prop, $vals)
                $parts = foreach ($v in @($vals)) { "($prop LIKE '" + ($v.Replace('\', '\\').Replace("'", "\'").Replace('*', '%').Replace('?', '_')) + "')" }
                '(' + ($parts -join ' OR ') + ')'
            }
            $wql = "SELECT * FROM $ClassName  WHERE " + (& $like 'TaskName' $Name) + ' AND ' + (& $like 'TaskPath' $Path)
            $id = 'CmdletizationQuery_NotFound'
            $msg = "No matching $ClassName objects found by CIM query for instances of the Root/$script:TsPath/$ClassName class on the  CIM server: $wql. Verify query parameters and retry."
            $errors.Add([System.Management.Automation.ErrorRecord]::new((New-TSCimJobException $msg $id ObjectNotFound), $id, 'ObjectNotFound', $ClassName))
        }
    }
    [pscustomobject]@{ Tasks = $hit; Errors = $errors }
}

# One task by name and folder (Start-/Stop-/Enable-/Disable-ScheduledTask, Get-ScheduledTaskInfo); writes the HRESULT error and returns $null when it fails
# What the task service did not keep of the submitted definition (it stores a subset of the settings and re-writes the triggers it
# understands): reported as a warning so a registration never claims more than the service holds.
function Get-TSDroppedItems {
    param([string]$Submitted, [string]$Stored)
    $lost = [System.Collections.Generic.List[string]]::new()
    try { $a = ConvertFrom-TSTaskXml $Submitted; $b = ConvertFrom-TSTaskXml $Stored } catch { return @() }
    $sa = $a.Settings; $sb = $b.Settings
    foreach ($n in 'RestartCount', 'RestartInterval', 'DeleteExpiredTaskAfter') {
        if ($null -ne $sa.$n -and "$($sa.$n)" -ne '0' -and "$($sa.$n)" -ne "$($sb.$n)") { $lost.Add($n) }
    }
    foreach ($n in 'Name', 'Id') {
        if ($sa.NetworkSettings.$n -and $sa.NetworkSettings.$n -ne $sb.NetworkSettings.$n) { $lost.Add("NetworkSettings.$n") }
    }
    if ($sa.RunOnlyIfIdle) {
        foreach ($n in 'IdleDuration', 'WaitTimeout') { if ($sa.IdleSettings.$n -and $sa.IdleSettings.$n -ne $sb.IdleSettings.$n) { $lost.Add("IdleSettings.$n") } }
    }
    if (@($a.Triggers).Count -ne @($b.Triggers).Count) { $lost.Add('Triggers') }
    $lost.ToArray()
}

function Get-TSTask {
    param($Cmdlet, [string]$Name, [string]$Path)
    try {
        (Get-TSService).GetFolder((Format-TSFolder $Path)).GetTask($Name)
    } catch {
        # a missing folder or a name with wildcard characters reads as a missing task, as on Windows (0x80070002 instead of the COM 0x80070003 / 0x8007007B)
        $hr = Get-TSHResult $_.Exception
        if ($hr -eq [int]0x80070003 -or $hr -eq [int]0x8007007B) { $hr = [int]0x80070002 }
        $Cmdlet.WriteError((New-TSHresultError $hr $_.Exception.Message))
        $null
    }
}

function Get-TSTargetFromObject {
    param($InputObject)
    [pscustomobject]@{ Name = [string]$InputObject.TaskName; Path = [string]$InputObject.TaskPath }
}

#endregion

#region cmdlets -----------------------------------------------------------------------------------------------------------

function Get-ScheduledTask {
    [CmdletBinding(DefaultParameterSetName = 'ByPath')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/MSFT_ScheduledTask')]
    param(
        [Parameter(ParameterSetName = 'ByPath', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$TaskName,

        [Parameter(ParameterSetName = 'ByPath', Position = 1, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$TaskPath,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        $r = Find-TSTasks 'MSFT_ScheduledTask' $TaskName $TaskPath $PSBoundParameters.ContainsKey('TaskName') $PSBoundParameters.ContainsKey('TaskPath')
        foreach ($t in $r.Tasks) { ConvertTo-TSTaskObject $t.Com $t.TaskPath }
        foreach ($e in $r.Errors) { $PSCmdlet.WriteError($e) }
    }
}

function Get-ScheduledTaskInfo {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskDynamicInfo')]
    param(
        [Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'Name', Position = 1)]
        [string]$TaskPath,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        if ($PSCmdlet.ParameterSetName -eq 'Object') { $name = [string]$InputObject.TaskName; $path = [string]$InputObject.TaskPath }
        else { $name = $TaskName; $path = if ($PSBoundParameters.ContainsKey('TaskPath')) { $TaskPath } else { '\' } }
        $com = Get-TSTask $PSCmdlet $name $path
        if ($null -eq $com) { return }
        ConvertTo-TSInfoObject $com $name $path
    }
}

function Start-ScheduledTask {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(ParameterSetName = 'Path', Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'Path', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$TaskPath,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        if ($PSCmdlet.ParameterSetName -eq 'Object') { $name = [string]$InputObject.TaskName; $path = [string]$InputObject.TaskPath }
        else { $name = $TaskName; $path = if ($PSBoundParameters.ContainsKey('TaskPath')) { $TaskPath } else { '\' } }
        $com = Get-TSTask $PSCmdlet $name $path
        if ($null -eq $com) { return }
        try { $null = $com.Run($null) } catch { Write-TSComError $PSCmdlet $_ }
    }
}

function Stop-ScheduledTask {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(ParameterSetName = 'Path', Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'Path', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$TaskPath,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 1, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        if ($PSCmdlet.ParameterSetName -eq 'Object') { $name = [string]$InputObject.TaskName; $path = [string]$InputObject.TaskPath }
        else { $name = $TaskName; $path = if ($PSBoundParameters.ContainsKey('TaskPath')) { $TaskPath } else { '\' } }
        $com = Get-TSTask $PSCmdlet $name $path
        if ($null -eq $com) { return }
        try { $com.Stop(0) } catch {
            # SCHED_E_TASK_NOT_RUNNING: stopping a task that is not running is not an error
            if ((Get-TSHResult $_.Exception) -ne [int]0x8004130B) { Write-TSComError $PSCmdlet $_ }
        }
    }
}

function Set-TSEnabled {
    param($Cmdlet, [string]$Name, [string]$Path, [bool]$Enabled)
    $com = Get-TSTask $Cmdlet $Name $Path
    if ($null -eq $com) { return }
    try { $com.Enabled = $Enabled } catch { Write-TSComError $Cmdlet $_; return }
    ConvertTo-TSTaskObject $com (Format-TSTaskPath $Path)
}

function Enable-ScheduledTask {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
    param(
        [Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'Name', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$TaskPath,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        if ($PSCmdlet.ParameterSetName -eq 'Object') { $name = [string]$InputObject.TaskName; $path = [string]$InputObject.TaskPath }
        else { $name = $TaskName; $path = if ($PSBoundParameters.ContainsKey('TaskPath')) { $TaskPath } else { '\' } }
        Set-TSEnabled $PSCmdlet $name $path $true
    }
}

function Disable-ScheduledTask {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
    param(
        [Parameter(ParameterSetName = 'Name', Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'Name', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$TaskPath,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        if ($PSCmdlet.ParameterSetName -eq 'Object') { $name = [string]$InputObject.TaskName; $path = [string]$InputObject.TaskPath }
        else { $name = $TaskName; $path = if ($PSBoundParameters.ContainsKey('TaskPath')) { $TaskPath } else { '\' } }
        Set-TSEnabled $PSCmdlet $name $path $false
    }
}

function Unregister-ScheduledTask {
    [CmdletBinding(DefaultParameterSetName = 'ByPath', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#Root/Microsoft/Windows/TaskScheduler/MSFT_ScheduledTask')]
    param(
        [Parameter(ParameterSetName = 'ByPath', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$TaskName,

        [Parameter(ParameterSetName = 'ByPath', Position = 1, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()][string[]]$TaskPath,

        [Parameter(ParameterSetName = 'InputObject', Mandatory = $true, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][ValidateNotNull()][object[]]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob,
        [switch]$PassThru
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        $targets = [System.Collections.Generic.List[object]]::new()
        if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
            foreach ($o in $InputObject) {
                $t = Get-TSTask $PSCmdlet ([string]$o.TaskName) ([string]$o.TaskPath)
                if ($null -ne $t) { $targets.Add([pscustomobject]@{ Name = [string]$o.TaskName; TaskPath = (Format-TSTaskPath ([string]$o.TaskPath)); Com = $t }) }
            }
        } else {
            $r = Find-TSTasks 'MSFT_ScheduledTask' $TaskName $TaskPath $PSBoundParameters.ContainsKey('TaskName') $PSBoundParameters.ContainsKey('TaskPath')
            foreach ($t in $r.Tasks) { $targets.Add($t) }
            foreach ($e in $r.Errors) { $PSCmdlet.WriteError($e) }
        }
        foreach ($t in $targets) {
            $target = $t.TaskPath + $t.Name
            $text = "Performing operation 'Delete' on Target '$target'."
            if (-not $PSCmdlet.ShouldProcess($text, $text, 'Confirm')) { continue }
            $obj = if ($PassThru) { ConvertTo-TSTaskObject $t.Com $t.TaskPath }
            try { (Get-TSService).GetFolder((Format-TSFolder $t.TaskPath)).DeleteTask($t.Name, 0) } catch { Write-TSComError $PSCmdlet $_; continue }
            if ($PassThru) { $obj }
        }
    }
}

function New-ScheduledTaskAction {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskAction')]
    param(
        [Parameter(ParameterSetName = 'Exec')][string]$Id,
        [Parameter(ParameterSetName = 'Exec', Mandatory = $true, Position = 0)][ValidateNotNullOrEmpty()][string]$Execute,
        [Parameter(ParameterSetName = 'Exec', Position = 1)][string]$Argument,
        [Parameter(ParameterSetName = 'Exec', Position = 2)][string]$WorkingDirectory,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        New-TSExecAction $(if ($Id) { $Id } else { $null }) $(if ($Argument) { $Argument } else { $null }) $Execute $(if ($WorkingDirectory) { $WorkingDirectory } else { $null })
    }
}

function New-ScheduledTaskTrigger {
    [CmdletBinding(DefaultParameterSetName = 'Once')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskTrigger')]
    param(
        [Parameter(ParameterSetName = 'Once')]
        [Parameter(ParameterSetName = 'Daily')]
        [Parameter(ParameterSetName = 'Weekly')]
        [Parameter(ParameterSetName = 'Startup')]
        [Parameter(ParameterSetName = 'Logon')]
        [timespan]$RandomDelay,

        [Parameter(ParameterSetName = 'Once', Mandatory = $true)]
        [Parameter(ParameterSetName = 'Daily', Mandatory = $true)]
        [Parameter(ParameterSetName = 'Weekly', Mandatory = $true)]
        [ValidateNotNullOrEmpty()][datetime]$At,

        [Parameter(ParameterSetName = 'Once', Mandatory = $true, Position = 0)][switch]$Once,
        [Parameter(ParameterSetName = 'Once')][timespan]$RepetitionDuration,
        [Parameter(ParameterSetName = 'Once')][timespan]$RepetitionInterval,

        [Parameter(ParameterSetName = 'Daily', Mandatory = $true, Position = 0)][switch]$Daily,
        [Parameter(ParameterSetName = 'Daily')][ValidateNotNullOrEmpty()][uint32]$DaysInterval,

        [Parameter(ParameterSetName = 'Weekly')][DayOfWeek[]]$DaysOfWeek,
        [Parameter(ParameterSetName = 'Weekly', Mandatory = $true, Position = 0)][switch]$Weekly,
        [Parameter(ParameterSetName = 'Weekly')][uint32]$WeeksInterval,

        [Parameter(ParameterSetName = 'Startup', Mandatory = $true, Position = 0)][switch]$AtStartup,

        [Parameter(ParameterSetName = 'Logon', Mandatory = $true, Position = 0)][switch]$AtLogOn,
        [Parameter(ParameterSetName = 'Logon')][string]$User,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        $rd = if ($PSBoundParameters.ContainsKey('RandomDelay')) { ConvertTo-IsoDuration $RandomDelay } else { $null }
        switch ($PSCmdlet.ParameterSetName) {
            'Once' {
                $rep = $null
                if ($PSBoundParameters.ContainsKey('RepetitionInterval') -or $PSBoundParameters.ContainsKey('RepetitionDuration')) {
                    $rep = New-TSRepetition $(if ($PSBoundParameters.ContainsKey('RepetitionDuration')) { ConvertTo-IsoDuration $RepetitionDuration } else { $null }) `
                        $(if ($PSBoundParameters.ContainsKey('RepetitionInterval')) { ConvertTo-IsoDuration $RepetitionInterval } else { $null }) $true
                }
                New-TSTrigger -Kind Time -Repetition $rep -StartBoundary (ConvertTo-TSTime $At) -Extra ([ordered]@{ RandomDelay = $rd })
            }
            'Daily' {
                $di = if ($PSBoundParameters.ContainsKey('DaysInterval')) { $DaysInterval } else { 1 }
                New-TSTrigger -Kind Daily -StartBoundary (ConvertTo-TSTime $At) -Extra ([ordered]@{ DaysInterval = [int16]$di; RandomDelay = $rd })
            }
            'Weekly' {
                $wi = if ($PSBoundParameters.ContainsKey('WeeksInterval')) { $WeeksInterval } else { 1 }
                # the Windows module stores the interval in a 16-bit field and fails with a general error above it (measured: 70000)
                if ($wi -gt 65535) { $PSCmdlet.ThrowTerminatingError((New-TSHresultError ([int]0xC0000095) 'A general error occurred that is not covered by a more specific error code.')) }
                $mask = 0
                if ($PSBoundParameters.ContainsKey('DaysOfWeek')) { foreach ($d in @($DaysOfWeek)) { $mask = $mask -bor $script:DayBits[[string]$d] } }
                New-TSTrigger -Kind Weekly -StartBoundary (ConvertTo-TSTime $At) -Extra ([ordered]@{ DaysOfWeek = [uint16]$mask; RandomDelay = $rd; WeeksInterval = [uint16]$wi })
            }
            'Startup' { New-TSTrigger -Kind Boot -Extra ([ordered]@{ Delay = $null }) }
            'Logon' { New-TSTrigger -Kind Logon -Extra ([ordered]@{ Delay = $null; UserId = $(if ($User) { $User } else { $null }) }) }
        }
    }
}

function New-ScheduledTaskPrincipal {
    [CmdletBinding(DefaultParameterSetName = 'User')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskPrincipal')]
    param(
        [Parameter(ParameterSetName = 'User')][Parameter(ParameterSetName = 'Group')][string]$Id,

        [Parameter(ParameterSetName = 'User', Position = 2)]
        [Parameter(ParameterSetName = 'Group', Position = 1)]
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.RunLevelEnum]$RunLevel,

        [Parameter(ParameterSetName = 'User', Position = 3)]
        [Parameter(ParameterSetName = 'Group', Position = 2)]
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ProcessTokenSidTypeEnum]$ProcessTokenSidType,

        [Parameter(ParameterSetName = 'User', Position = 4)]
        [Parameter(ParameterSetName = 'Group', Position = 3)]
        [string[]]$RequiredPrivilege,

        [Parameter(ParameterSetName = 'User', Mandatory = $true, Position = 0)][string]$UserId,
        [Parameter(ParameterSetName = 'User', Position = 1)]
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.LogonTypeEnum]$LogonType,

        [Parameter(ParameterSetName = 'Group', Mandatory = $true, Position = 0)][string]$GroupId,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        $rl = if ($PSBoundParameters.ContainsKey('RunLevel')) { $RunLevel } else { TSEnum 'RunLevelEnum' 0 }
        $pts = if ($PSBoundParameters.ContainsKey('ProcessTokenSidType')) { $ProcessTokenSidType } else { TSEnum 'ProcessTokenSidTypeEnum' 2 }
        $idv = if ($Id) { $Id } else { $null }
        if ($PSCmdlet.ParameterSetName -eq 'Group') {
            $g = $GroupId; $i = $g.LastIndexOf('\'); if ($i -ge 0) { $g = $g.Substring($i + 1) }
            New-TSPrincipal $rl (TSEnum 'LogonTypeEnum' 4) $pts $null $g $idv $null $RequiredPrivilege
        } else {
            $lt = if ($PSBoundParameters.ContainsKey('LogonType')) { $LogonType } else { TSEnum 'LogonTypeEnum' 3 }
            New-TSPrincipal $rl $lt $pts $null $null $idv $UserId $RequiredPrivilege
        }
    }
}

function New-ScheduledTaskSettingsSet {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_TaskSettings')]
    param(
        [switch]$DisallowDemandStart,
        [switch]$DisallowHardTerminate,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.CompatibilityEnum]$Compatibility,
        [timespan]$DeleteExpiredTaskAfter,
        [switch]$AllowStartIfOnBatteries,
        [switch]$Disable,
        [switch]$MaintenanceExclusive,
        [switch]$Hidden,
        [switch]$RunOnlyIfIdle,
        [timespan]$IdleWaitTimeout,
        [string]$NetworkId,
        [string]$NetworkName,
        [switch]$DisallowStartOnRemoteAppSession,
        [timespan]$MaintenancePeriod,
        [timespan]$MaintenanceDeadline,
        [switch]$StartWhenAvailable,
        [switch]$DontStopIfGoingOnBatteries,
        [switch]$WakeToRun,
        [timespan]$IdleDuration,
        [switch]$RestartOnIdle,
        [switch]$DontStopOnIdleEnd,
        [timespan]$ExecutionTimeLimit,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.MultipleInstancesEnum]$MultipleInstances,
        [ValidateNotNullOrEmpty()][int]$Priority,
        [ValidateNotNullOrEmpty()][int]$RestartCount,
        [timespan]$RestartInterval,
        [switch]$RunOnlyIfNetworkAvailable,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        foreach ($p in 'MaintenanceExclusive', 'MaintenancePeriod', 'MaintenanceDeadline') {
            if ($PSBoundParameters.ContainsKey($p)) { Stop-TSUnsupported $PSCmdlet "The maintenance settings (-$p)" }
        }
        if ($PSBoundParameters.ContainsKey('Priority') -and ($Priority -lt 0 -or $Priority -gt 10)) {
            $PSCmdlet.ThrowTerminatingError((New-TSHresultError ([int]0x80070057) 'The parameter is incorrect.'))
        }
        $s = New-TSDefaultSettings
        $s.AllowDemandStart = -not $DisallowDemandStart
        $s.AllowHardTerminate = -not $DisallowHardTerminate
        $s.DisallowStartIfOnBatteries = -not $AllowStartIfOnBatteries
        $s.Enabled = -not $Disable
        $s.Hidden = [bool]$Hidden
        $s.RunOnlyIfIdle = [bool]$RunOnlyIfIdle
        $s.StartWhenAvailable = [bool]$StartWhenAvailable
        $s.StopIfGoingOnBatteries = -not $DontStopIfGoingOnBatteries
        $s.WakeToRun = [bool]$WakeToRun
        $s.RunOnlyIfNetworkAvailable = [bool]$RunOnlyIfNetworkAvailable
        $s.DisallowStartOnRemoteAppSession = [bool]$DisallowStartOnRemoteAppSession
        if ($PSBoundParameters.ContainsKey('Compatibility')) { $s.Compatibility = $Compatibility }
        if ($PSBoundParameters.ContainsKey('MultipleInstances')) { $s.MultipleInstances = $MultipleInstances }
        if ($PSBoundParameters.ContainsKey('DeleteExpiredTaskAfter')) { $s.DeleteExpiredTaskAfter = ConvertTo-IsoDuration $DeleteExpiredTaskAfter }
        if ($PSBoundParameters.ContainsKey('ExecutionTimeLimit')) { $s.ExecutionTimeLimit = ConvertTo-IsoDuration $ExecutionTimeLimit }
        if ($PSBoundParameters.ContainsKey('Priority')) { $s.Priority = [uint32]$Priority }
        if ($PSBoundParameters.ContainsKey('RestartCount')) { $s.RestartCount = [uint32]$RestartCount }
        if ($PSBoundParameters.ContainsKey('RestartInterval')) { $s.RestartInterval = ConvertTo-IsoDuration $RestartInterval }
        $idle = $s.IdleSettings
        if ($PSBoundParameters.ContainsKey('IdleDuration')) { $idle.IdleDuration = ConvertTo-IsoDuration $IdleDuration }
        if ($PSBoundParameters.ContainsKey('IdleWaitTimeout')) { $idle.WaitTimeout = ConvertTo-IsoDuration $IdleWaitTimeout }
        $idle.RestartOnIdle = [bool]$RestartOnIdle
        $idle.StopOnIdleEnd = -not $DontStopOnIdleEnd
        if ($PSBoundParameters.ContainsKey('NetworkId')) { $s.NetworkSettings.Id = $NetworkId }
        if ($PSBoundParameters.ContainsKey('NetworkName')) { $s.NetworkSettings.Name = $NetworkName }
        $s
    }
}

function New-ScheduledTask {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
    param(
        [Parameter(ParameterSetName = 'New0', Position = 0)][object[]]$Action,
        [Parameter(ParameterSetName = 'New0', Position = 4)][string]$Description,
        [Parameter(ParameterSetName = 'New0', Position = 3)][object]$Principal,
        [Parameter(ParameterSetName = 'New0', Position = 2)][object]$Settings,
        [Parameter(ParameterSetName = 'New0', Position = 1)][object[]]$Trigger,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        New-TSTask -State $null -Actions ([object[]]$Action) -Description $(if ($Description) { $Description } else { $null }) `
            -Principal $Principal -SecurityDescriptor $null -Settings $Settings -Triggers ([object[]]$Trigger)
    }
}

function Register-ScheduledTask {
    [CmdletBinding(DefaultParameterSetName = 'User')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
    param(
        [Parameter(ParameterSetName = 'User')]
        [Parameter(ParameterSetName = 'Xml')]
        [Parameter(ParameterSetName = 'Principal')]
        [Parameter(ParameterSetName = 'Object')]
        [switch]$Force,

        [Parameter(ParameterSetName = 'User', Position = 6)]
        [Parameter(ParameterSetName = 'Xml', Position = 4)]
        [Parameter(ParameterSetName = 'Object', Position = 4)]
        [string]$Password,

        [Parameter(ParameterSetName = 'User', Position = 5)]
        [Parameter(ParameterSetName = 'Xml', Position = 3)]
        [Parameter(ParameterSetName = 'Object', Position = 3)]
        [string]$User,

        [Parameter(ParameterSetName = 'User', Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = 'Xml', Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = 'Principal', Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = 'Object', Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'User', Position = 1)]
        [Parameter(ParameterSetName = 'Xml', Position = 1)]
        [Parameter(ParameterSetName = 'Principal', Position = 1)]
        [Parameter(ParameterSetName = 'Object', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$TaskPath,

        [Parameter(ParameterSetName = 'Xml', Mandatory = $true, Position = 2, ValueFromPipeline = $true)]
        [string]$Xml,

        [Parameter(ParameterSetName = 'Principal', Position = 5)]
        [object]$Principal,

        [Parameter(ParameterSetName = 'User', Mandatory = $true, Position = 2)]
        [Parameter(ParameterSetName = 'Principal', Mandatory = $true, Position = 2)]
        [object[]]$Action,

        [Parameter(ParameterSetName = 'User', Position = 8)]
        [Parameter(ParameterSetName = 'Principal', Position = 6)]
        [string]$Description,

        [Parameter(ParameterSetName = 'User', Position = 4)]
        [Parameter(ParameterSetName = 'Principal', Position = 4)]
        [object]$Settings,

        [Parameter(ParameterSetName = 'User', Position = 3)]
        [Parameter(ParameterSetName = 'Principal', Position = 3)]
        [object[]]$Trigger,

        [Parameter(ParameterSetName = 'User', Position = 7)]
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.RunLevelEnum]$RunLevel,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 2, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        $set = $PSCmdlet.ParameterSetName
        $name = $TaskName
        $folder = if ($PSBoundParameters.ContainsKey('TaskPath')) { Format-TSTaskPath $TaskPath } else { $null }
        $uid = $null; $pw = $null; $lt = 0
        if ($PSBoundParameters.ContainsKey('Password')) { $pw = $Password }

        if ($set -eq 'Xml') {
            $xml = $Xml
        } else {
            if ($set -eq 'Object') {
                if (-not $name) { $name = [string]$InputObject.TaskName }
                if ($null -eq $folder) { $folder = Format-TSTaskPath ([string]$InputObject.TaskPath) }
                $actions = $InputObject.Actions; $triggers = $InputObject.Triggers; $principal = $InputObject.Principal
                $settings = $InputObject.Settings; $desc = $InputObject.Description
            } else {
                $actions = $Action; $triggers = $Trigger; $settings = $Settings; $desc = $Description
                $principal = if ($set -eq 'Principal') { $Principal } else { $null }
            }
            if (-not $name) { $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('A task name is required.'), 'TaskNameRequired', 'InvalidArgument', $null)) }
            foreach ($t in @(@($triggers) | Where-Object { $null -ne $_ })) {
                $k = Get-TSTriggerKind $t
                if ($k -notin $script:WritableKinds) { Stop-TSUnsupported $PSCmdlet "A trigger of kind '$k'" }
            }
            $cur = "$([Environment]::UserDomainName)\$([Environment]::UserName)"
            if ($set -eq 'User' -or $User) {
                $u = if ($User) { $User } else { $cur }
                $ltv = if ($Password) { 1 } elseif ($u -in $script:ServiceAccounts) { 5 } else { 3 }
                $rl = if ($PSBoundParameters.ContainsKey('RunLevel')) { $RunLevel } else { TSEnum 'RunLevelEnum' 0 }
                $principal = New-TSPrincipal $rl (TSEnum 'LogonTypeEnum' $ltv) (TSEnum 'ProcessTokenSidTypeEnum' 2) $null $null $null $u $null
            } elseif ($null -eq $principal) {
                $principal = New-TSPrincipal (TSEnum 'RunLevelEnum' 0) (TSEnum 'LogonTypeEnum' 3) (TSEnum 'ProcessTokenSidTypeEnum' 2) $null $null $null $cur $null
            }
            $xml = ConvertTo-TSTaskXml -Actions $actions -Triggers $triggers -Principal $principal -Settings $settings -Description $desc `
                -Author ("$([Environment]::UserDomainName)\$([Environment]::UserName)") -Uri $null
            if ($principal) {
                $lt = [int]$principal.LogonType
                if ($principal.GroupId) { $uid = $principal.GroupId } elseif ($principal.UserId) { $uid = $principal.UserId }
            }
        }
        if ($set -eq 'Xml' -or $set -eq 'Object') {
            if ($User) { $uid = $User; $lt = if ($Password) { 1 } elseif ($User -in $script:ServiceAccounts) { 5 } else { 3 } }
            foreach ($what in (Find-TSUnsupportedXml $xml)) { Stop-TSUnsupported $PSCmdlet "A task XML with $what" }
        }
        if ($null -eq $folder) { $folder = '\' }
        $full = $folder + $name
        $flags = if ($Force) { 6 } else { 2 }
        try {
            $svc = Get-TSService
            $com = $svc.GetFolder('\').RegisterTask($full, $xml, $flags, $uid, $pw, $lt, $null)
        } catch {
            $hr = Get-TSHResult $_.Exception
            $rec = New-TSHresultError $hr $_.Exception.Message
            $PSCmdlet.WriteError($rec)
            return
        }
        $dropped = @(Get-TSDroppedItems $xml ([string]$com.Xml))
        if ($dropped.Count -gt 0) { $PSCmdlet.WriteWarning("The task service did not keep these parts of the definition: $($dropped -join ', ').") }
        ConvertTo-TSTaskObject $com $folder
    }
}

# The XML of the definition a task object describes (Export-ScheduledTask -InputObject)
function ConvertTo-TSExportXml {
    param($Task)
    ConvertTo-TSTaskXml -Actions $Task.Actions -Triggers $Task.Triggers -Principal $Task.Principal -Settings $Task.Settings `
        -Description $Task.Description -Author $Task.Author -Uri $Task.URI -Source $Task.Source -Documentation $Task.Documentation `
        -Date $Task.Date -Version $Task.Version -SecurityDescriptor $Task.SecurityDescriptor -Export
}

function Export-ScheduledTask {
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    [OutputType([string])]
    param(
        [Parameter(ParameterSetName = 'Name', Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'Name', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$TaskPath,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][ValidateNotNullOrEmpty()][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        if ($PSCmdlet.ParameterSetName -eq 'Object') {
            # a task object is written out from its properties, not from the stored definition (Windows does the same: the two texts differ)
            try { ConvertTo-TSExportXml $InputObject } catch { $PSCmdlet.WriteError((New-TSHresultError ([int]0x80070057) 'The parameter is incorrect.')) }
            return
        }
        # no name (a path alone included) is an invalid argument on Windows; a name is exact, wildcards are not expanded
        if (-not $PSBoundParameters.ContainsKey('TaskName')) { $PSCmdlet.WriteError((New-TSHresultError ([int]0x80070057) 'The parameter is incorrect.')); return }
        $path = if ($PSBoundParameters.ContainsKey('TaskPath')) { $TaskPath } else { '\' }
        if ($path -match '\\\\') { $PSCmdlet.WriteError((New-TSHresultError ([int]0x8007007B) 'The filename, directory name, or volume label syntax is incorrect.')); return }
        $com = Get-TSTask $PSCmdlet $TaskName $path
        if ($null -eq $com) { return }
        [string]$com.Xml
    }
}

# Set-ScheduledTask: the task's stored definition with the parts the caller names replaced (or, for -InputObject, the whole
# definition the object describes), written back with TASK_UPDATE. Returns the task as it reads after the update.
function Set-ScheduledTask {
    [CmdletBinding(DefaultParameterSetName = 'User')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')]
    param(
        [Parameter(ParameterSetName = 'User', Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = 'Principal', Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()][string]$TaskName,

        [Parameter(ParameterSetName = 'User', Position = 1)]
        [Parameter(ParameterSetName = 'Principal', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$TaskPath,

        [Parameter(ParameterSetName = 'User', Position = 2)]
        [Parameter(ParameterSetName = 'Principal', Position = 2)]
        [ValidateNotNullOrEmpty()][object[]]$Action,

        [Parameter(ParameterSetName = 'User', Position = 3)]
        [Parameter(ParameterSetName = 'Principal', Position = 3)]
        [ValidateNotNullOrEmpty()][object[]]$Trigger,

        [Parameter(ParameterSetName = 'User', Position = 4)]
        [Parameter(ParameterSetName = 'Principal', Position = 4)]
        [ValidateNotNullOrEmpty()][object]$Settings,

        [Parameter(ParameterSetName = 'User', Position = 5)]
        [Parameter(ParameterSetName = 'Object', Position = 2)]
        [ValidateNotNullOrEmpty()][string]$User,

        [Parameter(ParameterSetName = 'User', Position = 6)]
        [Parameter(ParameterSetName = 'Object', Position = 1)]
        [ValidateNotNullOrEmpty()][string]$Password,

        [Parameter(ParameterSetName = 'Principal', Position = 5)]
        [ValidateNotNullOrEmpty()][object]$Principal,

        [Parameter(ParameterSetName = 'Object', Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask')][ValidateNotNullOrEmpty()][object]$InputObject,

        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if (Test-TSAsJob $PSCmdlet $AsJob) { return }
        $set = $PSCmdlet.ParameterSetName
        if ($set -eq 'Object') { $name = [string]$InputObject.TaskName; $path = [string]$InputObject.TaskPath }
        else { $name = $TaskName; $path = if ($PSBoundParameters.ContainsKey('TaskPath')) { $TaskPath } else { '\' } }
        $com = Get-TSTask $PSCmdlet $name $path
        if ($null -eq $com) { return }
        $folder = Format-TSTaskPath $path
        $cur = ConvertFrom-TSTaskXml ([string]$com.Xml)

        $uid = $null; $pw = $null
        if ($PSBoundParameters.ContainsKey('Password')) { $pw = $Password }
        $pr = $cur.Principal
        if ($set -eq 'Object') {
            $pr = $InputObject.Principal
            foreach ($t in @(@($InputObject.Triggers) | Where-Object { $null -ne $_ })) {
                $k = Get-TSTriggerKind $t
                if ($k -notin $script:WritableKinds) { Stop-TSUnsupported $PSCmdlet "A trigger of kind '$k'" }
            }
        } elseif ($PSBoundParameters.ContainsKey('Principal')) { $pr = $Principal }
        if ($PSBoundParameters.ContainsKey('Trigger')) {
            foreach ($t in @(@($Trigger) | Where-Object { $null -ne $_ })) {
                $k = Get-TSTriggerKind $t
                if ($k -notin $script:WritableKinds) { Stop-TSUnsupported $PSCmdlet "A trigger of kind '$k'" }
            }
        }
        if ($PSBoundParameters.ContainsKey('User')) {
            # -User replaces the principal's account: with a password the task runs whether or not the user is logged on
            $lt = if ($pw) { 1 } elseif ($User -in $script:ServiceAccounts) { 5 } else { 3 }
            $pr = New-TSPrincipal $pr.RunLevel (TSEnum 'LogonTypeEnum' $lt) $pr.ProcessTokenSidType $null $null $pr.Id $User $pr.RequiredPrivilege
        }
        $lt = [int]$pr.LogonType
        if ($pr.GroupId) { $uid = $pr.GroupId } elseif ($pr.UserId) { $uid = $pr.UserId }

        if ($set -eq 'Object') {
            # the object is the new definition
            $xml = ConvertTo-TSTaskXml -Actions $InputObject.Actions -Triggers $InputObject.Triggers -Principal $pr -Settings $InputObject.Settings `
                -Description $InputObject.Description -Author $InputObject.Author -Source $InputObject.Source -Documentation $InputObject.Documentation -Date $cur.Date -Uri $null
        } else {
            # the stored definition with only the named parts replaced: whatever else it holds (trigger kinds this module cannot write,
            # settings it does not model) stays as the task service has it
            $stored = [System.Xml.XmlDocument]::new()
            $stored.LoadXml([string]$com.Xml)
            $gen = [System.Xml.XmlDocument]::new()
            $gen.LoadXml((ConvertTo-TSTaskXml -Actions $(if ($PSBoundParameters.ContainsKey('Action')) { $Action } else { $cur.Actions }) `
                -Triggers $(if ($PSBoundParameters.ContainsKey('Trigger')) { $Trigger } else { @() }) -Principal $pr `
                -Settings $(if ($PSBoundParameters.ContainsKey('Settings')) { $Settings } else { $null }) -Description $cur.Description -Author $cur.Author -Uri $null))
            $root = $stored.DocumentElement
            $splice = {
                param([string]$Name)
                $n = $gen.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq $Name } | Select-Object -First 1
                $o = $root.ChildNodes | Where-Object { $_.LocalName -eq $Name } | Select-Object -First 1
                if ($null -eq $n) { if ($null -ne $o) { $null = $root.RemoveChild($o) }; return }
                $imp = $stored.ImportNode($n, $true)
                if ($null -ne $o) { $null = $root.ReplaceChild($imp, $o) } else { $null = $root.AppendChild($imp) }
            }
            if ($PSBoundParameters.ContainsKey('Action')) { & $splice 'Actions' }
            if ($PSBoundParameters.ContainsKey('Trigger')) { & $splice 'Triggers' }
            if ($PSBoundParameters.ContainsKey('Settings')) {
                & $splice 'Settings'
                $root.SetAttribute('version', $gen.DocumentElement.GetAttribute('version'))
            }
            if ($PSBoundParameters.ContainsKey('Principal') -or $PSBoundParameters.ContainsKey('User')) { & $splice 'Principals' }
            $xml = $stored.OuterXml
        }
        try {
            $new = (Get-TSService).GetFolder('\').RegisterTask((Format-TSFolder $path).TrimEnd('\') + '\' + $name, $xml, 4, $uid, $pw, $lt, $null)
        } catch {
            Write-TSComError $PSCmdlet $_
            return
        }
        $dropped = @(Get-TSDroppedItems $xml ([string]$new.Xml))
        if ($dropped.Count -gt 0) { $PSCmdlet.WriteWarning("The task service did not keep these parts of the definition: $($dropped -join ', ').") }
        ConvertTo-TSTaskObject $new $folder
    }
}

#endregion
