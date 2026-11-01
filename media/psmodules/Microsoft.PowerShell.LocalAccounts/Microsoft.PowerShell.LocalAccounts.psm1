# Microsoft.PowerShell.LocalAccounts for ReactOS-Nitro: a clean-room PowerShell 7 script module.
# Same module, cmdlet and parameter names and the same output types as the Windows module
# (Microsoft.PowerShell.Commands.LocalUser / LocalGroup / LocalPrincipal). The work is done by
# LocalAccountsNative (LocalAccountsNative.cs, netapi32 + advapi32), compiled by the nested types module.
#
# Failures travel as values (Op.Call returns an OpResult) and are written once, with Write-LAError, so that the
# ErrorRecord a caller sees is the Windows-shaped one and nothing else lands in $Error / -ErrorVariable.

Set-StrictMode -Version 2.0

$script:Native = [Microsoft.PowerShell.Commands.LocalAccountsNative]
$script:Op = [Microsoft.PowerShell.Commands.Op]

# ------------------------------------------------------------------ helpers
function Invoke-LANative {
    param([string]$Method, [Parameter(ValueFromRemainingArguments = $true)][object[]]$Arguments)
    $a = if ($null -eq $Arguments) { [object[]]@() } else { [object[]]$Arguments }
    $script:Op::Call($Method, $a)
}

function New-LASelector {
    param($Display, $Name, $SID, $Value)
    [pscustomobject]@{ Display = $Display; Name = $Name; SID = $SID; Value = $Value }
}

# One selector per account the caller named, whatever parameter set was used.
function Get-LASelector {
    param([string]$SetName, $Name, $SID, $InputObject)
    switch ($SetName) {
        { $_ -in 'InputObject', 'Group' } { foreach ($o in @($InputObject)) { New-LASelector $o.Name $o.Name $o.SID $o } }
        'SecurityIdentifier' { foreach ($s in @($SID)) { New-LASelector $s.Value $null $s $s } }
        default { foreach ($n in @($Name)) { New-LASelector $n $n $null $n } }
    }
}

function Write-LAError {
    param([System.Management.Automation.PSCmdlet]$Cmdlet, [Microsoft.PowerShell.Commands.LocalAccountsException]$Exception, $Target)
    $rec = [Microsoft.PowerShell.Commands.ErrorStamp]::Create($Exception, $Target, $Cmdlet.MyInvocation.MyCommand.Name, $Cmdlet.MyInvocation.DisplayScriptPosition)
    $Cmdlet.WriteError($rec)
}

# The two Resolve functions turn a selector into the account name the netapi32 calls take.
function Resolve-LAUser {
    param($Selector)
    if ($Selector.SID) {
        # match on the SID the user enumeration reports (the system's own name for a SID can differ)
        $r = Invoke-LANative GetUsers
        if ($r.Error) { return $r }
        $u = $r.Value | Where-Object { $_.SID -eq $Selector.SID } | Select-Object -First 1
        if ($u) { return $script:Op::Ok($u.Name) }
        return $script:Op::Fail([Microsoft.PowerShell.Commands.UserNotFoundException]::new($Selector.SID.Value))
    }
    $r = Invoke-LANative GetUser $Selector.Name
    if ($r.Error) { return $r }
    $script:Op::Ok($r.Value.Name)
}

function Resolve-LAGroup {
    param($Selector)
    if ($Selector.SID) {
        $r = Invoke-LANative GetGroups
        if ($r.Error) { return $r }
        $g = $r.Value | Where-Object { $_.SID -eq $Selector.SID } | Select-Object -First 1
        if ($g) { return $script:Op::Ok($g.Name) }
        return $script:Op::Fail([Microsoft.PowerShell.Commands.GroupNotFoundException]::new($Selector.SID.Value))
    }
    $r = Invoke-LANative GetGroup $Selector.Name
    if ($r.Error) { return $r }
    $script:Op::Ok($r.Value.Name)
}

# -Member values: a LocalPrincipal that carries a SID is used as is; a bare name is looked up.
function Resolve-LAMember {
    param($Member)
    if ($Member.SID) {
        return $script:Op::Ok([pscustomobject]@{ SID = $Member.SID; Display = $Member.Name })
    }
    $r = Invoke-LANative LookupName $Member.Name
    if ($r.Error) { return $r }
    if (-not $r.Value) { return $script:Op::Fail([Microsoft.PowerShell.Commands.PrincipalNotFoundException]::new($Member.Name)) }
    $script:Op::Ok([pscustomobject]@{ SID = $r.Value.SID; Display = $r.Value.FullName })
}

function Test-LAWildcard { param([string]$Text) [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Text) }

# Shared by Get-LocalUser / Get-LocalGroup: -Name with wildcards, or -SID.
function Select-LAByName {
    param($Cmdlet, $All, [string[]]$Name, $SID, [bool]$BySID, [string]$Kind)
    $notFound = if ($Kind -eq 'User') { [Microsoft.PowerShell.Commands.UserNotFoundException] } else { [Microsoft.PowerShell.Commands.GroupNotFoundException] }
    if ($BySID) {
        foreach ($s in $SID) {
            $m = @($All | Where-Object { $_.SID -eq $s })
            if ($m.Count) { $m } else { Write-LAError $Cmdlet $notFound::new($s.Value) $s }
        }
    }
    elseif ($null -eq $Name) { $All }
    else {
        foreach ($n in $Name) {
            if (Test-LAWildcard $n) {
                $wp = [System.Management.Automation.WildcardPattern]::new($n, [System.Management.Automation.WildcardOptions]::IgnoreCase)
                $All | Where-Object { $wp.IsMatch($_.Name) }
            }
            else {
                $m = @($All | Where-Object { $_.Name -eq $n })
                if ($m.Count) { $m } else { Write-LAError $Cmdlet $notFound::new($n) $n }
            }
        }
    }
}

# ------------------------------------------------------------------ users
function Get-LocalUser {
    [CmdletBinding(DefaultParameterSetName = 'Default', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717980')]
    [OutputType('Microsoft.PowerShell.Commands.LocalUser')]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string[]]$Name,

        [Parameter(Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]]$SID
    )
    process {
        $r = Invoke-LANative GetUsers
        if ($r.Error) { Write-LAError $PSCmdlet $r.Error 'users'; return }
        Select-LAByName $PSCmdlet @($r.Value) $Name $SID ($PSCmdlet.ParameterSetName -eq 'SecurityIdentifier') 'User'
    }
}

function New-LocalUser {
    [CmdletBinding(DefaultParameterSetName = 'Password', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717981')]
    [OutputType('Microsoft.PowerShell.Commands.LocalUser')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [ValidateLength(1, 20)]
        [string]$Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'Password')]
        [ValidateNotNull()]
        [securestring]$Password,

        [Parameter(Mandatory = $true, ParameterSetName = 'NoPassword')]
        [switch]$NoPassword,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [datetime]$AccountExpires,

        [Parameter()]
        [switch]$AccountNeverExpires,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [ValidateLength(0, 48)]
        [string]$Description,

        [Parameter()]
        [switch]$Disabled,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$FullName,

        [Parameter(ParameterSetName = 'Password')]
        [switch]$PasswordNeverExpires,

        [Parameter()]
        [switch]$UserMayNotChangePassword
    )
    process {
        if (-not $PSCmdlet.ShouldProcess($Name, 'Create new local user')) { return }
        if ($PSBoundParameters.ContainsKey('AccountExpires') -and $AccountNeverExpires) {
            $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('AccountExpires and AccountNeverExpires cannot be used together.'), 'InvalidParameters', 'InvalidArgument', $Name))
            return
        }
        $flags = 0x201   # UF_SCRIPT | UF_NORMAL_ACCOUNT
        if ($Disabled) { $flags = $flags -bor 0x2 }
        if ($UserMayNotChangePassword) { $flags = $flags -bor 0x40 }
        if ($PSCmdlet.ParameterSetName -eq 'NoPassword') { $flags = $flags -bor 0x20 }
        elseif ($PasswordNeverExpires) { $flags = $flags -bor 0x10000 }
        $pw = if ($PSCmdlet.ParameterSetName -eq 'Password') { $Password } else { $null }
        $desc = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { $null }
        $r = Invoke-LANative AddUser $Name $pw $desc $flags
        if ($r.Error) { Write-LAError $PSCmdlet $r.Error $Name; return }
        if ($PSBoundParameters.ContainsKey('FullName')) { $r = Invoke-LANative SetUserFullName $Name $FullName }
        if (-not $r.Error -and $PSBoundParameters.ContainsKey('AccountExpires')) { $r = Invoke-LANative SetUserAccountExpires $Name $AccountExpires }
        if ($r.Error) {
            # do not leave a half configured account behind
            $null = Invoke-LANative RemoveUser $Name
            Write-LAError $PSCmdlet $r.Error $Name
            return
        }
        $r = Invoke-LANative GetUser $Name
        if ($r.Error) { Write-LAError $PSCmdlet $r.Error $Name; return }
        $r.Value
    }
}

function Set-LocalUser {
    [CmdletBinding(DefaultParameterSetName = 'Name', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717984')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Name', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalUser]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier]$SID,

        [Parameter()] [datetime]$AccountExpires,
        [Parameter()] [switch]$AccountNeverExpires,
        [Parameter()] [ValidateNotNull()] [ValidateLength(0, 48)] [string]$Description,
        [Parameter()] [ValidateNotNull()] [string]$FullName,
        [Parameter()] [ValidateNotNull()] [securestring]$Password,
        [Parameter()] [bool]$PasswordNeverExpires,
        [Parameter()] [bool]$UserMayChangePassword
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            $r = Resolve-LAUser $sel
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value; continue }
            $n = $r.Value
            if (-not $PSCmdlet.ShouldProcess($sel.Display, 'Modify local user')) { continue }
            if ($PSBoundParameters.ContainsKey('AccountExpires') -and $AccountNeverExpires) {
                $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new([System.ArgumentException]::new('AccountExpires and AccountNeverExpires cannot be used together.'), 'InvalidParameters', 'InvalidArgument', $sel.Value))
                continue
            }
            $steps = [System.Collections.Generic.List[object[]]]::new()
            if ($PSBoundParameters.ContainsKey('Description')) { $steps.Add(@('SetUserDescription', $n, $Description)) }
            if ($PSBoundParameters.ContainsKey('FullName')) { $steps.Add(@('SetUserFullName', $n, $FullName)) }
            if ($PSBoundParameters.ContainsKey('AccountExpires')) { $steps.Add(@('SetUserAccountExpires', $n, $AccountExpires)) }
            if ($AccountNeverExpires) { $steps.Add(@('SetUserAccountExpires', $n, $null)) }
            if ($PSBoundParameters.ContainsKey('PasswordNeverExpires')) { $steps.Add(@('SetUserFlag', $n, 0x10000, $PasswordNeverExpires)) }
            if ($PSBoundParameters.ContainsKey('UserMayChangePassword')) { $steps.Add(@('SetUserFlag', $n, 0x40, (-not $UserMayChangePassword))) }
            if ($PSBoundParameters.ContainsKey('Password')) { $steps.Add(@('SetUserPassword', $n, $Password)) }
            foreach ($st in $steps) {
                $r = Invoke-LANative -Method $st[0] -Arguments $st[1..($st.Count - 1)]
                if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value; break }
            }
        }
    }
}

function Remove-LocalUser {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717982')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalUser[]]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]]$SID
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            if (-not $PSCmdlet.ShouldProcess($sel.Display, 'Remove local user')) { continue }
            $r = Resolve-LAUser $sel
            if (-not $r.Error) { $r = Invoke-LANative RemoveUser $r.Value }
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value }
        }
    }
}

function Enable-LocalUser {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717985')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalUser[]]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]]$SID
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            if (-not $PSCmdlet.ShouldProcess($sel.Display, 'Enable local user')) { continue }
            $r = Resolve-LAUser $sel
            if (-not $r.Error) { $r = Invoke-LANative SetUserFlag $r.Value 0x2 $false }
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value }
        }
    }
}

function Disable-LocalUser {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717986')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalUser[]]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]]$SID
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            if (-not $PSCmdlet.ShouldProcess($sel.Display, 'Disable local user')) { continue }
            $r = Resolve-LAUser $sel
            if (-not $r.Error) { $r = Invoke-LANative SetUserFlag $r.Value 0x2 $true }
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value }
        }
    }
}

function Rename-LocalUser {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkID=717983')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalUser]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier]$SID,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$NewName
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            if (-not $PSCmdlet.ShouldProcess($sel.Display, "Rename local user to $NewName")) { continue }
            $r = Resolve-LAUser $sel
            if (-not $r.Error) {
                $n = $r.Value
                $all = Invoke-LANative GetUsers
                if ($all.Error) { $r = $all }
                elseif ($all.Value | Where-Object { $_.Name -eq $NewName }) { $r = $script:Op::Fail([Microsoft.PowerShell.Commands.NameInUseException]::new($NewName)) }
                else { $r = Invoke-LANative RenameUser $n $NewName }
            }
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value }
        }
    }
}

# ------------------------------------------------------------------ groups
function Get-LocalGroup {
    [CmdletBinding(DefaultParameterSetName = 'Default', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717974')]
    [OutputType('Microsoft.PowerShell.Commands.LocalGroup')]
    param(
        [Parameter(Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string[]]$Name,

        [Parameter(Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]]$SID
    )
    process {
        $r = Invoke-LANative GetGroups
        if ($r.Error) { Write-LAError $PSCmdlet $r.Error 'groups'; return }
        Select-LAByName $PSCmdlet @($r.Value) $Name $SID ($PSCmdlet.ParameterSetName -eq 'SecurityIdentifier') 'Group'
    }
}

function New-LocalGroup {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717990')]
    [OutputType('Microsoft.PowerShell.Commands.LocalGroup')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 256)]
        [string]$Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [ValidateLength(0, 48)]
        [string]$Description
    )
    process {
        if (-not $PSCmdlet.ShouldProcess($Name, 'Create new local group')) { return }
        $desc = if ($PSBoundParameters.ContainsKey('Description')) { $Description } else { $null }
        $r = Invoke-LANative AddGroup $Name $desc
        if (-not $r.Error) { $r = Invoke-LANative GetGroup $Name }
        if ($r.Error) { Write-LAError $PSCmdlet $r.Error $Name; return }
        $r.Value
    }
}

function Set-LocalGroup {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717979')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalGroup]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier]$SID,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateLength(0, 48)]
        [string]$Description
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            $r = Resolve-LAGroup $sel
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value; continue }
            if (-not $PSCmdlet.ShouldProcess($sel.Display, 'Modify local group')) { continue }
            $r = Invoke-LANative SetGroupDescription $r.Value $Description
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value }
        }
    }
}

function Remove-LocalGroup {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717975')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalGroup[]]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier[]]$SID
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            if (-not $PSCmdlet.ShouldProcess($sel.Display, 'Remove local group')) { continue }
            $r = Resolve-LAGroup $sel
            if (-not $r.Error) { $r = Invoke-LANative RemoveGroup $r.Value }
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value }
        }
    }
}

function Rename-LocalGroup {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717978')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'InputObject', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalGroup]$InputObject,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier]$SID,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$NewName
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $InputObject) {
            if (-not $PSCmdlet.ShouldProcess($sel.Display, "Rename local group to $NewName")) { continue }
            $r = Resolve-LAGroup $sel
            if (-not $r.Error) {
                $n = $r.Value
                $all = Invoke-LANative GetGroups
                if ($all.Error) { $r = $all }
                elseif ($all.Value | Where-Object { $_.Name -eq $NewName }) { $r = $script:Op::Fail([Microsoft.PowerShell.Commands.NameInUseException]::new($NewName)) }
                else { $r = Invoke-LANative RenameGroup $n $NewName }
            }
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value }
        }
    }
}

# ------------------------------------------------------------------ group membership
function Get-LocalGroupMember {
    [CmdletBinding(DefaultParameterSetName = 'Default', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717988')]
    [OutputType('Microsoft.PowerShell.Commands.LocalPrincipal')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Group', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalGroup]$Group,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier]$SID,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$Member
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $Group) {
            $r = Resolve-LAGroup $sel
            if (-not $r.Error) { $r = Invoke-LANative GetGroupMembers $r.Value }
            if ($r.Error) { Write-LAError $PSCmdlet $r.Error $sel.Value; continue }
            $members = @($r.Value)
            if (-not $PSBoundParameters.ContainsKey('Member')) { $members; continue }
            # -Member is matched (wildcards allowed) against the account name without its domain part
            $wp = [System.Management.Automation.WildcardPattern]::new($Member, [System.Management.Automation.WildcardOptions]::IgnoreCase)
            $hit = @($members | Where-Object { $wp.IsMatch($script:Native::ShortName($_.Name)) })
            if ($hit.Count) { $hit }
            elseif (-not (Test-LAWildcard $Member)) { Write-LAError $PSCmdlet ([Microsoft.PowerShell.Commands.PrincipalNotFoundException]::new($Member)) $Member }
        }
    }
}

function Add-LocalGroupMember {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717987')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Group', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalGroup]$Group,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier]$SID,

        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.PowerShell.Commands.LocalPrincipal[]]$Member
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $Group) {
            foreach ($m in $Member) {
                $rm = Resolve-LAMember $m
                if ($rm.Error) { Write-LAError $PSCmdlet $rm.Error $m.Name; continue }
                if (-not $PSCmdlet.ShouldProcess($sel.Display, "Add member $($rm.Value.Display)")) { continue }
                $r = Resolve-LAGroup $sel
                if (-not $r.Error) { $r = Invoke-LANative AddGroupMember $r.Value $rm.Value.SID $rm.Value.Display }
                if ($r.Error) { Write-LAError $PSCmdlet $r.Error $m.Name }
            }
        }
    }
}

function Remove-LocalGroupMember {
    [CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true, ConfirmImpact = 'Medium', HelpUri = 'https://go.microsoft.com/fwlink/?LinkId=717989')]
    param(
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Group', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Microsoft.PowerShell.Commands.LocalGroup]$Group,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Default', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'SecurityIdentifier', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [System.Security.Principal.SecurityIdentifier]$SID,

        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.PowerShell.Commands.LocalPrincipal[]]$Member
    )
    process {
        foreach ($sel in Get-LASelector $PSCmdlet.ParameterSetName $Name $SID $Group) {
            foreach ($m in $Member) {
                $rm = Resolve-LAMember $m
                if ($rm.Error) { Write-LAError $PSCmdlet $rm.Error $m.Name; continue }
                if (-not $PSCmdlet.ShouldProcess($sel.Display, "Remove member $($rm.Value.Display)")) { continue }
                $r = Resolve-LAGroup $sel
                if (-not $r.Error) { $r = Invoke-LANative RemoveGroupMember $r.Value $rm.Value.SID $rm.Value.Display }
                if ($r.Error) { Write-LAError $PSCmdlet $r.Error $m.Name }
            }
        }
    }
}

Set-Alias -Name algm -Value Add-LocalGroupMember
Set-Alias -Name dlu -Value Disable-LocalUser
Set-Alias -Name elu -Value Enable-LocalUser
Set-Alias -Name glg -Value Get-LocalGroup
Set-Alias -Name glgm -Value Get-LocalGroupMember
Set-Alias -Name glu -Value Get-LocalUser
Set-Alias -Name nlg -Value New-LocalGroup
Set-Alias -Name nlu -Value New-LocalUser
Set-Alias -Name rlg -Value Remove-LocalGroup
Set-Alias -Name rlgm -Value Remove-LocalGroupMember
Set-Alias -Name rlu -Value Remove-LocalUser
Set-Alias -Name rnlg -Value Rename-LocalGroup
Set-Alias -Name rnlu -Value Rename-LocalUser
Set-Alias -Name slg -Value Set-LocalGroup
Set-Alias -Name slu -Value Set-LocalUser

Export-ModuleMember -Function Add-LocalGroupMember, Disable-LocalUser, Enable-LocalUser, Get-LocalGroup, Get-LocalGroupMember, Get-LocalUser, New-LocalGroup, New-LocalUser, Remove-LocalGroup, Remove-LocalGroupMember, Remove-LocalUser, Rename-LocalGroup, Rename-LocalUser, Set-LocalGroup, Set-LocalUser -Alias algm, dlu, elu, glg, glgm, glu, nlg, nlu, rlg, rlgm, rlu, rnlg, rnlu, slg, slu
