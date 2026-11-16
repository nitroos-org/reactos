# NetAdapter for ReactOS-Nitro: a clean-room PowerShell 7 script module (Get-NetAdapter, statistics, Enable/Disable/Restart). Same module, cmdlet and parameter
# names and the same object shape as the Windows module: the output objects carry the
# Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_* type names and the CIM properties in the
# order Windows reports them. The data comes from iphlpapi through Nitro.Net.Native (NitroNetNative.cs).

Set-StrictMode -Version 2.0

function Write-NetErrors {
    param([System.Management.Automation.PSCmdlet]$Cmdlet, $Errors)
    foreach ($e in $Errors) { $Cmdlet.WriteError($e) }
}

function Get-NetAdapter {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter')]
    param(
        [Parameter(ParameterSetName = 'ByName', Position = 0)]
        [Alias('ifAlias', 'InterfaceAlias')]
        [string[]]$Name,

        [Parameter(ParameterSetName = 'ByInstanceID', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifDesc')]
        [string[]]$InterfaceDescription,

        [Parameter(ParameterSetName = 'ByIfIndex', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifIndex')]
        [uint32[]]$InterfaceIndex,

        [switch]$IncludeHidden,
        [switch]$Physical,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        $q = [Nitro.Net.Query]::new()
        if ($PSBoundParameters.ContainsKey('Name')) { $q.Add('Name', $Name) }
        if ($PSBoundParameters.ContainsKey('InterfaceDescription')) { $q.Add('InterfaceDescription', $InterfaceDescription) }
        if ($PSBoundParameters.ContainsKey('InterfaceIndex')) { $q.Add('InterfaceIndex', $InterfaceIndex) }
        $items = [Nitro.Net.Native]::Adapters()
        if (-not $IncludeHidden) { $items = $items.Where({ -not $_['Hidden'] }) }
        if ($Physical) { $items = $items.Where({ $_['HardwareInterface'] }) }
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $found = $q.Run($items, 'MSFT_NetAdapter', $errors)
        foreach ($d in $found) { [Nitro.Net.CimBuilder]::Create('MSFT_NetAdapter', $d) }
        Write-NetErrors $PSCmdlet $errors
    }
}

function Get-NetAdapterStatistics {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapterStatisticsSettingData')]
    param(
        [Parameter(ParameterSetName = 'ByName', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifAlias', 'InterfaceAlias')]
        [string[]]$Name,

        [Parameter(ParameterSetName = 'ByInstanceID', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifDesc', 'InstanceID')]
        [string[]]$InterfaceDescription,

        [switch]$IncludeHidden,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        $q = [Nitro.Net.Query]::new()
        if ($PSBoundParameters.ContainsKey('Name')) { $q.Add('Name', $Name) }
        if ($PSBoundParameters.ContainsKey('InterfaceDescription')) { $q.Add('InterfaceDescription', $InterfaceDescription) }
        $items = [Nitro.Net.Native]::AdapterStats()
        if (-not $IncludeHidden) {
            $visible = @{}
            foreach ($a in [Nitro.Net.Native]::Adapters()) { if (-not $a['Hidden']) { $visible[$a['InstanceID']] = $true } }
            $items = $items.Where({ $visible.ContainsKey($_['InstanceID']) })
        }
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $found = $q.Run($items, 'MSFT_NetAdapterStatisticsSettingData', $errors)
        foreach ($d in $found) { [Nitro.Net.CimBuilder]::Create('MSFT_NetAdapterStatisticsSettingData', $d) }
        Write-NetErrors $PSCmdlet $errors
    }
}

# The administrative state of an adapter (the state of its device). mode: 0 disable, 1 enable, 2 restart. The cmdlets
# take the adapters like Get-NetAdapter does (Name, InterfaceDescription, or objects from the pipeline), ask for
# confirmation (high impact: -Confirm:$false in a script) and answer nothing, or the adapters with -PassThru.
function Invoke-NetAdapterState {
    param(
        [System.Management.Automation.PSCmdlet]$Cmdlet,
        [string]$CmdletName,
        [int]$Mode,
        [string[]]$Name,
        [string[]]$InterfaceDescription,
        [object[]]$InputObject,
        [bool]$IncludeHidden,
        [bool]$PassThru
    )
    $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
    $targets = @()
    if ($null -ne $InputObject) {
        foreach ($o in $InputObject) {
            $oid = if ($o.PSObject.Properties['InstanceID']) { [string]$o.InstanceID } else { '' }
            $oname = if ($o.PSObject.Properties['Name']) { [string]$o.Name } else { '' }
            $d = @([Nitro.Net.Native]::Adapters()).Where({ $_['InstanceID'] -eq $oid -or $_['Name'] -eq $oname })
            if ($d.Count -gt 0) { $targets += $d[0] }
        }
    } else {
        $q = [Nitro.Net.Query]::new()
        if ($null -ne $Name) { $q.Add('Name', $Name) }
        if ($null -ne $InterfaceDescription) { $q.Add('InterfaceDescription', $InterfaceDescription) }
        $items = [Nitro.Net.Native]::Adapters()
        if (-not $IncludeHidden) { $items = $items.Where({ -not $_['Hidden'] }) }
        $targets = @($q.Run($items, 'MSFT_NetAdapter', $errors))
    }
    foreach ($t in $targets) {
        $desc = "$CmdletName '" + $t['Name'] + "'"
        if (-not $Cmdlet.ShouldProcess($desc, $desc, 'Confirm')) { continue }
        $rc = [Nitro.Net.Native]::SetAdapterState([string]$t['PnPDeviceID'], $Mode)
        if ($rc -ne 0) {
            $ex = [System.ComponentModel.Win32Exception]::new([int]$rc)
            $Cmdlet.WriteError([System.Management.Automation.ErrorRecord]::new($ex, 'NetAdapterStateFailed,' + $CmdletName, [System.Management.Automation.ErrorCategory]::NotSpecified, $t['Name']))
            continue
        }
        if ($PassThru) {
            # the adapter takes a moment to be (de)configured: the object is read again, by its GUID
            $guid = $t['InstanceID']
            if ($Mode -ne 0) { for ($i = 0; $i -lt 20; $i++) { if (@([Nitro.Net.Native]::Adapters()).Where({ $_['InstanceID'] -eq $guid -and $_['InterfaceIndex'] -ne 0 }).Count -gt 0) { break }; Start-Sleep -Milliseconds 250 } }
            foreach ($d in @([Nitro.Net.Native]::Adapters()).Where({ $_['InstanceID'] -eq $guid })) { [Nitro.Net.CimBuilder]::Create('MSFT_NetAdapter', $d) }
        }
    }
    Write-NetErrors $Cmdlet $errors
}

function Disable-NetAdapter {
    [CmdletBinding(DefaultParameterSetName = 'ByName', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(ParameterSetName = 'ByName', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifAlias', 'InterfaceAlias')]
        [string[]]$Name,

        [Parameter(ParameterSetName = 'ByInstanceID', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifDesc')]
        [string[]]$InterfaceDescription,

        [switch]$IncludeHidden,

        [Parameter(ParameterSetName = 'InputObject', Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$InputObject,

        [switch]$PassThru,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        Invoke-NetAdapterState -Cmdlet $PSCmdlet -CmdletName 'Disable-NetAdapter' -Mode 0 -Name $Name -InterfaceDescription $InterfaceDescription -InputObject $InputObject -IncludeHidden $IncludeHidden.IsPresent -PassThru $PassThru.IsPresent
    }
}

function Enable-NetAdapter {
    [CmdletBinding(DefaultParameterSetName = 'ByName', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ParameterSetName = 'ByName', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifAlias', 'InterfaceAlias')]
        [string[]]$Name,

        [Parameter(ParameterSetName = 'ByInstanceID', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifDesc')]
        [string[]]$InterfaceDescription,

        [switch]$IncludeHidden,

        [Parameter(ParameterSetName = 'InputObject', Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$InputObject,

        [switch]$PassThru,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        Invoke-NetAdapterState -Cmdlet $PSCmdlet -CmdletName 'Enable-NetAdapter' -Mode 1 -Name $Name -InterfaceDescription $InterfaceDescription -InputObject $InputObject -IncludeHidden $IncludeHidden.IsPresent -PassThru $PassThru.IsPresent
    }
}

function Restart-NetAdapter {
    [CmdletBinding(DefaultParameterSetName = 'ByName', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(ParameterSetName = 'ByName', Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifAlias', 'InterfaceAlias')]
        [string[]]$Name,

        [Parameter(ParameterSetName = 'ByInstanceID', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('ifDesc')]
        [string[]]$InterfaceDescription,

        [switch]$IncludeHidden,

        [Parameter(ParameterSetName = 'InputObject', Mandatory = $true, ValueFromPipeline = $true)]
        [object[]]$InputObject,

        [switch]$PassThru,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        Invoke-NetAdapterState -Cmdlet $PSCmdlet -CmdletName 'Restart-NetAdapter' -Mode 2 -Name $Name -InterfaceDescription $InterfaceDescription -InputObject $InputObject -IncludeHidden $IncludeHidden.IsPresent -PassThru $PassThru.IsPresent
    }
}
