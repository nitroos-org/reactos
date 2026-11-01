# NetAdapter for ReactOS-Nitro: a clean-room PowerShell 7 script module (read side). Same module, cmdlet and parameter
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
