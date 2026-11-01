# DnsClient for ReactOS-Nitro: a clean-room PowerShell 7 script module. Same module, cmdlet and parameter names and the
# same output objects as the Windows module (Microsoft.DnsClient.Commands.DnsRecord_* records, the MSFT_DNSClientServerAddress
# CIM-shaped objects). Queries go through dnsapi DnsQuery_W (NitroDns.cs); the server lists come from iphlpapi.

Set-StrictMode -Version 2.0

function Get-DnsClientServerAddress {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_DNSClientServerAddress')]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][uint32[]]$InterfaceIndex,
        [Parameter(Position = 0)][string[]]$InterfaceAlias,
        [Alias('Family')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.DnsClientServerAddress.AddressFamily[]]$AddressFamily,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        $q = [Nitro.Net.Query]::new()
        if ($PSBoundParameters.ContainsKey('InterfaceIndex')) { $q.Add('InterfaceIndex', $InterfaceIndex) }
        if ($PSBoundParameters.ContainsKey('InterfaceAlias')) { $q.Add('InterfaceAlias', $InterfaceAlias) }
        if ($PSBoundParameters.ContainsKey('AddressFamily')) { $q.Add('AddressFamily', $AddressFamily) }
        $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
        $found = $q.Run([Nitro.Net.Native]::DnsServers(), 'MSFT_DNSClientServerAddress', $errors)
        foreach ($d in $found) { [Nitro.Net.CimBuilder]::Create('MSFT_DNSClientServerAddress', $d) }
        foreach ($e in $errors) { $PSCmdlet.WriteError($e) }
    }
}

function Resolve-DnsName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][string]$Name,
        [Parameter(Position = 1, ValueFromPipelineByPropertyName = $true)][Microsoft.DnsClient.Commands.RecordType]$Type,
        [string[]]$Server,
        [switch]$DnsOnly,
        [switch]$CacheOnly,
        [switch]$DnssecOk,
        [switch]$DnssecCd,
        [switch]$NoHostsFile,
        [switch]$LlmnrNetbiosOnly,
        [switch]$LlmnrFallback,
        [switch]$LlmnrOnly,
        [switch]$NetbiosFallback,
        [switch]$NoIdn,
        [switch]$NoRecursion,
        [switch]$QuickTimeout,
        [switch]$TcpOnly
    )
    process {
        [uint32]$opt = 0
        if ($TcpOnly) { $opt = $opt -bor 0x2 }
        if ($NoRecursion) { $opt = $opt -bor 0x4 }
        if ($CacheOnly) { $opt = $opt -bor 0x10 }
        if ($NoHostsFile) { $opt = $opt -bor 0x40 }
        if ($DnsOnly) { $opt = $opt -bor 0x100 }
        $qname = $Name
        $types = $null
        if ($PSBoundParameters.ContainsKey('Type') -and [int]$Type -ne 0) { $types = @([uint16]$Type) }
        else {
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($Name, [ref]$ip)) { $qname = [Microsoft.DnsClient.Commands.DnsNative]::ReverseName($ip); $types = @([uint16]12) }
            else { $types = @([uint16]1, [uint16]28) }
        }
        $failure = $null
        $any = $false
        foreach ($t in $types) {
            $res = [Microsoft.DnsClient.Commands.DnsNative]::Query($qname, $t, $opt, $Server)
            if ($res.Code -ne 0) { if (-not $failure) { $failure = $res.Code }; continue }
            $any = $true
            foreach ($rec in $res.Records) { $rec }
        }
        if (-not $any -and $failure) {
            $code = [int]$failure
            if ($code -eq 2) { $code = 9003 }   # dnsapi on this system reports a name that does not exist as ERROR_FILE_NOT_FOUND for address queries
            $ex = [Microsoft.DnsClient.Commands.DnsNative]::Failure($Name, $code)
            $id = [Microsoft.DnsClient.Commands.DnsNative]::ErrorName($code)
            $cat = [Microsoft.DnsClient.Commands.DnsNative]::ErrorCategoryOf($code)
            $PSCmdlet.WriteError([Microsoft.DnsClient.Commands.DnsNative]::StampedError($ex, $id, $cat, $Name, $MyInvocation.DisplayScriptPosition))
        }
    }
}

# Set-DnsClientServerAddress: the DNS servers of an interface live in the NameServer value of its
# Tcpip\Parameters\Interfaces\{guid} registry key (what the network control panel also writes and what iphlpapi reads back);
# -ResetServerAddresses removes the value, which hands the interface back to the servers its DHCP lease carries.
function Set-DnsClientServerAddress {
    [CmdletBinding(DefaultParameterSetName = 'ByAlias', SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_DNSClientServerAddress')]
    param(
        [Parameter(ParameterSetName = 'ByAlias', Mandatory = $true, Position = 0)][ValidateNotNull()][string[]]$InterfaceAlias,
        [Parameter(ParameterSetName = 'ByName', Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)][ValidateNotNull()][uint32[]]$InterfaceIndex,
        [Parameter(ParameterSetName = 'InputObject (cdxml)', Mandatory = $true, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_DNSClientServerAddress')][ValidateNotNull()][object[]]$InputObject,
        [Alias('Addresses')][string[]]$ServerAddresses,
        [switch]$Validate,
        [Alias('ResetAddresses')][switch]$ResetServerAddresses,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob,
        [switch]$PassThru
    )
    process {
        $class = 'MSFT_DNSClientServerAddress'
        if ($AsJob) { $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(50, "The -AsJob parameter is not supported by this implementation.`n", $class, 'NotImplemented')); return }
        $rows = @()
        if ($PSCmdlet.ParameterSetName -eq 'InputObject (cdxml)') { $rows = @($InputObject) }
        else {
            $q = [Nitro.Net.Query]::new()
            if ($PSBoundParameters.ContainsKey('InterfaceIndex')) { $q.Add('InterfaceIndex', $InterfaceIndex) }
            if ($PSBoundParameters.ContainsKey('InterfaceAlias')) { $q.Add('InterfaceAlias', $InterfaceAlias) }
            $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
            $found = $q.Run([Nitro.Net.Native]::DnsServers(), $class, $errors)
            foreach ($d in $found) { $rows += [Nitro.Net.CimBuilder]::Create($class, $d) }
            foreach ($e in $errors) { $PSCmdlet.WriteError($e) }
        }
        $addresses = @()
        $bad = $null
        if ($PSBoundParameters.ContainsKey('ServerAddresses')) {
            foreach ($a in $ServerAddresses) {
                $ip = $null
                if (-not [System.Net.IPAddress]::TryParse($a, [ref]$ip)) { $bad = $a }
                $addresses += $a
            }
        }
        foreach ($row in $rows) {
            $ifx = [uint32]$row.InterfaceIndex
            $fam = [int]$row.AddressFamily
            if ($ResetServerAddresses -and $PSBoundParameters.ContainsKey('ServerAddresses')) {
                $tgt = "MSFT_DNSClientServerAddress (Name = `"$ifx`", CreationClassName = `"`", SystemCreationClassName = `"`", SystemName = `"$fam`")"
                $PSCmdlet.WriteError([Nitro.Net.Errors]::Cimx('MI RESULT 4', "One or more parameter values passed to the method were invalid.`n", $tgt, 'InvalidArgument'))
                continue
            }
            if (-not $ResetServerAddresses -and -not $PSBoundParameters.ContainsKey('ServerAddresses')) { continue }
            $text = "Microsoft DNS Client settings will be changed as requested.`nThis will affect name resolutions on the adapter `"$($row.InterfaceAlias)`".`n"
            if (-not $PSCmdlet.ShouldProcess($text, $text, 'Confirm')) { continue }
            if ($fam -ne 2) {
                $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(50, "The request is not supported. This network stack has no IPv6.`n", $class, 'NotImplemented'))
                continue
            }
            $key = [Nitro.Net.Config]::InterfaceKey($ifx, $true)
            if ($null -eq $key) { $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(87, "Invalid parameter InterfaceIndex $ifx`n", $class, 'InvalidArgument')); continue }
            try {
                if ($ResetServerAddresses) {
                    if ($null -ne $key.GetValue('NameServer', $null)) { $key.DeleteValue('NameServer') }
                } else {
                    $v4 = @(); $v6 = @()
                    foreach ($a in $addresses) {
                        $ip = $null
                        if (-not [System.Net.IPAddress]::TryParse($a, [ref]$ip)) { $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(87, "Invalid parameter ServerAddresses $a`n", $class, 'InvalidArgument')); $v4 = $null; break }
                        if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $v4 += $ip.ToString() } else { $v6 += $a }
                    }
                    if ($null -eq $v4) { continue }
                    # the IPv6 servers belong to the IPv6 row, which this network stack does not have
                    if ($v6.Count -gt 0) { $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(50, "The request is not supported. This network stack has no IPv6: $($v6 -join ', ') was not set.`n", $class, 'NotImplemented')) }
                    if ($v4.Count -eq 0) { if ($null -ne $key.GetValue('NameServer', $null)) { $key.DeleteValue('NameServer') } }
                    else { $key.SetValue('NameServer', ($v4 -join ','), [Microsoft.Win32.RegistryValueKind]::String) }
                }
            } finally { $key.Dispose() }
            [Nitro.Net.Config]::FlushDnsCache()
            if ($PassThru) {
                $q2 = [Nitro.Net.Query]::new(); $q2.Add('InterfaceIndex', @($ifx)); $q2.Add('AddressFamily', @($fam))
                $e2 = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
                foreach ($d in $q2.Run([Nitro.Net.Native]::DnsServers(), $class, $e2)) { [Nitro.Net.CimBuilder]::Create($class, $d) }
            }
        }
    }
}
