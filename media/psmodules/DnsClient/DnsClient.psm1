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

# Set-DnsClientServerAddress: the IPv4 DNS servers of an interface live in the NameServer value of its
# Tcpip\Parameters\Interfaces\{guid} registry key (what the network control panel also writes and what iphlpapi reads back), the
# IPv6 ones in the NameServer value of Tcpip6\Parameters\Interfaces\{guid} (the IPv6 row; iphlpapi lists them before the servers a
# router advertisement carries). -ResetServerAddresses removes the values, which hands the interface back to the servers its DHCP
# lease or its router advertisements carry.
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
        $badReported = $false; $badText = $null
        if ($PSBoundParameters.ContainsKey('ServerAddresses')) {
            foreach ($a in $ServerAddresses) { $addresses += $a }
        }
        # IPv6 servers for an interface that has no IPv6 row (the stack's IPv6 switch is off) cannot be kept: refused, never dropped silently
        if (-not $ResetServerAddresses -and $PSCmdlet.ParameterSetName -ne 'InputObject (cdxml)' -and @($rows | Where-Object { [int]$_.AddressFamily -eq 23 }).Count -eq 0) {
            $off = @($addresses | Where-Object { $ip = $null; [System.Net.IPAddress]::TryParse($_, [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 })
            if ($off.Count -gt 0) {
                $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(50, "The request is not supported. IPv6 is turned off on this system (Tcpip\Parameters\Ipv6Enable = 0): $($off -join ', ') was not set.`n", $class, 'NotImplemented'))
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
            # the servers of each family belong to the row of that family: IPv4 ones to the NameServer value of
            # Tcpip\Parameters\Interfaces\{guid}, IPv6 ones to that of Tcpip6\Parameters\Interfaces\{guid} (where Windows keeps them too)
            $v4 = @(); $v6 = @()
            if (-not $ResetServerAddresses) {
                foreach ($a in $addresses) {
                    $ip = $null
                    if (-not [System.Net.IPAddress]::TryParse($a, [ref]$ip)) { $v4 = $null; $badText = $a; break }
                    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { $v4 += $ip.ToString() } else { $v6 += $ip.ToString() }
                }
                if ($null -eq $v4) {
                    if (-not $badReported) { $badReported = $true; $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(87, "Invalid parameter ServerAddresses $badText`n", $class, 'InvalidArgument')) }
                    continue
                }
            }
            $isV6 = $fam -eq 23
            $mine = @(if ($isV6) { $v6 } else { $v4 })
            # a list without any server of this row's family leaves the row as it is; an empty list clears it
            if (-not $ResetServerAddresses -and $addresses.Count -gt 0 -and $mine.Count -eq 0) { continue }
            $key = if ($isV6) { [Nitro.Net.Config]::InterfaceKey6($ifx, $true) } else { [Nitro.Net.Config]::InterfaceKey($ifx, $true) }
            if ($null -eq $key) { $PSCmdlet.WriteError([Nitro.Net.Errors]::Win32(87, "Invalid parameter InterfaceIndex $ifx`n", $class, 'InvalidArgument')); continue }
            try {
                if ($ResetServerAddresses -or $mine.Count -eq 0) {
                    if ($null -ne $key.GetValue('NameServer', $null)) { $key.DeleteValue('NameServer') }
                } else { $key.SetValue('NameServer', ($mine -join ','), [Microsoft.Win32.RegistryValueKind]::String) }
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
