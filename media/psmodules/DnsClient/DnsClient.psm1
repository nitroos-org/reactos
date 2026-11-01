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
