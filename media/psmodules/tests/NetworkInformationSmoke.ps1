# The whole System.Net.NetworkInformation enumeration path of .NET, in one script: every interface, every property that the
# framework reads for it (GetIPProperties, GetIPv4Properties, GetIPv6Properties, statistics), the IPGlobalProperties
# statistics and the connection lists. A flag or field that one call reads can open a code path in another (ipv4p made
# GetAllNetworkInterfaces throw on 2026-11-03), so a change to anything the stack or iphlpapi reports for an interface runs
# this before and after. Prints one line per value and "FAIL <what>: <exception>" for every call that throws; the last
# line is "SMOKE failures=<n> interfaces=<n>". Exit code = number of failures (capped at 100).
# Usage: pwsh -File NetworkInformationSmoke.ps1 [-OutFile path]
param([string]$OutFile)
$ErrorActionPreference = 'Continue'
$script:fail = 0
$script:lines = [System.Collections.Generic.List[string]]::new()
function Emit([string]$s) { $script:lines.Add($s); if (-not $OutFile) { $s } }
function Probe([string]$What, [scriptblock]$Body) {
    try {
        $v = & $Body
        $t = if ($null -eq $v) { '<null>' } elseif ($v -is [System.Array] -or $v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { (@($v) | ForEach-Object { "$_" }) -join ',' } else { "$v" }
        Emit "  $What = $t"
    } catch {
        $script:fail++
        Emit "FAIL $What : $($_.Exception.GetType().Name): $($_.Exception.Message)"
    }
}
$nics = $null
try { $nics = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) } catch { $script:fail++; Emit "FAIL GetAllNetworkInterfaces : $($_.Exception.GetType().Name): $($_.Exception.Message)"; $nics = @() }
Emit "interfaces=$($nics.Count)"
foreach ($n in $nics) {
    Emit "NIC $($n.Name)"
    foreach ($p in 'Id', 'Description', 'NetworkInterfaceType', 'OperationalStatus', 'Speed', 'SupportsMulticast', 'IsReceiveOnly') { Probe "$p" { $n.$p } }
    Probe 'GetPhysicalAddress' { $n.GetPhysicalAddress().ToString() }
    Probe 'Supports(IPv4)' { $n.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4) }
    Probe 'Supports(IPv6)' { $n.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6) }
    $ip = $null
    try { $ip = $n.GetIPProperties() } catch { $script:fail++; Emit "FAIL GetIPProperties : $($_.Exception.GetType().Name): $($_.Exception.Message)" }
    if ($ip) {
        foreach ($p in 'DnsSuffix', 'IsDnsEnabled', 'IsDynamicDnsEnabled') { Probe "ip.$p" { $ip.$p } }
        foreach ($p in 'DnsAddresses', 'DhcpServerAddresses', 'WinsServersAddresses') { Probe "ip.$p" { $ip.$p } }
        Probe 'ip.GatewayAddresses' { $ip.GatewayAddresses | ForEach-Object { $_.Address } }
        Probe 'ip.MulticastAddresses' { $ip.MulticastAddresses | ForEach-Object { $_.Address } }
        Probe 'ip.AnycastAddresses' { $ip.AnycastAddresses | ForEach-Object { $_.Address } }
        foreach ($u in $ip.UnicastAddresses) {
            foreach ($p in 'Address', 'PrefixLength', 'PrefixOrigin', 'SuffixOrigin', 'DuplicateAddressDetectionState', 'AddressPreferredLifetime', 'AddressValidLifetime', 'DhcpLeaseLifetime', 'IsDnsEligible', 'IsTransient') {
                Probe "unicast[$($u.Address)].$p" { $u.$p }
            }
            if ($u.Address.AddressFamily -eq 'InterNetwork') { Probe "unicast[$($u.Address)].IPv4Mask" { $u.IPv4Mask } }
        }
        if ($n.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv4)) {
            $v4 = $null
            try { $v4 = $ip.GetIPv4Properties() } catch { $script:fail++; Emit "FAIL GetIPv4Properties : $($_.Exception.GetType().Name): $($_.Exception.Message)" }
            if ($v4) { foreach ($p in 'Index', 'IsAutomaticPrivateAddressingActive', 'IsAutomaticPrivateAddressingEnabled', 'IsDhcpEnabled', 'IsForwardingEnabled', 'Mtu', 'UsesWins') { Probe "v4.$p" { $v4.$p } } }
            $st = $null
            try { $st = $n.GetIPv4Statistics() } catch { $script:fail++; Emit "FAIL GetIPv4Statistics : $($_.Exception.GetType().Name): $($_.Exception.Message)" }
            if ($st) { foreach ($p in 'BytesReceived', 'BytesSent', 'IncomingPacketsDiscarded', 'IncomingPacketsWithErrors', 'IncomingUnknownProtocolPackets', 'NonUnicastPacketsReceived', 'NonUnicastPacketsSent', 'OutgoingPacketsDiscarded', 'OutgoingPacketsWithErrors', 'OutputQueueLength', 'UnicastPacketsReceived', 'UnicastPacketsSent') { Probe "stat.$p" { $st.$p } } }
        }
        if ($n.Supports([System.Net.NetworkInformation.NetworkInterfaceComponent]::IPv6)) {
            try { $v6 = $ip.GetIPv6Properties(); Probe 'v6.Index' { $v6.Index }; Probe 'v6.Mtu' { $v6.Mtu } } catch { $script:fail++; Emit "FAIL GetIPv6Properties : $($_.Exception.GetType().Name): $($_.Exception.Message)" }
        }
    }
}
$g = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
foreach ($p in 'HostName', 'DomainName', 'NodeType', 'IsWinsProxy', 'DhcpScopeName') { Probe "global.$p" { $g.$p } }
Probe 'ipv4stats.NumberOfInterfaces' { $g.GetIPv4GlobalStatistics().NumberOfInterfaces }
Probe 'ipv4stats.NumberOfIPAddresses' { $g.GetIPv4GlobalStatistics().NumberOfIPAddresses }
Probe 'ipv4stats.NumberOfRoutes' { $g.GetIPv4GlobalStatistics().NumberOfRoutes }
Probe 'ipv4stats.DefaultTtl' { $g.GetIPv4GlobalStatistics().DefaultTtl }
Probe 'ipv4stats.ForwardingEnabled' { $g.GetIPv4GlobalStatistics().ForwardingEnabled }
Probe 'tcp4.CurrentConnections' { $null = $g.GetTcpIPv4Statistics().CurrentConnections; 'ok' }
Probe 'udp4.DatagramsReceived' { $null = $g.GetUdpIPv4Statistics().DatagramsReceived; 'ok' }
Probe 'icmp4.MessagesSent' { $null = $g.GetIcmpV4Statistics().MessagesSent; 'ok' }
Probe 'GetActiveTcpConnections' { @($g.GetActiveTcpConnections()).Count -ge 0 }
Probe 'GetActiveTcpListeners' { @($g.GetActiveTcpListeners()).Count -ge 0 }
Probe 'GetActiveUdpListeners' { @($g.GetActiveUdpListeners()).Count -ge 0 }
Probe 'NetworkChange.NetworkAvailable' { [System.Net.NetworkInformation.NetworkInterface]::GetIsNetworkAvailable() }
Probe 'LoopbackInterfaceIndex' { [System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex }
Emit "SMOKE failures=$($script:fail) interfaces=$($nics.Count)"
if ($OutFile) { [System.IO.File]::WriteAllLines($OutFile, $script:lines.ToArray()) }
exit ([Math]::Min($script:fail, 100))
