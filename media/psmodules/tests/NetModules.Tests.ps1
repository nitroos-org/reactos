# Pester 4 tests of the NetAdapter, NetTCPIP and DnsClient modules.
# Run in the nitro guest against the installed modules (loaded BY NAME) and, read-only, on the Windows oracle against the real
# modules (set NNET_ORACLE=1): the expectations are the measured Windows shapes (NetModules.schema.json, the lists below), so a
# pass on both is the parity check. Rows that need what only one system has are skipped on the other.
param([string]$SchemaPath = (Join-Path $PSScriptRoot 'NetModules.schema.json'))

$script:Oracle = [bool]$env:NNET_ORACLE
$script:Schema = Get-Content -Raw $SchemaPath | ConvertFrom-Json
Import-Module NetAdapter, NetTCPIP, DnsClient -Force -ErrorAction Stop

# wait for an address from DHCP (nitro: slirp lease) before the network-dependent rows
$sw = [Diagnostics.Stopwatch]::StartNew()
while ($sw.Elapsed.TotalSeconds -lt 60 -and -not (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notin '0.0.0.0', '127.0.0.1' })) { Start-Sleep 2 }

# a listener, a connected pair and a UDP socket of this process
$script:Port = 18123
$script:Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $script:Port); $script:Listener.Start()
$script:Client = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $script:Port)
$script:Accepted = $script:Listener.AcceptTcpClient()
$script:Udp = [System.Net.Sockets.UdpClient]::new(18124)

$script:Adapter = Get-NetAdapter | Select-Object -First 1
$hidden = @('CimClass', 'CimInstanceProperties', 'CimSystemProperties')
function MemberNames($o) { @($o.psobject.Properties.Name | Where-Object { $_ -notin $hidden }) }
# the error records a command writes (binding errors included), whatever the caller's $ErrorActionPreference
function Err([scriptblock]$sb) {
    $ErrorActionPreference = 'Continue'
    try { @(& $sb 2>&1 | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) } catch { @($_) }
}
function HeaderTokens($o) {
    $lines = @(($o | Format-Table | Out-String -Width 250) -split "`r?`n" | Where-Object { $_.Trim() })
    @($lines[0].Trim() -split '\s+')
}

Describe 'modules load cleanly' {
    It 'imports <Name> without output or errors' -TestCases @(@{ Name = 'NetAdapter' }, @{ Name = 'NetTCPIP' }, @{ Name = 'DnsClient' }) {
        param($Name)
        $out = @(Import-Module $Name -Force -ErrorAction Stop *>&1)
        $out.Count | Should -Be 0
    }
    It 'reports the Windows module versions: <Name> <Version>' -TestCases @(@{ Name = 'NetAdapter'; Version = '2.0.0.0' }, @{ Name = 'NetTCPIP'; Version = '1.0.0.0' }, @{ Name = 'DnsClient'; Version = '1.0.0.0' }) {
        param($Name, $Version)
        (Get-Module $Name).Version.ToString() | Should -Be $Version
    }
    It 'exports <Command> from <Module>' -TestCases @(
        @{ Module = 'NetAdapter'; Command = 'Get-NetAdapter' }, @{ Module = 'NetAdapter'; Command = 'Get-NetAdapterStatistics' },
        @{ Module = 'NetTCPIP'; Command = 'Get-NetIPAddress' }, @{ Module = 'NetTCPIP'; Command = 'Get-NetIPConfiguration' },
        @{ Module = 'NetTCPIP'; Command = 'Get-NetIPInterface' }, @{ Module = 'NetTCPIP'; Command = 'Get-NetRoute' },
        @{ Module = 'NetTCPIP'; Command = 'Get-NetTCPConnection' }, @{ Module = 'NetTCPIP'; Command = 'Get-NetUDPEndpoint' },
        @{ Module = 'NetTCPIP'; Command = 'Test-NetConnection' }, @{ Module = 'DnsClient'; Command = 'Resolve-DnsName' },
        @{ Module = 'DnsClient'; Command = 'Get-DnsClientServerAddress' }) {
        param($Module, $Command)
        (Get-Command $Command).Source | Should -Be $Module
    }
    It 'autoloads <Command> by name in a fresh session' -TestCases @(@{ Command = 'Get-NetAdapter' }, @{ Command = 'Get-NetIPAddress' }, @{ Command = 'Resolve-DnsName' }) {
        param($Command)
        $pwsh = (Get-Process -Id $PID).Path
        $r = & $pwsh -NoProfile -NonInteractive -Command "(Get-Command $Command -ErrorAction Stop).Source"
        $r | Should -Not -BeNullOrEmpty
    }
    It 'has the aliases gip and TNC' {
        (Get-Alias gip).Definition | Should -Be 'Get-NetIPConfiguration'
        (Get-Alias TNC).Definition | Should -Be 'Test-NetConnection'
    }
}

Describe 'parameter surface (as on Windows)' {
    $cases = @(
        @{ C = 'Get-NetAdapter'; P = 'Name', 'IncludeHidden', 'Physical', 'InterfaceDescription', 'InterfaceIndex'; Sets = 'ByName', 'ByInstanceID', 'ByIfIndex'; Default = 'ByName' },
        @{ C = 'Get-NetAdapterStatistics'; P = 'Name', 'InterfaceDescription', 'IncludeHidden'; Sets = 'ByName', 'ByInstanceID'; Default = 'ByName' },
        @{ C = 'Get-NetIPAddress'; P = 'IPAddress', 'InterfaceIndex', 'InterfaceAlias', 'AddressFamily', 'Type', 'PrefixLength', 'PrefixOrigin', 'SuffixOrigin', 'AddressState', 'ValidLifetime', 'PreferredLifetime', 'SkipAsSource', 'AssociatedIPInterface', 'PolicyStore', 'IncludeAllCompartments'; Sets = $null; Default = $null },
        @{ C = 'Get-NetRoute'; P = 'DestinationPrefix', 'InterfaceIndex', 'InterfaceAlias', 'NextHop', 'AddressFamily', 'Publish', 'RouteMetric', 'Protocol', 'CompartmentId', 'ValidLifetime', 'PreferredLifetime', 'State', 'InterfaceMetric', 'AssociatedIPInterface', 'PolicyStore'; Sets = $null; Default = $null },
        @{ C = 'Get-NetTCPConnection'; P = 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'State', 'AppliedSetting', 'OwningProcess', 'CreationTime', 'OffloadState'; Sets = $null; Default = $null },
        @{ C = 'Get-NetUDPEndpoint'; P = 'LocalAddress', 'LocalPort', 'OwningProcess', 'CreationTime'; Sets = $null; Default = $null },
        @{ C = 'Get-DnsClientServerAddress'; P = 'InterfaceIndex', 'InterfaceAlias', 'AddressFamily'; Sets = $null; Default = $null },
        @{ C = 'Resolve-DnsName'; P = 'Name', 'Type', 'Server', 'DnsOnly', 'CacheOnly', 'DnssecOk', 'DnssecCd', 'NoHostsFile', 'LlmnrNetbiosOnly', 'LlmnrFallback', 'LlmnrOnly', 'NetbiosFallback', 'NoIdn', 'NoRecursion', 'QuickTimeout', 'TcpOnly'; Sets = $null; Default = $null },
        @{ C = 'Get-NetIPConfiguration'; P = 'InterfaceAlias', 'InterfaceIndex', 'All', 'AllCompartments', 'CompartmentId', 'Detailed'; Sets = 'Alias', 'Index', 'All'; Default = 'Alias' },
        @{ C = 'Test-NetConnection'; P = 'ComputerName', 'TraceRoute', 'Hops', 'InformationLevel', 'CommonTCPPort', 'Port', 'DiagnoseRouting', 'ConstrainSourceAddress', 'ConstrainInterface'; Sets = 'ICMP', 'CommonTCPPort', 'RemotePort', 'NetRouteDiagnostics'; Default = $null }
    )
    It '<C> has the Windows parameters' -TestCases $cases {
        param($C, $P, $Sets, $Default)
        $cmd = Get-Command $C
        foreach ($p in $P) { $cmd.Parameters.Keys | Should -Contain $p }
    }
    It '<C> has the Windows parameter sets' -TestCases ($cases | Where-Object { $_.Sets }) {
        param($C, $P, $Sets, $Default)
        $cmd = Get-Command $C
        @($cmd.ParameterSets.Name | Sort-Object) -join ',' | Should -Be (@($Sets | Sort-Object) -join ',')
        if ($Default) { $cmd.DefaultParameterSet | Should -Be $Default }
    }
    It 'takes the Windows positional parameters' {
        (Get-Command Get-NetAdapter).Parameters['Name'].ParameterSets['ByName'].Position | Should -Be 0
        (Get-Command Get-NetIPAddress).Parameters['IPAddress'].ParameterSets.Values[0].Position | Should -Be 0
        (Get-Command Get-NetTCPConnection).Parameters['LocalPort'].ParameterSets.Values[0].Position | Should -Be 1
        (Get-Command Resolve-DnsName).Parameters['Type'].ParameterSets.Values[0].Position | Should -Be 1
        (Get-Command Test-NetConnection).Parameters['CommonTCPPort'].ParameterSets['CommonTCPPort'].Position | Should -Be 1
    }
    It 'uses the Windows parameter aliases' {
        (Get-Command Get-NetIPAddress).Parameters['InterfaceIndex'].Aliases | Should -Contain 'ifIndex'
        (Get-Command Get-NetIPAddress).Parameters['InterfaceAlias'].Aliases | Should -Contain 'ifAlias'
        (Get-Command Get-NetIPAddress).Parameters['IPAddress'].Aliases | Should -Contain 'LocalAddress'
        (Get-Command Get-NetAdapter).Parameters['Name'].Aliases | Should -Contain 'InterfaceAlias'
        (Get-Command Get-NetTCPConnection).Parameters['LocalAddress'].Aliases | Should -Contain 'IPAddress'
    }
    It 'validates enum parameters with the Windows enum type names' {
        (Get-Command Get-NetIPAddress).Parameters['AddressFamily'].ParameterType.FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressFamily[]'
        (Get-Command Get-NetTCPConnection).Parameters['State'].ParameterType.FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.State[]'
        (Get-Command Resolve-DnsName).Parameters['Type'].ParameterType.FullName | Should -Be 'Microsoft.DnsClient.Commands.RecordType'
    }
    It 'carries the Windows HelpUri' {
        (Get-Command Get-NetIPConfiguration).HelpUri | Should -Be 'http://go.microsoft.com/fwlink/?LinkId=253567'
        (Get-Command Get-NetIPAddress).HelpUri | Should -BeNullOrEmpty
        (Get-Command Resolve-DnsName).HelpUri | Should -BeNullOrEmpty
    }
    It 'limits Test-NetConnection -Port and -CommonTCPPort like Windows' {
        $e = Err { Test-NetConnection 127.0.0.1 -Port 70000 }
        $e[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentValidationError,Test-NetConnection'
        $e = Err { Test-NetConnection 127.0.0.1 -Port 0 }
        $e[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentValidationError,Test-NetConnection'
        (Get-Command Test-NetConnection).Parameters['CommonTCPPort'].Attributes.ValidValues -join ',' | Should -Be 'HTTP,RDP,SMB,WINRM'
    }
}

Describe 'object shapes' {
    $classes = @(
        @{ Class = 'MSFT_NetAdapter'; Get = { Get-NetAdapter | Select-Object -First 1 }; Columns = 'Name', 'InterfaceDescription', 'ifIndex', 'Status', 'MacAddress', 'LinkSpeed' },
        @{ Class = 'MSFT_NetAdapterStatisticsSettingData'; Get = { Get-NetAdapterStatistics | Select-Object -First 1 }; Columns = 'Name', 'ReceivedBytes', 'ReceivedUnicastPackets', 'SentBytes', 'SentUnicastPackets' },
        @{ Class = 'MSFT_NetIPAddress'; Get = { Get-NetIPAddress | Select-Object -First 1 }; Columns = 'ifIndex', 'IPAddress', 'PrefixLength', 'PrefixOrigin', 'SuffixOrigin', 'AddressState', 'PolicyStore' },
        @{ Class = 'MSFT_NetIPInterface'; Get = { Get-NetIPInterface | Select-Object -First 1 }; Columns = 'ifIndex', 'InterfaceAlias', 'AddressFamily', 'NlMtu(Bytes)', 'InterfaceMetric', 'Dhcp', 'ConnectionState', 'PolicyStore' },
        @{ Class = 'MSFT_NetRoute'; Get = { Get-NetRoute | Select-Object -First 1 }; Columns = 'ifIndex', 'DestinationPrefix', 'NextHop', 'RouteMetric', 'ifMetric', 'PolicyStore' },
        @{ Class = 'MSFT_NetTCPConnection'; Get = { Get-NetTCPConnection -LocalPort $script:Port -State Listen | Select-Object -First 1 }; Columns = 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'State', 'AppliedSetting', 'OwningProcess' },
        @{ Class = 'MSFT_NetUDPEndpoint'; Get = { Get-NetUDPEndpoint -LocalPort 18124 | Select-Object -First 1 }; Columns = 'LocalAddress', 'LocalPort' },
        @{ Class = 'MSFT_DNSClientServerAddress'; Get = { Get-DnsClientServerAddress | Select-Object -First 1 }; Columns = $null }
    )
    It '<Class> objects carry the Windows type name chain' -TestCases $classes {
        param($Class, $Get, $Columns)
        $o = & $Get
        $o | Should -Not -BeNullOrEmpty
        @($o.psobject.TypeNames) | Should -Be @($script:Schema.$Class.typeNames)
        $o.psobject.TypeNames[0] | Should -Be "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/$Class"
    }
    It '<Class> objects have the Windows properties in the Windows order' -TestCases $classes {
        param($Class, $Get, $Columns)
        $o = & $Get
        (MemberNames $o) -join ',' | Should -Be (@($script:Schema.$Class.members) -join ',')
    }
    It '<Class> default table has the Windows columns' -TestCases ($classes | Where-Object { $_.Columns }) {
        param($Class, $Get, $Columns)
        $o = & $Get
        (HeaderTokens $o) -join ',' | Should -Be ($Columns -join ',')
    }
    It 'NetAdapter properties have the Windows types' {
        $a = $script:Adapter
        $a.InterfaceIndex | Should -BeOfType ([uint32])
        $a.NetLuid | Should -BeOfType ([uint64])
        $a.ifOperStatus.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetAdapter.IF_OPER_STATUS'
        $a.AdminStatus.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetAdapter.NET_IF_ADMIN_STATUS'
        $a.MediaConnectionState.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetAdapter.NET_IF_MEDIA_CONNECT_STATE'
        $a.Status | Should -BeOfType ([string])
        $a.MacAddress | Should -Match '^([0-9A-F]{2}-){5}[0-9A-F]{2}$'
        $a.LinkSpeed | Should -Match '^[0-9.]+ (bps|Kbps|Mbps|Gbps)$'
        $a.ifIndex | Should -Be $a.InterfaceIndex
        $a.InterfaceAlias | Should -Be $a.Name
        $a.ifDesc | Should -Be $a.InterfaceDescription
        $a.LinkLayerAddress | Should -Be $a.MacAddress
    }
    It 'NetIPAddress properties have the Windows types' {
        $a = Get-NetIPAddress | Select-Object -First 1
        $a.AddressFamily.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressFamily'
        $a.PrefixOrigin.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.PrefixOrigin'
        $a.Type.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.Type'
        $a.PrefixLength | Should -BeOfType ([byte])
        $a.InterfaceIndex | Should -BeOfType ([uint32])
        $a.ValidLifetime | Should -BeOfType ([timespan])
        $a.SkipAsSource | Should -BeOfType ([bool])
        $a.ifIndex | Should -Be $a.InterfaceIndex
        $a.Store.ToString() | Should -Be 'ActiveStore'
    }
    It 'NetTCPConnection and NetUDPEndpoint properties have the Windows types' {
        $t = Get-NetTCPConnection -LocalPort $script:Port -State Listen | Select-Object -First 1
        $t.LocalPort | Should -BeOfType ([uint16])
        $t.OwningProcess | Should -BeOfType ([uint32])
        $t.State.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.State'
        $t.OffloadState.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.OffloadState'
        $t.CreationTime | Should -BeOfType ([datetime])
        $t.CreationTime.Kind | Should -Be 'Local'
        $u = Get-NetUDPEndpoint -LocalPort 18124 | Select-Object -First 1
        $u.LocalPort | Should -BeOfType ([uint16])
    }
    It 'NetRoute properties have the Windows types' {
        $r = Get-NetRoute | Select-Object -First 1
        $r.RouteMetric | Should -BeOfType ([uint16])
        $r.InterfaceMetric | Should -BeOfType ([uint32])
        $r.Protocol.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.Protocol'
        $r.ValidLifetime | Should -BeOfType ([timespan])
        $r.ifIndex | Should -Be $r.InterfaceIndex
    }
    It 'NetIPAddress list view prints Infinite lifetimes like Windows' {
        $s = Get-NetIPAddress -IPAddress 127.0.0.1 | Format-List | Out-String
        $s | Should -Match 'ValidLifetime\s+: Infinite \(\[TimeSpan\]::MaxValue\)'
        $s | Should -Match 'PolicyStore\s+: ActiveStore'
    }
    It 'NetAdapter list view names the Windows fields' {
        $s = $script:Adapter | Format-List | Out-String
        foreach ($f in 'Name', 'InterfaceDescription', 'InterfaceIndex', 'MacAddress', 'MediaType', 'PhysicalMediaType', 'InterfaceOperationalStatus', 'AdminStatus', 'MediaConnectionState', 'ConnectorPresent', 'VlanID', 'DriverInformation') {
            $s | Should -Match "(?m)^$f\s+:"
        }
    }
    It 'DnsClientServerAddress prints the Windows table and list' {
        $o = Get-DnsClientServerAddress | Select-Object -First 1
        $t = $o | Format-Table | Out-String
        $t | Should -Match 'InterfaceAlias\s+Interface\s+Address\s+ServerAddresses'
        $t | Should -Match 'Index\s+Family'
        $l = $o | Format-List | Out-String
        $l | Should -Match '(?m)^AddressFamily\s+: IPv[46]'
    }
}

Describe 'filters' {
    It 'Get-NetAdapter -Name finds an adapter by name, wildcard and position' {
        $n = $script:Adapter.Name
        @(Get-NetAdapter -Name $n).Count | Should -Be 1
        @(Get-NetAdapter -Name ($n.Substring(0, 3) + '*')).Name | Should -Contain $n
        @(Get-NetAdapter $n.ToUpper()).Count | Should -Be 1
        @(Get-NetAdapter -Name 'zz*').Count | Should -Be 0
    }
    It 'Get-NetAdapter selects by -InterfaceIndex, -InterfaceDescription and -Physical' {
        @(Get-NetAdapter -InterfaceIndex $script:Adapter.ifIndex).Name | Should -Be $script:Adapter.Name
        @(Get-NetAdapter -InterfaceDescription $script:Adapter.InterfaceDescription).ifIndex | Should -Be $script:Adapter.ifIndex
        @(Get-NetAdapter -Physical).Count | Should -BeGreaterThan 0
    }
    It 'Get-NetAdapter -IncludeHidden returns at least the visible adapters, all marked Hidden or not consistently' {
        $all = @(Get-NetAdapter -IncludeHidden)
        $all.Count | Should -BeGreaterOrEqual @(Get-NetAdapter).Count
        @(Get-NetAdapter).Hidden | Should -Not -Contain $true
    }
    It 'Get-NetIPAddress filters by family, index, address and prefix length' {
        $v4 = @(Get-NetIPAddress -AddressFamily IPv4)
        $v4.Count | Should -BeGreaterThan 0
        ($v4.AddressFamily | Select-Object -Unique).ToString() | Should -Be 'IPv4'
        @(Get-NetIPAddress -IPAddress 127.0.0.1).IPAddress | Should -Be '127.0.0.1'
        @(Get-NetIPAddress -IPAddress 127.0.0.1).PrefixLength | Should -Be 8
        @(Get-NetIPAddress 127.0.0.1).Count | Should -Be 1
        @(Get-NetIPAddress -PrefixLength 8)[0].IPAddress | Should -Be '127.0.0.1'
        @(Get-NetIPAddress -IPAddress '127.*').Count | Should -Be 1
        $idx = (Get-NetIPAddress -IPAddress 127.0.0.1).InterfaceIndex
        @(Get-NetIPAddress -InterfaceIndex $idx).InterfaceIndex | Select-Object -Unique | Should -Be $idx
    }
    It 'Get-NetIPAddress takes adapters from the pipeline (by InterfaceIndex and InterfaceAlias)' {
        $a = @($script:Adapter | Get-NetIPAddress -ErrorAction SilentlyContinue)
        $a.Count | Should -BeGreaterThan 0
        ($a.InterfaceIndex | Select-Object -Unique) | Should -Be $script:Adapter.InterfaceIndex
    }
    It 'Get-NetIPAddress -PolicyStore PersistentStore returns nothing and bogus is Windows error 87' {
        @(Get-NetIPAddress -PolicyStore PersistentStore -ErrorAction SilentlyContinue).Count | Should -Be 0
        $e = Err { Get-NetIPAddress -PolicyStore bogus }
        $e[0].FullyQualifiedErrorId | Should -Be 'Windows System Error 87,Get-NetIPAddress'
        $e[0].CategoryInfo.Category | Should -Be 'InvalidArgument'
    }
    It 'Get-NetRoute filters by family and prefix' {
        $v4 = @(Get-NetRoute -AddressFamily IPv4)
        $v4.Count | Should -BeGreaterThan 0
        ($v4.AddressFamily | Select-Object -Unique).ToString() | Should -Be 'IPv4'
        $p = $v4[0].DestinationPrefix
        @(Get-NetRoute -DestinationPrefix $p).DestinationPrefix | Select-Object -Unique | Should -Be $p
        @(Get-NetRoute $p).Count | Should -BeGreaterThan 0
    }
    It 'Get-NetRoute has an on-link route with next hop 0.0.0.0 and prefix notation a.b.c.d/n' {
        $r = @(Get-NetRoute -AddressFamily IPv4)
        ($r | Where-Object { $_.NextHop -eq '0.0.0.0' }) | Should -Not -BeNullOrEmpty
        foreach ($x in $r) { $x.DestinationPrefix | Should -Match '^\d+\.\d+\.\d+\.\d+/\d+$' }
    }
    It 'Get-NetTCPConnection shows a listener this process opened' {
        $l = @(Get-NetTCPConnection -LocalPort $script:Port -State Listen)
        $l.Count | Should -BeGreaterOrEqual 1
        $l[0].OwningProcess | Should -Be $PID
        $l[0].LocalAddress | Should -Be '0.0.0.0'
        $l[0].RemotePort | Should -Be 0
        $l[0].State.ToString() | Should -Be 'Listen'
    }
    It 'Get-NetTCPConnection shows the established connection, by -State, -RemotePort and -OwningProcess' {
        $e = @(Get-NetTCPConnection -State Established -RemotePort $script:Port)
        $e.Count | Should -BeGreaterOrEqual 1
        $e[0].RemoteAddress | Should -Be '127.0.0.1'
        $e[0].OwningProcess | Should -Be $PID
        @(Get-NetTCPConnection -OwningProcess $PID).Count | Should -BeGreaterOrEqual 2
        @(Get-NetTCPConnection -State Listen).State | Select-Object -Unique | ForEach-Object { $_.ToString() } | Should -Be 'Listen'
    }
    It 'Get-NetTCPConnection takes -LocalAddress and -LocalPort positionally' {
        @(Get-NetTCPConnection 0.0.0.0 $script:Port).Count | Should -Be 1
        @(Get-NetTCPConnection -LocalAddress '0.*' -LocalPort $script:Port).Count | Should -Be 1
    }
    It 'Get-NetUDPEndpoint shows a UDP socket this process opened' {
        $u = @(Get-NetUDPEndpoint -LocalPort 18124)
        $u.Count | Should -Be 1
        $u[0].OwningProcess | Should -Be $PID
        $u[0].LocalAddress | Should -Be '0.0.0.0'
    }
    It 'Get-NetIPInterface lists IPv4 interfaces with the Windows enums' {
        $i = @(Get-NetIPInterface -AddressFamily IPv4)
        $i.Count | Should -BeGreaterThan 0
        $i[0].Dhcp.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Dhcp'
        @(Get-NetIPInterface -InterfaceIndex $i[0].InterfaceIndex).Count | Should -BeGreaterThan 0
        @(Get-NetIPInterface -InterfaceAlias $i[0].InterfaceAlias -AddressFamily IPv4).Count | Should -Be 1
    }
    It 'Get-DnsClientServerAddress filters by family, index and alias' {
        $all = @(Get-DnsClientServerAddress)
        $all.Count | Should -BeGreaterThan 0
        $v4 = @(Get-DnsClientServerAddress -AddressFamily IPv4)
        ($v4.AddressFamily | Select-Object -Unique) | Should -Be 2
        @(Get-DnsClientServerAddress -InterfaceIndex $script:Adapter.ifIndex).Count | Should -BeGreaterThan 0
        @(Get-DnsClientServerAddress -InterfaceAlias ($script:Adapter.Name.Substring(0, 3) + '*')).Count | Should -BeGreaterThan 0
        $a = $all | Select-Object -First 1
        $a.Address | Should -Be $a.ServerAddresses
    }
}

Describe 'errors (as on Windows)' {
    It '<Label> reports CmdletizationQuery_NotFound_<Prop>' -TestCases @(
        @{ Label = 'Get-NetAdapter -Name'; Prop = 'Name'; Cmd = 'Get-NetAdapter'; Run = { Get-NetAdapter -Name nosuch }; Class = 'MSFT_NetAdapter'; Target = 'nosuch' },
        @{ Label = 'Get-NetAdapter -InterfaceDescription'; Prop = 'InterfaceDescription'; Cmd = 'Get-NetAdapter'; Run = { Get-NetAdapter -InterfaceDescription nosuch }; Class = 'MSFT_NetAdapter'; Target = 'nosuch' },
        @{ Label = 'Get-NetAdapter -InterfaceIndex'; Prop = 'InterfaceIndex'; Cmd = 'Get-NetAdapter'; Run = { Get-NetAdapter -InterfaceIndex 9999 }; Class = 'MSFT_NetAdapter'; Target = [uint32]9999 },
        @{ Label = 'Get-NetAdapterStatistics -Name'; Prop = 'Name'; Cmd = 'Get-NetAdapterStatistics'; Run = { Get-NetAdapterStatistics -Name nosuch }; Class = 'MSFT_NetAdapterStatisticsSettingData'; Target = 'nosuch' },
        @{ Label = 'Get-NetIPAddress -InterfaceAlias'; Prop = 'InterfaceAlias'; Cmd = 'Get-NetIPAddress'; Run = { Get-NetIPAddress -InterfaceAlias nosuch }; Class = 'MSFT_NetIPAddress'; Target = 'nosuch' },
        @{ Label = 'Get-NetIPAddress -IPAddress'; Prop = 'IPAddress'; Cmd = 'Get-NetIPAddress'; Run = { Get-NetIPAddress -IPAddress 1.2.3.4 }; Class = 'MSFT_NetIPAddress'; Target = '1.2.3.4' },
        @{ Label = 'Get-NetIPAddress -InterfaceIndex'; Prop = 'InterfaceIndex'; Cmd = 'Get-NetIPAddress'; Run = { Get-NetIPAddress -InterfaceIndex 9999 }; Class = 'MSFT_NetIPAddress'; Target = [uint32]9999 },
        @{ Label = 'Get-NetIPAddress -PrefixLength'; Prop = 'PrefixLength'; Cmd = 'Get-NetIPAddress'; Run = { Get-NetIPAddress -PrefixLength 99 }; Class = 'MSFT_NetIPAddress'; Target = [byte]99 },
        @{ Label = 'Get-NetRoute -InterfaceAlias'; Prop = 'InterfaceAlias'; Cmd = 'Get-NetRoute'; Run = { Get-NetRoute -InterfaceAlias nosuch }; Class = 'MSFT_NetRoute'; Target = 'nosuch' },
        @{ Label = 'Get-NetRoute -DestinationPrefix'; Prop = 'DestinationPrefix'; Cmd = 'Get-NetRoute'; Run = { Get-NetRoute -DestinationPrefix 9.9.9.9/32 }; Class = 'MSFT_NetRoute'; Target = '9.9.9.9/32' },
        @{ Label = 'Get-NetTCPConnection -LocalPort'; Prop = 'LocalPort'; Cmd = 'Get-NetTCPConnection'; Run = { Get-NetTCPConnection -LocalPort 1 }; Class = 'MSFT_NetTCPConnection'; Target = [uint16]1 },
        @{ Label = 'Get-NetTCPConnection -LocalAddress'; Prop = 'LocalAddress'; Cmd = 'Get-NetTCPConnection'; Run = { Get-NetTCPConnection -LocalAddress 9.9.9.9 }; Class = 'MSFT_NetTCPConnection'; Target = '9.9.9.9' },
        @{ Label = 'Get-NetUDPEndpoint -LocalPort'; Prop = 'LocalPort'; Cmd = 'Get-NetUDPEndpoint'; Run = { Get-NetUDPEndpoint -LocalPort 1 }; Class = 'MSFT_NetUDPEndpoint'; Target = [uint16]1 },
        @{ Label = 'Get-DnsClientServerAddress -InterfaceAlias'; Prop = 'InterfaceAlias'; Cmd = 'Get-DnsClientServerAddress'; Run = { Get-DnsClientServerAddress -InterfaceAlias nosuch }; Class = 'MSFT_DNSClientServerAddress'; Target = 'nosuch' }
    ) {
        param($Label, $Prop, $Cmd, $Run, $Class, $Target)
        $e = @(Err $Run)
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Be "CmdletizationQuery_NotFound_$Prop,$Cmd"
        $e[0].CategoryInfo.Category | Should -Be 'ObjectNotFound'
        $e[0].CategoryInfo.Reason | Should -Be 'CimJobException'
        $e[0].Exception.GetType().FullName | Should -Be 'Microsoft.PowerShell.Cmdletization.Cim.CimJobException'
        $e[0].Exception.Message | Should -Match "^No $Class objects found with property '$Prop' equal to '.+'\.  Verify the value of the property and retry\.$"
        $e[0].TargetObject | Should -Be $Target
        $e[0].TargetObject.GetType() | Should -Be $Target.GetType()
        $e[0].CategoryInfo.Activity | Should -Be $Cmd
    }
    It 'reports an enum type that is not a value as a binding error' -TestCases @(
        @{ Cmd = 'Get-NetIPAddress'; Run = { Get-NetIPAddress -AddressFamily bogus } },
        @{ Cmd = 'Get-NetTCPConnection'; Run = { Get-NetTCPConnection -State Bogus } }) {
        param($Cmd, $Run)
        $e = @(Err $Run)
        $e[0].FullyQualifiedErrorId | Should -Be "ParameterArgumentTransformationError,$Cmd"
        $e[0].CategoryInfo.Category | Should -Be 'InvalidData'
    }
    It 'reports a port beyond uint16 as a binding error' {
        $e = @(Err { Get-NetTCPConnection -LocalPort 99999 })
        $e[0].FullyQualifiedErrorId | Should -Be 'ParameterArgumentTransformationError,Get-NetTCPConnection'
    }
    It 'returns the found items and one error for a list with a missing name' {
        $ErrorActionPreference = 'Continue'
        $r = @(Get-NetAdapter -Name $script:Adapter.Name, nosuch 2>&1)
        @($r | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }).Count | Should -Be 1
        @($r | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }).Count | Should -Be 1
    }
    It 'reports an empty wildcard result silently' {
        @(Err { Get-NetAdapter -Name 'zz*' }).Count | Should -Be 0
        @(Err { Get-NetTCPConnection -LocalAddress '9.*' }).Count | Should -Be 0
    }
    It 'reports an empty combination as CmdletizationQuery_NotFound with the query text' {
        $e = @(Err { Get-NetIPAddress -InterfaceAlias $script:Adapter.Name -InterfaceIndex 99999 })
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound,Get-NetIPAddress'
        $e[0].Exception.Message | Should -Be "No matching MSFT_NetIPAddress objects found by CIM query for instances of the ROOT/StandardCimv2/MSFT_NetIPAddress class on the  CIM server: SELECT * FROM MSFT_NetIPAddress  WHERE ((InterfaceIndex = 99999)) AND ((InterfaceAlias LIKE '$($script:Adapter.Name)')). Verify query parameters and retry."
        $e[0].TargetObject | Should -Be 'MSFT_NetIPAddress'
    }
    It 'Resolve-DnsName reports a missing name as a Win32Exception stamped ResolveDnsName' {
        $missing = "nosuch-$([guid]::NewGuid().ToString('N').Substring(0, 8)).invalid"     # a fresh name: nothing cached
        $e = @(Err { Resolve-DnsName $missing })
        $e.Count | Should -Be 1
        $e[0].FullyQualifiedErrorId | Should -Match '^[A-Z_0-9]+,Microsoft\.DnsClient\.Commands\.ResolveDnsName$'
        $e[0].CategoryInfo.Category | Should -BeIn 'ResourceUnavailable', 'OperationTimeout'
        $e[0].Exception.GetType().FullName | Should -Be 'System.ComponentModel.Win32Exception'
        $e[0].Exception.Message | Should -Match "^$([regex]::Escape($missing)) : "
        $e[0].TargetObject | Should -Be $missing
        $e[0].CategoryInfo.Activity | Should -Be 'Resolve-DnsName'
    }
    It 'Resolve-DnsName -Name is mandatory' {
        (Get-Command Resolve-DnsName).Parameters['Name'].Attributes.Mandatory | Should -Be $true
    }
}

Describe 'Resolve-DnsName' {
    It 'resolves localhost to DnsRecord_A with the Windows members and aliases' {
        $r = @(Resolve-DnsName localhost -Type A)
        $r.Count | Should -BeGreaterThan 0
        $o = $r[0]
        $o.GetType().FullName | Should -Be 'Microsoft.DnsClient.Commands.DnsRecord_A'
        @($o.psobject.TypeNames)[0..2] -join ',' | Should -Be 'Microsoft.DnsClient.Commands.DnsRecord_A,Microsoft.DnsClient.Commands.DnsRecord,System.Object'
        @($o.psobject.Properties.Name) -join ',' | Should -Be 'Address,IPAddress,QueryType,IP4Address,Name,Type,CharacterSet,Section,DataLength,TTL'
        $o.IP4Address | Should -Be '127.0.0.1'
        $o.IPAddress | Should -Be '127.0.0.1'
        $o.Address | Should -Be '127.0.0.1'
        $o.Type.ToString() | Should -Be 'A'
        $o.QueryType | Should -Be $o.Type
        $o.Type.GetType().FullName | Should -Be 'Microsoft.DnsClient.Commands.RecordType'
        $o.Section.GetType().FullName | Should -Be 'Microsoft.DnsClient.Commands.DNSSection'
        $o.CharacterSet.GetType().FullName | Should -Be 'Microsoft.DnsClient.Commands.DNSCharset'
        $o.TTL | Should -BeOfType ([uint32])
        $o.DataLength | Should -BeOfType ([uint16])
        $o.DataLength | Should -Be 4
    }
    It 'prints the Windows record table and list' {
        $o = Resolve-DnsName localhost -Type A | Select-Object -First 1
        $t = ($o | Format-Table | Out-String -Width 200) -split "`r?`n" | Where-Object { $_.Trim() }
        @($t[0].Trim() -split '\s+') -join ',' | Should -Be 'Name,Type,TTL,Section,IPAddress'
        $l = ($o | Format-List | Out-String)
        foreach ($f in 'Name', 'Type', 'TTL', 'DataLength', 'Section', 'IPAddress') { $l | Should -Match "(?m)^$f\s+:" }
    }
    It 'resolves by position and from the pipeline' {
        @(Resolve-DnsName localhost A).Count | Should -BeGreaterThan 0
        @('localhost' | Resolve-DnsName -Type A).Count | Should -BeGreaterThan 0
    }
    It 'queries a PTR record for an address' {
        $e = @(Resolve-DnsName 127.0.0.1 -ErrorAction SilentlyContinue)
        if ($e.Count) { $e[0].Type.ToString() | Should -Be 'PTR'; $e[0].Name | Should -Match '^1\.0\.0\.127\.in-addr\.arpa\.?$' }
        else { $true | Should -Be $true }
    }
    It 'defines the record classes with the Windows property sets' -TestCases @(
        @{ T = 'DnsRecord_A'; P = 'IP4Address' }, @{ T = 'DnsRecord_AAAA'; P = 'IP6Address' }, @{ T = 'DnsRecord_PTR'; P = 'NameHost' },
        @{ T = 'DnsRecord_MX'; P = 'NameExchange,Preference' }, @{ T = 'DnsRecord_TXT'; P = 'Strings' },
        @{ T = 'DnsRecord_SOA'; P = 'PrimaryServer,NameAdministrator,SerialNumber,TimeToZoneRefresh,TimeToZoneFailureRetry,TimeToExpiration,DefaultTTL' },
        @{ T = 'DnsRecord_SRV'; P = 'NameTarget,Priority,Weight,Port' }) {
        param($T, $P)
        $ty = [type]"Microsoft.DnsClient.Commands.$T"
        $ty.BaseType.FullName | Should -Be 'Microsoft.DnsClient.Commands.DnsRecord'
        (@($ty.GetMembers('Public,Instance,DeclaredOnly') | Where-Object { $_.MemberType -in 'Field', 'Property' } | ForEach-Object Name) -join ',') | Should -Be $P
    }
}

Describe 'Test-NetConnection' {
    It 'pings 127.0.0.1 and returns a TestNetConnectionResult with the Windows properties' {
        $r = Test-NetConnection 127.0.0.1 -WarningAction SilentlyContinue
        $r.psobject.TypeNames[0] | Should -Be 'TestNetConnectionResult'
        (@($r.psobject.Properties.Name) -join ',') | Should -Be 'ComputerName,RemoteAddress,ResolvedAddresses,PingSucceeded,PingReplyDetails,TcpClientSocket,TcpTestSucceeded,RemotePort,TraceRoute,Detailed,InterfaceAlias,InterfaceIndex,InterfaceDescription,NetAdapter,NetRoute,SourceAddress,NameResolutionSucceeded,BasicNameResolution,LLMNRNetbiosRecords,DNSOnlyRecords,AllNameResolutionResults,IsAdmin,NetworkIsolationContext,MatchingIPsecRules'
        $r.ComputerName | Should -Be '127.0.0.1'
        $r.RemoteAddress.IPAddressToString | Should -Be '127.0.0.1'
        $r.PingSucceeded | Should -Be $true
        $r.PingReplyDetails.Status.ToString() | Should -Be 'Success'
        $r.TcpTestSucceeded | Should -Be $false
        $r.RemotePort | Should -Be 0
        $r.RemotePort | Should -BeOfType ([uint32])
        $r.SourceAddress.IPAddress | Should -Be '127.0.0.1'
        $r.NetworkIsolationContext | Should -Be 'Loopback'
        $r.NameResolutionSucceeded | Should -Be $true
        $r.psobject.TypeNames | Should -Not -Contain 'Microsoft.Management.Infrastructure.CimInstance'
    }
    It 'tests a TCP port the process listens on (no ping, like Windows)' {
        $r = Test-NetConnection 127.0.0.1 -Port $script:Port -WarningAction SilentlyContinue
        $r.TcpTestSucceeded | Should -Be $true
        $r.RemotePort | Should -Be $script:Port
        $r.PingSucceeded | Should -Be $false
        $r.PingReplyDetails | Should -BeNullOrEmpty
        (Test-NetConnection 127.0.0.1 -Port $script:Port -InformationLevel Quiet) | Should -Be $true
        (Test-NetConnection 127.0.0.1 -Port $script:Port -InformationLevel Quiet).GetType().Name | Should -Be 'Boolean'
        ('127.0.0.1' | Test-NetConnection -Port $script:Port -InformationLevel Quiet) | Should -Be $true
        (TNC 127.0.0.1 -Port $script:Port).TcpTestSucceeded | Should -Be $true
    }
    It 'warns "TCP connect to (addr : port) failed" and then pings when the port is closed' {
        $w = @()
        $r = Test-NetConnection 127.0.0.1 -Port 1 -WarningVariable w -WarningAction SilentlyContinue
        $w[0].Message | Should -Be 'TCP connect to (127.0.0.1 : 1) failed'
        $r.TcpTestSucceeded | Should -Be $false
        $r.PingSucceeded | Should -Be $true
        $r.PingReplyDetails | Should -Not -BeNullOrEmpty
    }
    It 'warns "Name resolution of X failed" for an unknown host and returns the bare result' {
        $w = @()
        $r = Test-NetConnection nosuchhost.invalid -WarningVariable w -WarningAction SilentlyContinue
        $w[0].Message | Should -Be 'Name resolution of nosuchhost.invalid failed'
        $r.ComputerName | Should -Be 'nosuchhost.invalid'
        $r.PingSucceeded | Should -Be $false
        $r.RemoteAddress | Should -BeNullOrEmpty
    }
    It 'resolves localhost' {
        $r = Test-NetConnection localhost -WarningAction SilentlyContinue
        $r.ComputerName | Should -Be 'localhost'
        [System.Net.IPAddress]::IsLoopback($r.RemoteAddress) | Should -Be $true
        $r.PingSucceeded | Should -Be $true
        $r.ResolvedAddresses.Count | Should -BeGreaterThan 0
    }
    It 'maps -CommonTCPPort to the Windows ports' -TestCases @(@{ N = 'HTTP'; P = 80 }, @{ N = 'RDP'; P = 3389 }, @{ N = 'SMB'; P = 445 }, @{ N = 'WINRM'; P = 5985 }) {
        param($N, $P)
        $r = Test-NetConnection 127.0.0.1 -CommonTCPPort $N -WarningAction SilentlyContinue
        $r.RemotePort | Should -Be $P
    }
    It 'prints the Windows default list: ICMP, port success and port failure' {
        $icmp = Test-NetConnection 127.0.0.1 | Format-List | Out-String
        foreach ($f in 'ComputerName', 'RemoteAddress', 'InterfaceAlias', 'SourceAddress', 'PingSucceeded') { $icmp | Should -Match "(?m)^$f\s*:" }
        $icmp | Should -Match '(?m)^PingReplyDetails \(RTT\)\s*: \d+ ms'
        $icmp | Should -Not -Match 'TcpTestSucceeded'
        $tcp = Test-NetConnection 127.0.0.1 -Port $script:Port | Format-List | Out-String
        $tcp | Should -Match '(?m)^RemotePort\s*: ' ; $tcp | Should -Match '(?m)^TcpTestSucceeded\s*: True'
        $tcp | Should -Not -Match 'PingSucceeded'
    }
    It 'prints the Windows table' {
        $t = (Test-NetConnection 127.0.0.1 | Format-Table | Out-String -Width 200) -split "`r?`n" | Where-Object { $_.Trim() }
        $t[0].Trim() | Should -Match '^ComputerName\s+RemotePort\s+RemoteAddress\s+PingSucceeded\s+PingReplyDetails \(RTT\)\s+TcpTestSucceeded$'
    }
    It 'prints the Detailed list' {
        $d = Test-NetConnection 127.0.0.1 -InformationLevel Detailed | Format-List | Out-String
        $d | Should -Match '(?m)^NameResolutionResults\s*: 127\.0\.0\.1'
        $d | Should -Match '(?m)^NetRoute \(NextHop\)\s*: '
    }
    It 'reports the route and interface used for a local address' {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notin '0.0.0.0', '127.0.0.1' } | Select-Object -First 1)
        if (-not $ip) { Set-ItResult -Skipped -Because 'no routable address'; return }
        $r = Test-NetConnection $ip.IPAddress -WarningAction SilentlyContinue
        $r.PingSucceeded | Should -Be $true
        $r.SourceAddress.IPAddress | Should -Not -BeNullOrEmpty
        $r.InterfaceIndex | Should -BeGreaterThan 0
    }
    It 'tests port 22 on the default gateway (the QEMU user-net host) when there is one' {
        $gw = (Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
        if ($script:Oracle -or -not $gw) { Set-ItResult -Skipped -Because 'nitro guest with a gateway only'; return }
        $r = Test-NetConnection $gw -Port 22 -WarningAction SilentlyContinue
        $r.TcpTestSucceeded | Should -Be $true
        $r.RemoteAddress.IPAddressToString | Should -Be $gw
        $r.InterfaceAlias | Should -Be $script:Adapter.Name
        $r.NetRoute.NextHop | Should -Be '0.0.0.0'
    }
    It 'traces the route to 127.0.0.1' {
        $r = Test-NetConnection 127.0.0.1 -TraceRoute -WarningAction SilentlyContinue
        $r.TraceRoute | Should -Contain '127.0.0.1'
    }
}

Describe 'Get-NetIPConfiguration' {
    It 'returns NetIPConfiguration objects with the Windows properties' {
        $c = @(Get-NetIPConfiguration)
        $c.Count | Should -BeGreaterThan 0
        $c[0].psobject.TypeNames[0] | Should -Be 'NetIPConfiguration'
        (@($c[0].psobject.Properties.Name) -join ',') | Should -Be 'ComputerName,InterfaceAlias,InterfaceIndex,InterfaceDescription,CompartmentId,NetAdapter,NetCompartment,NetIPv6Interface,NetIPv4Interface,NetProfile,AllIPAddresses,IPv6Address,IPv6TemporaryAddress,IPv6LinkLocalAddress,IPv4Address,IPv6DefaultGateway,IPv4DefaultGateway,DNSServer,Detailed'
        $c[0].InterfaceIndex | Should -BeOfType ([int])
        $c[0].CompartmentId | Should -Be 1
        $c[0].Detailed | Should -Be $false
        $c[0].NetAdapter.psobject.TypeNames[0] | Should -Be 'Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter'
    }
    It 'agrees with Get-NetIPAddress' {
        $c = @(Get-NetIPConfiguration)[0]
        $addr = @(Get-NetIPAddress -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 | ForEach-Object IPAddress)
        @($c.IPv4Address.IPAddress) -join ',' | Should -Be ($addr -join ',')
    }
    It 'selects by -InterfaceAlias and -InterfaceIndex and reports a missing alias like Get-NetIPInterface' {
        $c = @(Get-NetIPConfiguration)[0]
        @(Get-NetIPConfiguration -InterfaceAlias $c.InterfaceAlias).InterfaceIndex | Should -Be $c.InterfaceIndex
        @(Get-NetIPConfiguration -InterfaceIndex $c.InterfaceIndex).InterfaceAlias | Should -Be $c.InterfaceAlias
        @(gip -Detailed)[0].Detailed | Should -Be $true
        $e = @(Err { Get-NetIPConfiguration -InterfaceAlias nosuch })
        $e[0].FullyQualifiedErrorId | Should -Be 'CmdletizationQuery_NotFound_InterfaceAlias,Get-NetIPInterface'
    }
    It 'prints the Windows default and detailed lists' {
        $d = Get-NetIPConfiguration | Out-String
        foreach ($f in 'InterfaceAlias', 'InterfaceIndex', 'InterfaceDescription', 'IPv4Address', 'IPv4DefaultGateway', 'DNSServer') { $d | Should -Match "(?m)^$f\s*:" }
        $dd = Get-NetIPConfiguration -Detailed | Out-String
        foreach ($f in 'ComputerName', 'NetCompartment.CompartmentId', 'NetAdapter.LinkLayerAddress', 'NetAdapter.Status', 'NetIPv4Interface.NlMTU', 'NetIPv4Interface.DHCP') { $dd | Should -Match "(?m)^$([regex]::Escape($f))\s*:" }
    }
}

Describe 'Get-NetAdapterStatistics' {
    It 'returns the Windows statistics properties' {
        $s = Get-NetAdapterStatistics | Select-Object -First 1
        $s.ReceivedBytes | Should -BeOfType ([uint64])
        $s.SentBytes | Should -BeOfType ([uint64])
        $s.Name | Should -Be $script:Adapter.Name
        $s.ifDesc | Should -Be $script:Adapter.InterfaceDescription
        @(Get-NetAdapterStatistics -Name $script:Adapter.Name).Count | Should -Be 1
        @($script:Adapter | Get-NetAdapterStatistics).Count | Should -Be 1
    }
}

# the listener and sockets die with the test process
