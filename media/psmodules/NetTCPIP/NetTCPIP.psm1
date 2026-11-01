# NetTCPIP for ReactOS-Nitro: a clean-room PowerShell 7 script module (read side and the write cmdlets New-/Remove-NetIPAddress, Set-NetIPInterface -Dhcp). Same module, cmdlet and parameter names
# and the same object shapes as the Windows module (see NetAdapter.psm1). The data comes from iphlpapi through
# Nitro.Net.Native (NitroNetNative.cs); the IPv4 forwarding table is the only route source this system offers.

Set-StrictMode -Version 2.0

# Test-NetConnection and Get-NetIPConfiguration use the adapter and DNS cmdlets; they are imported for this module's own use.
Import-Module -Name NetAdapter, DnsClient -ErrorAction SilentlyContinue

$script:EnumNs = 'Microsoft.PowerShell.Cmdletization.GeneratedTypes'

# A CIM-typed pipeline parameter takes only objects of its class: other objects (an adapter piped to Get-NetIPAddress)
# bind through their InterfaceIndex / InterfaceAlias properties instead.
function Test-NetCimType {
    param($Object, [string]$Class)
    ($null -ne $Object) -and (@($Object.psobject.TypeNames) -contains "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/$Class")
}

# Runs one CDXML-style query: the filter parameters the caller bound (in declaration order) against the native rows.
function Invoke-NetQuery {
    param(
        [System.Management.Automation.PSCmdlet]$Cmdlet,
        [string]$Class,
        [object]$Rows,
        [System.Collections.IDictionary]$Bound,
        [string[]]$Filters,
        [hashtable]$PropertyOf = @{},
        [System.Collections.IDictionary]$Extra = $null
    )
    if ($Bound.ContainsKey('PolicyStore') -and $Bound['PolicyStore'] -ne 'ActiveStore') {
        if ($Bound['PolicyStore'] -eq 'PersistentStore') { return }
        $Cmdlet.WriteError([Nitro.Net.Errors]::InvalidStore([string]$Bound['PolicyStore']))
        return
    }
    $q = [Nitro.Net.Query]::new()
    foreach ($f in $Filters) {
        if ($Bound.ContainsKey($f)) {
            $prop = if ($PropertyOf.ContainsKey($f)) { $PropertyOf[$f] } else { $f }
            $q.Add($prop, $Bound[$f])
        }
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $q.Add($k, $Extra[$k]) } }
    $errors = [System.Collections.Generic.List[System.Management.Automation.ErrorRecord]]::new()
    $found = $q.Run($Rows, $Class, $errors)
    foreach ($d in $found) { [Nitro.Net.CimBuilder]::Create($Class, $d) }
    foreach ($e in $errors) { $Cmdlet.WriteError($e) }
}

function Get-NetIPAddress {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPAddress')]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)][Alias('LocalAddress')][string[]]$IPAddress,
        [Parameter(ValueFromPipelineByPropertyName = $true)][Alias('ifIndex')][uint32[]]$InterfaceIndex,
        [Parameter(ValueFromPipelineByPropertyName = $true)][Alias('ifAlias')][string[]]$InterfaceAlias,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressFamily[]]$AddressFamily,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.Type[]]$Type,
        [byte[]]$PrefixLength,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.PrefixOrigin[]]$PrefixOrigin,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.SuffixOrigin[]]$SuffixOrigin,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressState[]]$AddressState,
        [timespan[]]$ValidLifetime,
        [timespan[]]$PreferredLifetime,
        [bool[]]$SkipAsSource,
        [Parameter(ValueFromPipeline = $true)][object]$AssociatedIPInterface,
        [string]$PolicyStore,
        [switch]$IncludeAllCompartments,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        $extra = $null
        if ($PSBoundParameters.ContainsKey('AssociatedIPInterface') -and (Test-NetCimType $AssociatedIPInterface 'MSFT_NetIPInterface')) {
            $extra = [ordered]@{ InterfaceIndex = [uint32]$AssociatedIPInterface.InterfaceIndex; AddressFamily = [uint16]$AssociatedIPInterface.AddressFamily }
        }
        Invoke-NetQuery $PSCmdlet 'MSFT_NetIPAddress' ([Nitro.Net.Native]::IPAddresses()) $PSBoundParameters `
            @('IPAddress', 'InterfaceIndex', 'InterfaceAlias', 'AddressFamily', 'Type', 'PrefixLength', 'PrefixOrigin', 'SuffixOrigin',
              'AddressState', 'ValidLifetime', 'PreferredLifetime', 'SkipAsSource') -Extra $extra
    }
}

function Get-NetIPInterface {
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPInterface')]
    param(
        [Parameter(ParameterSetName = 'ByName', ValueFromPipelineByPropertyName = $true)][Alias('ifIndex')][uint32[]]$InterfaceIndex,
        [Parameter(ParameterSetName = 'ByName', Position = 0, ValueFromPipelineByPropertyName = $true)][Alias('ifAlias')][string[]]$InterfaceAlias,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AddressFamily[]]$AddressFamily,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Forwarding[]]$Forwarding,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ClampMss[]]$ClampMss,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Advertising[]]$Advertising,
        [Parameter(ParameterSetName = 'ByName')][uint32[]]$NlMtuBytes,
        [Parameter(ParameterSetName = 'ByName')][uint32[]]$InterfaceMetric,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.NeighborUnreachabilityDetection[]]$NeighborUnreachabilityDetection,
        [Parameter(ParameterSetName = 'ByName')][Alias('BaseReachableTime')][uint32[]]$BaseReachableTimeMs,
        [Parameter(ParameterSetName = 'ByName')][Alias('ReachableTime')][uint32[]]$ReachableTimeMs,
        [Parameter(ParameterSetName = 'ByName')][Alias('RetransmitTime')][uint32[]]$RetransmitTimeMs,
        [Parameter(ParameterSetName = 'ByName')][uint32[]]$DadTransmits,
        [Parameter(ParameterSetName = 'ByName')][Alias('DadRetransmitTime')][uint32[]]$DadRetransmitTimeMs,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.RouterDiscovery[]]$RouterDiscovery,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ManagedAddressConfiguration[]]$ManagedAddressConfiguration,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.OtherStatefulConfiguration[]]$OtherStatefulConfiguration,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.WeakHostSend[]]$WeakHostSend,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.WeakHostReceive[]]$WeakHostReceive,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.IgnoreDefaultRoutes[]]$IgnoreDefaultRoutes,
        [Parameter(ParameterSetName = 'ByName')][timespan[]]$AdvertisedRouterLifetime,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AdvertiseDefaultRoute[]]$AdvertiseDefaultRoute,
        [Parameter(ParameterSetName = 'ByName')][uint32[]]$CurrentHopLimit,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ForceArpNdWolPattern[]]$ForceArpNdWolPattern,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.DirectedMacWolPattern[]]$DirectedMacWolPattern,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.EcnMarking[]]$EcnMarking,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Dhcp[]]$Dhcp,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ConnectionState[]]$ConnectionState,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AutomaticMetric[]]$AutomaticMetric,
        [Parameter(ParameterSetName = 'ByName')][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.NeighborDiscoverySupported[]]$NeighborDiscoverySupported,
        [Parameter(ParameterSetName = 'ByName')][uint32[]]$CompartmentId,
        [Parameter(ParameterSetName = 'ByName')][string]$PolicyStore,
        [Parameter(ParameterSetName = 'ByRoute', ValueFromPipeline = $true)][object]$AssociatedRoute,
        [Parameter(ParameterSetName = 'ByIPAddress', ValueFromPipeline = $true)][object]$AssociatedIPAddress,
        [Parameter(ParameterSetName = 'ByAdapter', ValueFromPipeline = $true)][object]$AssociatedAdapter,
        [switch]$IncludeAllCompartments,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        $extra = $null
        $assoc = if ($PSBoundParameters.ContainsKey('AssociatedRoute') -and (Test-NetCimType $AssociatedRoute 'MSFT_NetRoute')) { $AssociatedRoute }
            elseif ($PSBoundParameters.ContainsKey('AssociatedIPAddress') -and (Test-NetCimType $AssociatedIPAddress 'MSFT_NetIPAddress')) { $AssociatedIPAddress } else { $null }
        if ($assoc) { $extra = [ordered]@{ InterfaceIndex = [uint32]$assoc.InterfaceIndex; AddressFamily = [uint16]$assoc.AddressFamily } }
        elseif ($PSBoundParameters.ContainsKey('AssociatedAdapter') -and (Test-NetCimType $AssociatedAdapter 'MSFT_NetAdapter')) { $extra = [ordered]@{ InterfaceIndex = [uint32]$AssociatedAdapter.InterfaceIndex } }
        Invoke-NetQuery $PSCmdlet 'MSFT_NetIPInterface' ([Nitro.Net.Native]::IPInterfaces()) $PSBoundParameters `
            @('InterfaceIndex', 'InterfaceAlias', 'AddressFamily', 'Forwarding', 'ClampMss', 'Advertising', 'NlMtuBytes', 'InterfaceMetric',
              'NeighborUnreachabilityDetection', 'BaseReachableTimeMs', 'ReachableTimeMs', 'RetransmitTimeMs', 'DadTransmits',
              'DadRetransmitTimeMs', 'RouterDiscovery', 'ManagedAddressConfiguration', 'OtherStatefulConfiguration', 'WeakHostSend',
              'WeakHostReceive', 'IgnoreDefaultRoutes', 'AdvertisedRouterLifetime', 'AdvertiseDefaultRoute', 'CurrentHopLimit',
              'ForceArpNdWolPattern', 'DirectedMacWolPattern', 'EcnMarking', 'Dhcp', 'ConnectionState', 'AutomaticMetric',
              'NeighborDiscoverySupported', 'CompartmentId') `
            @{ NlMtuBytes = 'NlMtu'; BaseReachableTimeMs = 'BaseReachableTime'; ReachableTimeMs = 'ReachableTime'; RetransmitTimeMs = 'RetransmitTime'; DadRetransmitTimeMs = 'DadRetransmitTime' } -Extra $extra
    }
}

function Get-NetRoute {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetRoute')]
    param(
        [Parameter(Position = 0)][string[]]$DestinationPrefix,
        [Parameter(ValueFromPipelineByPropertyName = $true)][Alias('ifIndex')][uint32[]]$InterfaceIndex,
        [Parameter(ValueFromPipelineByPropertyName = $true)][Alias('ifAlias')][string[]]$InterfaceAlias,
        [string[]]$NextHop,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.AddressFamily[]]$AddressFamily,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.Publish[]]$Publish,
        [uint16[]]$RouteMetric,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.Protocol[]]$Protocol,
        [uint32[]]$CompartmentId,
        [timespan[]]$ValidLifetime,
        [timespan[]]$PreferredLifetime,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.State[]]$State,
        [uint32[]]$InterfaceMetric,
        [Parameter(ValueFromPipeline = $true)][object]$AssociatedIPInterface,
        [string]$PolicyStore,
        [switch]$IncludeAllCompartments,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        $extra = $null
        if ($PSBoundParameters.ContainsKey('AssociatedIPInterface') -and (Test-NetCimType $AssociatedIPInterface 'MSFT_NetIPInterface')) {
            $extra = [ordered]@{ InterfaceIndex = [uint32]$AssociatedIPInterface.InterfaceIndex; AddressFamily = [uint16]$AssociatedIPInterface.AddressFamily }
        }
        Invoke-NetQuery $PSCmdlet 'MSFT_NetRoute' ([Nitro.Net.Native]::Routes()) $PSBoundParameters `
            @('DestinationPrefix', 'InterfaceIndex', 'InterfaceAlias', 'NextHop', 'AddressFamily', 'Publish', 'RouteMetric', 'Protocol',
              'CompartmentId', 'ValidLifetime', 'PreferredLifetime', 'State', 'InterfaceMetric') -Extra $extra
    }
}

function Get-NetTCPConnection {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetTCPConnection')]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)][Alias('IPAddress')][string[]]$LocalAddress,
        [Parameter(Position = 1)][uint16[]]$LocalPort,
        [string[]]$RemoteAddress,
        [uint16[]]$RemotePort,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.State[]]$State,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.AppliedSetting[]]$AppliedSetting,
        [uint32[]]$OwningProcess,
        [datetime[]]$CreationTime,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.OffloadState[]]$OffloadState,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        Invoke-NetQuery $PSCmdlet 'MSFT_NetTCPConnection' ([Nitro.Net.Native]::TcpConnections()) $PSBoundParameters `
            @('LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'State', 'AppliedSetting', 'OwningProcess', 'CreationTime', 'OffloadState')
    }
}

function Get-NetUDPEndpoint {
    [CmdletBinding()]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetUDPEndpoint')]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)][Alias('IPAddress')][string[]]$LocalAddress,
        [Parameter(Position = 1)][uint16[]]$LocalPort,
        [uint32[]]$OwningProcess,
        [datetime[]]$CreationTime,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        Invoke-NetQuery $PSCmdlet 'MSFT_NetUDPEndpoint' ([Nitro.Net.Native]::UdpEndpoints()) $PSBoundParameters `
            @('LocalAddress', 'LocalPort', 'OwningProcess', 'CreationTime')
    }
}

# ------------------------------------------------------------------------------------------ Get-NetIPConfiguration
function Get-NetIPConfiguration {
    [CmdletBinding(DefaultParameterSetName = 'Alias', HelpUri = 'http://go.microsoft.com/fwlink/?LinkId=253567')]
    [Alias('gip')]
    param(
        [Parameter(ParameterSetName = 'Alias', Position = 0, ValueFromPipelineByPropertyName = $true)][Alias('ifAlias')][string]$InterfaceAlias,
        [Parameter(ParameterSetName = 'Index', Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ifIndex')][int]$InterfaceIndex,
        [Parameter(ParameterSetName = 'All', Mandatory = $true)][Alias('IncludeAllInterfaces')][switch]$All,
        [Alias('IncludeAllCompartments')][switch]$AllCompartments,
        [Parameter(ValueFromPipelineByPropertyName = $true)][int]$CompartmentId,
        [switch]$Detailed,
        [Parameter(ValueFromPipelineByPropertyName = $true)][Alias('PSComputerName', 'ComputerName')][object]$CimSession
    )
    process {
        $ifaces = switch ($PSCmdlet.ParameterSetName) {
            'Alias' { if ($PSBoundParameters.ContainsKey('InterfaceAlias')) { Get-NetIPInterface -InterfaceAlias $InterfaceAlias } else { Get-NetIPInterface } }
            'Index' { Get-NetIPInterface -InterfaceIndex $InterfaceIndex }
            default { Get-NetIPInterface }
        }
        $named = $PSCmdlet.ParameterSetName -eq 'Index' -or $PSBoundParameters.ContainsKey('InterfaceAlias')
        $indexes = @($ifaces | ForEach-Object { $_.InterfaceIndex } | Select-Object -Unique)
        $allAddr = @(Get-NetIPAddress -ErrorAction SilentlyContinue)
        $routes = @(Get-NetRoute -ErrorAction SilentlyContinue)
        $dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue)
        foreach ($idx in $indexes) {
            $adapter = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
            if (-not $adapter) { continue }
            if (-not $All -and -not $named -and $adapter.Status -ne 'Up') { continue }
            $mine = @($ifaces | Where-Object { $_.InterfaceIndex -eq $idx })
            $v6if = $mine | Where-Object { $_.AddressFamily -eq 'IPv6' } | Select-Object -First 1
            $v4if = $mine | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
            $addrs = @($allAddr | Where-Object { $_.InterfaceIndex -eq $idx })
            $v4 = @($addrs | Where-Object { $_.AddressFamily -eq 'IPv4' })
            $v6 = @($addrs | Where-Object { $_.AddressFamily -eq 'IPv6' })
            $gw4 = @($routes | Where-Object { $_.InterfaceIndex -eq $idx -and $_.DestinationPrefix -eq '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0' })
            $gw6 = @($routes | Where-Object { $_.InterfaceIndex -eq $idx -and $_.DestinationPrefix -eq '::/0' -and $_.NextHop -ne '::' })
            $cfg = [NetIPConfiguration]::new()
            $cfg.ComputerName = [Nitro.Net.Native]::MachineName
            $cfg.InterfaceAlias = $adapter.InterfaceAlias
            $cfg.InterfaceIndex = [int]$idx
            $cfg.InterfaceDescription = $adapter.InterfaceDescription
            $cfg.CompartmentId = 1
            $cfg.NetAdapter = $adapter
            $comp = [pscustomobject][ordered]@{ CompartmentId = [uint32]1; CompartmentDescription = 'Default Compartment' }
            $comp.psobject.TypeNames.Clear()
            foreach ($t in 'Microsoft.Management.Infrastructure.CimInstance#root/StandardCimv2/MSFT_NetCompartment', 'Microsoft.Management.Infrastructure.CimInstance', 'System.Object') { $comp.psobject.TypeNames.Add($t) }
            $cfg.NetCompartment = $comp
            $cfg.NetIPv6Interface = $v6if
            $cfg.NetIPv4Interface = $v4if
            $cfg.NetProfile = $null     # no network location awareness on this system
            $cfg.AllIPAddresses = [object[]](@($v4) + @($v6))
            $cfg.IPv6Address = [object[]]@($v6 | Where-Object { $_.IPAddress -notlike 'fe80:*' -and $_.SuffixOrigin -ne 'Random' })
            $cfg.IPv6TemporaryAddress = [object[]]@($v6 | Where-Object { $_.SuffixOrigin -eq 'Random' })
            $cfg.IPv6LinkLocalAddress = [object[]]@($v6 | Where-Object { $_.IPAddress -like 'fe80:*' })
            $cfg.IPv4Address = [object[]]@($v4)
            $cfg.IPv6DefaultGateway = if ($gw6.Count) { [object[]]$gw6 } else { $null }
            $cfg.IPv4DefaultGateway = if ($gw4.Count) { [object[]]$gw4 } else { $null }
            $cfg.DNSServer = [object[]]@($dns | Where-Object { $_.InterfaceIndex -eq $idx })
            $cfg.Detailed = [bool]$Detailed
            $cfg
        }
    }
}

# ------------------------------------------------------------------------------------------ Test-NetConnection
function Test-NetConnection {
    [CmdletBinding(DefaultParameterSetName = 'ICMP')]
    [Alias('TNC')]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('RemoteAddress', 'cn')][string]$ComputerName = 'internetbeacon.msedge.net',

        [Parameter(ParameterSetName = 'CommonTCPPort', Mandatory = $true, Position = 1)]
        [ValidateSet('HTTP', 'RDP', 'SMB', 'WINRM')][string]$CommonTCPPort,

        [Parameter(ParameterSetName = 'RemotePort', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('RemotePort')][ValidateRange(1, 65535)][int]$Port,

        [Parameter(ParameterSetName = 'NetRouteDiagnostics', Mandatory = $true)][switch]$DiagnoseRouting,
        [Parameter(ParameterSetName = 'NetRouteDiagnostics')][string]$ConstrainSourceAddress,
        [Parameter(ParameterSetName = 'NetRouteDiagnostics')][uint32]$ConstrainInterface,
        [Parameter(ParameterSetName = 'ICMP')][switch]$TraceRoute,
        [Parameter(ParameterSetName = 'ICMP')][int]$Hops = 30,
        [ValidateSet('Quiet', 'Detailed')][string]$InformationLevel
    )
    process {
        if ($PSCmdlet.ParameterSetName -eq 'NetRouteDiagnostics') {
            $PSCmdlet.WriteError([System.Management.Automation.ErrorRecord]::new([System.NotSupportedException]::new('-DiagnoseRouting is not supported on this system.'), 'NotSupported', 'NotImplemented', $ComputerName))
            return
        }
        $tcpPort = 0
        if ($PSCmdlet.ParameterSetName -eq 'CommonTCPPort') { $tcpPort = @{ HTTP = 80; RDP = 3389; SMB = 445; WINRM = 5985 }[$CommonTCPPort] }
        elseif ($PSCmdlet.ParameterSetName -eq 'RemotePort') { $tcpPort = $Port }
        $detailed = $InformationLevel -eq 'Detailed'

        $r = [TestNetConnectionResult]::new()
        $r.ComputerName = $ComputerName
        $r.Detailed = $detailed
        $r.NameResolutionSucceeded = $true
        $r.IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $r.LLMNRNetbiosRecords = [object[]]@()

        # name resolution
        $ip = $null
        $addresses = @()
        if ([System.Net.IPAddress]::TryParse($ComputerName, [ref]$ip)) { $addresses = @($ip); $r.BasicNameResolution = [object[]]@(); $r.DNSOnlyRecords = [object[]]@() }
        else {
            $recs = @(Resolve-DnsName -Name $ComputerName -ErrorAction SilentlyContinue | Where-Object { $_.Type -in 'A', 'AAAA' })
            if ($recs.Count -eq 0) { try { $recs = @() ; $addresses = @([System.Net.Dns]::GetHostAddresses($ComputerName)) } catch { $addresses = @() } }
            else { $addresses = @($recs | ForEach-Object { [System.Net.IPAddress]::Parse($_.IPAddress) }) }
            $r.BasicNameResolution = [object[]]$recs
            $r.DNSOnlyRecords = [object[]]$recs
            $r.AllNameResolutionResults = if ($recs.Count -eq 1) { $recs[0] } else { [object[]]$recs }
        }
        if ($addresses.Count -eq 0) {
            $r.NameResolutionSucceeded = $false
            Write-Warning "Name resolution of $ComputerName failed"
            if ($InformationLevel -eq 'Quiet') { return $false }
            return $r
        }
        $r.ResolvedAddresses = [System.Net.IPAddress[]]$addresses
        $r.RemoteAddress = $addresses[0]

        # routing: the source address and interface Windows would pick
        $dest = $r.RemoteAddress
        $srcText = $null
        try {
            $s = [System.Net.Sockets.Socket]::new($dest.AddressFamily, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
            try { $s.Connect($dest, 9); $srcText = $s.LocalEndPoint.Address.ToString() } finally { $s.Dispose() }
        } catch { }
        $src = $null
        if ($srcText) { $src = Get-NetIPAddress -IPAddress $srcText -ErrorAction SilentlyContinue | Select-Object -First 1 }
        if ($src) {
            $r.SourceAddress = $src
            $r.InterfaceAlias = $src.InterfaceAlias
            $r.InterfaceIndex = [uint32]$src.InterfaceIndex
            $ad = Get-NetAdapter -InterfaceIndex $src.InterfaceIndex -ErrorAction SilentlyContinue
            $r.InterfaceDescription = if ($ad) { $ad.InterfaceDescription } else { '' }
            if ($ad) { $r.NetAdapter = $ad }
            $rt = [Nitro.Net.Native]::FindRoute($dest, [uint32]$src.InterfaceIndex)
            if ($rt) { $r.NetRoute = [Nitro.Net.CimBuilder]::Create('MSFT_NetRoute', $rt) }
        }
        $r.NetworkIsolationContext = if ([System.Net.IPAddress]::IsLoopback($dest)) { 'Loopback' }
            elseif ($dest.AddressFamily -eq 'InterNetwork' -and (($b = $dest.GetAddressBytes())[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))) { 'Private Network' }
            else { 'Internet' }

        $doPing = $true
        if ($tcpPort -gt 0) {
            $doPing = $false
            $r.RemotePort = [uint32]$tcpPort
            $ok = $false
            $client = [System.Net.Sockets.TcpClient]::new($dest.AddressFamily)
            try {
                $iar = $client.BeginConnect($dest, $tcpPort, $null, $null)
                if ($iar.AsyncWaitHandle.WaitOne(10000) -and $client.Connected) { $client.EndConnect($iar); $ok = $true }
            } catch { $ok = $false }
            finally { $client.Close() }
            $r.TcpTestSucceeded = $ok
            if (-not $ok) { Write-Warning "TCP connect to ($($dest) : $tcpPort) failed"; $doPing = $true }
        }
        if ($doPing) {
            $ping = [System.Net.NetworkInformation.Ping]::new()
            try {
                $reply = $ping.Send($dest, 4000)
                $r.PingReplyDetails = $reply
                $r.PingSucceeded = $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
                if (-not $r.PingSucceeded) { Write-Warning "Ping to $($dest) failed with status: $($reply.Status)" }
            } catch {
                Write-Warning "Ping to $($dest) failed with status: $($_.Exception.InnerException.Message)"
            } finally { $ping.Dispose() }
        }
        if ($TraceRoute -and $PSCmdlet.ParameterSetName -eq 'ICMP') {
            $hopsFound = [System.Collections.Generic.List[string]]::new()
            $p = [System.Net.NetworkInformation.Ping]::new()
            try {
                for ($ttl = 1; $ttl -le $Hops; $ttl++) {
                    $opt = [System.Net.NetworkInformation.PingOptions]::new($ttl, $true)
                    $rep = $p.Send($dest, 2000, [byte[]]::new(32), $opt)
                    if ($rep.Status -eq 'Success') { $hopsFound.Add($rep.Address.ToString()); break }
                    elseif ($rep.Status -eq 'TtlExpired') { $hopsFound.Add($rep.Address.ToString()) }
                    else { $hopsFound.Add('0.0.0.0') }
                }
            } finally { $p.Dispose() }
            $r.TraceRoute = $hopsFound.ToArray()
        }
        if ($InformationLevel -eq 'Quiet') { if ($tcpPort -gt 0) { return $r.TcpTestSucceeded } return $r.PingSucceeded }
        $r
    }
}

# =========================================================================================== write side
# New-/Remove-NetIPAddress and Set-NetIPInterface act through iphlpapi (AddIPAddress/DeleteIPAddress, IpRenew/IpReleaseAddress,
# the IPv4 route table) for the ActiveStore and through the Tcpip\Parameters\Interfaces\{guid} registry values (IPAddress,
# SubnetMask, DefaultGateway, EnableDHCP) for the PersistentStore, which the stack and the DHCP client read at bind time.
# The stack holds one IPv4 address per interface and has no IPv6: what it cannot do is refused with an error, never faked.

$script:StoreText = @{ ActiveStore = 'Active'; PersistentStore = 'Persistent' }

# The stores a -PolicyStore value selects: both when it is not given (as on Windows)
function Get-NetStores {
    param($Cmdlet, [System.Collections.IDictionary]$Bound, [string]$Class)
    if (-not $Bound.ContainsKey('PolicyStore')) { return @('Active', 'Persistent') }
    switch ($Bound['PolicyStore']) {
        'ActiveStore' { return @('Active') }
        'PersistentStore' { return @('Persistent') }
        default { $Cmdlet.WriteError([Nitro.Net.Errors]::Win32(87, "Invalid parameter PolicyStore $($Bound['PolicyStore'])`n", $Class, 'InvalidArgument')); return $null }
    }
}

function Write-NetWin32Error {
    param($Cmdlet, [int]$Code, [string]$Message, $Target, [string]$Category = 'InvalidArgument')
    $Cmdlet.WriteError([Nitro.Net.Errors]::Win32($Code, $Message, $Target, $Category))
}

# The one IPv4 address (not 0.0.0.0) the stack holds for an interface, or $null
function Get-NetActiveIPv4 {
    param([uint32]$IfIndex)
    foreach ($a in [Nitro.Net.Native]::IPAddresses()) {
        if ([uint32]$a['InterfaceIndex'] -eq $IfIndex -and [int]$a['AddressFamily'] -eq 2 -and $a['IPAddress'] -ne '0.0.0.0') { return $a }
    }
    $null
}

function Get-NetRegStrings {
    param($Key, [string]$Name)
    $v = $Key.GetValue($Name, $null)
    @(@($v) | Where-Object { $_ -is [string] -and $_ -ne '' -and $_ -ne '0.0.0.0' })
}

function Set-NetRegStatic {
    param($Key, [string[]]$Addresses, [string[]]$Masks)
    if ($Addresses.Count -eq 0) { $Addresses = @('0.0.0.0'); $Masks = @('0.0.0.0') }
    $Key.SetValue('IPAddress', [string[]]$Addresses, [Microsoft.Win32.RegistryValueKind]::MultiString)
    $Key.SetValue('SubnetMask', [string[]]$Masks, [Microsoft.Win32.RegistryValueKind]::MultiString)
}

function Resolve-NetInterfaceIndex {
    param($Cmdlet, [string]$Alias, [uint32]$Index, [bool]$ByAlias)
    foreach ($r in [Nitro.Net.Native]::IPInterfaces()) {
        if ($ByAlias) { if ([string]$r['InterfaceAlias'] -eq $Alias) { return [uint32]$r['InterfaceIndex'] } }
        elseif ([uint32]$r['InterfaceIndex'] -eq $Index) { return [uint32]$r['InterfaceIndex'] }
    }
    $prop = if ($ByAlias) { "InterfaceAlias $Alias" } else { "InterfaceIndex $Index" }
    Write-NetWin32Error $Cmdlet 87 "Invalid parameter $prop`n" 'MSFT_NetIPAddress'
    $null
}

function New-NetIPAddress {
    [CmdletBinding(DefaultParameterSetName = 'ByInterfaceAlias', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPAddress')]
    param(
        [Parameter(ParameterSetName = 'ByInterfaceIndex', Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'ByInterfaceAlias', Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('LocalAddress')][string]$IPAddress,
        [Parameter(ParameterSetName = 'ByInterfaceAlias', Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ifAlias')][string]$InterfaceAlias,
        [Parameter(ParameterSetName = 'ByInterfaceIndex', Mandatory = $true, ValueFromPipelineByPropertyName = $true)][Alias('ifIndex')][uint32]$InterfaceIndex,
        [string]$DefaultGateway,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressFamily]$AddressFamily,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.Type]$Type,
        [byte]$PrefixLength,
        [timespan]$ValidLifetime,
        [timespan]$PreferredLifetime,
        [bool]$SkipAsSource,
        [string]$PolicyStore,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob
    )
    process {
        if ($AsJob) { Write-NetWin32Error $PSCmdlet 50 "The -AsJob parameter is not supported by this implementation.`n" 'MSFT_NetIPAddress' 'NotImplemented'; return }
        $class = 'MSFT_NetIPAddress'
        $byAlias = $PSCmdlet.ParameterSetName -eq 'ByInterfaceAlias'
        $ifx = Resolve-NetInterfaceIndex $PSCmdlet $InterfaceAlias $InterfaceIndex $byAlias
        if ($null -eq $ifx) { return }
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$ip)) { Write-NetWin32Error $PSCmdlet 87 "Invalid parameter IPv4Address $IPAddress`n" $class; return }
        $stores = Get-NetStores $PSCmdlet $PSBoundParameters $class
        if ($null -eq $stores) { return }
        $v6 = $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
        if ($v6 -or ($PSBoundParameters.ContainsKey('AddressFamily') -and [int]$AddressFamily -eq 23)) {
            Write-NetWin32Error $PSCmdlet 50 "The request is not supported. This network stack has no IPv6.`n" $class 'NotImplemented'; return
        }
        $plen = if ($PSBoundParameters.ContainsKey('PrefixLength')) { [int]$PrefixLength } else { 32 }
        $gw = $null
        if ($PSBoundParameters.ContainsKey('DefaultGateway') -and $DefaultGateway) {
            $g = $null
            if (-not [System.Net.IPAddress]::TryParse($DefaultGateway, [ref]$g) -or $g.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                Write-NetWin32Error $PSCmdlet 87 "Invalid parameter NextHop $DefaultGateway`n" 'MSFT_NetRoute'; return
            }
            $gw = $g.ToString()
        }

        # the targets Windows names: the address, then its default route, per store
        $targets = foreach ($st in $stores) {
            "NetIPAddress -IPv4Address $($ip.ToString()) -InterfaceIndex $ifx -Store $st"
            if ($gw) { "NetRoute -DestinationPrefix 0.0.0.0/0 -InterfaceIndex $ifx -NextHop $gw -Store $st" }
        }
        # Windows asks per store and per object; the first line of a store stands for it
        $go = @{}
        foreach ($t in $targets) {
            $text = "Performing operation `"New`" on Target `"$t`""
            $go[$t] = $PSCmdlet.ShouldProcess($text, $text, 'Confirm')
        }
        $doActive = ('Active' -in $stores) -and $go["NetIPAddress -IPv4Address $($ip.ToString()) -InterfaceIndex $ifx -Store Active"]
        $doPersist = ('Persistent' -in $stores) -and $go["NetIPAddress -IPv4Address $($ip.ToString()) -InterfaceIndex $ifx -Store Persistent"]
        if (-not $doActive -and -not $doPersist) { return }

        # what the method itself rejects
        if ($plen -gt 32) { Write-NetWin32Error $PSCmdlet 87 "Invalid parameter PrefixLength $plen`n" $class; return }
        if (($PSBoundParameters.ContainsKey('Type') -and [int]$Type -ne 1) -or ($PSBoundParameters.ContainsKey('SkipAsSource') -and $SkipAsSource) -or
            ($PSBoundParameters.ContainsKey('ValidLifetime') -and $ValidLifetime -ne [timespan]::MaxValue) -or
            ($PSBoundParameters.ContainsKey('PreferredLifetime') -and $PreferredLifetime -ne [timespan]::MaxValue)) {
            Write-NetWin32Error $PSCmdlet 50 "The request is not supported. This network stack only configures permanent unicast addresses.`n" $class 'NotImplemented'; return
        }
        $key = [Nitro.Net.Config]::InterfaceKey($ifx, $true)
        if ($null -eq $key) { Write-NetWin32Error $PSCmdlet 87 "Invalid parameter InterfaceIndex $ifx`n" $class; return }
        try {
            if ($doPersist -and [int]$key.GetValue('EnableDHCP', 1) -ne 0) {
                Write-NetWin32Error $PSCmdlet 87 "Inconsistent parameters PolicyStore PersistentStore and Dhcp Enabled`n" $class; return
            }
            foreach ($a in [Nitro.Net.Native]::IPAddresses()) {
                if ([int]$a['AddressFamily'] -eq 2 -and $a['IPAddress'] -eq $ip.ToString()) {
                    if ($doActive) { Write-NetWin32Error $PSCmdlet 5010 "Instance MSFT_NetIPAddress already exists`n" $class 'ResourceExists'; return }
                }
            }
            if ($doActive) {
                $have = Get-NetActiveIPv4 $ifx
                if ($null -ne $have) {
                    Write-NetWin32Error $PSCmdlet 5010 "Instance MSFT_NetIPAddress already exists: this network stack holds one IPv4 address per interface and $($have['IPAddress']) is configured on interface $ifx; remove it first.`n" $class 'ResourceExists'
                    return
                }
                $rc = [Nitro.Net.Config]::AddIPv4($ifx, $ip.ToString(), $plen)
                if ($rc -ne 0) { Write-NetWin32Error $PSCmdlet ([int]$rc) ([System.ComponentModel.Win32Exception]::new([int]$rc).Message + "`n") $class; return }
                if ($gw) {
                    $rc = [Nitro.Net.Config]::AddDefaultRoute($ifx, $gw, 256)
                    if ($rc -ne 0) { Write-NetWin32Error $PSCmdlet ([int]$rc) ([System.ComponentModel.Win32Exception]::new([int]$rc).Message + "`n") 'MSFT_NetRoute' }
                }
            }
            if ($doPersist) {
                Set-NetRegStatic $key @($ip.ToString()) @([Nitro.Net.Config]::MaskText($plen))
                if ($gw) {
                    $key.SetValue('DefaultGateway', [string[]]@($gw), [Microsoft.Win32.RegistryValueKind]::MultiString)
                    $key.SetValue('DefaultGatewayMetric', [string[]]@('0'), [Microsoft.Win32.RegistryValueKind]::MultiString)
                }
            }
        } finally { $key.Dispose() }

        # the new address as the stores report it
        $row = $null
        foreach ($a in [Nitro.Net.Native]::IPAddresses()) { if ([int]$a['AddressFamily'] -eq 2 -and $a['IPAddress'] -eq $ip.ToString() -and [uint32]$a['InterfaceIndex'] -eq $ifx) { $row = $a } }
        if ($null -eq $row) {
            $row = [System.Collections.Generic.Dictionary[string, object]]::new()
            foreach ($kv in @{ InstanceID = "$($ip.ToString())++$ifx"; CreationClassName = ''; SystemCreationClassName = ''; SystemName = ''; EnabledDefault = 2; RequestedState = 12
                TransitioningToState = 12; ProtocolIFType = 4096; AddressOrigin = 0; IPv4Address = $ip.ToString(); PrefixLength = [byte]$plen; AddressFamily = 2
                InterfaceIndex = $ifx; IPAddress = $ip.ToString(); PrefixOrigin = 1; SuffixOrigin = 1; SkipAsSource = $false; Type = 1 }.GetEnumerator()) { $row[$kv.Key] = $kv.Value }
            $row['InterfaceAlias'] = if ($byAlias) { $InterfaceAlias } else { (Get-NetAdapter -InterfaceIndex $ifx -ErrorAction SilentlyContinue).Name }
        }
        if ($doActive) { $row['Store'] = 1; [Nitro.Net.CimBuilder]::Create($class, $row) }
        if ($doPersist) {
            $p = [System.Collections.Generic.Dictionary[string, object]]::new()
            foreach ($k in $row.Keys) { $p[$k] = $row[$k] }
            $p['Store'] = 0; $p['AddressState'] = 0
            [Nitro.Net.CimBuilder]::Create($class, $p)
        }
    }
}

function Remove-NetIPAddress {
    [CmdletBinding(DefaultParameterSetName = 'Query (cdxml)', SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(ParameterSetName = 'Query (cdxml)', Position = 0, ValueFromPipelineByPropertyName = $true)][ValidateNotNull()][Alias('LocalAddress')][string[]]$IPAddress,
        [Parameter(ParameterSetName = 'Query (cdxml)', ValueFromPipelineByPropertyName = $true)][ValidateNotNull()][Alias('ifIndex')][uint32[]]$InterfaceIndex,
        [Parameter(ParameterSetName = 'Query (cdxml)', ValueFromPipelineByPropertyName = $true)][ValidateNotNull()][Alias('ifAlias')][string[]]$InterfaceAlias,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressFamily[]]$AddressFamily,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.Type[]]$Type,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][byte[]]$PrefixLength,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.PrefixOrigin[]]$PrefixOrigin,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.SuffixOrigin[]]$SuffixOrigin,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressState[]]$AddressState,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][timespan[]]$ValidLifetime,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][timespan[]]$PreferredLifetime,
        [Parameter(ParameterSetName = 'Query (cdxml)')][ValidateNotNull()][bool[]]$SkipAsSource,
        [Parameter(ParameterSetName = 'Query (cdxml)')][string]$PolicyStore,
        [Parameter(ParameterSetName = 'Query (cdxml)')][string]$DefaultGateway,
        [Parameter(ParameterSetName = 'Query (cdxml)')][switch]$IncludeAllCompartments,
        [Parameter(ParameterSetName = 'InputObject (cdxml)', Mandatory = $true, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_NetIPAddress')][ValidateNotNull()][object[]]$InputObject,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob,
        [switch]$PassThru
    )
    process {
        if ($AsJob) { Write-NetWin32Error $PSCmdlet 50 "The -AsJob parameter is not supported by this implementation.`n" 'MSFT_NetIPAddress' 'NotImplemented'; return }
        $class = 'MSFT_NetIPAddress'
        $rows = @()
        $persistOnly = $false
        if ($PSCmdlet.ParameterSetName -eq 'InputObject (cdxml)') { $rows = @($InputObject) }
        elseif ($PSBoundParameters.ContainsKey('PolicyStore') -and $PolicyStore -eq 'PersistentStore') {
            # the PersistentStore holds the registry configuration: matched by address and interface only
            $persistOnly = $true
            foreach ($r in [Nitro.Net.Native]::IPInterfaces()) {
                if ($r['AddressFamily'] -ne 2) { continue }
                $ix = [uint32]$r['InterfaceIndex']
                if ($PSBoundParameters.ContainsKey('InterfaceIndex') -and $ix -notin $InterfaceIndex) { continue }
                if ($PSBoundParameters.ContainsKey('InterfaceAlias') -and [string]$r['InterfaceAlias'] -notin $InterfaceAlias) { continue }
                $k = [Nitro.Net.Config]::InterfaceKey($ix, $false)
                if ($null -eq $k) { continue }
                try {
                    foreach ($a in (Get-NetRegStrings $k 'IPAddress')) {
                        if ($PSBoundParameters.ContainsKey('IPAddress') -and $a -notin $IPAddress) { continue }
                        $rows += [pscustomobject]@{ IPAddress = $a; InterfaceIndex = $ix; AddressFamily = 2; InterfaceAlias = $r['InterfaceAlias'] }
                    }
                } finally { $k.Dispose() }
            }
            if ($rows.Count -eq 0) {
                if ($PSBoundParameters.ContainsKey('IPAddress')) {
                    foreach ($a in $IPAddress) {
                        $PSCmdlet.WriteError([Nitro.Net.Errors]::NotFoundValue($class, 'IPAddress', $a, $a))
                    }
                }
                return
            }
        } else {
            $filters = @('IPAddress', 'InterfaceIndex', 'InterfaceAlias', 'AddressFamily', 'Type', 'PrefixLength', 'PrefixOrigin', 'SuffixOrigin', 'AddressState', 'ValidLifetime', 'PreferredLifetime', 'SkipAsSource')
            $rows = @(Invoke-NetQuery $PSCmdlet $class ([Nitro.Net.Native]::IPAddresses()) $PSBoundParameters $filters)
        }
        foreach ($row in $rows) {
            $ifx = [uint32]$row.InterfaceIndex
            $addr = [string]$row.IPAddress
            if ($persistOnly) { $stores = @('Persistent') } else { $stores = @('Active') }
            $key = [Nitro.Net.Config]::InterfaceKey($ifx, $true)
            $inReg = $false
            if ($null -ne $key -and -not $persistOnly) { $inReg = $addr -in (Get-NetRegStrings $key 'IPAddress'); if ($inReg -and -not $PSBoundParameters.ContainsKey('PolicyStore')) { $stores += 'Persistent' } }
            $ok = @{}
            foreach ($st in $stores) {
                $text = "Performing operation `"Remove`" on Target `"NetIPAddress -IPv4Address $addr -InterfaceIndex $ifx -Store $st`""
                $ok[$st] = $PSCmdlet.ShouldProcess($text, $text, 'Confirm')
            }
            try {
                if ($row.AddressFamily -ne 2 -and "$($row.AddressFamily)" -ne 'IPv4') { Write-NetWin32Error $PSCmdlet 50 "The request is not supported. This network stack has no IPv6.`n" $class 'NotImplemented'; continue }
                if ($ok['Active']) {
                    $have = Get-NetActiveIPv4 $ifx
                    if ($null -eq $have -or $have['IPAddress'] -ne $addr) { Write-NetWin32Error $PSCmdlet 1168 "Element not found.`n" $class 'ObjectNotFound'; continue }
                    foreach ($rt in [Nitro.Net.Native]::Routes()) {
                        if ([uint32]$rt['InterfaceIndex'] -eq $ifx -and $rt['DestinationPrefix'] -eq '0.0.0.0/0' -and $rt['NextHop'] -ne '0.0.0.0') { $null = [Nitro.Net.Config]::RemoveDefaultRoute($ifx, [string]$rt['NextHop']) }
                    }
                    $rc = [Nitro.Net.Config]::DeleteIPv4($ifx)
                    if ($rc -ne 0) { Write-NetWin32Error $PSCmdlet ([int]$rc) ([System.ComponentModel.Win32Exception]::new([int]$rc).Message + "`n") $class; continue }
                }
                if ($ok['Persistent'] -and $null -ne $key) {
                    $ips = @(Get-NetRegStrings $key 'IPAddress'); $masks = @(Get-NetRegStrings $key 'SubnetMask')
                    $keepIp = @(); $keepMask = @()
                    for ($i = 0; $i -lt $ips.Count; $i++) { if ($ips[$i] -ne $addr) { $keepIp += $ips[$i]; $keepMask += $(if ($i -lt $masks.Count) { $masks[$i] } else { '255.255.255.255' }) } }
                    Set-NetRegStatic $key $keepIp $keepMask
                    if ($PSBoundParameters.ContainsKey('DefaultGateway')) {
                        $gws = @(Get-NetRegStrings $key 'DefaultGateway' | Where-Object { $_ -ne $DefaultGateway })
                        $key.SetValue('DefaultGateway', [string[]]$(if ($gws.Count) { $gws } else { @('') }), [Microsoft.Win32.RegistryValueKind]::MultiString)
                    }
                }
            } finally { if ($null -ne $key) { $key.Dispose() } }
            if ($PassThru -and ($ok.Values -contains $true)) { $row }
        }
    }
}

function Set-NetIPInterface {
    [CmdletBinding(DefaultParameterSetName = 'ByName', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType('Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPInterface')]
    param(
        [Parameter(ParameterSetName = 'ByName', ValueFromPipelineByPropertyName = $true)][ValidateNotNull()][Alias('ifIndex')][uint32[]]$InterfaceIndex,
        [Parameter(ParameterSetName = 'ByName', Position = 0, ValueFromPipelineByPropertyName = $true)][ValidateNotNull()][Alias('ifAlias')][string[]]$InterfaceAlias,
        [Parameter(ParameterSetName = 'ByName')][ValidateNotNull()][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AddressFamily[]]$AddressFamily,
        [Parameter(ParameterSetName = 'ByName')][ValidateNotNull()][uint32[]]$ReachableTime,
        [Parameter(ParameterSetName = 'ByName')][ValidateNotNull()][Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.NeighborDiscoverySupported[]]$NeighborDiscoverySupported,
        [Parameter(ParameterSetName = 'ByName')][ValidateNotNull()][uint32[]]$CompartmentId,
        [Parameter(ParameterSetName = 'ByName')][string]$PolicyStore,
        [Parameter(ParameterSetName = 'ByName')][switch]$IncludeAllCompartments,
        [Parameter(ParameterSetName = 'InputObject (cdxml)', Mandatory = $true, ValueFromPipeline = $true)]
        [PSTypeName('Microsoft.Management.Infrastructure.CimInstance#MSFT_NetIPInterface')][ValidateNotNull()][object[]]$InputObject,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Forwarding]$Forwarding,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ClampMss]$ClampMss,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Advertising]$Advertising,
        [uint32]$NlMtuBytes,
        [uint32]$InterfaceMetric,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.NeighborUnreachabilityDetection]$NeighborUnreachabilityDetection,
        [Alias('BaseReachableTime')][uint32]$BaseReachableTimeMs,
        [Alias('RetransmitTime')][uint32]$RetransmitTimeMs,
        [uint32]$DadTransmits,
        [Alias('DadRetransmitTime')][uint32]$DadRetransmitTimeMs,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.RouterDiscovery]$RouterDiscovery,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ManagedAddressConfiguration]$ManagedAddressConfiguration,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.OtherStatefulConfiguration]$OtherStatefulConfiguration,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.WeakHostSend]$WeakHostSend,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.WeakHostReceive]$WeakHostReceive,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.IgnoreDefaultRoutes]$IgnoreDefaultRoutes,
        [timespan]$AdvertisedRouterLifetime,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AdvertiseDefaultRoute]$AdvertiseDefaultRoute,
        [uint32]$CurrentHopLimit,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ForceArpNdWolPattern]$ForceArpNdWolPattern,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.DirectedMacWolPattern]$DirectedMacWolPattern,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.EcnMarking]$EcnMarking,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Dhcp]$Dhcp,
        [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AutomaticMetric]$AutomaticMetric,
        [Alias('Session')][object[]]$CimSession,
        [int]$ThrottleLimit,
        [switch]$AsJob,
        [switch]$PassThru
    )
    process {
        $class = 'MSFT_NetIPInterface'
        if ($AsJob) { Write-NetWin32Error $PSCmdlet 50 "The -AsJob parameter is not supported by this implementation.`n" $class 'NotImplemented'; return }
        $rows = @()
        if ($PSCmdlet.ParameterSetName -eq 'InputObject (cdxml)') { $rows = @($InputObject) }
        else {
            $filters = @('InterfaceIndex', 'InterfaceAlias', 'AddressFamily', 'ReachableTime', 'NeighborDiscoverySupported', 'CompartmentId')
            $rows = @(Invoke-NetQuery $PSCmdlet $class ([Nitro.Net.Native]::IPInterfaces()) $PSBoundParameters $filters)
        }
        $stores = Get-NetStores $PSCmdlet $PSBoundParameters $class
        if ($null -eq $stores) { return }
        $settable = 'Forwarding', 'ClampMss', 'Advertising', 'NlMtuBytes', 'InterfaceMetric', 'NeighborUnreachabilityDetection', 'BaseReachableTimeMs',
            'RetransmitTimeMs', 'DadTransmits', 'DadRetransmitTimeMs', 'RouterDiscovery', 'ManagedAddressConfiguration', 'OtherStatefulConfiguration',
            'WeakHostSend', 'WeakHostReceive', 'IgnoreDefaultRoutes', 'AdvertisedRouterLifetime', 'AdvertiseDefaultRoute', 'CurrentHopLimit',
            'ForceArpNdWolPattern', 'DirectedMacWolPattern', 'EcnMarking', 'Dhcp', 'AutomaticMetric'
        $asked = @($settable | Where-Object { $PSBoundParameters.ContainsKey($_) })
        $unsupported = @($asked | Where-Object { $_ -ne 'Dhcp' })
        foreach ($row in $rows) {
            $ifx = [uint32]$row.InterfaceIndex
            $fam = "$($row.AddressFamily)"
            $famName = if ($fam -in '2', 'IPv4') { 'IPv4' } else { 'IPv6' }
            $ok = @{}
            foreach ($st in $stores) {
                $text = "Performing operation `"Set`" on Target `"NetIPInterface -InterfaceIndex $ifx -AddressFamily $famName -Store $st`""
                $ok[$st] = $PSCmdlet.ShouldProcess($text, $text, 'Confirm')
            }
            if (-not ($ok.Values -contains $true)) { continue }
            if ($unsupported.Count -gt 0) {
                Write-NetWin32Error $PSCmdlet 50 "The request is not supported. This network stack cannot set: $($unsupported -join ', ').`n" $class 'NotImplemented'
                continue
            }
            if ($asked.Count -gt 0) {
                if ($famName -ne 'IPv4') { Write-NetWin32Error $PSCmdlet 50 "The request is not supported. This network stack has no IPv6.`n" $class 'NotImplemented'; continue }
                $key = [Nitro.Net.Config]::InterfaceKey($ifx, $true)
                if ($null -eq $key) { Write-NetWin32Error $PSCmdlet 87 "Invalid parameter InterfaceIndex $ifx`n" $class; continue }
                try {
                    $was = [int]$key.GetValue('EnableDHCP', 1)
                    $want = if ([int]$Dhcp -eq 1) { 1 } else { 0 }   # Dhcp: Disabled = 0, Enabled = 1
                    if ($want -ne $was) {
                        if ($want -eq 1) {
                            Set-NetRegStatic $key @() @()
                            $key.SetValue('EnableDHCP', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
                            $key.SetValue('DefaultGateway', [string[]]@(''), [Microsoft.Win32.RegistryValueKind]::MultiString)
                            foreach ($rt in [Nitro.Net.Native]::Routes()) {
                                if ([uint32]$rt['InterfaceIndex'] -eq $ifx -and $rt['DestinationPrefix'] -eq '0.0.0.0/0' -and $rt['NextHop'] -ne '0.0.0.0') { $null = [Nitro.Net.Config]::RemoveDefaultRoute($ifx, [string]$rt['NextHop']) }
                            }
                            if ($ok['Active']) { $null = [Nitro.Net.Config]::DeleteIPv4($ifx); $null = [Nitro.Net.Config]::Renew($ifx) }
                        } else {
                            $key.SetValue('EnableDHCP', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
                            if ($ok['Active']) {
                                $null = [Nitro.Net.Config]::Release($ifx)
                                foreach ($rt in [Nitro.Net.Native]::Routes()) {
                                    if ([uint32]$rt['InterfaceIndex'] -eq $ifx -and $rt['DestinationPrefix'] -eq '0.0.0.0/0' -and $rt['NextHop'] -ne '0.0.0.0') { $null = [Nitro.Net.Config]::RemoveDefaultRoute($ifx, [string]$rt['NextHop']) }
                                }
                                $null = [Nitro.Net.Config]::DeleteIPv4($ifx)
                            }
                            if ($null -ne $key.GetValue('DhcpNameServer', $null)) { $key.DeleteValue('DhcpNameServer') }
                        }
                    }
                } finally { $key.Dispose() }
            }
            if ($PassThru) { Invoke-NetQuery $PSCmdlet $class ([Nitro.Net.Native]::IPInterfaces()) @{ InterfaceIndex = @($ifx); AddressFamily = @($row.AddressFamily) } @('InterfaceIndex', 'AddressFamily') }
        }
    }
}
