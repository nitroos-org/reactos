# NetTCPIP for ReactOS-Nitro: a clean-room PowerShell 7 script module (read side). Same module, cmdlet and parameter names
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
