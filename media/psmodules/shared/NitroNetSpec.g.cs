// Generated from measured Windows 10 object schemas (names, order, types, enum values); see the PSMODULES commit message.
// Do not edit by hand: regenerate from the measurement script.
using System;

namespace Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress
{
    public enum AddressFamily : ushort
    {
        IPv4 = 2,
        IPv6 = 23,
    }
    public enum Type : byte
    {
        Unicast = 1,
        Anycast = 2,
    }
    public enum PrefixOrigin : ushort
    {
        Other = 0,
        Manual = 1,
        WellKnown = 2,
        Dhcp = 3,
        RouterAdvertisement = 4,
    }
    public enum SuffixOrigin : ushort
    {
        Other = 0,
        Manual = 1,
        WellKnown = 2,
        Dhcp = 3,
        Link = 4,
        Random = 5,
    }
    public enum AddressState : ushort
    {
        Invalid = 0,
        Tentative = 1,
        Duplicate = 2,
        Deprecated = 3,
        Preferred = 4,
    }
    public enum Store : byte
    {
        PersistentStore = 0,
        ActiveStore = 1,
    }
}

namespace Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface
{
    public enum AddressFamily : ushort
    {
        IPv4 = 2,
        IPv6 = 23,
    }
    public enum Forwarding : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum ClampMss : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum Advertising : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum NeighborUnreachabilityDetection : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum RouterDiscovery : byte
    {
        Disabled = 0,
        Enabled = 1,
        ControlledByDHCP = 2,
    }
    public enum ManagedAddressConfiguration : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum OtherStatefulConfiguration : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum WeakHostSend : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum WeakHostReceive : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum IgnoreDefaultRoutes : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum AdvertiseDefaultRoute : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum ForceArpNdWolPattern : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum DirectedMacWolPattern : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum EcnMarking : byte
    {
        Disabled = 0,
        UseEct1 = 1,
        UseEct0 = 2,
        AppDecide = 3,
    }
    public enum Dhcp : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum ConnectionState : byte
    {
        Disconnected = 0,
        Connected = 1,
    }
    public enum AutomaticMetric : byte
    {
        Disabled = 0,
        Enabled = 1,
    }
    public enum NeighborDiscoverySupported : byte
    {
        No = 0,
        Yes = 1,
    }
    public enum Store : byte
    {
        PersistentStore = 0,
        ActiveStore = 1,
    }
}

namespace Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute
{
    public enum AddressFamily : ushort
    {
        IPv4 = 2,
        IPv6 = 23,
    }
    public enum Publish : byte
    {
        No = 0,
        Age = 1,
        Yes = 2,
    }
    public enum Protocol : ushort
    {
        Other = 1,
        Local = 2,
        NetMgmt = 3,
        Icmp = 4,
        Egp = 5,
        Ggp = 6,
        Hello = 7,
        Rip = 8,
        IsIs = 9,
        EsIs = 10,
        Igrp = 11,
        Bbn = 12,
        Ospf = 13,
        Bgp = 14,
        Idpr = 15,
        Eigrp = 16,
        Dvmrp = 17,
        Rpl = 18,
        Dhcp = 19,
    }
    public enum State : byte
    {
        Alive = 0,
        Dead = 1,
        Probe = 2,
    }
    public enum Store : byte
    {
        PersistentStore = 0,
        ActiveStore = 1,
    }
}

namespace Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection
{
    public enum State : byte
    {
        Closed = 1,
        Listen = 2,
        SynSent = 3,
        SynReceived = 4,
        Established = 5,
        FinWait1 = 6,
        FinWait2 = 7,
        CloseWait = 8,
        Closing = 9,
        LastAck = 10,
        TimeWait = 11,
        DeleteTCB = 12,
        Bound = 100,
    }
    public enum AppliedSetting : byte
    {
        Internet = 0,
        Datacenter = 1,
        Compat = 2,
        DatacenterCustom = 3,
        InternetCustom = 4,
    }
    public enum OffloadState : byte
    {
        InHost = 0,
        Offloading = 1,
        Offloaded = 2,
        Uploading = 3,
    }
}

namespace Microsoft.PowerShell.Cmdletization.GeneratedTypes.DnsClientServerAddress
{
    public enum AddressFamily : ushort
    {
        IPv4 = 2,
        IPv6 = 23,
    }
}

namespace Microsoft.DnsClient.Commands
{
    public enum RecordType : ushort
    {
        UNKNOWN = 0,
        A_AAAA = 0,
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        X25 = 19,
        ISDN = 20,
        RT = 21,
        AAAA = 28,
        SRV = 33,
        DNAME = 39,
        OPT = 41,
        DS = 43,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        ANY = 255,
        ALL = 255,
        WINS = 65281,
    }
}

namespace Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetAdapter
{
    public enum NET_IF_ADMIN_STATUS : uint
    {
        Up = 1,
        Down = 2,
        Testing = 3,
    }
    public enum IF_OPER_STATUS : uint
    {
        Up = 1,
        Down = 2,
        Testing = 3,
        Unknown = 4,
        Dormant = 5,
        NotPresent = 6,
        LowerLayerDown = 7,
    }
    public enum NET_IF_MEDIA_CONNECT_STATE : uint
    {
        Unknown = 0,
        Connected = 1,
        Disconnected = 2,
    }
}

namespace Microsoft.DnsClient.Commands
{
    public enum DNSSection : int { Question = 0, Answer = 1, Authority = 2, Additional = 3 }
    public enum DNSCharset : int { Unknown = 0, Unicode = 1, Utf8 = 2, Ansi = 3 }
}

namespace Nitro.NetSchema
{
    public static class Schemas
    {
        // class name -> "type names|...", members "name~kind~cimtype~aux" ; kind P raw, S computed (aux = enum type), A alias (aux = target)
        public static readonly string[][] All = new string[][] {
            new string[] { "MSFT_NetAdapter", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapter|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_NetworkPort|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalPort|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalDevice|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetAdapter|Microsoft.Management.Infrastructure.CimInstance#CIM_NetworkPort|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalPort|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalDevice|Microsoft.Management.Infrastructure.CimInstance#CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "MacAddress~S~String~;Status~S~String~;LinkSpeed~S~String~;MediaType~S~String~;PhysicalMediaType~S~String~;AdminStatus~S~String~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetAdapter.NET_IF_ADMIN_STATUS;MediaConnectionState~S~String~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetAdapter.NET_IF_MEDIA_CONNECT_STATE;DriverInformation~S~String~;DriverFileName~S~String~;NdisVersion~S~String~;ifOperStatus~S~String~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetAdapter.IF_OPER_STATUS;ifAlias~A~~Name;InterfaceAlias~A~~Name;ifIndex~A~~InterfaceIndex;ifDesc~A~~InterfaceDescription;ifName~A~~InterfaceName;DriverVersion~A~~DriverVersionString;LinkLayerAddress~A~~MacAddress;Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;CommunicationStatus~P~UInt16~;DetailedStatus~P~UInt16~;HealthState~P~UInt16~;InstallDate~P~DateTime~;Name~P~String~;OperatingStatus~P~UInt16~;OperationalStatus~P~UInt16Array~;PrimaryStatus~P~UInt16~;StatusDescriptions~P~StringArray~;AvailableRequestedStates~P~UInt16Array~;EnabledDefault~P~UInt16~;EnabledState~P~UInt16~;OtherEnabledState~P~String~;RequestedState~P~UInt16~;TimeOfLastStateChange~P~DateTime~;TransitioningToState~P~UInt16~;AdditionalAvailability~P~UInt16Array~;Availability~P~UInt16~;CreationClassName~P~String~;DeviceID~P~String~;ErrorCleared~P~Boolean~;ErrorDescription~P~String~;IdentifyingDescriptions~P~StringArray~;LastErrorCode~P~UInt32~;MaxQuiesceTime~P~UInt64~;OtherIdentifyingInfo~P~StringArray~;PowerManagementCapabilities~P~UInt16Array~;PowerManagementSupported~P~Boolean~;PowerOnHours~P~UInt64~;StatusInfo~P~UInt16~;SystemCreationClassName~P~String~;SystemName~P~String~;TotalPowerOnHours~P~UInt64~;MaxSpeed~P~UInt64~;OtherPortType~P~String~;PortType~P~UInt16~;RequestedSpeed~P~UInt64~;Speed~P~UInt64~;UsageRestriction~P~UInt16~;ActiveMaximumTransmissionUnit~P~UInt64~;AutoSense~P~Boolean~;FullDuplex~P~Boolean~;LinkTechnology~P~UInt16~;NetworkAddresses~P~StringArray~;OtherLinkTechnology~P~String~;OtherNetworkPortType~P~String~;PermanentAddress~P~String~;PortNumber~P~UInt16~;SupportedMaximumTransmissionUnit~P~UInt64~;AdminLocked~P~Boolean~;ComponentID~P~String~;ConnectorPresent~P~Boolean~;DeviceName~P~String~;DeviceWakeUpEnable~P~Boolean~;DriverDate~P~String~;DriverDateData~P~UInt64~;DriverDescription~P~String~;DriverMajorNdisVersion~P~UInt8~;DriverMinorNdisVersion~P~UInt8~;DriverName~P~String~;DriverProvider~P~String~;DriverVersionString~P~String~;EndPointInterface~P~Boolean~;HardwareInterface~P~Boolean~;Hidden~P~Boolean~;HigherLayerInterfaceIndices~P~UInt32Array~;IMFilter~P~Boolean~;InterfaceAdminStatus~P~UInt32~;InterfaceDescription~P~String~;InterfaceGuid~P~String~;InterfaceIndex~P~UInt32~;InterfaceName~P~String~;InterfaceOperationalStatus~P~UInt32~;InterfaceType~P~UInt32~;iSCSIInterface~P~Boolean~;LowerLayerInterfaceIndices~P~UInt32Array~;MajorDriverVersion~P~UInt16~;MediaConnectState~P~UInt32~;MediaDuplexState~P~UInt32~;MinorDriverVersion~P~UInt16~;MtuSize~P~UInt32~;NdisMedium~P~UInt32~;NdisPhysicalMedium~P~UInt32~;NetLuid~P~UInt64~;NetLuidIndex~P~UInt32~;NotUserRemovable~P~Boolean~;OperationalStatusDownDefaultPortNotAuthenticated~P~Boolean~;OperationalStatusDownInterfacePaused~P~Boolean~;OperationalStatusDownLowPowerState~P~Boolean~;OperationalStatusDownMediaDisconnected~P~Boolean~;PnPDeviceID~P~String~;PromiscuousMode~P~Boolean~;ReceiveLinkSpeed~P~UInt64~;State~P~UInt32~;TransmitLinkSpeed~P~UInt64~;Virtual~P~Boolean~;VlanID~P~UInt16~;WdmInterface~P~Boolean~" },
            new string[] { "MSFT_NetAdapterStatisticsSettingData", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapterStatisticsSettingData|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetAdapterSettingData|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetSettingData|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_SettingData|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetAdapterStatisticsSettingData|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetAdapterSettingData|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetSettingData|Microsoft.Management.Infrastructure.CimInstance#CIM_SettingData|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "ifAlias~A~~Name;InterfaceAlias~A~~Name;ifDesc~A~~InterfaceDescription;Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;InterfaceDescription~P~String~;Name~P~String~;Source~P~UInt32~;SystemName~P~String~;OutboundDiscardedPackets~P~UInt64~;OutboundPacketErrors~P~UInt64~;RdmaStatistics~P~Instance~;ReceivedBroadcastBytes~P~UInt64~;ReceivedBroadcastPackets~P~UInt64~;ReceivedBytes~P~UInt64~;ReceivedDiscardedPackets~P~UInt64~;ReceivedMulticastBytes~P~UInt64~;ReceivedMulticastPackets~P~UInt64~;ReceivedPacketErrors~P~UInt64~;ReceivedUnicastBytes~P~UInt64~;ReceivedUnicastPackets~P~UInt64~;RscStatistics~P~Instance~;SentBroadcastBytes~P~UInt64~;SentBroadcastPackets~P~UInt64~;SentBytes~P~UInt64~;SentMulticastBytes~P~UInt64~;SentMulticastPackets~P~UInt64~;SentUnicastBytes~P~UInt64~;SentUnicastPackets~P~UInt64~;SupportedStatistics~P~UInt32~" },
            new string[] { "MSFT_NetIPAddress", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPAddress|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_IPProtocolEndpoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ProtocolEndpoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetIPAddress|Microsoft.Management.Infrastructure.CimInstance#CIM_IPProtocolEndpoint|Microsoft.Management.Infrastructure.CimInstance#CIM_ProtocolEndpoint|Microsoft.Management.Infrastructure.CimInstance#CIM_ServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "PrefixOrigin~S~UInt16~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.PrefixOrigin;SuffixOrigin~S~UInt16~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.SuffixOrigin;Type~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.Type;Store~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.Store;AddressFamily~S~UInt16~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressFamily;AddressState~S~UInt16~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPAddress.AddressState;ifIndex~A~~InterfaceIndex;Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;CommunicationStatus~P~UInt16~;DetailedStatus~P~UInt16~;HealthState~P~UInt16~;InstallDate~P~DateTime~;Name~P~String~;OperatingStatus~P~UInt16~;OperationalStatus~P~UInt16Array~;PrimaryStatus~P~UInt16~;Status~P~String~;StatusDescriptions~P~StringArray~;AvailableRequestedStates~P~UInt16Array~;EnabledDefault~P~UInt16~;EnabledState~P~UInt16~;OtherEnabledState~P~String~;RequestedState~P~UInt16~;TimeOfLastStateChange~P~DateTime~;TransitioningToState~P~UInt16~;CreationClassName~P~String~;SystemCreationClassName~P~String~;SystemName~P~String~;NameFormat~P~String~;OtherTypeDescription~P~String~;ProtocolIFType~P~UInt16~;ProtocolType~P~UInt16~;Address~P~String~;AddressOrigin~P~UInt16~;AddressType~P~UInt16~;IPv4Address~P~String~;IPv6Address~P~String~;IPVersionSupport~P~UInt16~;PrefixLength~P~UInt8~;SubnetMask~P~String~;InterfaceAlias~P~String~;InterfaceIndex~P~UInt32~;IPAddress~P~String~;PreferredLifetime~P~DateTime~;SkipAsSource~P~Boolean~;ValidLifetime~P~DateTime~" },
            new string[] { "MSFT_NetIPInterface", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPInterface|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LANEndpoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ProtocolEndpoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetIPInterface|Microsoft.Management.Infrastructure.CimInstance#CIM_LANEndpoint|Microsoft.Management.Infrastructure.CimInstance#CIM_ProtocolEndpoint|Microsoft.Management.Infrastructure.CimInstance#CIM_ServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "Store~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Store;AddressFamily~S~UInt16~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AddressFamily;Forwarding~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Forwarding;ClampMss~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ClampMss;Advertising~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Advertising;NeighborUnreachabilityDetection~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.NeighborUnreachabilityDetection;RouterDiscovery~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.RouterDiscovery;NeighborDiscoverySupported~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.NeighborDiscoverySupported;ManagedAddressConfiguration~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ManagedAddressConfiguration;OtherStatefulConfiguration~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.OtherStatefulConfiguration;WeakHostSend~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.WeakHostSend;WeakHostReceive~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.WeakHostReceive;IgnoreDefaultRoutes~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.IgnoreDefaultRoutes;AdvertiseDefaultRoute~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AdvertiseDefaultRoute;ForceArpNdWolPattern~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ForceArpNdWolPattern;DirectedMacWolPattern~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.DirectedMacWolPattern;EcnMarking~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.EcnMarking;Dhcp~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.Dhcp;ConnectionState~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.ConnectionState;AutomaticMetric~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetIPInterface.AutomaticMetric;ifIndex~A~~InterfaceIndex;ifAlias~A~~InterfaceAlias;Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;CommunicationStatus~P~UInt16~;DetailedStatus~P~UInt16~;HealthState~P~UInt16~;InstallDate~P~DateTime~;Name~P~String~;OperatingStatus~P~UInt16~;OperationalStatus~P~UInt16Array~;PrimaryStatus~P~UInt16~;Status~P~String~;StatusDescriptions~P~StringArray~;AvailableRequestedStates~P~UInt16Array~;EnabledDefault~P~UInt16~;EnabledState~P~UInt16~;OtherEnabledState~P~String~;RequestedState~P~UInt16~;TimeOfLastStateChange~P~DateTime~;TransitioningToState~P~UInt16~;CreationClassName~P~String~;SystemCreationClassName~P~String~;SystemName~P~String~;NameFormat~P~String~;OtherTypeDescription~P~String~;ProtocolIFType~P~UInt16~;ProtocolType~P~UInt16~;AliasAddresses~P~StringArray~;GroupAddresses~P~StringArray~;LANID~P~String~;LANType~P~UInt16~;MACAddress~P~String~;MaxDataSize~P~UInt32~;OtherLANType~P~String~;AdvertisedRouterLifetime~P~DateTime~;BaseReachableTime~P~UInt32~;CompartmentId~P~UInt32~;CurrentHopLimit~P~UInt32~;DadRetransmitTime~P~UInt32~;DadTransmits~P~UInt32~;InterfaceAlias~P~String~;InterfaceIndex~P~UInt32~;InterfaceMetric~P~UInt32~;IsolationId~P~UInt32~;LowestIfNetLuid~P~UInt64~;NlMtu~P~UInt32~;ReachableTime~P~UInt32~;RetransmitTime~P~UInt32~" },
            new string[] { "MSFT_NetRoute", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetRoute|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_NextHopRoute|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetRoute|Microsoft.Management.Infrastructure.CimInstance#CIM_NextHopRoute|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "Publish~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.Publish;Protocol~S~UInt16~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.Protocol;Store~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.Store;AddressFamily~S~UInt16~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.AddressFamily;State~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetRoute.State;ifIndex~A~~InterfaceIndex;Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;AdminDistance~P~UInt16~;DestinationAddress~P~String~;IsStatic~P~Boolean~;RouteMetric~P~UInt16~;TypeOfRoute~P~UInt16~;CompartmentId~P~UInt32~;DestinationPrefix~P~String~;InterfaceAlias~P~String~;InterfaceIndex~P~UInt32~;InterfaceMetric~P~UInt32~;NextHop~P~String~;PreferredLifetime~P~DateTime~;ValidLifetime~P~DateTime~" },
            new string[] { "MSFT_NetTCPConnection", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetTCPConnection|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetTransportConnection|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_NetworkPipe|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetTCPConnection|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetTransportConnection|Microsoft.Management.Infrastructure.CimInstance#CIM_NetworkPipe|Microsoft.Management.Infrastructure.CimInstance#CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "State~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.State;AppliedSetting~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.AppliedSetting;OffloadState~S~UInt8~Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.OffloadState;Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;CommunicationStatus~P~UInt16~;DetailedStatus~P~UInt16~;HealthState~P~UInt16~;InstallDate~P~DateTime~;Name~P~String~;OperatingStatus~P~UInt16~;OperationalStatus~P~UInt16Array~;PrimaryStatus~P~UInt16~;Status~P~String~;StatusDescriptions~P~StringArray~;AvailableRequestedStates~P~UInt16Array~;EnabledDefault~P~UInt16~;EnabledState~P~UInt16~;OtherEnabledState~P~String~;RequestedState~P~UInt16~;TimeOfLastStateChange~P~DateTime~;TransitioningToState~P~UInt16~;AggregationBehavior~P~UInt16~;Directionality~P~UInt16~;CreationTime~P~DateTime~;LocalAddress~P~String~;LocalPort~P~UInt16~;OwningProcess~P~UInt32~;RemoteAddress~P~String~;RemotePort~P~UInt16~" },
            new string[] { "MSFT_NetUDPEndpoint", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetUDPEndpoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetTransportConnection|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_NetworkPipe|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetUDPEndpoint|Microsoft.Management.Infrastructure.CimInstance#MSFT_NetTransportConnection|Microsoft.Management.Infrastructure.CimInstance#CIM_NetworkPipe|Microsoft.Management.Infrastructure.CimInstance#CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;CommunicationStatus~P~UInt16~;DetailedStatus~P~UInt16~;HealthState~P~UInt16~;InstallDate~P~DateTime~;Name~P~String~;OperatingStatus~P~UInt16~;OperationalStatus~P~UInt16Array~;PrimaryStatus~P~UInt16~;Status~P~String~;StatusDescriptions~P~StringArray~;AvailableRequestedStates~P~UInt16Array~;EnabledDefault~P~UInt16~;EnabledState~P~UInt16~;OtherEnabledState~P~String~;RequestedState~P~UInt16~;TimeOfLastStateChange~P~DateTime~;TransitioningToState~P~UInt16~;AggregationBehavior~P~UInt16~;Directionality~P~UInt16~;CreationTime~P~DateTime~;LocalAddress~P~String~;LocalPort~P~UInt16~;OwningProcess~P~UInt32~" },
            new string[] { "MSFT_DNSClientServerAddress", "Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_DNSClientServerAddress|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_RemoteServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance#MSFT_DNSClientServerAddress|Microsoft.Management.Infrastructure.CimInstance#CIM_RemoteServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#CIM_ServiceAccessPoint|Microsoft.Management.Infrastructure.CimInstance#CIM_EnabledLogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_LogicalElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedSystemElement|Microsoft.Management.Infrastructure.CimInstance#CIM_ManagedElement|Microsoft.Management.Infrastructure.CimInstance|System.Object", "Address~A~~ServerAddresses;Caption~P~String~;Description~P~String~;ElementName~P~String~;InstanceID~P~String~;CommunicationStatus~P~UInt16~;DetailedStatus~P~UInt16~;HealthState~P~UInt16~;InstallDate~P~DateTime~;Name~P~String~;OperatingStatus~P~UInt16~;OperationalStatus~P~UInt16Array~;PrimaryStatus~P~UInt16~;Status~P~String~;StatusDescriptions~P~StringArray~;AvailableRequestedStates~P~UInt16Array~;EnabledDefault~P~UInt16~;EnabledState~P~UInt16~;OtherEnabledState~P~String~;RequestedState~P~UInt16~;TimeOfLastStateChange~P~DateTime~;TransitioningToState~P~UInt16~;CreationClassName~P~String~;SystemCreationClassName~P~String~;SystemName~P~String~;AccessContext~P~UInt16~;AccessInfo~P~String~;InfoFormat~P~UInt16~;OtherAccessContext~P~String~;OtherInfoFormatDescription~P~String~;AddressFamily~P~UInt16~;InterfaceAlias~P~String~;InterfaceIndex~P~UInt32~;ServerAddresses~P~StringArray~" },
        };
    }
}
