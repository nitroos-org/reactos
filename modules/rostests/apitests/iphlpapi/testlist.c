
#define STANDALONE
#include <apitest.h>

extern void func_AddrSortEngine(void);
extern void func_ArpNeighbor(void);
extern void func_CreateSortedAddressPairs(void);
extern void func_GetAdaptersAddresses(void);
extern void func_GetBestInterfaceEx(void);
extern void func_GetBestRoute2(void);
extern void func_GetExtendedTcpTable(void);
extern void func_GetExtendedUdpTable(void);
extern void func_GetIfTableConcurrent(void);
extern void func_GetInterfaceName(void);
extern void func_GetNetworkParams(void);
extern void func_GetPerAdapterInfo(void);
extern void func_GetOwnerModuleFromTcpEntry(void);
extern void func_GetOwnerModuleFromUdpEntry(void);
extern void func_icmp(void);
extern void func_Icmp6Echo(void);
extern void func_IfStatistics(void);
extern void func_IpInterface(void);
extern void func_SetIpInterfaceEntry(void);
extern void func_IpTables2(void);
extern void func_Ipv6AddressConfig(void);
extern void func_Ipv6ConfigApi(void);
extern void func_Ipv6Statistics(void);
extern void func_IpNetTable6(void);
extern void func_IpForwardTable6(void);
extern void func_Ipv6Dns(void);
extern void func_Ipv6Followups(void);
extern void func_Ipv6Persist(void);
extern void func_Ipv6Reporting(void);
extern void func_Ipv6RouteConfig(void);
extern void func_Ipv6StableId(void);
extern void func_Ipv6UnscopedLinkLocal(void);
extern void func_Ipv6Temporary(void);
extern void func_NeighborEntry2(void);
extern void func_NetstatOutput(void);
extern void func_NslookupErrors(void);
extern void func_NslookupOutput(void);
extern void func_NotifyAddrChange(void);
extern void func_NotifyChanges(void);
extern void func_NotifyIpInterfaceChange(void);
extern void func_NotifyIpv6(void);
extern void func_NotifyRouteChange2(void);
extern void func_NotifyStableUnicastIpAddressTable(void);
extern void func_PortProxy(void);
extern void func_IpReleaseAddress(void);
extern void func_LeaseRenew(void);
extern void func_SendARP(void);
extern void func_Tcp6Table2(void);
extern void func_TcpTimeWait(void);
extern void func_TcpUdpTableRows(void);
extern void func_Win6Exports(void);

const struct test winetest_testlist[] =
{
    { "AddrSortEngine",             func_AddrSortEngine },
    { "ArpNeighbor",                func_ArpNeighbor },
    { "CreateSortedAddressPairs",   func_CreateSortedAddressPairs },
    { "GetAdaptersAddresses",       func_GetAdaptersAddresses },
    { "GetBestInterfaceEx",         func_GetBestInterfaceEx },
    { "GetBestRoute2",             func_GetBestRoute2 },
    { "GetExtendedTcpTable",        func_GetExtendedTcpTable },
    { "GetExtendedUdpTable",        func_GetExtendedUdpTable },
    { "GetIfTableConcurrent",       func_GetIfTableConcurrent },
    { "GetInterfaceName",           func_GetInterfaceName },
    { "GetNetworkParams",           func_GetNetworkParams },
    { "GetPerAdapterInfo",         func_GetPerAdapterInfo },
    { "GetOwnerModuleFromTcpEntry", func_GetOwnerModuleFromTcpEntry },
    { "GetOwnerModuleFromUdpEntry", func_GetOwnerModuleFromUdpEntry },
    { "icmp",                       func_icmp },
    { "Icmp6Echo",                  func_Icmp6Echo },
    { "IfStatistics",               func_IfStatistics },
    { "IpInterface",               func_IpInterface },
    { "SetIpInterfaceEntry",       func_SetIpInterfaceEntry },
    { "IpTables2",                  func_IpTables2 },
    { "Ipv6AddressConfig",          func_Ipv6AddressConfig },
    { "Ipv6ConfigApi",              func_Ipv6ConfigApi },
    { "Ipv6Statistics",             func_Ipv6Statistics },
    { "IpNetTable6",                func_IpNetTable6 },
    { "IpForwardTable6",            func_IpForwardTable6 },
    { "Ipv6Followups",              func_Ipv6Followups },
    { "Ipv6Dns",                    func_Ipv6Dns },
    { "Ipv6Persist",                func_Ipv6Persist },
    { "Ipv6Reporting",              func_Ipv6Reporting },
    { "Ipv6RouteConfig",            func_Ipv6RouteConfig },
    { "Ipv6StableId",               func_Ipv6StableId },
    { "Ipv6UnscopedLinkLocal",      func_Ipv6UnscopedLinkLocal },
    { "Ipv6Temporary",              func_Ipv6Temporary },
    { "NeighborEntry2",             func_NeighborEntry2 },
    { "NetstatOutput",              func_NetstatOutput },
    { "NslookupErrors",             func_NslookupErrors },
    { "NslookupOutput",             func_NslookupOutput },
    { "NotifyAddrChange",          func_NotifyAddrChange },
    { "NotifyChanges",              func_NotifyChanges },
    { "NotifyIpInterfaceChange",    func_NotifyIpInterfaceChange },
    { "NotifyIpv6",                 func_NotifyIpv6 },
    { "NotifyRouteChange2",         func_NotifyRouteChange2 },
    { "PortProxy",                  func_PortProxy },
    { "NotifyStableUnicastIpAddressTable", func_NotifyStableUnicastIpAddressTable },
    { "IpReleaseAddress",           func_IpReleaseAddress },
    { "LeaseRenew",                 func_LeaseRenew },
    { "SendARP",                    func_SendARP },
    { "Tcp6Table2",                 func_Tcp6Table2 },
    { "TcpTimeWait",                func_TcpTimeWait },
    { "TcpUdpTableRows",            func_TcpUdpTableRows },
    { "Win6Exports",                func_Win6Exports },

    { 0, 0 }
};

