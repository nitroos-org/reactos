
#define STANDALONE
#include <apitest.h>

extern void func_ArpNeighbor(void);
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
extern void func_IfStatistics(void);
extern void func_IpInterface(void);
extern void func_IpTables2(void);
extern void func_NeighborEntry2(void);
extern void func_NotifyAddrChange(void);
extern void func_NotifyChanges(void);
extern void func_NotifyIpInterfaceChange(void);
extern void func_NotifyRouteChange2(void);
extern void func_NotifyStableUnicastIpAddressTable(void);
extern void func_SendARP(void);
extern void func_TcpUdpTableRows(void);

const struct test winetest_testlist[] =
{
    { "ArpNeighbor",                func_ArpNeighbor },
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
    { "IfStatistics",               func_IfStatistics },
    { "IpInterface",               func_IpInterface },
    { "IpTables2",                  func_IpTables2 },
    { "NeighborEntry2",             func_NeighborEntry2 },
    { "NotifyAddrChange",          func_NotifyAddrChange },
    { "NotifyChanges",              func_NotifyChanges },
    { "NotifyIpInterfaceChange",    func_NotifyIpInterfaceChange },
    { "NotifyRouteChange2",         func_NotifyRouteChange2 },
    { "NotifyStableUnicastIpAddressTable", func_NotifyStableUnicastIpAddressTable },
    { "SendARP",                    func_SendARP },
    { "TcpUdpTableRows",            func_TcpUdpTableRows },

    { 0, 0 }
};

