
list(APPEND SOURCE
    GetAdaptersAddresses.c
    GetBestInterfaceEx.c
    GetBestRoute2.c
    GetExtendedTcpTable.c
    GetExtendedUdpTable.c
    GetIfTableConcurrent.c
    GetInterfaceName.c
    GetNetworkParams.c
    GetPerAdapterInfo.c
    GetOwnerModuleFromTcpEntry.c
    GetOwnerModuleFromUdpEntry.c
    ArpNeighbor.c
    icmp.c
    Icmp6Echo.c
    IfStatistics.c
    IpInterface.c
    IpForwardTable6.c
    IpNetTable6.c
    IpTables2.c
    Ipv6AddressConfig.c
    Ipv6ConfigApi.c
    Ipv6Statistics.c
    Ipv6Dns.c
    Ipv6Reporting.c
    Ipv6RouteConfig.c
    Ipv6StableId.c
    NeighborEntry2.c
    NetstatOutput.c
    NotifyAddrChange.c
    NotifyChanges.c
    NotifyIpInterfaceChange.c
    NotifyIpv6.c
    NotifyRouteChange2.c
    NotifyStableUnicastIpAddressTable.c
    SendARP.c
    Tcp6Table2.c
    TcpTimeWait.c
    TcpUdpTableRows.c
    Win6Exports.c
    testlist.c)

add_executable(iphlpapi_apitest ${SOURCE})
target_link_libraries(iphlpapi_apitest wine ${PSEH_LIB})
set_module_type(iphlpapi_apitest win32cui)
add_importlibs(iphlpapi_apitest iphlpapi ws2_32 advapi32 msvcrt kernel32 ntdll)
add_rostests_file(TARGET iphlpapi_apitest)
