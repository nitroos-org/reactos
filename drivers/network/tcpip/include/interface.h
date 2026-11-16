#pragma once

#define IFENT_SOFTWARE_LOOPBACK 24 /* This is an SNMP constant from rfc1213 */

NTSTATUS GetInterfaceIPv4Address( PIP_INTERFACE Interface,
				  ULONG Type,
				  PULONG Address );
UINT CountInterfaces(VOID);
UINT CountInterfaceAddresses( PIP_INTERFACE Interface );
NTSTATUS GetInterfaceSpeed( PIP_INTERFACE Interface, PUINT Speed );
NTSTATUS GetInterfaceName( PIP_INTERFACE Interface, PCHAR NameBuffer,
			   UINT NameMaxLen );
VOID GetInterfaceConnectionStatus( PIP_INTERFACE Interface, PULONG OperStatus );
PIP_INTERFACE FindOnLinkInterface(PIP_ADDRESS Address);
/* Additional addresses (IP_NTE) of an interface, see ip.h */
BOOLEAN IFIsOwnIPv4Address(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address);
BOOLEAN IFIsNteIPv4Address(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address);
BOOLEAN IFIsNteSubnet(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address);
IPv4_RAW_ADDRESS IFSelectSourceAddress(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Destination);
UINT IFCopyNtes(PIP_INTERFACE Interface, PIP_NTE Entries, UINT Capacity);
UINT IFCountNtes(PIP_INTERFACE Interface);
NTSTATUS IFAddNte(PIP_INTERFACE Interface, IPv4_RAW_ADDRESS Address, IPv4_RAW_ADDRESS Netmask, PUSHORT Context);
BOOLEAN IFRemoveNteByContext(USHORT Context, PIP_NTE Removed, PIP_INTERFACE *Owner);
VOID IFClearNtes(PIP_INTERFACE Interface);
PIP_INTERFACE GetDefaultInterface(VOID);
PIP_INTERFACE IPReferenceDefaultInterface(VOID);

/* tcpip/addrchange.c: wake the IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST waiters */
VOID AddrChangeInitialize(VOID);
/* Wake the waiters of these families (TCP_CHANGE_FAMILY_*): an IPv4 waiter does not wake for an IPv6 change, as on
   Windows */
VOID AddrChangeNotifyFamilies(ULONG Families);
VOID RouteChangeNotifyFamilies(ULONG Families);
#define AddrChangeNotify4()   AddrChangeNotifyFamilies(TCP_CHANGE_FAMILY_IPV4)
#define AddrChangeNotify6()   AddrChangeNotifyFamilies(TCP_CHANGE_FAMILY_IPV6)
#define AddrChangeNotifyAll() AddrChangeNotifyFamilies(TCP_CHANGE_FAMILY_IPV4 | TCP_CHANGE_FAMILY_IPV6)
#define RouteChangeNotify4()  RouteChangeNotifyFamilies(TCP_CHANGE_FAMILY_IPV4)
#define RouteChangeNotify6()  RouteChangeNotifyFamilies(TCP_CHANGE_FAMILY_IPV6)
NTSTATUS DispRouteChangeNotifyRequest(PIRP Irp);
NTSTATUS DispAddrChangeNotifyRequest(PIRP Irp);
NTSTATUS DispAddrChangeCancelRequest(PIRP Irp);
NTSTATUS NTAPI TiDispatchCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp);
