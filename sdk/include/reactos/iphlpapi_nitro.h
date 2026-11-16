/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Private iphlpapi exports of the IPv6 configuration for route.exe and netsh (ifmon.dll)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#ifndef __IPHLPAPI_NITRO_H__
#define __IPHLPAPI_NITRO_H__

#include <wine/netioapi.h>

/* Operation of NitroConfigureIpv6Route and NitroConfigureIpv6Address: CREATE fails with ERROR_OBJECT_ALREADY_EXISTS if
   the entry exists, SET with ERROR_NOT_FOUND if it does not, DELETE removes it */
#define NITRO_IPV6_CREATE   1
#define NITRO_IPV6_SET      2
#define NITRO_IPV6_DELETE   3

/*
 * Configure an IPv6 route (DestinationPrefix, NextHop, InterfaceIndex or InterfaceLuid name it; the other fields are
 * what it becomes, as for CreateIpForwardEntry2 and SetIpForwardEntry2) or an IPv6 unicast address, in the active
 * store (Persistent FALSE: gone when the computer restarts or the interface goes) or in both stores (Persistent
 * TRUE: the stack applies it again whenever the adapter starts, the way New-NetRoute and New-NetIPAddress with
 * -PolicyStore PersistentStore do). A DELETE with Persistent TRUE takes the entry out of both stores; one with
 * Persistent FALSE keeps its persistent record. Errors are Win32 errors.
 */
DWORD WINAPI NitroConfigureIpv6Route(ULONG Operation, BOOL Persistent, const MIB_IPFORWARD_ROW2 *Row);
DWORD WINAPI NitroConfigureIpv6Address(ULONG Operation, BOOL Persistent, const MIB_UNICASTIPADDRESS_ROW *Row);

/* The routes of the persistent store (Tcpip6\Parameters\Interfaces\<GUID>\PersistentRoutes of every adapter), whether
   or not they are active now. The table is freed with FreeMibTable; no route is a table with no entries */
DWORD WINAPI NitroGetPersistentIpv6Routes(PMIB_IPFORWARD_TABLE2 *Table);

/*
 * Per-interface parameters of both families (the request behind SetIpInterfaceEntry), in the active store or in both
 * stores (Persistent TRUE: written under the adapter's key, read when the adapter starts, and in force now:
 * Set-NetIPInterface -PolicyStore PersistentStore, netsh set interface store=persistent). Unlike SetIpInterfaceEntry
 * every field named in Fields is sent, also when it equals the value in force, so that it is stored. Family is 4
 * or 6; Metric 0 = automatic. The stack checks the values (ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED for what it
 * cannot do: IPv4 router discovery other than DHCP, IPv4 DAD transmits, forwarding on).
 */
#define NITRO_IPIF_MTU                  0x01
#define NITRO_IPIF_METRIC               0x02
#define NITRO_IPIF_ROUTER_DISCOVERY     0x04    /* NL_ROUTER_DISCOVERY_BEHAVIOR: 0 disabled, 1 enabled, 2 DHCP */
#define NITRO_IPIF_DAD_TRANSMITS        0x08
#define NITRO_IPIF_FORWARDING           0x10

typedef struct _NITRO_IP_INTERFACE_CONFIG
{
    ULONG Family;
    ULONG InterfaceIndex;
    ULONG Fields;
    ULONG Mtu;
    ULONG Metric;
    ULONG RouterDiscovery;
    ULONG DadTransmits;
    ULONG Forwarding;
} NITRO_IP_INTERFACE_CONFIG, *PNITRO_IP_INTERFACE_CONFIG;

DWORD WINAPI NitroConfigureIpInterface(BOOL Persistent, const NITRO_IP_INTERFACE_CONFIG *Config);

/*
 * The IPv6 prefix policy table (RFC 6724) that CreateSortedAddressPairs and getaddrinfo use. NitroGetPrefixPolicies
 * returns the table in force, or with Stored TRUE the stored one (an active-only table is left out). Count is the
 * capacity of Rows on entry and the number of rows on return; ERROR_MORE_DATA when the table does not fit.
 * NitroSetPrefixPolicies replaces the whole table (at least one row, at most
 * NITRO_MAX_PREFIX_POLICIES, precedence and label at most 100000): Persistent TRUE writes the stored table
 * (Tcpip6\Parameters\PrefixPolicies) and drops an active-only one, Persistent FALSE writes a table that lasts until
 * the computer restarts (a volatile key). Prefix bits beyond PrefixLength must be zero.
 */
#define NITRO_MAX_PREFIX_POLICIES       64
#define NITRO_MAX_POLICY_VALUE          100000

typedef struct _NITRO_PREFIX_POLICY
{
    UCHAR Prefix[16];
    ULONG PrefixLength;
    ULONG Precedence;
    ULONG Label;
} NITRO_PREFIX_POLICY, *PNITRO_PREFIX_POLICY;

DWORD WINAPI NitroGetPrefixPolicies(BOOL Stored, PNITRO_PREFIX_POLICY Rows, PULONG Count);
DWORD WINAPI NitroSetPrefixPolicies(BOOL Persistent, const NITRO_PREFIX_POLICY *Rows, ULONG Count);

#endif /* __IPHLPAPI_NITRO_H__ */
