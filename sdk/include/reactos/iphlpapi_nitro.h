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

#endif /* __IPHLPAPI_NITRO_H__ */
