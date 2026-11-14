/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The IPv6 state of the stack (tcpip's IP_IPV6_TABLE_ENTRY_ID query)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

/*
 * IPv6 is off unless the stack says it is on (Tcpip\Parameters\Ipv6Enable, read by tcpip.sys when it starts):
 * every answer of this DLL that talks about IPv6 follows what the stack reports here, so that no table claims an
 * address, an interface or a flag the stack does not have. A stack that does not know the query, or any failure,
 * counts as "off".
 */

/* The state of the stack, from an open handle to it. TRUE: IPv6 is on and State is filled in (release it with
   Ipv6FreeState). FALSE: off, State is empty */
BOOL Ipv6GetStateFromFile(HANDLE TcpFile, PIPV6_STATE State)
{
  PVOID Blob = NULL;
  DWORD Size = 0;
  PTCP_IPV6_TABLE_HEADER Header;
  SIZE_T Needed;
  NTSTATUS Status;

  RtlZeroMemory(State, sizeof(*State));

  /* The size is the unit: the answer is one blob (entry size 1, nothing fixed) */
  Status = tdiGetSetOfThings(TcpFile, INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER, IP_IPV6_TABLE_ENTRY_ID,
                             CL_NL_ENTITY, 0, 0, 1, &Blob, &Size);
  if (!NT_SUCCESS(Status) || !Blob)
    return FALSE;

  Header = Blob;
  if (Size < sizeof(*Header) || !Header->Enabled)
    goto Off;

  /* the counts come from the stack, the size is what was delivered */
  Needed = (SIZE_T)sizeof(*Header) + (SIZE_T)Header->InterfaceCount * sizeof(TCP_IPV6_INTERFACE_ROW) +
           (SIZE_T)Header->AddressCount * sizeof(TCP_IPV6_ADDRESS_ROW);
  if (Header->InterfaceCount > 0xFFFF || Header->AddressCount > 0xFFFF || Needed > Size)
    goto Off;

  State->Memory = Blob;
  State->Header = Header;
  State->Interfaces = (PTCP_IPV6_INTERFACE_ROW)(Header + 1);
  State->Addresses = (PTCP_IPV6_ADDRESS_ROW)(State->Interfaces + Header->InterfaceCount);
  return TRUE;

Off:
  tdiFreeThingSet(Blob);
  return FALSE;
}

BOOL Ipv6GetState(PIPV6_STATE State)
{
  HANDLE TcpFile;
  BOOL Result;

  RtlZeroMemory(State, sizeof(*State));
  if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
    return FALSE;

  Result = Ipv6GetStateFromFile(TcpFile, State);
  NtClose(TcpFile);
  return Result;
}

VOID Ipv6FreeState(PIPV6_STATE State)
{
  if (State->Memory)
    tdiFreeThingSet(State->Memory);
  RtlZeroMemory(State, sizeof(*State));
}

/* The row of the interface with this index, or NULL when IPv6 is not usable on it */
const TCP_IPV6_INTERFACE_ROW *Ipv6FindInterface(const IPV6_STATE *State, DWORD IfIndex)
{
  ULONG i;

  if (!State->Header)
    return NULL;
  for (i = 0; i < State->Header->InterfaceCount; i++)
  {
    if (State->Interfaces[i].IfIndex == IfIndex)
      return (State->Interfaces[i].Flags & TCP_IPV6_IF_ENABLED) ? &State->Interfaces[i] : NULL;
  }
  return NULL;
}
