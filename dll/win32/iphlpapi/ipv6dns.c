/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     IPv6 DNS servers and default routers of an adapter
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

/*
 * The IPv6 name servers of an interface are the ones configured for it (the NameServer value of
 * Services\Tcpip6\Parameters\Interfaces\<adapter GUID>, addresses separated by comma, semicolon or blank) and
 * the ones its router advertisements carry (RFC 8106, from tcpip.sys: IP_IPV6_DNS_ENTRY_ID). Configured ones
 * come first. The default routers come from the advertisements too.
 */

/* The answer of the stack, from an open handle to it. FALSE: IPv6 is off, or the stack does not know the query;
   State is empty then. Release with Ipv6FreeDns */
BOOL Ipv6GetDnsFromFile(HANDLE TcpFile, PIPV6_DNS_STATE State)
{
  PVOID Blob = NULL;
  DWORD Size = 0;
  PTCP_IPV6_DNS_HEADER Header;
  NTSTATUS Status;

  RtlZeroMemory(State, sizeof(*State));

  Status = tdiGetSetOfThings(TcpFile, INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER, IP_IPV6_DNS_ENTRY_ID,
                             CL_NL_ENTITY, 0, 0, 1, &Blob, &Size);
  if (!NT_SUCCESS(Status) || !Blob)
    return FALSE;

  Header = Blob;
  if (Size < sizeof(*Header) || !Header->Enabled || Header->Count > 0xFFFF ||
      (SIZE_T)sizeof(*Header) + (SIZE_T)Header->Count * sizeof(TCP_IPV6_DNS_ROW) > Size)
  {
    tdiFreeThingSet(Blob);
    return FALSE;
  }

  State->Memory = Blob;
  State->Header = Header;
  State->Rows = (PTCP_IPV6_DNS_ROW)(Header + 1);
  return TRUE;
}

VOID Ipv6FreeDns(PIPV6_DNS_STATE State)
{
  if (State->Memory)
    tdiFreeThingSet(State->Memory);
  RtlZeroMemory(State, sizeof(*State));
}

static BOOL IsUsableServer(const UCHAR *Address)
{
  static const UCHAR Zero[16];

  /* not the unspecified address, not multicast (a link-local one needs the scope of its interface) */
  return memcmp(Address, Zero, 16) != 0 && Address[0] != 0xFF;
}

static BOOL AlreadyListed(const IPV6_ADAPTER_SERVER *List, ULONG Count, const UCHAR *Address, ULONG Scope)
{
  ULONG i;

  for (i = 0; i < Count; i++)
  {
    if (List[i].Scope == Scope && memcmp(List[i].Address, Address, 16) == 0)
      return TRUE;
  }
  return FALSE;
}

/* Up to Max servers of the adapter (index, GUID name) into List; returns how many */
ULONG Ipv6CollectDnsServers(const IPV6_DNS_STATE *State, DWORD IfIndex, PCSTR AdapterName,
                            PIPV6_ADAPTER_SERVER List, ULONG Max)
{
  ULONG Count = 0, i;
  CHAR KeyName[256];
  HKEY Key;

  if (AdapterName && AdapterName[0])
  {
    snprintf(KeyName, sizeof(KeyName),
             "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s", AdapterName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
      /* the configured servers first, then the ones the DHCPv6 client of the DHCP service learned (the value is
         written there and removed with the data), then (below) the ones of router advertisements */
      static const WCHAR *const ValueNames[] = { L"NameServer", L"Dhcpv6NameServer" };
      ULONG Source;

      for (Source = 0; Source < ARRAYSIZE(ValueNames); Source++)
      {
      WCHAR Value[512];
      DWORD Type, Size = sizeof(Value) - sizeof(WCHAR);

      if (RegQueryValueExW(Key, ValueNames[Source], NULL, &Type, (LPBYTE)Value, &Size) == ERROR_SUCCESS &&
          Type == REG_SZ)
      {
        PWCHAR Cursor = Value, Token;

        Value[Size / sizeof(WCHAR)] = L'\0';
        while (Count < Max)
        {
          IN6_ADDR Address;
          ULONG Scope = 0;
          USHORT Port = 0;
          WCHAR Saved;

          while (*Cursor == L',' || *Cursor == L';' || *Cursor == L' ')
            Cursor++;
          if (!*Cursor)
            break;
          Token = Cursor;
          while (*Cursor && *Cursor != L',' && *Cursor != L';' && *Cursor != L' ')
            Cursor++;
          Saved = *Cursor;
          *Cursor = L'\0';

          /* IPv4 text (the other key's servers) is not ours; a link-local server needs its zone */
          if (NT_SUCCESS(RtlIpv6StringToAddressExW(Token, &Address, &Scope, &Port)) && Port == 0 &&
              IsUsableServer(Address.u.Byte))
          {
            BOOL LinkLocal = Address.u.Byte[0] == 0xFE && (Address.u.Byte[1] & 0xC0) == 0x80;

            if (LinkLocal && Scope == 0)
              Scope = IfIndex;
            if (!LinkLocal)
              Scope = 0;
            if (!AlreadyListed(List, Count, Address.u.Byte, Scope))
            {
              memcpy(List[Count].Address, Address.u.Byte, 16);
              List[Count].Scope = Scope;
              Count++;
            }
          }
          *Cursor = Saved;
        }
      }
      }
      RegCloseKey(Key);
    }
  }

  for (i = 0; State && State->Header && i < State->Header->Count && Count < Max; i++)
  {
    const TCP_IPV6_DNS_ROW *Row = &State->Rows[i];
    BOOL LinkLocal = Row->Address[0] == 0xFE && (Row->Address[1] & 0xC0) == 0x80;
    ULONG Scope = LinkLocal ? Row->IfIndex : 0;

    if (Row->Kind != TCP_IPV6_DNS_SERVER || Row->IfIndex != IfIndex || !IsUsableServer(Row->Address))
      continue;
    if (AlreadyListed(List, Count, Row->Address, Scope))
      continue;
    memcpy(List[Count].Address, Row->Address, 16);
    List[Count].Scope = Scope;
    Count++;
  }

  return Count;
}

/* Up to Max default routers of the interface into List; returns how many */
ULONG Ipv6CollectGateways(const IPV6_DNS_STATE *State, DWORD IfIndex, PIPV6_ADAPTER_SERVER List, ULONG Max)
{
  ULONG Count = 0, i;

  for (i = 0; State && State->Header && i < State->Header->Count && Count < Max; i++)
  {
    const TCP_IPV6_DNS_ROW *Row = &State->Rows[i];
    BOOL LinkLocal = Row->Address[0] == 0xFE && (Row->Address[1] & 0xC0) == 0x80;
    ULONG Scope = LinkLocal ? Row->IfIndex : 0;

    if (Row->Kind != TCP_IPV6_DNS_ROUTER || Row->IfIndex != IfIndex)
      continue;
    if (AlreadyListed(List, Count, Row->Address, Scope))
      continue;
    memcpy(List[Count].Address, Row->Address, 16);
    List[Count].Scope = Scope;
    Count++;
  }

  return Count;
}

/* The search domains of router advertisements, from an open handle to the stack. FALSE: IPv6 is off, or the stack
   does not know the query; State is empty then. Release with Ipv6FreeRa */
BOOL Ipv6GetRaFromFile(HANDLE TcpFile, PIPV6_RA_STATE State)
{
  PVOID Blob = NULL;
  DWORD Size = 0;
  PTCP_IPV6_RA_HEADER Header;
  NTSTATUS Status;

  RtlZeroMemory(State, sizeof(*State));

  Status = tdiGetSetOfThings(TcpFile, INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER, IP_IPV6_RA_ENTRY_ID,
                             CL_NL_ENTITY, 0, 0, 1, &Blob, &Size);
  if (!NT_SUCCESS(Status) || !Blob)
    return FALSE;

  Header = Blob;
  if (Size < sizeof(*Header) || !Header->Enabled || Header->Count > 0xFFFF ||
      (SIZE_T)sizeof(*Header) + (SIZE_T)Header->Count * sizeof(TCP_IPV6_RA_ROW) > Size)
  {
    tdiFreeThingSet(Blob);
    return FALSE;
  }

  State->Memory = Blob;
  State->Header = Header;
  State->Rows = (PTCP_IPV6_RA_ROW)(Header + 1);
  return TRUE;
}

VOID Ipv6FreeRa(PIPV6_RA_STATE State)
{
  if (State->Memory)
    tdiFreeThingSet(State->Memory);
  RtlZeroMemory(State, sizeof(*State));
}

/* Up to Max search domains of the interface into List (each once, a name the stack could not have made is
   skipped); returns how many */
ULONG Ipv6CollectSuffixes(const IPV6_RA_STATE *State, DWORD IfIndex, PCSTR AdapterName, PIPV6_ADAPTER_SUFFIX List,
                          ULONG Max)
{
  ULONG Count = 0, i, k;

  /* the domains the DHCPv6 client of the DHCP service learned come first (option 24, blank separated), then the
     ones of router advertisements */
  if (AdapterName && AdapterName[0])
  {
    /* the service writes up to 16 names of up to 253 characters, blank separated (dhcp6.c): 4064 bytes */
    CHAR KeyName[256], Value[4096];
    HKEY Key;

    snprintf(KeyName, sizeof(KeyName),
             "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s", AdapterName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
      DWORD Type, Size = sizeof(Value) - 1;

      if (RegQueryValueExA(Key, "Dhcpv6DomainSearchList", NULL, &Type, (LPBYTE)Value, &Size) == ERROR_SUCCESS &&
          Type == REG_SZ)
      {
        PSTR Cursor = Value;

        Value[Size] = '\0';
        while (Count < Max)
        {
          PSTR Token;
          BOOL Seen = FALSE;

          while (*Cursor == ' ')
            Cursor++;
          if (!*Cursor)
            break;
          Token = Cursor;
          while (*Cursor && *Cursor != ' ')
            Cursor++;
          if (*Cursor)
            *Cursor++ = '\0';
          if (strlen(Token) >= sizeof(List[0].Name))
            continue;
          for (k = 0; k < Count; k++)
          {
            if (!_stricmp(List[k].Name, Token))
              Seen = TRUE;
          }
          if (!Seen)
          {
            strcpy(List[Count].Name, Token);
            Count++;
          }
        }
      }
      RegCloseKey(Key);
    }
  }

  for (i = 0; State && State->Header && i < State->Header->Count && Count < Max; i++)
  {
    const TCP_IPV6_RA_ROW *Row = &State->Rows[i];
    BOOL Seen = FALSE;

    if (Row->IfIndex != IfIndex || Row->Name[0] == '\0' || memchr(Row->Name, '\0', sizeof(Row->Name)) == NULL)
      continue;
    for (k = 0; k < Count; k++)
    {
      if (!_stricmp(List[k].Name, Row->Name))
        Seen = TRUE;
    }
    if (Seen)
      continue;
    strcpy(List[Count].Name, Row->Name);
    Count++;
  }

  return Count;
}

/* The DHCPv6 identity of an IPv6 adapter (Dhcpv6Iaid, Dhcpv6ClientDuid and its length of the LH structure) from what
   the DHCP service keeps (base/services/dhcpcsvc/dhcp6.h): the machine's DUID under Tcpip6\Parameters, the IAID
   under the interface's key. Nothing is set while the service has not made them (the members stay zero). */
VOID Ipv6FillDhcpIdentity(PIP_ADAPTER_ADDRESSES_LH Out, PCSTR AdapterName)
{
  CHAR KeyName[256];
  HKEY Key;
  DWORD Type, Size;

  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters", 0, KEY_READ, &Key) ==
      ERROR_SUCCESS)
  {
    Size = sizeof(Out->Dhcpv6ClientDuid);
    if (RegQueryValueExA(Key, "Dhcpv6DUID", NULL, &Type, Out->Dhcpv6ClientDuid, &Size) == ERROR_SUCCESS &&
        Type == REG_BINARY && Size >= 4)
      Out->Dhcpv6ClientDuidLength = Size;
    RegCloseKey(Key);
  }

  if (AdapterName && AdapterName[0])
  {
    snprintf(KeyName, sizeof(KeyName),
             "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s", AdapterName);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &Key) == ERROR_SUCCESS)
    {
      DWORD Iaid = 0;

      Size = sizeof(Iaid);
      if (RegQueryValueExA(Key, "Dhcpv6Iaid", NULL, &Type, (LPBYTE)&Iaid, &Size) == ERROR_SUCCESS && Type == REG_DWORD)
        Out->Dhcpv6Iaid = Iaid;
      RegCloseKey(Key);
    }
  }
}

/* The link-local address of the DHCPv6 server that answered the DHCP service last (Dhcpv6ServerAddress under the
   interface's Tcpip6 key, written by the service); FALSE when the interface has none */
BOOL Ipv6ReadDhcpServer(PCSTR AdapterName, PUCHAR Address)
{
  CHAR KeyName[256], Text[64];
  HKEY Key;
  DWORD Type, Size = sizeof(Text) - 1;
  BOOL Found = FALSE;

  if (!AdapterName || !AdapterName[0])
    return FALSE;
  snprintf(KeyName, sizeof(KeyName),
           "SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\%s", AdapterName);
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyName, 0, KEY_READ, &Key) != ERROR_SUCCESS)
    return FALSE;
  if (RegQueryValueExA(Key, "Dhcpv6ServerAddress", NULL, &Type, (LPBYTE)Text, &Size) == ERROR_SUCCESS && Type == REG_SZ)
  {
    IN6_ADDR Parsed;
    PCSTR End;

    Text[Size] = '\0';
    Text[sizeof(Text) - 1] = '\0';
    if (NT_SUCCESS(RtlIpv6StringToAddressA(Text, &End, &Parsed)) && *End == '\0')
    {
      memcpy(Address, &Parsed, 16);
      Found = TRUE;
    }
  }
  RegCloseKey(Key);
  return Found;
}
