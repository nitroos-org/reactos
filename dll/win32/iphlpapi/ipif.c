/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     SetIpInterfaceEntry and the per-interface parameters of tcpip.sys (IOCTL_IP_INTERFACE_CONFIG)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * Changes go to the active store (in force at once, gone when the computer restarts or the adapter starts again); the
 * persistent store is written by the same request with TCP_IPV6_STORE_PERSISTENT (Set-NetIPInterface).
 *
 * SetIpInterfaceEntry compares the row with what GetIpInterfaceEntry reports for the interface and sends the stack what
 * differs, for the fields the stack has: NlMtu (0 = not given), UseAutomaticMetric / Metric, RouterDiscoveryBehavior
 * (0xffffffff = not given), DadTransmits (0xffffffff = not given), ForwardingEnabled. The fields the documentation
 * lists as ignored (MaxReassemblySize, the router advertisement intervals, Connected, SupportsWakeUpPatterns,
 * SupportsNeighborDiscovery, SupportsRouterDiscovery, ReachableTime, the offloads) and the other row fields, which this
 * stack has no setting for (reachability and retransmit times, link-local behaviour, weak host, ...), are ignored.
 * What the stack cannot do is refused: IPv4 router discovery and DAD transmits other than the ones it reports,
 * forwarding on (ERROR_NOT_SUPPORTED); the loopback interface has nothing to set (ERROR_NOT_SUPPORTED).
 */

#include "iphlpapi_private.h"
#include <wine/netioapi.h>
#include "ipv6net.h"
#include <iphlpapi_nitro.h>

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

BOOL IpGetInterfaceConfig(PIP_INTERFACE_CONFIG Config)
{
  HANDLE TcpFile;
  PVOID Blob = NULL;
  DWORD Size = 0;
  PTCP_IP_INTERFACE_HEADER Header;
  NTSTATUS Status;

  RtlZeroMemory(Config, sizeof(*Config));
  if (!NT_SUCCESS(openTcpFile(&TcpFile, FILE_READ_DATA)))
    return FALSE;
  Status = tdiGetSetOfThings(TcpFile, INFO_CLASS_PROTOCOL, INFO_TYPE_PROVIDER, IP_INTERFACE_CONFIG_ENTRY_ID,
                             CL_NL_ENTITY, 0, 0, 1, &Blob, &Size);
  closeTcpFile(TcpFile);
  if (!NT_SUCCESS(Status) || !Blob)
    return FALSE;

  Header = Blob;
  if (Size < sizeof(*Header) || Header->Count > 0xFFFF ||
      (SIZE_T)sizeof(*Header) + (SIZE_T)Header->Count * sizeof(TCP_IP_INTERFACE_ROW) > Size)
  {
    tdiFreeThingSet(Blob);
    return FALSE;
  }
  Config->Memory = Blob;
  Config->Rows = (PTCP_IP_INTERFACE_ROW)(Header + 1);
  Config->Count = Header->Count;
  return TRUE;
}

VOID IpFreeInterfaceConfig(PIP_INTERFACE_CONFIG Config)
{
  if (Config->Memory)
    tdiFreeThingSet(Config->Memory);
  RtlZeroMemory(Config, sizeof(*Config));
}

const TCP_IP_INTERFACE_ROW *IpFindInterfaceConfig(const IP_INTERFACE_CONFIG *Config, DWORD IfIndex)
{
  ULONG i;

  for (i = 0; i < Config->Count; i++)
    if (Config->Rows[i].IfIndex == IfIndex)
      return &Config->Rows[i];
  return NULL;
}

static DWORD status_to_error(NTSTATUS Status)
{
  switch (Status)
  {
    case STATUS_SUCCESS:                return NO_ERROR;
    case STATUS_INVALID_PARAMETER:      return ERROR_INVALID_PARAMETER;
    case STATUS_NOT_FOUND:              return ERROR_NOT_FOUND;
    case STATUS_ACCESS_DENIED:          return ERROR_ACCESS_DENIED;
    case STATUS_NOT_SUPPORTED:          return ERROR_NOT_SUPPORTED;
    case STATUS_INSUFFICIENT_RESOURCES: return ERROR_NOT_ENOUGH_MEMORY;
    default:                            return RtlNtStatusToDosError(Status);
  }
}

DWORD IpSetInterfaceConfig(PTCP_IP_INTERFACE_REQUEST Request, ULONG Store)
{
  HANDLE TcpFile;
  IO_STATUS_BLOCK Iosb;
  NTSTATUS Status;

  Request->Store = Store;
  Status = openTcpFile(&TcpFile, FILE_READ_DATA | FILE_WRITE_DATA);
  if (!NT_SUCCESS(Status))
    return status_to_error(Status);
  Status = NtDeviceIoControlFile(TcpFile, NULL, NULL, NULL, &Iosb, IOCTL_IP_INTERFACE_CONFIG, Request,
                                 sizeof(*Request), NULL, 0);
  closeTcpFile(TcpFile);
  return status_to_error(Status);
}

DWORD WINAPI SetIpInterfaceEntry(PMIB_IPINTERFACE_ROW Row)
{
  MIB_IPINTERFACE_ROW Current;
  TCP_IP_INTERFACE_REQUEST Request;
  DWORD Error;

  if (!Row || (Row->Family != AF_INET && Row->Family != AF_INET6))
    return ERROR_INVALID_PARAMETER;

  /* what the interface has now (this also names the interface: unknown luid / index / family) */
  memset(&Current, 0, sizeof(Current));
  Current.Family = Row->Family;
  Current.InterfaceLuid = Row->InterfaceLuid;
  Current.InterfaceIndex = Row->InterfaceIndex;
  Error = GetIpInterfaceEntry(&Current);
  if (Error != NO_ERROR)
    return Error;
  Row->InterfaceLuid = Current.InterfaceLuid;

  memset(&Request, 0, sizeof(Request));
  Request.Family = (Row->Family == AF_INET6) ? TCP_IPIF_IPV6 : TCP_IPIF_IPV4;
  Request.IfIndex = Current.InterfaceIndex;

  if (Row->NlMtu != 0 && Row->NlMtu != Current.NlMtu)
  {
    Request.Fields |= TCP_IPIF_SET_MTU;
    Request.Mtu = Row->NlMtu;
  }
  if (Row->UseAutomaticMetric)
  {
    if (!Current.UseAutomaticMetric)
      Request.Fields |= TCP_IPIF_SET_METRIC;   /* Metric 0: automatic */
  }
  else if (Current.UseAutomaticMetric || Row->Metric != Current.Metric)
  {
    /* a metric by hand is 1..9999 (0 is what automatic is) */
    if (Row->Metric == 0 || Row->Metric > 9999)
      return ERROR_INVALID_PARAMETER;
    Request.Fields |= TCP_IPIF_SET_METRIC;
    Request.Metric = Row->Metric;
  }
  if (Row->RouterDiscoveryBehavior != 0xffffffff && Row->RouterDiscoveryBehavior != Current.RouterDiscoveryBehavior)
  {
    Request.Fields |= TCP_IPIF_SET_ROUTER_DISCOVERY;
    Request.RouterDiscovery = Row->RouterDiscoveryBehavior;
  }
  if (Row->DadTransmits != 0xffffffff && Row->DadTransmits != Current.DadTransmits)
  {
    Request.Fields |= TCP_IPIF_SET_DAD_TRANSMITS;
    Request.DadTransmits = Row->DadTransmits;
  }
  /* a BOOLEAN of 1 asks for forwarding; Initialize...Entry leaves 0xff there, which names nothing */
  if (Row->ForwardingEnabled == TRUE && !Current.ForwardingEnabled)
  {
    Request.Fields |= TCP_IPIF_SET_FORWARDING;
    Request.Forwarding = 1;
  }
  /* DisableDefaultRoutes is what VPN clients set to stop split tunnelling: the stack has no such switch, and a success
     would tell the caller the default routes of the interface are no longer used when they are */
  if (Row->DisableDefaultRoutes == TRUE && !Current.DisableDefaultRoutes)
    return ERROR_NOT_SUPPORTED;

  /* the loopback interface has none of these to set */
  if (Request.Fields && Current.NlMtu == 0xffffffff)
    return ERROR_NOT_SUPPORTED;

  if (!Request.Fields)
    return NO_ERROR;

  /* the active store, as the other row functions of this DLL (gone when the computer restarts); the persistent one
     is reached through the request alone (Set-NetIPInterface) */
  return IpSetInterfaceConfig(&Request, TCP_IPV6_STORE_ACTIVE);
}

/*
 * The request of SetIpInterfaceEntry with the fields named by the caller, for the private iphlpapi_nitro.h export:
 * what is named is sent, also when it equals the value in force (the persistent store has to get it), and the store
 * is the caller's choice.
 */
DWORD WINAPI NitroConfigureIpInterface(BOOL Persistent, const NITRO_IP_INTERFACE_CONFIG *Config)
{
  TCP_IP_INTERFACE_REQUEST Request;

  if (!Config || (Config->Family != 4 && Config->Family != 6) || Config->InterfaceIndex == 0 || Config->Fields == 0 ||
      (Config->Fields & ~(ULONG)(NITRO_IPIF_MTU | NITRO_IPIF_METRIC | NITRO_IPIF_ROUTER_DISCOVERY |
                                 NITRO_IPIF_DAD_TRANSMITS | NITRO_IPIF_FORWARDING)))
    return ERROR_INVALID_PARAMETER;

  memset(&Request, 0, sizeof(Request));
  Request.Family = (Config->Family == 6) ? TCP_IPIF_IPV6 : TCP_IPIF_IPV4;
  Request.IfIndex = Config->InterfaceIndex;
  if (Config->Fields & NITRO_IPIF_MTU)
  {
    Request.Fields |= TCP_IPIF_SET_MTU;
    Request.Mtu = Config->Mtu;
  }
  if (Config->Fields & NITRO_IPIF_METRIC)
  {
    Request.Fields |= TCP_IPIF_SET_METRIC;
    Request.Metric = Config->Metric;
  }
  if (Config->Fields & NITRO_IPIF_ROUTER_DISCOVERY)
  {
    Request.Fields |= TCP_IPIF_SET_ROUTER_DISCOVERY;
    Request.RouterDiscovery = Config->RouterDiscovery;
  }
  if (Config->Fields & NITRO_IPIF_DAD_TRANSMITS)
  {
    Request.Fields |= TCP_IPIF_SET_DAD_TRANSMITS;
    Request.DadTransmits = Config->DadTransmits;
  }
  if (Config->Fields & NITRO_IPIF_FORWARDING)
  {
    Request.Fields |= TCP_IPIF_SET_FORWARDING;
    Request.Forwarding = Config->Forwarding;
  }
  return IpSetInterfaceConfig(&Request, Persistent ? TCP_IPV6_STORE_PERSISTENT : TCP_IPV6_STORE_ACTIVE);
}
