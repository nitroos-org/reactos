/*
 * PROJECT:     ReactOS IP Helper API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     NotifyIpInterfaceChange, NotifyUnicastIpAddressChange, NotifyRouteChange2,
 *              CancelMibChangeNotify2
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "iphlpapi_private.h"
#include <wine/netioapi.h>
#include "ipv6net.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

/*
 * Each registration has a worker thread. tcpip.sys completes a pending request when the IPv4 or IPv6 address table
 * (also an interface or a link coming or going) or the route table (IPv4 routes, IPv6 default routers and
 * on-link prefixes) changes; the worker then takes a new
 * snapshot of the table, compares it with the last one and calls back for each row that was added, deleted
 * or changed. The request is queued again before the snapshot is taken, so a change in between is not lost.
 *
 * As on Windows 10, the initial notification is made by the caller's thread before the Notify function
 * returns, and CancelMibChangeNotify2 waits for a callback that is running. Windows deadlocks when a callback
 * cancels its own registration; here that call returns without waiting and the registration is freed when the
 * callback returns.
 */

enum { KIND_INTERFACE, KIND_UNICAST, KIND_ROUTE, KIND_STABLE };

typedef VOID (WINAPI *MIB_CALLBACK)(PVOID Context, PVOID Row, MIB_NOTIFICATION_TYPE Type);

typedef struct _MIB_NOTIFY
{
  struct _MIB_NOTIFY *Next;
  int Kind;
  MIB_CALLBACK Callback;
  PVOID Context;
  HANDLE Thread;
  HANDLE Stop;
  HANDLE File;
  HANDLE IoEvent;
  DWORD ThreadId;
  HMODULE Module;               /* this DLL, held for the worker */
  BOOL Detached;                /* a callback cancelled its own registration: the worker frees it */
  ADDRESS_FAMILY Family;        /* AF_UNSPEC, AF_INET or AF_INET6 */
  PVOID Rows;                   /* the last snapshot */
  ULONG Count;
} MIB_NOTIFY;

static MIB_NOTIFY *NotifyHead;
static CRITICAL_SECTION RegistrationLock;

void NotifyRegistrationInit(void)
{
  InitializeCriticalSection(&RegistrationLock);
}

void NotifyRegistrationFree(void)
{
  DeleteCriticalSection(&RegistrationLock);
}

/* ---- the tables ---- */

typedef struct _KIND_OPS
{
  SIZE_T RowSize;
  DWORD (*Snapshot)(ADDRESS_FAMILY Family, PVOID *Rows, ULONG *Count);
  BOOL (*SameKey)(const void *A, const void *B);
  BOOL (*SameData)(const void *A, const void *B);
  ULONG IoControl;
} KIND_OPS;

static DWORD snapshot_interfaces(ADDRESS_FAMILY Family, PVOID *Rows, ULONG *Count)
{
  PMIB_IPINTERFACE_TABLE Table;
  DWORD Result = GetIpInterfaceTable(Family, &Table);

  if (Result != NO_ERROR)
    return Result;
  *Count = Table->NumEntries;
  *Rows = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(Table->NumEntries + 1) * sizeof(MIB_IPINTERFACE_ROW));
  if (*Rows)
    memcpy(*Rows, Table->Table, (SIZE_T)Table->NumEntries * sizeof(MIB_IPINTERFACE_ROW));
  FreeMibTable(Table);
  return *Rows ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}

static BOOL same_interface_key(const void *A, const void *B)
{
  const MIB_IPINTERFACE_ROW *X = A, *Y = B;
  return X->Family == Y->Family && X->InterfaceLuid.Value == Y->InterfaceLuid.Value;
}

static BOOL same_interface_data(const void *A, const void *B)
{
  return !memcmp(A, B, sizeof(MIB_IPINTERFACE_ROW));
}

static DWORD snapshot_unicast(ADDRESS_FAMILY Family, PVOID *Rows, ULONG *Count)
{
  PMIB_UNICASTIPADDRESS_TABLE Table;
  DWORD Result = GetUnicastIpAddressTable(Family, &Table);

  if (Result != NO_ERROR)
    return Result;
  *Count = Table->NumEntries;
  *Rows = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)(Table->NumEntries + 1) * sizeof(MIB_UNICASTIPADDRESS_ROW));
  if (*Rows)
    memcpy(*Rows, Table->Table, (SIZE_T)Table->NumEntries * sizeof(MIB_UNICASTIPADDRESS_ROW));
  FreeMibTable(Table);
  return *Rows ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}

/* The same IPv4 or IPv6 address (the scope id of an IPv6 one follows the interface, which is in the key) */
static BOOL same_address(const SOCKADDR_INET *A, const SOCKADDR_INET *B)
{
  if (A->si_family != B->si_family)
    return FALSE;
  if (A->si_family == AF_INET6)
    return !memcmp(&A->Ipv6.sin6_addr, &B->Ipv6.sin6_addr, sizeof(A->Ipv6.sin6_addr));
  return A->Ipv4.sin_addr.s_addr == B->Ipv4.sin_addr.s_addr;
}

static BOOL same_unicast_key(const void *A, const void *B)
{
  const MIB_UNICASTIPADDRESS_ROW *X = A, *Y = B;
  return X->InterfaceLuid.Value == Y->InterfaceLuid.Value && same_address(&X->Address, &Y->Address);
}

/* The lifetimes of a lease and the time stamp are not compared: they change with the clock. */
static BOOL same_unicast_data(const void *A, const void *B)
{
  const MIB_UNICASTIPADDRESS_ROW *X = A, *Y = B;
  return X->PrefixOrigin == Y->PrefixOrigin && X->SuffixOrigin == Y->SuffixOrigin &&
         X->OnLinkPrefixLength == Y->OnLinkPrefixLength && X->SkipAsSource == Y->SkipAsSource &&
         X->DadState == Y->DadState && X->InterfaceIndex == Y->InterfaceIndex;
}

static DWORD snapshot_routes(ADDRESS_FAMILY Family, PVOID *Rows, ULONG *Count)
{
  PMIB_IPFORWARD_ROW2 Rows4 = NULL, Rows6 = NULL, Out;
  ULONG Count4 = 0, Count6 = 0;
  DWORD Result;

  if (Family != AF_INET6)
  {
    Result = Ipv4GetRouteRows(&Rows4, &Count4);
    if (Result != NO_ERROR)
      return Result;
  }
  if (Family != AF_INET)
  {
    Result = Ipv6GetRouteRows(&Rows6, &Count6);
    if (Result != NO_ERROR)
    {
      HeapFree(GetProcessHeap(), 0, Rows4);
      return Result;
    }
  }

  Out = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)(Count4 + Count6 + 1) * sizeof(*Out));
  if (Out)
  {
    if (Count4)
      memcpy(Out, Rows4, (SIZE_T)Count4 * sizeof(*Out));
    if (Count6)
      memcpy(Out + Count4, Rows6, (SIZE_T)Count6 * sizeof(*Out));
    *Rows = Out;
    *Count = Count4 + Count6;
  }
  HeapFree(GetProcessHeap(), 0, Rows4);
  HeapFree(GetProcessHeap(), 0, Rows6);
  return Out ? NO_ERROR : ERROR_NOT_ENOUGH_MEMORY;
}

static BOOL same_route_key(const void *A, const void *B)
{
  const MIB_IPFORWARD_ROW2 *X = A, *Y = B;
  return X->InterfaceIndex == Y->InterfaceIndex &&
         X->DestinationPrefix.PrefixLength == Y->DestinationPrefix.PrefixLength &&
         same_address(&X->DestinationPrefix.Prefix, &Y->DestinationPrefix.Prefix) &&
         same_address(&X->NextHop, &Y->NextHop) &&
         X->Metric == Y->Metric;
}

/* A route whose metric changes is a deleted route and an added one: the metric is part of the key. */
static BOOL same_route_data(const void *A, const void *B)
{
  const MIB_IPFORWARD_ROW2 *X = A, *Y = B;
  return X->Protocol == Y->Protocol;
}

static const KIND_OPS Kinds[] =
{
  { sizeof(MIB_IPINTERFACE_ROW), snapshot_interfaces, same_interface_key, same_interface_data, IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST },
  { sizeof(MIB_UNICASTIPADDRESS_ROW), snapshot_unicast, same_unicast_key, same_unicast_data, IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST },
  { sizeof(MIB_IPFORWARD_ROW2), snapshot_routes, same_route_key, same_route_data, IOCTL_IP_ROUTECHANGE_NOTIFY_REQUEST },
};

/* ---- the worker ---- */

static BOOL is_stopping(MIB_NOTIFY *Notify)
{
  return WaitForSingleObject(Notify->Stop, 0) == WAIT_OBJECT_0;
}

/* Calls back for what differs between the last snapshot and a new one, and keeps the new one. */
static void report_changes(MIB_NOTIFY *Notify)
{
  const KIND_OPS *Ops = &Kinds[Notify->Kind];
  PVOID NewRows = NULL;
  ULONG NewCount = 0, i, j;
  BYTE *Old, *New;

  if (Ops->Snapshot(Notify->Family, &NewRows, &NewCount) != NO_ERROR)
    return;

  Old = Notify->Rows;
  New = NewRows;

  /* deleted rows first, then the new and the changed ones */
  for (i = 0; i < Notify->Count && !is_stopping(Notify); i++)
  {
    for (j = 0; j < NewCount; j++)
      if (Ops->SameKey(Old + i * Ops->RowSize, New + j * Ops->RowSize))
        break;
    if (j == NewCount)
      Notify->Callback(Notify->Context, Old + i * Ops->RowSize, MibDeleteInstance);
  }
  for (j = 0; j < NewCount && !is_stopping(Notify); j++)
  {
    for (i = 0; i < Notify->Count; i++)
      if (Ops->SameKey(Old + i * Ops->RowSize, New + j * Ops->RowSize))
        break;
    if (i == Notify->Count)
      Notify->Callback(Notify->Context, New + j * Ops->RowSize, MibAddInstance);
    else if (!Ops->SameData(Old + i * Ops->RowSize, New + j * Ops->RowSize))
      Notify->Callback(Notify->Context, New + j * Ops->RowSize, MibParameterNotification);
  }

  HeapFree(GetProcessHeap(), 0, Notify->Rows);
  Notify->Rows = NewRows;
  Notify->Count = NewCount;
}

static void free_notify(MIB_NOTIFY *Notify)
{
  if (Notify->File)
    NtClose(Notify->File);
  if (Notify->IoEvent)
    CloseHandle(Notify->IoEvent);
  if (Notify->Stop)
    CloseHandle(Notify->Stop);
  if (Notify->Thread)
    CloseHandle(Notify->Thread);
  HeapFree(GetProcessHeap(), 0, Notify->Rows);
  HeapFree(GetProcessHeap(), 0, Notify);
}

static void notify_worker_main(MIB_NOTIFY *Notify)
{
  const KIND_OPS *Ops = &Kinds[Notify->Kind];
  IO_STATUS_BLOCK Iosb;
  NTSTATUS Status;
  HANDLE Wait[2];
  BOOL Detached;

  /* a request wakes for the families that were asked for: the stack keeps IPv4 and IPv6 changes apart, as Windows */
  ULONG Families = (Notify->Family == AF_INET) ? TCP_CHANGE_FAMILY_IPV4 :
                   (Notify->Family == AF_INET6) ? TCP_CHANGE_FAMILY_IPV6 :
                   (TCP_CHANGE_FAMILY_IPV4 | TCP_CHANGE_FAMILY_IPV6);

  Wait[0] = Notify->IoEvent;
  Wait[1] = Notify->Stop;

  while (!is_stopping(Notify))
  {
    /* queue the request first: a change after it is queued completes it, however soon the snapshot is taken */
    ResetEvent(Notify->IoEvent);
    Iosb.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(Notify->File, Notify->IoEvent, NULL, NULL, &Iosb,
                                   Ops->IoControl, &Families, sizeof(Families), NULL, 0);
    if (Status == STATUS_NOT_IMPLEMENTED || Status == STATUS_NOT_SUPPORTED || Status == STATUS_INVALID_DEVICE_REQUEST)
    {
      /* an older tcpip.sys without this request: there is nothing to wait for, so do not poll */
      WaitForSingleObject(Notify->Stop, INFINITE);
      break;
    }
    if (!NT_SUCCESS(Status))
    {
      /* nothing to wait on: look again in a second, or leave when stopped */
      if (WaitForSingleObject(Notify->Stop, 1000) == WAIT_OBJECT_0)
        break;
      report_changes(Notify);
      continue;
    }

    report_changes(Notify);

    if (WaitForMultipleObjects(2, Wait, FALSE, INFINITE) != WAIT_OBJECT_0)
    {
      /* stopped with the request still queued: complete it before Iosb goes away */
      NtDeviceIoControlFile(Notify->File, NULL, NULL, NULL, &Iosb,
                            IOCTL_IP_ADDCHANGE_CANCEL_REQUEST, NULL, 0, NULL, 0);
      WaitForSingleObject(Notify->IoEvent, INFINITE);
      break;
    }
  }

  EnterCriticalSection(&RegistrationLock);
  Detached = Notify->Detached;
  LeaveCriticalSection(&RegistrationLock);
  if (Detached)
    free_notify(Notify);
}

/*
 * The worker holds a reference of this DLL until it is done, and leaves through FreeLibraryAndExitThread: a
 * FreeLibrary of the application cannot unmap the code of a worker that still runs. A registration that is not
 * cancelled therefore keeps the DLL loaded.
 */
static DWORD WINAPI notify_worker(PVOID Parameter)
{
  HMODULE Module = ((MIB_NOTIFY *)Parameter)->Module;

  notify_worker_main(Parameter);
  FreeLibraryAndExitThread(Module, 0);
  return 0;
}

static VOID WINAPI no_callback(PVOID Context, PVOID Row, MIB_NOTIFICATION_TYPE Type)
{
}

static DWORD register_notify(int Kind, ADDRESS_FAMILY Family, PVOID Callback, PVOID Context,
                             BOOLEAN InitialNotification, HANDLE *NotificationHandle)
{
  MIB_NOTIFY *Notify;
  UNICODE_STRING Name;
  OBJECT_ATTRIBUTES Attrs;
  IO_STATUS_BLOCK Iosb;
  NTSTATUS Status;
  DWORD Result;

  if ((Family != AF_UNSPEC && Family != AF_INET && Family != AF_INET6) || !NotificationHandle)
    return ERROR_INVALID_PARAMETER;

  Notify = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Notify));
  if (!Notify)
    return ERROR_NOT_ENOUGH_MEMORY;
  Notify->Kind = Kind;
  /* Windows accepts no callback and faults on the first change; this never calls one */
  Notify->Callback = Callback ? Callback : no_callback;
  Notify->Context = Context;
  Notify->Family = Family;

  {
    Notify->Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
    Notify->IoEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    RtlInitUnicodeString(&Name, L"\\Device\\Tcp");
    InitializeObjectAttributes(&Attrs, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Notify->File, FILE_READ_DATA | SYNCHRONIZE, &Attrs, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (!Notify->Stop || !Notify->IoEvent || !NT_SUCCESS(Status))
    {
      Result = NT_SUCCESS(Status) ? ERROR_NOT_ENOUGH_MEMORY : RtlNtStatusToDosError(Status);
      if (!NT_SUCCESS(Status))
        Notify->File = NULL;
      free_notify(Notify);
      return Result;
    }
    Result = Kinds[Kind].Snapshot(Family, &Notify->Rows, &Notify->Count);
    if (Result != NO_ERROR)
    {
      free_notify(Notify);
      return Result;
    }
  }

  /* the initial notification comes from this thread, before the call returns: one per address family, so
     two for AF_UNSPEC while the stack has IPv6 (Windows 10, oracle probe) */
  if (InitialNotification)
  {
    ULONG Initial = 1;

    if (Family == AF_UNSPEC)
    {
      IPV6_STATE V6;

      if (Ipv6GetState(&V6))
      {
        Initial = 2;
        Ipv6FreeState(&V6);
      }
    }
    while (Initial--)
      Notify->Callback(Context, NULL, MibInitialNotification);
  }

  if (Notify->File)
  {
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)notify_worker, &Notify->Module))
    {
      Result = GetLastError();
      free_notify(Notify);
      return Result;
    }
    Notify->Thread = CreateThread(NULL, 0, notify_worker, Notify, CREATE_SUSPENDED, &Notify->ThreadId);
    if (!Notify->Thread)
    {
      Result = GetLastError();
      FreeLibrary(Notify->Module);
      free_notify(Notify);
      return Result;
    }
  }

  EnterCriticalSection(&RegistrationLock);
  Notify->Next = NotifyHead;
  NotifyHead = Notify;
  LeaveCriticalSection(&RegistrationLock);

  if (Notify->Thread)
    ResumeThread(Notify->Thread);

  *NotificationHandle = Notify;
  return NO_ERROR;
}

DWORD WINAPI NotifyIpInterfaceChange(ADDRESS_FAMILY Family, PVOID Callback, PVOID CallerContext,
                                     BOOLEAN InitialNotification, HANDLE *NotificationHandle)
{
  return register_notify(KIND_INTERFACE, Family, Callback, CallerContext, InitialNotification, NotificationHandle);
}

DWORD WINAPI NotifyUnicastIpAddressChange(ADDRESS_FAMILY Family, PVOID Callback, PVOID CallerContext,
                                          BOOLEAN InitialNotification, HANDLE *NotificationHandle)
{
  return register_notify(KIND_UNICAST, Family, Callback, CallerContext, InitialNotification, NotificationHandle);
}

typedef VOID (WINAPI *STABLE_CALLBACK)(PVOID Context, PMIB_UNICASTIPADDRESS_TABLE Table);

/* An address whose duplicate address detection is under way. The probes are only sent while the interface has its
   link: an address of an interface without one (cable out) stays tentative until the link comes, so it does not
   make the table unstable, or a caller would wait for as long as the cable is out */
static BOOL has_tentative(const MIB_UNICASTIPADDRESS_TABLE *Table)
{
  ULONG i;

  for (i = 0; i < Table->NumEntries; i++)
  {
    MIB_IPINTERFACE_ROW Interface;

    if (Table->Table[i].DadState != IpDadStateTentative)
      continue;
    memset(&Interface, 0, sizeof(Interface));
    Interface.Family = Table->Table[i].Address.si_family;
    Interface.InterfaceLuid = Table->Table[i].InterfaceLuid;
    if (GetIpInterfaceEntry(&Interface) == NO_ERROR && !Interface.Connected)
      continue;
    return TRUE;
  }
  return FALSE;
}

/*
 * The worker of a registration for a table that was not stable: looks again every quarter of a second (an address
 * leaves the tentative state after the probes of duplicate address detection, about a second), gives the first stable
 * table to the callback and is done. The registration stays until CancelMibChangeNotify2, as with the others.
 */
static void stable_worker_main(MIB_NOTIFY *Notify)
{
  BOOL Detached;

  while (WaitForSingleObject(Notify->Stop, 250) == WAIT_TIMEOUT)
  {
    PMIB_UNICASTIPADDRESS_TABLE Table;

    if (GetUnicastIpAddressTable(Notify->Family, &Table) != NO_ERROR)
      continue;
    if (has_tentative(Table))
    {
      FreeMibTable(Table);
      continue;
    }
    if (!is_stopping(Notify) && Notify->Callback != no_callback)
      ((STABLE_CALLBACK)Notify->Callback)(Notify->Context, Table);
    else
      FreeMibTable(Table);
    break;
  }

  EnterCriticalSection(&RegistrationLock);
  Detached = Notify->Detached;
  LeaveCriticalSection(&RegistrationLock);
  if (Detached)
    free_notify(Notify);
}

static DWORD WINAPI stable_worker(PVOID Parameter)
{
  HMODULE Module = ((MIB_NOTIFY *)Parameter)->Module;

  stable_worker_main(Parameter);
  FreeLibraryAndExitThread(Module, 0);
  return 0;
}

/*
 * Returns the unicast address table at once when it is stable (no address is tentative: duplicate address
 * detection of an IPv6 address is still under way), with no notification handle. Otherwise ERROR_IO_PENDING, no
 * table, and a handle: the callback gets the table, once it is stable (the caller frees it with FreeMibTable),
 * and the handle is cancelled with CancelMibChangeNotify2.
 */
DWORD WINAPI NotifyStableUnicastIpAddressTable(ADDRESS_FAMILY Family, PMIB_UNICASTIPADDRESS_TABLE *Table,
                                               PVOID Callback, PVOID CallerContext, HANDLE *NotificationHandle)
{
  MIB_NOTIFY *Notify;
  DWORD Result;

  if (!Table || !NotificationHandle)
    return ERROR_INVALID_PARAMETER;

  *NotificationHandle = NULL;
  Result = GetUnicastIpAddressTable(Family, Table);
  if (Result != NO_ERROR || !has_tentative(*Table))
    return Result;

  /* not stable */
  FreeMibTable(*Table);
  *Table = NULL;

  Notify = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Notify));
  if (!Notify)
    return ERROR_NOT_ENOUGH_MEMORY;
  Notify->Kind = KIND_STABLE;
  Notify->Callback = Callback ? Callback : no_callback;
  Notify->Context = CallerContext;
  Notify->Family = Family;
  Notify->Stop = CreateEventW(NULL, TRUE, FALSE, NULL);
  if (!Notify->Stop || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)stable_worker, &Notify->Module))
  {
    Result = Notify->Stop ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY;
    free_notify(Notify);
    return Result;
  }
  Notify->Thread = CreateThread(NULL, 0, stable_worker, Notify, CREATE_SUSPENDED, &Notify->ThreadId);
  if (!Notify->Thread)
  {
    Result = GetLastError();
    FreeLibrary(Notify->Module);
    free_notify(Notify);
    return Result;
  }

  EnterCriticalSection(&RegistrationLock);
  Notify->Next = NotifyHead;
  NotifyHead = Notify;
  LeaveCriticalSection(&RegistrationLock);

  ResumeThread(Notify->Thread);
  *NotificationHandle = Notify;
  return ERROR_IO_PENDING;
}

DWORD WINAPI NotifyRouteChange2(ADDRESS_FAMILY Family, PVOID Callback, PVOID CallerContext,
                                BOOLEAN InitialNotification, HANDLE *NotificationHandle)
{
  return register_notify(KIND_ROUTE, Family, Callback, CallerContext, InitialNotification, NotificationHandle);
}

/*
 * Waits for a callback that is running, so none runs after this returns. A callback that cancels its own
 * registration does not wait for itself.
 */
DWORD WINAPI CancelMibChangeNotify2(HANDLE NotificationHandle)
{
  MIB_NOTIFY *Notify, **Link;
  BOOL Self = FALSE;

  /* Windows answers ERROR_INVALID_HANDLE for no handle; a handle that was cancelled is unknown as well */
  if (!NotificationHandle)
    return ERROR_INVALID_HANDLE;

  EnterCriticalSection(&RegistrationLock);
  for (Link = &NotifyHead; *Link && *Link != NotificationHandle; Link = &(*Link)->Next)
    ;
  Notify = *Link;
  if (Notify)
  {
    *Link = Notify->Next;
    if (Notify->Thread && Notify->ThreadId == GetCurrentThreadId())
    {
      Notify->Detached = TRUE;
      Self = TRUE;
    }
  }
  LeaveCriticalSection(&RegistrationLock);

  if (!Notify)
    return ERROR_INVALID_HANDLE;

  if (Notify->Stop)
    SetEvent(Notify->Stop);
  if (Self)
    return NO_ERROR;

  if (Notify->Thread)
    WaitForSingleObject(Notify->Thread, INFINITE);
  free_notify(Notify);
  return NO_ERROR;
}
