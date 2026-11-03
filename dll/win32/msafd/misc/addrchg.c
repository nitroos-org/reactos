/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS Ancillary Function Driver DLL
 * FILE:        dll/win32/msafd/misc/addrchg.c
 * PURPOSE:     SIO_ADDRESS_LIST_CHANGE, FD_ADDRESS_LIST_CHANGE and SIO_ADDRESS_LIST_QUERY
 */

/*
 * The change of the local address list comes from tcpip, the source NotifyAddrChange uses
 * (IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST on \Device\Tcp). The requests of all sockets of the
 * process share one worker thread and one request in the driver:
 *
 *  - blocking socket, no OVERLAPPED: the call waits for the change;
 *  - non-blocking socket, no OVERLAPPED: the call fails with WSAEWOULDBLOCK and arms the
 *    socket. The next change signals the event of WSAEventSelect (or posts the message of
 *    WSAAsyncSelect) if FD_ADDRESS_LIST_CHANGE is selected at that time, and disarms the
 *    socket (the application issues the ioctl again);
 *  - OVERLAPPED: the call fails with WSA_IO_PENDING and the request completes on the change
 *    (event, completion routine or the completion port of the socket).
 *
 * Closing the socket completes its requests with STATUS_CANCELLED (a blocked call returns
 * WSAEINTR). All the state is under AddrChangeLock; a completion is made with the lock held,
 * with calls that cannot block, so a request is never completed for a socket that is gone.
 */

#include <msafd.h>
#include <tcpioctl.h>

#ifndef IS_INTRESOURCE
#define IS_INTRESOURCE(x) ((((ULONG_PTR)(x)) >> 16) == 0)
#endif

/* The most requests one process keeps waiting */
#define MAX_ADDR_WAITERS 1024

typedef struct _ADDR_WAITER
{
    LIST_ENTRY Link;
    PSOCKET_INFORMATION Socket;
    SOCKET Handle;
    LPWSAOVERLAPPED Overlapped;                     /* the overlapped form */
    LPWSAOVERLAPPED_COMPLETION_ROUTINE Routine;
    HANDLE Thread;                                  /* the issuing thread, for the completion routine */
    HANDLE BlockEvent;                              /* the blocking form: signalled on completion */
    NTSTATUS Result;
    BOOLEAN Done;
} ADDR_WAITER, *PADDR_WAITER;

typedef struct _ADDR_APC
{
    LPWSAOVERLAPPED_COMPLETION_ROUTINE Routine;
    LPWSAOVERLAPPED Overlapped;
    DWORD Error;
} ADDR_APC, *PADDR_APC;

static CRITICAL_SECTION AddrChangeLock;
static LIST_ENTRY AddrWaiters;
static ULONG AddrWaiterCount;
static BOOLEAN AddrThreadRunning;   /* a worker exists and will look at the list again before it exits */
static BOOLEAN AddrRequestPending;  /* the worker's request is in the driver */
static HANDLE AddrTcpFile;          /* valid while AddrRequestPending */

VOID
MsafdAddrChangeInit(VOID)
{
    InitializeCriticalSection(&AddrChangeLock);
    InitializeListHead(&AddrWaiters);
}

VOID
MsafdAddrChangeExit(VOID)
{
    DeleteCriticalSection(&AddrChangeLock);
}

static
VOID
CALLBACK
AddrApc(ULONG_PTR Param)
{
    PADDR_APC Apc = (PADDR_APC)Param;

    Apc->Routine(Apc->Error, 0, Apc->Overlapped, 0);
    HeapFree(GlobalHeap, 0, Apc);
}

/* Lock held. Wakes the worker out of its wait in the driver, if it has no request to serve */
static
VOID
CancelDriverRequestIfIdle(VOID)
{
    IO_STATUS_BLOCK Iosb;

    if (!IsListEmpty(&AddrWaiters) || !AddrRequestPending)
        return;

    NtDeviceIoControlFile(AddrTcpFile, NULL, NULL, NULL, &Iosb,
                          IOCTL_IP_ADDCHANGE_CANCEL_REQUEST, NULL, 0, NULL, 0);
}

/* Lock held. A change the socket has not reported yet goes out if FD_ADDRESS_LIST_CHANGE is selected */
static
VOID
DeliverPendingLocked(PSOCKET_INFORMATION Socket)
{
    if (!Socket->AddrChangePending)
        return;

    if (Socket->EventObject && (Socket->NetworkEvents & FD_ADDRESS_LIST_CHANGE))
    {
        /* Stays pending for WSAEnumNetworkEvents */
        SetEvent(Socket->EventObject);
    }
    else if (Socket->SharedData->hWnd &&
             (Socket->SharedData->AsyncEvents & FD_ADDRESS_LIST_CHANGE) &&
             !(Socket->SharedData->AsyncDisabledEvents & FD_ADDRESS_LIST_CHANGE))
    {
        Socket->AddrChangePending = FALSE;
        (Upcalls.lpWPUPostMessage)(Socket->SharedData->hWnd,
                                   Socket->SharedData->wMsg,
                                   Socket->Handle,
                                   WSAMAKESELECTREPLY(FD_ADDRESS_LIST_CHANGE, 0));
    }
}

/* Lock held, the waiter is off the list. The overlapped form is freed */
static
VOID
CompleteWaiter(PADDR_WAITER Waiter, NTSTATUS Status)
{
    PSOCKET_INFORMATION Socket = Waiter->Socket;
    PADDR_APC Apc;

    if (Waiter->BlockEvent)
    {
        /* The caller owns the waiter and looks at it after it has taken the lock */
        Waiter->Result = Status;
        Waiter->Done = TRUE;
        SetEvent(Waiter->BlockEvent);
        return;
    }

    if (Waiter->Overlapped)
    {
        LPWSAOVERLAPPED Overlapped = Waiter->Overlapped;

        Overlapped->Internal = Status;
        Overlapped->InternalHigh = 0;

        if (Waiter->Routine)
        {
            /* The routine runs in the thread that issued the call, in an alertable wait */
            Apc = HeapAlloc(GlobalHeap, 0, sizeof(*Apc));
            if (Apc)
            {
                Apc->Routine = Waiter->Routine;
                Apc->Overlapped = Overlapped;
                Apc->Error = TranslateNtStatusError(Status);
                if (!QueueUserAPC(AddrApc, Waiter->Thread, (ULONG_PTR)Apc))
                    HeapFree(GlobalHeap, 0, Apc);
            }
        }
        else
        {
            if (Overlapped->hEvent)
                SetEvent(Overlapped->hEvent);
            /* The port of the socket, if it has one */
            if (!((ULONG_PTR)Overlapped->hEvent & 1))
                PostQueuedCompletionStatus((HANDLE)Waiter->Handle, 0, 0, Overlapped);
        }

        if (Waiter->Thread)
            CloseHandle(Waiter->Thread);
        HeapFree(GlobalHeap, 0, Waiter);
        return;
    }

    /* Armed: Windows keeps the change with the socket until FD_ADDRESS_LIST_CHANGE is selected and enumerated */
    if (NT_SUCCESS(Status))
    {
        Socket->AddrChangePending = TRUE;
        DeliverPendingLocked(Socket);
    }
    HeapFree(GlobalHeap, 0, Waiter);
}

/* Lock held */
static
VOID
CompleteAllWaiters(NTSTATUS Status)
{
    PLIST_ENTRY Entry;

    while (!IsListEmpty(&AddrWaiters))
    {
        Entry = RemoveHeadList(&AddrWaiters);
        AddrWaiterCount--;
        CompleteWaiter(CONTAINING_RECORD(Entry, ADDR_WAITER, Link), Status);
    }
}

static
DWORD
WINAPI
AddrChangeThread(PVOID Param)
{
    HMODULE Module = Param;
    UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\Tcp");
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK Iosb;
    HANDLE Event = NULL, File = NULL;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    /* An asynchronous handle: another thread can cancel the request on it */
    Status = NtOpenFile(&File, FILE_READ_DATA | SYNCHRONIZE, &Attributes, &Iosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
    if (NT_SUCCESS(Status))
        Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);

    if (!NT_SUCCESS(Status))
    {
        EnterCriticalSection(&AddrChangeLock);
        CompleteAllWaiters(Status);
        AddrThreadRunning = FALSE;
        LeaveCriticalSection(&AddrChangeLock);
        goto done;
    }

    for (;;)
    {
        EnterCriticalSection(&AddrChangeLock);
        if (IsListEmpty(&AddrWaiters))
        {
            AddrThreadRunning = FALSE;
            LeaveCriticalSection(&AddrChangeLock);
            break;
        }
        LeaveCriticalSection(&AddrChangeLock);

        Status = NtDeviceIoControlFile(File, Event, NULL, NULL, &Iosb,
                                       IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST, NULL, 0, NULL, 0);
        if (Status == STATUS_PENDING)
        {
            /* The last waiter may have left since the check above: cancel for it */
            EnterCriticalSection(&AddrChangeLock);
            AddrTcpFile = File;
            AddrRequestPending = TRUE;
            CancelDriverRequestIfIdle();
            LeaveCriticalSection(&AddrChangeLock);

            NtWaitForSingleObject(Event, FALSE, NULL);
            Status = Iosb.Status;
        }

        EnterCriticalSection(&AddrChangeLock);
        AddrRequestPending = FALSE;
        AddrTcpFile = NULL;
        if (Status != STATUS_CANCELLED)
        {
            /* A change, or the transport refuses the request: every waiter gets the result */
            CompleteAllWaiters(Status);
        }
        LeaveCriticalSection(&AddrChangeLock);
    }

done:
    if (Event)
        NtClose(Event);
    if (File)
        NtClose(File);
    FreeLibraryAndExitThread(Module, 0);
    return 0;
}

/* Lock held */
static
BOOL
InsertWaiter(PADDR_WAITER Waiter)
{
    HMODULE Module;
    HANDLE Thread;

    if (AddrWaiterCount >= MAX_ADDR_WAITERS)
        return FALSE;

    if (!AddrThreadRunning)
    {
        /* The worker runs msafd's code: keep the DLL mapped until it is gone */
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                                (LPCWSTR)AddrChangeThread, &Module))
            return FALSE;

        Thread = CreateThread(NULL, 0, AddrChangeThread, Module, 0, NULL);
        if (!Thread)
        {
            FreeLibrary(Module);
            return FALSE;
        }
        CloseHandle(Thread);
        AddrThreadRunning = TRUE;
    }

    InsertTailList(&AddrWaiters, &Waiter->Link);
    AddrWaiterCount++;
    return TRUE;
}

INT
MsafdAddressListChange(
    _In_ PSOCKET_INFORMATION Socket,
    _In_ DWORD cbInBuffer,
    _In_ DWORD cbOutBuffer,
    _In_opt_ LPWSAOVERLAPPED lpOverlapped,
    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    PADDR_WAITER Waiter, Other;
    PLIST_ENTRY Entry;
    INT Errno;

    /* The request takes no data */
    if (cbInBuffer != 0 || cbOutBuffer != 0)
        return WSAEINVAL;

    /* A new request starts over: a change kept for an earlier one is not reported to the selection
     * again (.NET repeats the ioctl and WSAEventSelect after each event, without enumerating) */
    EnterCriticalSection(&AddrChangeLock);
    Socket->AddrChangePending = FALSE;
    LeaveCriticalSection(&AddrChangeLock);

    Waiter = HeapAlloc(GlobalHeap, HEAP_ZERO_MEMORY, sizeof(*Waiter));
    if (!Waiter)
        return WSAENOBUFS;

    Waiter->Socket = Socket;
    Waiter->Handle = Socket->Handle;

    if (lpOverlapped)
    {
        Waiter->Overlapped = lpOverlapped;
        Waiter->Routine = lpCompletionRoutine;
        if (lpCompletionRoutine &&
            !DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                             &Waiter->Thread, THREAD_SET_CONTEXT, FALSE, 0))
        {
            HeapFree(GlobalHeap, 0, Waiter);
            return WSAENOBUFS;
        }

        EnterCriticalSection(&AddrChangeLock);
        lpOverlapped->Internal = STATUS_PENDING;
        lpOverlapped->InternalHigh = 0;
        if (!InsertWaiter(Waiter))
        {
            LeaveCriticalSection(&AddrChangeLock);
            if (Waiter->Thread)
                CloseHandle(Waiter->Thread);
            HeapFree(GlobalHeap, 0, Waiter);
            return WSAENOBUFS;
        }
        LeaveCriticalSection(&AddrChangeLock);
        return WSA_IO_PENDING;
    }

    if (Socket->SharedData->NonBlocking)
    {
        /* One arming per socket is enough */
        EnterCriticalSection(&AddrChangeLock);
        for (Entry = AddrWaiters.Flink; Entry != &AddrWaiters; Entry = Entry->Flink)
        {
            Other = CONTAINING_RECORD(Entry, ADDR_WAITER, Link);
            if (Other->Socket == Socket && !Other->Overlapped && !Other->BlockEvent)
                break;
        }
        if (Entry != &AddrWaiters)
        {
            LeaveCriticalSection(&AddrChangeLock);
            HeapFree(GlobalHeap, 0, Waiter);
            return WSAEWOULDBLOCK;
        }
        if (!InsertWaiter(Waiter))
        {
            LeaveCriticalSection(&AddrChangeLock);
            HeapFree(GlobalHeap, 0, Waiter);
            return WSAENOBUFS;
        }
        LeaveCriticalSection(&AddrChangeLock);
        return WSAEWOULDBLOCK;
    }

    /* Blocking: the waiter lives on this thread's stack of the call; the worker or a close completes it */
    Waiter->BlockEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!Waiter->BlockEvent)
    {
        HeapFree(GlobalHeap, 0, Waiter);
        return WSAENOBUFS;
    }

    EnterCriticalSection(&AddrChangeLock);
    if (!InsertWaiter(Waiter))
    {
        LeaveCriticalSection(&AddrChangeLock);
        CloseHandle(Waiter->BlockEvent);
        HeapFree(GlobalHeap, 0, Waiter);
        return WSAENOBUFS;
    }
    LeaveCriticalSection(&AddrChangeLock);

    WaitForSingleObject(Waiter->BlockEvent, INFINITE);

    /* The completion signalled with the lock held: once it is ours, the waiter is nobody else's */
    EnterCriticalSection(&AddrChangeLock);
    LeaveCriticalSection(&AddrChangeLock);

    if (Waiter->Result == STATUS_CANCELLED)
        Errno = WSAEINTR;
    else if (NT_SUCCESS(Waiter->Result))
        Errno = NO_ERROR;
    else
        Errno = TranslateNtStatusError(Waiter->Result);

    CloseHandle(Waiter->BlockEvent);
    HeapFree(GlobalHeap, 0, Waiter);
    return Errno;
}

/* The socket is going away: complete what waits for it */
VOID
MsafdAddrChangeSocketClosing(
    _In_ PSOCKET_INFORMATION Socket)
{
    PLIST_ENTRY Entry, Next;
    PADDR_WAITER Waiter;

    EnterCriticalSection(&AddrChangeLock);
    for (Entry = AddrWaiters.Flink; Entry != &AddrWaiters; Entry = Next)
    {
        Next = Entry->Flink;
        Waiter = CONTAINING_RECORD(Entry, ADDR_WAITER, Link);
        if (Waiter->Socket != Socket)
            continue;

        RemoveEntryList(&Waiter->Link);
        AddrWaiterCount--;
        CompleteWaiter(Waiter, STATUS_CANCELLED);
    }
    CancelDriverRequestIfIdle();
    LeaveCriticalSection(&AddrChangeLock);
}

/* WSPEventSelect, WSPAsyncSelect: the selection changed */
VOID
MsafdAddrChangeSelectionChanged(
    _In_ PSOCKET_INFORMATION Socket)
{
    EnterCriticalSection(&AddrChangeLock);
    DeliverPendingLocked(Socket);
    LeaveCriticalSection(&AddrChangeLock);
}

/* WSPEnumNetworkEvents: FD_ADDRESS_LIST_CHANGE is reported once per change */
BOOLEAN
MsafdAddrChangeTakePending(
    _In_ PSOCKET_INFORMATION Socket)
{
    BOOLEAN Pending;

    EnterCriticalSection(&AddrChangeLock);
    Pending = Socket->AddrChangePending;
    Socket->AddrChangePending = FALSE;
    LeaveCriticalSection(&AddrChangeLock);
    return Pending;
}

/*
 * SIO_ADDRESS_LIST_QUERY: the IPv4 addresses of the host, other than the loopback, as a
 * SOCKET_ADDRESS_LIST. The SOCKADDRs follow the array of SOCKET_ADDRESS in the same buffer.
 */
INT
MsafdQueryAddressList(
    _In_ PSOCKET_INFORMATION Socket,
    _Out_writes_bytes_opt_(cbOutBuffer) LPVOID lpvOutBuffer,
    _In_ DWORD cbOutBuffer,
    _Out_ LPDWORD pcbRet)
{
    INTERFACE_INFO *Info = NULL;
    DWORD InfoSize = 16 * sizeof(INTERFACE_INFO), Returned = 0, Count = 0, Needed, i;
    BOOL Completion;
    PSOCKET_ADDRESS_LIST List;
    PSOCKADDR_IN Sockaddr;
    INT Errno = NO_ERROR;

    *pcbRet = 0;

    if (Socket->SharedData->AddressFamily == AF_INET)
    {
        /* The interface list of the helper DLL; it does not say how much room it needs */
        for (;;)
        {
            Info = HeapAlloc(GlobalHeap, 0, InfoSize);
            if (!Info)
                return WSAENOBUFS;

            Returned = 0;
            Completion = FALSE;
            Errno = Socket->HelperData->WSHIoctl(Socket->HelperContext, Socket->Handle,
                                                 Socket->TdiAddressHandle, Socket->TdiConnectionHandle,
                                                 SIO_GET_INTERFACE_LIST, NULL, 0, Info, InfoSize,
                                                 &Returned, NULL, NULL, &Completion);
            if (Errno != WSAEFAULT || InfoSize >= 1024 * sizeof(INTERFACE_INFO))
                break;

            HeapFree(GlobalHeap, 0, Info);
            Info = NULL;
            InfoSize *= 2;
        }

        if (Errno != NO_ERROR)
        {
            HeapFree(GlobalHeap, 0, Info);
            return Errno == WSAEFAULT ? WSAENOBUFS : Errno;
        }

        Returned /= sizeof(INTERFACE_INFO);
        for (i = 0; i < Returned; i++)
        {
            ULONG Address = Info[i].iiAddress.AddressIn.sin_addr.s_addr;

            if (Address != 0 && (Address & 0xFF) != 127)
                Count++;
        }
    }

    Needed = FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address) +
             Count * (sizeof(SOCKET_ADDRESS) + sizeof(SOCKADDR_IN));
    *pcbRet = Needed;

    if (IS_INTRESOURCE(lpvOutBuffer))
    {
        Errno = WSAEFAULT;
    }
    else if (cbOutBuffer < sizeof(INT))
    {
        Errno = WSAEINVAL;
        *pcbRet = 0;
    }
    else if (cbOutBuffer < Needed)
    {
        Errno = WSAEFAULT;
    }
    else
    {
        List = lpvOutBuffer;
        Sockaddr = (PSOCKADDR_IN)((PUCHAR)List + FIELD_OFFSET(SOCKET_ADDRESS_LIST, Address) +
                                  Count * sizeof(SOCKET_ADDRESS));
        List->iAddressCount = Count;
        Count = 0;
        for (i = 0; Info && i < Returned; i++)
        {
            ULONG Address = Info[i].iiAddress.AddressIn.sin_addr.s_addr;

            if (Address == 0 || (Address & 0xFF) == 127)
                continue;

            RtlZeroMemory(Sockaddr, sizeof(*Sockaddr));
            Sockaddr->sin_family = AF_INET;
            Sockaddr->sin_addr.s_addr = Address;
            List->Address[Count].lpSockaddr = (LPSOCKADDR)Sockaddr;
            List->Address[Count].iSockaddrLength = sizeof(*Sockaddr);
            Sockaddr++;
            Count++;
        }
        Errno = NO_ERROR;
    }

    if (Info)
        HeapFree(GlobalHeap, 0, Info);
    return Errno;
}
