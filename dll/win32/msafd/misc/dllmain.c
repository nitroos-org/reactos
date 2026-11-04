/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS Ancillary Function Driver DLL
 * FILE:        dll/win32/msafd/misc/dllmain.c
 * PURPOSE:     DLL entry point
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 *              Alex Ionescu (alex@relsoft.net)
 *              Pierre Schweitzer (pierre@reactos.org)
 * REVISIONS:
 *              CSH 01/09-2000 Created
 *              Alex 16/07/2004 - Complete Rewrite
 */

#include <msafd.h>

#include <winuser.h>
#include <wchar.h>

HANDLE GlobalHeap;
WSPUPCALLTABLE Upcalls;
DWORD CatalogEntryId; /* CatalogEntryId for upcalls */
LPWPUCOMPLETEOVERLAPPEDREQUEST lpWPUCompleteOverlappedRequest;
PSOCKET_INFORMATION SocketListHead = NULL;
CRITICAL_SECTION SocketListLock;
/* Serialises the state WSPAsyncSelect, its completion routine and the re-enabling of events change */
CRITICAL_SECTION AsyncSelectLock;
LIST_ENTRY SockHelpersListHead = { NULL, NULL };
ULONG SockAsyncThreadRefCount;
HANDLE SockAsyncHelperAfdHandle;
HANDLE SockAsyncCompletionPort = NULL;
BOOLEAN SockAsyncSelectCalled;



/*
 * FUNCTION: Creates a new socket
 * ARGUMENTS:
 *     af             = Address family
 *     type           = Socket type
 *     protocol       = Protocol type
 *     lpProtocolInfo = Pointer to protocol information
 *     g              = Reserved
 *     dwFlags        = Socket flags
 *     lpErrno        = Address of buffer for error information
 * RETURNS:
 *     Created socket, or INVALID_SOCKET if it could not be created
 */
SOCKET
WSPAPI
WSPSocket(int AddressFamily,
          int SocketType,
          int Protocol,
          LPWSAPROTOCOL_INFOW lpProtocolInfo,
          GROUP g,
          DWORD dwFlags,
          LPINT lpErrno)
{
    OBJECT_ATTRIBUTES           Object;
    IO_STATUS_BLOCK             IOSB;
    USHORT                      SizeOfPacket;
    ULONG                       SizeOfEA;
    PAFD_CREATE_PACKET          AfdPacket;
    HANDLE                      Sock;
    PSOCKET_INFORMATION         Socket = NULL;
    PFILE_FULL_EA_INFORMATION   EABuffer = NULL;
    PHELPER_DATA                HelperData;
    PVOID                       HelperDLLContext;
    DWORD                       HelperEvents;
    UNICODE_STRING              TransportName;
    UNICODE_STRING              DevName;
    LARGE_INTEGER               GroupData;
    INT                         Status;
    PSOCK_SHARED_INFO           SharedData = NULL;

    TRACE("Creating Socket, getting TDI Name - AddressFamily (%d)  SocketType (%d)  Protocol (%d).\n",
        AddressFamily, SocketType, Protocol);

    if (lpProtocolInfo && lpProtocolInfo->dwServiceFlags3 != 0 && lpProtocolInfo->dwServiceFlags4 != 0)
    {
        /* Duplpicating socket from different process */
        if (UlongToPtr(lpProtocolInfo->dwServiceFlags3) == INVALID_HANDLE_VALUE)
        {
            Status = WSAEINVAL;
            goto error;
        }
        if (UlongToPtr(lpProtocolInfo->dwServiceFlags4) == INVALID_HANDLE_VALUE)
        {
            Status = WSAEINVAL;
            goto error;
        }
        SharedData = MapViewOfFile(UlongToPtr(lpProtocolInfo->dwServiceFlags3),
                                   FILE_MAP_ALL_ACCESS,
                                   0,
                                   0,
                                   sizeof(SOCK_SHARED_INFO));
        if (!SharedData)
        {
            Status = WSAEINVAL;
            goto error;
        }
        InterlockedIncrement(&SharedData->RefCount);
        AddressFamily = SharedData->AddressFamily;
        SocketType = SharedData->SocketType;
        Protocol = SharedData->Protocol;
    }

    if (AddressFamily == AF_UNSPEC && SocketType == 0 && Protocol == 0)
    {
        Status = WSAEINVAL;
        goto error;
    }

    /* Set the defaults */
    if (AddressFamily == AF_UNSPEC)
        AddressFamily = AF_INET;

    if (SocketType == 0)
    {
        switch (Protocol)
        {
        case IPPROTO_TCP:
            SocketType = SOCK_STREAM;
            break;
        case IPPROTO_UDP:
            SocketType = SOCK_DGRAM;
            break;
        case IPPROTO_RAW:
            SocketType = SOCK_RAW;
            break;
        default:
            TRACE("Unknown Protocol (%d). We will try SOCK_STREAM.\n", Protocol);
            SocketType = SOCK_STREAM;
            break;
        }
    }

    if (Protocol == 0)
    {
        switch (SocketType)
        {
        case SOCK_STREAM:
            Protocol = IPPROTO_TCP;
            break;
        case SOCK_DGRAM:
            Protocol = IPPROTO_UDP;
            break;
        case SOCK_RAW:
            Protocol = IPPROTO_RAW;
            break;
        default:
            TRACE("Unknown SocketType (%d). We will try IPPROTO_TCP.\n", SocketType);
            Protocol = IPPROTO_TCP;
            break;
        }
    }

    /* Get Helper Data and Transport */
    Status = SockGetTdiName (&AddressFamily,
                             &SocketType,
                             &Protocol,
                             g,
                             dwFlags,
                             &TransportName,
                             &HelperDLLContext,
                             &HelperData,
                             &HelperEvents);

    /* Check for error */
    if (Status != NO_ERROR)
    {
        ERR("SockGetTdiName: Status %x\n", Status);
        goto error;
    }

    /* AFD Device Name */
    RtlInitUnicodeString(&DevName, L"\\Device\\Afd\\Endpoint");

    /* Set Socket Data */
    Socket = HeapAlloc(GlobalHeap, 0, sizeof(*Socket));
    if (!Socket)
    {
        Status = WSAENOBUFS;
        goto error;
    }
    RtlZeroMemory(Socket, sizeof(*Socket));
    if (SharedData)
    {
        Socket->SharedData = SharedData;
        Socket->SharedDataHandle = UlongToHandle(lpProtocolInfo->dwServiceFlags3);
        Sock = UlongToHandle(lpProtocolInfo->dwServiceFlags4);
        Socket->Handle = (SOCKET)lpProtocolInfo->dwServiceFlags4;

        /* The handle WSPDuplicateSocket made for this process is not inheritable;
         * the socket made from it is, as on Windows, unless the caller opts out */
        SetHandleInformation(Sock, HANDLE_FLAG_INHERIT,
                             (dwFlags & WSA_FLAG_NO_HANDLE_INHERIT) ? 0 : HANDLE_FLAG_INHERIT);
    }
    else
    {
        Socket->SharedDataHandle = INVALID_HANDLE_VALUE;
        Socket->SharedData = HeapAlloc(GlobalHeap, 0, sizeof(*Socket->SharedData));
        if (!Socket->SharedData)
        {
            Status = WSAENOBUFS;
            goto error;
        }
        RtlZeroMemory(Socket->SharedData, sizeof(*Socket->SharedData));
        Socket->SharedData->State = SocketOpen;
        Socket->SharedData->RefCount = 1L;
        Socket->SharedData->Listening = FALSE;
        Socket->SharedData->AddressFamily = AddressFamily;
        Socket->SharedData->SocketType = SocketType;
        Socket->SharedData->Protocol = Protocol;
        Socket->SharedData->SizeOfLocalAddress = HelperData->MaxWSAddressLength;
        Socket->SharedData->SizeOfRemoteAddress = HelperData->MaxWSAddressLength;
        Socket->SharedData->UseDelayedAcceptance = HelperData->UseDelayedAcceptance;
        Socket->SharedData->CreateFlags = dwFlags;
        Socket->SharedData->ServiceFlags1 = lpProtocolInfo->dwServiceFlags1;
        Socket->SharedData->ProviderFlags = lpProtocolInfo->dwProviderFlags;
        Socket->SharedData->UseSAN = FALSE;
        Socket->SharedData->NonBlocking = FALSE; /* Sockets start blocking */
        Socket->SharedData->RecvTimeout = 0;
        Socket->SharedData->SendTimeout = 0;
        Socket->SharedData->OobInline = FALSE;

        /* Ask alex about this */
        if( Socket->SharedData->SocketType == SOCK_DGRAM ||
            Socket->SharedData->SocketType == SOCK_RAW )
        {
            TRACE("Connectionless socket\n");
            Socket->SharedData->ServiceFlags1 |= XP1_CONNECTIONLESS;
        }
        Socket->Handle = INVALID_SOCKET;
    }

    Socket->HelperContext = HelperDLLContext;
    Socket->HelperData = HelperData;
    Socket->HelperEvents = HelperEvents;
    Socket->LocalAddress = &Socket->SharedData->WSLocalAddress;
    Socket->RemoteAddress = &Socket->SharedData->WSRemoteAddress;
    Socket->SanData = NULL;
    RtlCopyMemory(&Socket->ProtocolInfo, lpProtocolInfo, sizeof(Socket->ProtocolInfo));
    if (SharedData)
        goto ok;

    /* Packet Size */
    SizeOfPacket = TransportName.Length + sizeof(AFD_CREATE_PACKET) + sizeof(WCHAR);

    /* EA Size */
    SizeOfEA = SizeOfPacket + sizeof(FILE_FULL_EA_INFORMATION) + AFD_PACKET_COMMAND_LENGTH;

    /* Set up EA Buffer */
    EABuffer = HeapAlloc(GlobalHeap, 0, SizeOfEA);
    if (!EABuffer)
    {
        Status = WSAENOBUFS;
        goto error;
    }

    RtlZeroMemory(EABuffer, SizeOfEA);
    EABuffer->NextEntryOffset = 0;
    EABuffer->Flags = 0;
    EABuffer->EaNameLength = AFD_PACKET_COMMAND_LENGTH;
    RtlCopyMemory (EABuffer->EaName,
                   AfdCommand,
                   AFD_PACKET_COMMAND_LENGTH + 1);
    EABuffer->EaValueLength = SizeOfPacket;

    /* Set up AFD Packet */
    AfdPacket = (PAFD_CREATE_PACKET)(EABuffer->EaName + EABuffer->EaNameLength + 1);
    AfdPacket->SizeOfTransportName = TransportName.Length;
    RtlCopyMemory (AfdPacket->TransportName,
                   TransportName.Buffer,
                   TransportName.Length + sizeof(WCHAR));
    AfdPacket->GroupID = g;

    /* Set up Endpoint Flags */
    if ((Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS) != 0)
    {
        if ((SocketType != SOCK_DGRAM) && (SocketType != SOCK_RAW))
        {
            /* Only RAW or UDP can be Connectionless */
            Status = WSAEINVAL;
            goto error;
        }
        AfdPacket->EndpointFlags |= AFD_ENDPOINT_CONNECTIONLESS;
    }

    if ((Socket->SharedData->ServiceFlags1 & XP1_MESSAGE_ORIENTED) != 0)
    {
        if (SocketType == SOCK_STREAM)
        {
            if ((Socket->SharedData->ServiceFlags1 & XP1_PSEUDO_STREAM) == 0)
            {
                /* The Provider doesn't actually support Message Oriented Streams */
                Status = WSAEINVAL;
                goto error;
            }
        }
        AfdPacket->EndpointFlags |= AFD_ENDPOINT_MESSAGE_ORIENTED;
    }

    if (SocketType == SOCK_RAW) AfdPacket->EndpointFlags |= AFD_ENDPOINT_RAW;

    if (dwFlags & (WSA_FLAG_MULTIPOINT_C_ROOT |
                   WSA_FLAG_MULTIPOINT_C_LEAF |
                   WSA_FLAG_MULTIPOINT_D_ROOT |
                   WSA_FLAG_MULTIPOINT_D_LEAF))
    {
        if ((Socket->SharedData->ServiceFlags1 & XP1_SUPPORT_MULTIPOINT) == 0)
        {
            /* The Provider doesn't actually support Multipoint */
            Status = WSAEINVAL;
            goto error;
        }
        AfdPacket->EndpointFlags |= AFD_ENDPOINT_MULTIPOINT;

        if (dwFlags & WSA_FLAG_MULTIPOINT_C_ROOT)
        {
            if (((Socket->SharedData->ServiceFlags1 & XP1_MULTIPOINT_CONTROL_PLANE) == 0)
                || ((dwFlags & WSA_FLAG_MULTIPOINT_C_LEAF) != 0))
            {
                /* The Provider doesn't support Control Planes, or you already gave a leaf */
                Status = WSAEINVAL;
                goto error;
            }
            AfdPacket->EndpointFlags |= AFD_ENDPOINT_C_ROOT;
        }

        if (dwFlags & WSA_FLAG_MULTIPOINT_D_ROOT)
        {
            if (((Socket->SharedData->ServiceFlags1 & XP1_MULTIPOINT_DATA_PLANE) == 0)
                || ((dwFlags & WSA_FLAG_MULTIPOINT_D_LEAF) != 0))
            {
                /* The Provider doesn't support Data Planes, or you already gave a leaf */
                Status = WSAEINVAL;
                goto error;
            }
            AfdPacket->EndpointFlags |= AFD_ENDPOINT_D_ROOT;
        }
    }

    /* Set up Object Attributes. Sockets are inheritable unless WSA_FLAG_NO_HANDLE_INHERIT is set */
    InitializeObjectAttributes (&Object,
                                &DevName,
                                (dwFlags & WSA_FLAG_NO_HANDLE_INHERIT) ?
                                    OBJ_CASE_INSENSITIVE : (OBJ_CASE_INSENSITIVE | OBJ_INHERIT),
                                0,
                                0);

    /* Create the Socket as asynchronous. That means we have to block
    ourselves after every call to NtDeviceIoControlFile. This is
    because the kernel doesn't support overlapping synchronous I/O
    requests (made from multiple threads) at this time (Sep 2005) */
    Status = NtCreateFile(&Sock,
                          GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                          &Object,
                          &IOSB,
                          NULL,
                          0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN_IF,
                          0,
                          EABuffer,
                          SizeOfEA);

    HeapFree(GlobalHeap, 0, EABuffer);

    if (!NT_SUCCESS(Status))
    {
        ERR("Failed to open socket. Status 0x%08x\n", Status);
        Status = TranslateNtStatusError(Status);
        goto error;
    }

    /* Save Handle */
    Socket->Handle = (SOCKET)Sock;

    /* Save Group Info */
    if (g != 0)
    {
        GetSocketInformation(Socket,
                             AFD_INFO_GROUP_ID_TYPE,
                             NULL,
                             NULL,
                             &GroupData,
                             NULL,
                             NULL);
        Socket->SharedData->GroupID = GroupData.u.LowPart;
        Socket->SharedData->GroupType = GroupData.u.HighPart;
    }

    /* Get Window Sizes and Save them */
    GetSocketInformation (Socket,
                          AFD_INFO_SEND_WINDOW_SIZE,
                          NULL,
                          &Socket->SharedData->SizeOfSendBuffer,
                          NULL,
                          NULL,
                          NULL);

    GetSocketInformation (Socket,
                          AFD_INFO_RECEIVE_WINDOW_SIZE,
                          NULL,
                          &Socket->SharedData->SizeOfRecvBuffer,
                          NULL,
                          NULL,
                          NULL);
ok:

    /* Save in Process Sockets List */
    EnterCriticalSection(&SocketListLock);
    Socket->NextSocket = SocketListHead;
    SocketListHead = Socket;
    LeaveCriticalSection(&SocketListLock);

    /* Create the Socket Context */
    CreateContext(Socket);

    /* Notify Winsock */
    Upcalls.lpWPUModifyIFSHandle(Socket->ProtocolInfo.dwCatalogEntryId, (SOCKET)Sock, lpErrno);

    /* Return Socket Handle */
    TRACE("Success %x\n", Sock);

    return (SOCKET)Sock;

error:
    TRACE("Ending %x\n", Status);

    if( SharedData )
    {
        UnmapViewOfFile(SharedData);
        NtClose(UlongToHandle(lpProtocolInfo->dwServiceFlags3));
    }
    else
    {
        if( Socket && Socket->SharedData )
            HeapFree(GlobalHeap, 0, Socket->SharedData);
    }

    if( Socket )
        HeapFree(GlobalHeap, 0, Socket);

    if( EABuffer )
        HeapFree(GlobalHeap, 0, EABuffer);

    if( lpErrno )
        *lpErrno = Status;

    return INVALID_SOCKET;
}


INT
WSPAPI
WSPDuplicateSocket(
    IN  SOCKET Handle,
    IN  DWORD dwProcessId,
    OUT LPWSAPROTOCOL_INFOW lpProtocolInfo,
    OUT LPINT lpErrno)
{
    HANDLE hProcess, hDuplicatedSharedData, hDuplicatedHandle;
    PSOCKET_INFORMATION Socket;
    PSOCK_SHARED_INFO pSharedData, pOldSharedData;
    BOOL bDuplicated;

    if (Handle == INVALID_SOCKET)
        return MsafdReturnWithErrno(STATUS_INVALID_PARAMETER, lpErrno, 0, NULL);
    Socket = GetSocketStructure(Handle);
    if( !Socket )
    {
        if( lpErrno )
            *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    if ( !(hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId)) )
        return MsafdReturnWithErrno(STATUS_INVALID_PARAMETER, lpErrno, 0, NULL);

    /* It is a not yet duplicated socket, so map the memory, copy the SharedData and free heap */
    if( Socket->SharedDataHandle == INVALID_HANDLE_VALUE )
    {
        Socket->SharedDataHandle = CreateFileMapping(INVALID_HANDLE_VALUE,
                                                     NULL,
                                                     PAGE_READWRITE | SEC_COMMIT,
                                                     0,
                                                     (sizeof(SOCK_SHARED_INFO) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1),
                                                     NULL);
        if( Socket->SharedDataHandle == INVALID_HANDLE_VALUE )
            return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, NULL);
        pSharedData = MapViewOfFile(Socket->SharedDataHandle,
                                    FILE_MAP_ALL_ACCESS,
                                    0,
                                    0,
                                    sizeof(SOCK_SHARED_INFO));

        RtlCopyMemory(pSharedData, Socket->SharedData, sizeof(SOCK_SHARED_INFO));
        pOldSharedData = Socket->SharedData;
        Socket->SharedData = pSharedData;
        HeapFree(GlobalHeap, 0, pOldSharedData);
    }
    /* Duplicate the handles for the new process */
    bDuplicated = DuplicateHandle(GetCurrentProcess(),
                                  Socket->SharedDataHandle,
                                  hProcess,
                                  (LPHANDLE)&hDuplicatedSharedData,
                                  0,
                                  FALSE,
                                  DUPLICATE_SAME_ACCESS);
    if (!bDuplicated)
    {
        NtClose(hProcess);
        return MsafdReturnWithErrno(STATUS_ACCESS_DENIED, lpErrno, 0, NULL);
    }
    bDuplicated = DuplicateHandle(GetCurrentProcess(),
                                  (HANDLE)Socket->Handle,
                                  hProcess,
                                  (LPHANDLE)&hDuplicatedHandle,
                                  0,
                                  FALSE,
                                  DUPLICATE_SAME_ACCESS);
    NtClose(hProcess);
    if( !bDuplicated )
        return MsafdReturnWithErrno(STATUS_ACCESS_DENIED, lpErrno, 0, NULL);


    if (!lpProtocolInfo)
        return MsafdReturnWithErrno(STATUS_ACCESS_VIOLATION, lpErrno, 0, NULL);

    RtlCopyMemory(lpProtocolInfo, &Socket->ProtocolInfo, sizeof(*lpProtocolInfo));

    lpProtocolInfo->iAddressFamily = Socket->SharedData->AddressFamily;
    lpProtocolInfo->iProtocol = Socket->SharedData->Protocol;
    lpProtocolInfo->iSocketType = Socket->SharedData->SocketType;
    lpProtocolInfo->dwServiceFlags3 = HandleToUlong(hDuplicatedSharedData);
    lpProtocolInfo->dwServiceFlags4 = HandleToUlong(hDuplicatedHandle);

    if( lpErrno )
        *lpErrno = NO_ERROR;

    return NO_ERROR;
}

INT
TranslateNtStatusError(NTSTATUS Status)
{
    switch (Status)
    {
       case STATUS_CANT_WAIT:
          return WSAEWOULDBLOCK;

       case STATUS_TIMEOUT:
       case STATUS_IO_TIMEOUT:
          return WSAETIMEDOUT;

       case STATUS_SUCCESS:
          return NO_ERROR;

       case STATUS_FILE_CLOSED:
         return WSAECONNRESET;

       case STATUS_END_OF_FILE:
          return WSAESHUTDOWN;

       case STATUS_PENDING:
          return WSA_IO_PENDING;

       case STATUS_BUFFER_TOO_SMALL:
       case STATUS_BUFFER_OVERFLOW:
          return WSAEMSGSIZE;

       case STATUS_NO_MEMORY:
       case STATUS_INSUFFICIENT_RESOURCES:
          return WSAENOBUFS;

       case STATUS_INVALID_CONNECTION:
          return WSAENOTCONN;

       case STATUS_CONNECTION_ACTIVE:
          return WSAEISCONN;

       case STATUS_CONNECTION_IN_USE:
          return WSAEALREADY;

       case STATUS_PROTOCOL_NOT_SUPPORTED:
          return WSAEAFNOSUPPORT;

       case STATUS_INVALID_ADDRESS:
          return WSAEADDRNOTAVAIL;

       case STATUS_REMOTE_NOT_LISTENING:
       case STATUS_REMOTE_DISCONNECT:
       case STATUS_CONNECTION_REFUSED:
          return WSAECONNREFUSED;

       case STATUS_CONNECTION_RESET:
          return WSAECONNRESET;

       case STATUS_NETWORK_UNREACHABLE:
          return WSAENETUNREACH;

       case STATUS_HOST_UNREACHABLE:
          return WSAEHOSTUNREACH;

       case STATUS_INVALID_PARAMETER:
          return WSAEINVAL;

       case STATUS_CANCELLED:
          return WSA_OPERATION_ABORTED;

       case STATUS_ADDRESS_ALREADY_EXISTS:
          return WSAEADDRINUSE;

       case STATUS_LOCAL_DISCONNECT:
       case STATUS_CONNECTION_ABORTED:
          return WSAECONNABORTED;

       case STATUS_ACCESS_VIOLATION:
          return WSAEFAULT;

       case STATUS_ACCESS_DENIED:
          return WSAEACCES;

       case STATUS_NOT_IMPLEMENTED:
          return WSAEOPNOTSUPP;

       default:
          ERR("MSAFD: Unhandled NTSTATUS value: 0x%x\n", Status);
          return WSAENETDOWN;
    }
}

VOID
MsafdWaitForAlert(
    _In_ HANDLE hObject)
{
    DWORD Result;

    for (;;)
    {
        Result = WaitForSingleObjectEx(hObject, INFINITE, TRUE);
        if (Result != WAIT_IO_COMPLETION)
            break;
    }
}

/*
 * A blocking request waits for Timeout milliseconds (0 and INFINITE: without limit). On expiry the
 * request is cancelled and waited for, so the status block is not used after this returns.
 */
VOID
MsafdWaitForRequest(
    _In_ HANDLE hSocket,
    _In_ HANDLE hEvent,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Timeout)
{
#if DLL_EXPORT_VERSION >= _WIN32_WINNT_VISTA
    IO_STATUS_BLOCK CancelStatusBlock;
    DWORD Start, Elapsed, Result;

    if (Timeout == 0 || Timeout == INFINITE)
    {
        MsafdWaitForAlert(hEvent);
        return;
    }

    Start = GetTickCount();
    for (;;)
    {
        Elapsed = GetTickCount() - Start;
        if (Elapsed >= Timeout)
        {
            Result = WAIT_TIMEOUT;
            break;
        }

        Result = WaitForSingleObjectEx(hEvent, Timeout - Elapsed, TRUE);
        if (Result != WAIT_IO_COMPLETION)
            break;
    }

    if (Result == WAIT_OBJECT_0)
        return;

    /* Only this request is cancelled: it is the status block that names it */
    NtCancelIoFileEx(hSocket, IoStatusBlock, &CancelStatusBlock);

    /* The request that completed before the cancellation keeps its own status */
    MsafdWaitForAlert(hEvent);
    if (IoStatusBlock->Status == STATUS_CANCELLED)
        IoStatusBlock->Status = STATUS_IO_TIMEOUT;
#else
    /* Below 0x600 ntdll has no per-request cancel, and NtCancelIoFile would cancel the thread's other requests too */
    UNREFERENCED_PARAMETER(hSocket);
    UNREFERENCED_PARAMETER(IoStatusBlock);
    UNREFERENCED_PARAMETER(Timeout);
    MsafdWaitForAlert(hEvent);
#endif
}

/* TRUE if another handle (here, in a child process, or a duplicate) refers to the same endpoint */
static
BOOLEAN
MsafdEndpointHasOtherHandles(
    _In_ HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION BasicInfo;
    NTSTATUS Status;

    Status = NtQueryObject(Handle, ObjectBasicInformation, &BasicInfo, sizeof(BasicInfo), NULL);
    return NT_SUCCESS(Status) && BasicInfo.HandleCount > 1;
}

/*
 * FUNCTION: Closes an open socket
 * ARGUMENTS:
 *     s       = Socket descriptor
 *     lpErrno = Address of buffer for error information
 * RETURNS:
 *     NO_ERROR, or SOCKET_ERROR if the socket could not be closed
 */
INT
WSPAPI
WSPCloseSocket(IN SOCKET Handle,
               OUT LPINT lpErrno)
{
    IO_STATUS_BLOCK IoStatusBlock;
    PSOCKET_INFORMATION Socket = NULL, CurrentSocket;
    NTSTATUS Status;
    HANDLE SockEvent;
    AFD_DISCONNECT_INFO DisconnectInfo;
    SOCKET_STATE OldState;
    LONG LingerWait = -1;
    DWORD References;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
       if (lpErrno) *lpErrno = WSAENOTSOCK;
       return SOCKET_ERROR;
    }

    /* HACK: Allow APC to be processed */
    SleepEx(0, TRUE);

    if (Socket->HelperEvents & WSH_NOTIFY_CLOSE)
    {
        Status = Socket->HelperData->WSHNotify(Socket->HelperContext,
                                               Socket->Handle,
                                               Socket->TdiAddressHandle,
                                               Socket->TdiConnectionHandle,
                                               WSH_NOTIFY_CLOSE);

        if (Status)
        {
            ERR("WSHNotify failed. Error 0x%#x\n", Status);
            if (lpErrno) *lpErrno = Status;
            return SOCKET_ERROR;
        }
    }

    /* If a Close is already in Process, give up */
    if (Socket->SharedData->State == SocketClosed)
    {
        WARN("Socket is closing.\n");
        if (lpErrno) *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }

    /* Create the Wait Event */
    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);
    if (!NT_SUCCESS(Status))
    {
        ERR("NtCreateEvent failed: 0x%08x\n", Status);
        return SOCKET_ERROR;
    }

    /* Decrement reference count on SharedData */
    References = InterlockedDecrement(&Socket->SharedData->RefCount);
    if (References)
        goto ok;

    /* Set the state to close */
    OldState = Socket->SharedData->State;
    Socket->SharedData->State = SocketClosed;

    /* If SO_LINGER is ON and the Socket is connected, we need to disconnect */
    /* FIXME: Should we do this on Datagram Sockets too? */
    if ((OldState == SocketConnected) && (Socket->SharedData->LingerData.l_onoff))
    {
        ULONG SendsInProgress;
        ULONG SleepWait;

        /* We need to respect the timeout */
        SleepWait = 100;
        LingerWait = Socket->SharedData->LingerData.l_linger * 1000;

        /* Loop until no more sends are pending, within the timeout */
        while (LingerWait)
        {
            /* Find out how many Sends are in Progress */
            if (GetSocketInformation(Socket,
                                     AFD_INFO_SENDS_IN_PROGRESS,
                                     NULL,
                                     &SendsInProgress,
                                     NULL,
                                     NULL,
                                     NULL))
            {
                /* Bail out if anything but NO_ERROR */
                LingerWait = 0;
                break;
            }

            /* Bail out if no more sends are pending */
            if (!SendsInProgress)
            {
                LingerWait = -1;
                break;
            }

            /*
             * We have to execute a sleep, so it's kind of like
             * a block. If the socket is Nonblock, we cannot
             * go on since asynchronous operation is expected
             * and we cannot offer it
             */
            if (Socket->SharedData->NonBlocking)
            {
                WARN("Would block!\n");
                NtClose(SockEvent);
                Socket->SharedData->State = OldState;
                if (lpErrno) *lpErrno = WSAEWOULDBLOCK;
                return SOCKET_ERROR;
            }

            /* Now we can sleep, and decrement the linger wait */
            /*
            * FIXME: It seems Windows does some funky acceleration
            * since the waiting seems to be longer and longer. I
            * don't think this improves performance so much, so we
            * wait a fixed time instead.
            */
            Sleep(SleepWait);
            LingerWait -= SleepWait;
        }
    }

    /*
     * The endpoint belongs to every process that holds a handle to it: a child that inherited the socket
     * (OpenSSH's sshd gives its connection to sshd-session and closes its own handle) must find the
     * connection alive. Disconnect it only when this is the last handle; the close of that one does.
     */
    if (OldState == SocketConnected && !MsafdEndpointHasOtherHandles((HANDLE)Handle))
    {
        if (LingerWait <= 0)
        {
            DisconnectInfo.Timeout.QuadPart = 0LL;
            DisconnectInfo.DisconnectType = LingerWait < 0 ? AFD_DISCONNECT_SEND : AFD_DISCONNECT_ABORT;

            if (((DisconnectInfo.DisconnectType & AFD_DISCONNECT_SEND) && (!Socket->SharedData->SendShutdown)) ||
                ((DisconnectInfo.DisconnectType & AFD_DISCONNECT_ABORT) && (!Socket->SharedData->ReceiveShutdown)))
            {
                /* Send IOCTL */
                Status = NtDeviceIoControlFile((HANDLE)Handle,
                                               SockEvent,
                                               NULL,
                                               NULL,
                                               &IoStatusBlock,
                                               IOCTL_AFD_DISCONNECT,
                                               &DisconnectInfo,
                                               sizeof(DisconnectInfo),
                                               NULL,
                                               0);

                /* Wait for return */
                if (Status == STATUS_PENDING)
                {
                    MsafdWaitForAlert(SockEvent);
                    Status = IoStatusBlock.Status;
                }
            }
        }
    }

    /* Cleanup Time! */
    Socket->HelperContext = NULL;
    Socket->SharedData->AsyncDisabledEvents = -1;
    NtClose(Socket->TdiAddressHandle);
    Socket->TdiAddressHandle = NULL;
    NtClose(Socket->TdiConnectionHandle);
    Socket->TdiConnectionHandle = NULL;
ok:
    /* Complete the address list change requests of the socket before it goes */
    MsafdAddrChangeSocketClosing(Socket);
    /* and the transmits */
    MsafdTransmitSocketClosing(Socket);

    EnterCriticalSection(&SocketListLock);
    if (SocketListHead == Socket)
    {
        SocketListHead = SocketListHead->NextSocket;
    }
    else
    {
        CurrentSocket = SocketListHead;
        while (CurrentSocket->NextSocket)
        {
            if (CurrentSocket->NextSocket == Socket)
            {
                CurrentSocket->NextSocket = CurrentSocket->NextSocket->NextSocket;
                break;
            }

            CurrentSocket = CurrentSocket->NextSocket;
        }
    }
    LeaveCriticalSection(&SocketListLock);

    /* Close the handle */
    NtClose((HANDLE)Handle);
    NtClose(SockEvent);

    if( Socket->SharedDataHandle != INVALID_HANDLE_VALUE )
    {
        /* It is a duplicated socket, so unmap the memory */
        UnmapViewOfFile(Socket->SharedData);
        NtClose(Socket->SharedDataHandle);
        Socket->SharedData = NULL;
    }
    if( !References && Socket->SharedData )
    {
        HeapFree(GlobalHeap, 0, Socket->SharedData);
    }
    HeapFree(GlobalHeap, 0, Socket);
    return MsafdReturnWithErrno(Status, lpErrno, 0, NULL);
}


/*
 * FUNCTION: Associates a local address with a socket
 * ARGUMENTS:
 *     s       = Socket descriptor
 *     name    = Pointer to local address
 *     namelen = Length of name
 *     lpErrno = Address of buffer for error information
 * RETURNS:
 *     0, or SOCKET_ERROR if the socket could not be bound
 */
INT
WSPAPI
WSPBind(SOCKET Handle,
        const struct sockaddr *SocketAddress,
        int SocketAddressLength,
        LPINT lpErrno)
{
    IO_STATUS_BLOCK         IOSB;
    PAFD_BIND_DATA          BindData;
    PSOCKET_INFORMATION     Socket = NULL;
    NTSTATUS                Status;
    SOCKADDR_INFO           SocketInfo;
    HANDLE                  SockEvent;
    ULONG connectSize;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
       if (lpErrno) *lpErrno = WSAENOTSOCK;
       return SOCKET_ERROR;
    }
    if (Socket->SharedData->State != SocketOpen)
    {
       if (lpErrno) *lpErrno = WSAEINVAL;
       return SOCKET_ERROR;
    }
    if (!SocketAddress || SocketAddressLength < Socket->SharedData->SizeOfLocalAddress)
    {
        if (lpErrno) *lpErrno = WSAEINVAL;
        return SOCKET_ERROR;
    }

    /* Get Address Information */
    Socket->HelperData->WSHGetSockaddrType ((PSOCKADDR)SocketAddress,
                                            SocketAddressLength,
                                            &SocketInfo);

    if (SocketInfo.AddressInfo == SockaddrAddressInfoBroadcast && !Socket->SharedData->Broadcast)
    {
       if (lpErrno) *lpErrno = WSAEADDRNOTAVAIL;
       return SOCKET_ERROR;
    }

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if (!NT_SUCCESS(Status))
    {
        return SOCKET_ERROR;
    }

    connectSize = FIELD_OFFSET(AFD_BIND_DATA, Address.Address[SocketAddressLength]);

    /* See below */
    BindData = HeapAlloc(GlobalHeap, 0, connectSize);
    if (!BindData)
    {
        return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, NULL);
    }

    /* Set up Address in TDI Format */
    BindData->Address.TAAddressCount = 1;
    BindData->Address.Address[0].AddressLength = (USHORT)(SocketAddressLength - sizeof(SocketAddress->sa_family));
    BindData->Address.Address[0].AddressType = SocketAddress->sa_family;
    RtlCopyMemory (BindData->Address.Address[0].Address,
                   SocketAddress->sa_data,
                   SocketAddressLength - sizeof(SocketAddress->sa_family));

    /* Set the Share Type */
    if (Socket->SharedData->ExclusiveAddressUse)
    {
        BindData->ShareType = AFD_SHARE_EXCLUSIVE;
    }
    else if (SocketInfo.EndpointInfo == SockaddrEndpointInfoWildcard)
    {
        BindData->ShareType = AFD_SHARE_WILDCARD;
    }
    else if (Socket->SharedData->ReuseAddresses)
    {
        BindData->ShareType = AFD_SHARE_REUSE;
    }
    else
    {
        BindData->ShareType = AFD_SHARE_UNIQUE;
    }

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_BIND,
                                   BindData,
                                   connectSize,
                                   BindData,
                                   connectSize);

    /* Wait for return */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    NtClose( SockEvent );
    HeapFree(GlobalHeap, 0, BindData);

    Socket->SharedData->SocketLastError = TranslateNtStatusError(Status);
    if (Status != STATUS_SUCCESS)
        return MsafdReturnWithErrno ( Status, lpErrno, 0, NULL );

    /* Set up Socket Data */
    Socket->SharedData->State = SocketBound;
    Socket->TdiAddressHandle = (HANDLE)IOSB.Information;

    if (Socket->HelperEvents & WSH_NOTIFY_BIND)
    {
        Status = Socket->HelperData->WSHNotify(Socket->HelperContext,
                                               Socket->Handle,
                                               Socket->TdiAddressHandle,
                                               Socket->TdiConnectionHandle,
                                               WSH_NOTIFY_BIND);

        if (Status)
        {
            if (lpErrno) *lpErrno = Status;
            return SOCKET_ERROR;
        }
    }

    return MsafdReturnWithErrno ( Status, lpErrno, 0, NULL );
}

int
WSPAPI
WSPListen(SOCKET Handle,
          int Backlog,
          LPINT lpErrno)
{
    IO_STATUS_BLOCK         IOSB;
    AFD_LISTEN_DATA         ListenData;
    PSOCKET_INFORMATION     Socket = NULL;
    HANDLE                  SockEvent;
    NTSTATUS                Status;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
       if (lpErrno) *lpErrno = WSAENOTSOCK;
       return SOCKET_ERROR;
    }

    if (Socket->SharedData->Listening)
        return NO_ERROR;

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if( !NT_SUCCESS(Status) )
        return SOCKET_ERROR;

    /* Set Up Listen Structure */
    ListenData.UseSAN = FALSE;
    ListenData.UseDelayedAcceptance = Socket->SharedData->UseDelayedAcceptance;
    ListenData.Backlog = Backlog;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_START_LISTEN,
                                   &ListenData,
                                   sizeof(ListenData),
                                   NULL,
                                   0);

    /* Wait for return */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    NtClose( SockEvent );

    Socket->SharedData->SocketLastError = TranslateNtStatusError(Status);
    if (Status != STATUS_SUCCESS)
       return MsafdReturnWithErrno ( Status, lpErrno, 0, NULL );

    /* Set to Listening */
    Socket->SharedData->Listening = TRUE;

    if (Socket->HelperEvents & WSH_NOTIFY_LISTEN)
    {
        Status = Socket->HelperData->WSHNotify(Socket->HelperContext,
                                               Socket->Handle,
                                               Socket->TdiAddressHandle,
                                               Socket->TdiConnectionHandle,
                                               WSH_NOTIFY_LISTEN);

        if (Status)
        {
           if (lpErrno) *lpErrno = Status;
           return SOCKET_ERROR;
        }
    }

    return MsafdReturnWithErrno ( Status, lpErrno, 0, NULL );
}


int
WSPAPI
WSPSelect(IN int nfds,
          IN OUT fd_set *readfds OPTIONAL,
          IN OUT fd_set *writefds OPTIONAL,
          IN OUT fd_set *exceptfds OPTIONAL,
          IN const struct timeval *timeout OPTIONAL,
          OUT LPINT lpErrno)
{
    IO_STATUS_BLOCK     IOSB;
    PAFD_POLL_INFO      PollInfo;
    NTSTATUS            Status;
    ULONG               HandleCount;
    ULONG               PollBufferSize;
    PVOID               PollBuffer;
    ULONG               i, j = 0, x;
    HANDLE              SockEvent;
    LARGE_INTEGER       Timeout;
    PSOCKET_INFORMATION Socket;
    SOCKET              Handle;
    ULONG               Events;
    fd_set              selectfds;

    /* Find out how many sockets we have, and how large the buffer needs
     * to be */
    FD_ZERO(&selectfds);
    if (readfds != NULL)
    {
        for (i = 0; i < readfds->fd_count; i++)
        {
            FD_SET(readfds->fd_array[i], &selectfds);
        }
    }
    if (writefds != NULL)
    {
        for (i = 0; i < writefds->fd_count; i++)
        {
            FD_SET(writefds->fd_array[i], &selectfds);
        }
    }
    if (exceptfds != NULL)
    {
        for (i = 0; i < exceptfds->fd_count; i++)
        {
            FD_SET(exceptfds->fd_array[i], &selectfds);
        }
    }

    HandleCount = selectfds.fd_count;

    if ( HandleCount == 0 )
    {
        WARN("No handles! Returning SOCKET_ERROR\n", HandleCount);
        if (lpErrno) *lpErrno = WSAEINVAL;
        return SOCKET_ERROR;
    }

    PollBufferSize = sizeof(*PollInfo) + ((HandleCount - 1) * sizeof(AFD_HANDLE));

    TRACE("HandleCount: %u BufferSize: %u\n", HandleCount, PollBufferSize);

    /* Convert Timeout to NT Format */
    if (timeout == NULL)
    {
        Timeout.u.LowPart = -1;
        Timeout.u.HighPart = 0x7FFFFFFF;
        TRACE("Infinite timeout\n");
    }
    else
    {
        /* Like Windows: the timeout is tv_sec * 10^6 + tv_usec microseconds, as a
         * signed 64-bit sum of the two (signed, 32-bit) fields. Nothing is rejected:
         * a sum <= 0 (negative tv_sec, negative tv_usec) polls without waiting, a
         * tv_usec >= 10^6 just adds to the seconds, and large sums simply wait very
         * long (INT_MAX seconds in 100 ns units still fits 64 bits). The kernel
         * takes a relative timeout as a negative number. */
        LONGLONG Micro = (LONGLONG)timeout->tv_sec * 1000000 + timeout->tv_usec;

        if (Micro <= 0)
            Timeout.QuadPart = 0;
        else
            Timeout.QuadPart = -(Micro * 10);
        TRACE("Timeout: Orig %d.%06d kernel %I64d\n",
                     timeout->tv_sec, timeout->tv_usec,
                     Timeout.QuadPart);
    }

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if(!NT_SUCCESS(Status))
    {
        if (lpErrno)
            *lpErrno = WSAEFAULT;

        ERR("NtCreateEvent failed, 0x%08x\n", Status);
        return SOCKET_ERROR;
    }

    /* Allocate */
    PollBuffer = HeapAlloc(GlobalHeap, 0, PollBufferSize);

    if (!PollBuffer)
    {
        if (lpErrno)
            *lpErrno = WSAEFAULT;
        NtClose(SockEvent);
        return SOCKET_ERROR;
    }

    PollInfo = (PAFD_POLL_INFO)PollBuffer;

    RtlZeroMemory( PollInfo, PollBufferSize );

    /* Number of handles for AFD to Check */
    PollInfo->Exclusive = FALSE;
    PollInfo->Timeout = Timeout;

    for (i = 0; i < selectfds.fd_count; i++)
    {
        PollInfo->Handles[i].Handle = selectfds.fd_array[i];
    }
    if (readfds != NULL) {
        for (i = 0; i < readfds->fd_count; i++)
        {
            for (j = 0; j < HandleCount; j++)
            {
                if (PollInfo->Handles[j].Handle == readfds->fd_array[i])
                    break;
            }
            if (j >= HandleCount)
            {
                ERR("Error while counting readfds %ld > %ld\n", j, HandleCount);
                if (lpErrno) *lpErrno = WSAEFAULT;
                HeapFree(GlobalHeap, 0, PollBuffer);
                NtClose(SockEvent);
                return SOCKET_ERROR;
            }
            Socket = GetSocketStructure(readfds->fd_array[i]);
            if (!Socket)
            {
                ERR("Invalid socket handle provided in readfds %d\n", readfds->fd_array[i]);
                if (lpErrno) *lpErrno = WSAENOTSOCK;
                HeapFree(GlobalHeap, 0, PollBuffer);
                NtClose(SockEvent);
                return SOCKET_ERROR;
            }
            PollInfo->Handles[j].Events |= AFD_EVENT_RECEIVE |
                                           AFD_EVENT_DISCONNECT |
                                           AFD_EVENT_ABORT |
                                           AFD_EVENT_CLOSE |
                                           AFD_EVENT_ACCEPT;
            //if (Socket->SharedData->OobInline != 0)
            //    PollInfo->Handles[j].Events |= AFD_EVENT_OOB_RECEIVE;
        }
    }
    if (writefds != NULL)
    {
        for (i = 0; i < writefds->fd_count; i++)
        {
            for (j = 0; j < HandleCount; j++)
            {
                if (PollInfo->Handles[j].Handle == writefds->fd_array[i])
                    break;
            }
            if (j >= HandleCount)
            {
                ERR("Error while counting writefds %ld > %ld\n", j, HandleCount);
                if (lpErrno) *lpErrno = WSAEFAULT;
                HeapFree(GlobalHeap, 0, PollBuffer);
                NtClose(SockEvent);
                return SOCKET_ERROR;
            }
            Socket = GetSocketStructure(writefds->fd_array[i]);
            if (!Socket)
            {
                ERR("Invalid socket handle provided in writefds %d\n", writefds->fd_array[i]);
                if (lpErrno) *lpErrno = WSAENOTSOCK;
                HeapFree(GlobalHeap, 0, PollBuffer);
                NtClose(SockEvent);
                return SOCKET_ERROR;
            }
            PollInfo->Handles[j].Handle = writefds->fd_array[i];
            PollInfo->Handles[j].Events |= AFD_EVENT_SEND;
            if (Socket->SharedData->NonBlocking != 0)
                PollInfo->Handles[j].Events |= AFD_EVENT_CONNECT;
        }
    }
    if (exceptfds != NULL)
    {
        for (i = 0; i < exceptfds->fd_count; i++)
        {
            for (j = 0; j < HandleCount; j++)
            {
                if (PollInfo->Handles[j].Handle == exceptfds->fd_array[i])
                    break;
            }
            if (j > HandleCount)
            {
                ERR("Error while counting exceptfds %ld > %ld\n", j, HandleCount);
                if (lpErrno) *lpErrno = WSAEFAULT;
                HeapFree(GlobalHeap, 0, PollBuffer);
                NtClose(SockEvent);
                return SOCKET_ERROR;
            }
            Socket = GetSocketStructure(exceptfds->fd_array[i]);
            if (!Socket)
            {
                TRACE("Invalid socket handle provided in exceptfds %d\n", exceptfds->fd_array[i]);
                if (lpErrno) *lpErrno = WSAENOTSOCK;
                HeapFree(GlobalHeap, 0, PollBuffer);
                NtClose(SockEvent);
                return SOCKET_ERROR;
            }
            PollInfo->Handles[j].Handle = exceptfds->fd_array[i];
            if (Socket->SharedData->OobInline == 0)
                PollInfo->Handles[j].Events |= AFD_EVENT_OOB_RECEIVE;
            if (Socket->SharedData->NonBlocking != 0)
                PollInfo->Handles[j].Events |= AFD_EVENT_CONNECT_FAIL;
        }
    }

    PollInfo->HandleCount = HandleCount;
    PollBufferSize = FIELD_OFFSET(AFD_POLL_INFO, Handles) + PollInfo->HandleCount * sizeof(AFD_HANDLE);

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)PollInfo->Handles[0].Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_SELECT,
                                   PollInfo,
                                   PollBufferSize,
                                   PollInfo,
                                   PollBufferSize);

    TRACE("DeviceIoControlFile => %x\n", Status);

    /* Wait for Completion */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    /* Clear the Structures */
    if( readfds )
        FD_ZERO(readfds);
    if( writefds )
        FD_ZERO(writefds);
    if( exceptfds )
        FD_ZERO(exceptfds);

    /* Loop through return structure */
    HandleCount = PollInfo->HandleCount;

    /* Return in FDSET Format */
    for (i = 0; i < HandleCount; i++)
    {
        Events = PollInfo->Handles[i].Events;
        Handle = PollInfo->Handles[i].Handle;
        for(x = 1; x; x<<=1)
        {
            Socket = GetSocketStructure(Handle);
            if (!Socket)
            {
                TRACE("Invalid socket handle found %d\n", Handle);
                if (lpErrno) *lpErrno = WSAENOTSOCK;
                HeapFree(GlobalHeap, 0, PollBuffer);
                NtClose(SockEvent);
                return SOCKET_ERROR;
            }
            switch (Events & x)
            {
                case AFD_EVENT_RECEIVE:
                case AFD_EVENT_DISCONNECT:
                case AFD_EVENT_ABORT:
                case AFD_EVENT_ACCEPT:
                case AFD_EVENT_CLOSE:
                    TRACE("Event %x on handle %x\n",
                        Events,
                        Handle);
                    /* SO_ERROR stays 0 after a reset or an abort, as on Windows */
                    if( readfds )
                        FD_SET(Handle, readfds);
                    break;
                case AFD_EVENT_SEND:
                    TRACE("Event %x on handle %x\n",
                        Events,
                        Handle);
                    if (writefds)
                        FD_SET(Handle, writefds);
                    break;
                case AFD_EVENT_CONNECT:
                    TRACE("Event %x on handle %x\n",
                        Events,
                        Handle);
                    if( writefds && Socket->SharedData->NonBlocking != 0 )
                        FD_SET(Handle, writefds);
                    break;
                case AFD_EVENT_OOB_RECEIVE:
                    TRACE("Event %x on handle %x\n",
                        Events,
                        Handle);
                    if( readfds && Socket->SharedData->OobInline != 0 )
                        FD_SET(Handle, readfds);
                    if( exceptfds && Socket->SharedData->OobInline == 0 )
                        FD_SET(Handle, exceptfds);
                    break;
                case AFD_EVENT_CONNECT_FAIL:
                    TRACE("Event %x on handle %x\n",
                        Events,
                        Handle);
                    if( exceptfds && Socket->SharedData->NonBlocking != 0 )
                        FD_SET(Handle, exceptfds);
                    break;
            }
        }
    }

    HeapFree( GlobalHeap, 0, PollBuffer );
    NtClose( SockEvent );

    if( lpErrno )
    {
        switch( IOSB.Status )
        {
            case STATUS_SUCCESS:
            case STATUS_TIMEOUT:
                *lpErrno = 0;
                break;
            default:
                *lpErrno = WSAEINVAL;
                break;
        }
        TRACE("*lpErrno = %x\n", *lpErrno);
    }

    HandleCount = (readfds ? readfds->fd_count : 0) +
                  (writefds && writefds != readfds ? writefds->fd_count : 0) +
                  (exceptfds && exceptfds != readfds && exceptfds != writefds ? exceptfds->fd_count : 0);

    TRACE("%d events\n", HandleCount);

    return HandleCount;
}

DWORD
GetCurrentTimeInSeconds(VOID)
{
    SYSTEMTIME st1970 = { 1970, 1, 0, 1, 0, 0, 0, 0 };
    union
    {
        FILETIME ft;
        ULONGLONG ll;
    } u1970, Time;

    GetSystemTimeAsFileTime(&Time.ft);
    SystemTimeToFileTime(&st1970, &u1970.ft);
    return (DWORD)((Time.ll - u1970.ll) / 10000000ULL);
}

/*
 * A nonblocking connect leaves the user-mode socket state to MsafdConnectAPC,
 * which runs only in an alertable wait of the connecting thread, while select
 * and WSAEventSelect report the finished connection without one. Where the
 * state matters before the APC ran, ask AFD. Only the connected state is taken
 * over, quietly: no asynchronous select event is re-armed and the helper is
 * not notified, the APC still does both. Returns a Winsock error code,
 * NO_ERROR also when the socket is simply not connected.
 */
static
INT
MsafdAdoptConnectedState(
    _In_ PSOCKET_INFORMATION Socket)
{
    IO_STATUS_BLOCK IOSB;
    SOCK_SHARED_INFO SharedData;
    AFD_TDI_HANDLE_DATA HandleData;
    ULONG Flags = AFD_CONNECTION_HANDLE;
    HANDLE SockEvent;
    NTSTATUS Status;

    /* Every connected socket passed through the bound state in this process */
    if (Socket->SharedData->State != SocketBound)
        return NO_ERROR;

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);
    if (!NT_SUCCESS(Status))
        return TranslateNtStatusError(Status);

    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_GET_CONTEXT,
                                   NULL,
                                   0,
                                   &SharedData,
                                   sizeof(SharedData));
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    /* AFD and the shared enumeration agree on the connected value only */
    if (NT_SUCCESS(Status) && SharedData.State == SocketConnected)
    {
        Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                       SockEvent,
                                       NULL,
                                       NULL,
                                       &IOSB,
                                       IOCTL_AFD_GET_TDI_HANDLES,
                                       &Flags,
                                       sizeof(Flags),
                                       &HandleData,
                                       sizeof(HandleData));
        if (Status == STATUS_PENDING)
        {
            MsafdWaitForAlert(SockEvent);
            Status = IOSB.Status;
        }

        if (NT_SUCCESS(Status))
        {
            Socket->TdiConnectionHandle = HandleData.TdiConnectionHandle;
            Socket->SharedData->ConnectTime = GetCurrentTimeInSeconds();
            Socket->SharedData->State = SocketConnected;
        }
    }

    NtClose(SockEvent);

    return NT_SUCCESS(Status) ? NO_ERROR : TranslateNtStatusError(Status);
}

_Must_inspect_result_
SOCKET
WSPAPI
WSPAccept(
    _In_ SOCKET Handle,
    _Out_writes_bytes_to_opt_(*addrlen, *addrlen) struct sockaddr FAR *SocketAddress,
    _Inout_opt_ LPINT SocketAddressLength,
    _In_opt_ LPCONDITIONPROC lpfnCondition,
    _In_opt_ DWORD_PTR dwCallbackData,
    _Out_ LPINT lpErrno)
{
    IO_STATUS_BLOCK             IOSB;
    PAFD_RECEIVED_ACCEPT_DATA   ListenReceiveData;
    AFD_ACCEPT_DATA             AcceptData;
    AFD_DEFER_ACCEPT_DATA       DeferData;
    AFD_PENDING_ACCEPT_DATA     PendingAcceptData;
    PSOCKET_INFORMATION         Socket = NULL;
    NTSTATUS                    Status;
    struct fd_set               ReadSet;
    struct timeval              Timeout;
    PVOID                       PendingData = NULL;
    ULONG                       PendingDataLength = 0;
    PVOID                       CalleeDataBuffer = NULL;
    WSABUF                      CallerData, CalleeID, CallerID, CalleeData;
    PSOCKADDR                   RemoteAddress =  NULL;
    GROUP                       GroupID = 0;
    ULONG                       CallBack;
    SOCKET                      AcceptSocket;
    PSOCKET_INFORMATION         AcceptSocketInfo;
    UCHAR                       ReceiveBuffer[0x1A];
    HANDLE                      SockEvent;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
       if (lpErrno) *lpErrno = WSAENOTSOCK;
       return INVALID_SOCKET;
    }
    if (!Socket->SharedData->Listening)
    {
       if (lpErrno) *lpErrno = WSAEINVAL;
       return INVALID_SOCKET;
    }
    if ((SocketAddress && !SocketAddressLength) ||
        (SocketAddressLength && !SocketAddress) ||
        (SocketAddressLength && *SocketAddressLength < sizeof(SOCKADDR)))
    {
       if (lpErrno) *lpErrno = WSAEFAULT;
       return INVALID_SOCKET;
    }

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if( !NT_SUCCESS(Status) )
    {
        return MsafdReturnInvalidSocket(Status, lpErrno);
    }

    /* Dynamic Structure...ugh */
    ListenReceiveData = (PAFD_RECEIVED_ACCEPT_DATA)ReceiveBuffer;

    /* If this is non-blocking, make sure there's something for us to accept */
    if (Socket->SharedData->NonBlocking)
    {
        FD_ZERO(&ReadSet);
        FD_SET(Socket->Handle, &ReadSet);
        Timeout.tv_sec=0;
        Timeout.tv_usec=0;

        if (WSPSelect(0, &ReadSet, NULL, NULL, &Timeout, lpErrno) == SOCKET_ERROR)
        {
            NtClose(SockEvent);
            return INVALID_SOCKET;
        }

        if (ReadSet.fd_array[0] != Socket->Handle)
        {
            NtClose(SockEvent);
            if (lpErrno) *lpErrno = WSAEWOULDBLOCK;
            return INVALID_SOCKET;
        }
    }

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_WAIT_FOR_LISTEN,
                                   NULL,
                                   0,
                                   ListenReceiveData,
                                   0xA + sizeof(*ListenReceiveData));

    /* Wait for return */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    if (!NT_SUCCESS(Status))
    {
        NtClose( SockEvent );
        return MsafdReturnInvalidSocket(Status, lpErrno);
    }

    if (lpfnCondition != NULL)
    {
        if ((Socket->SharedData->ServiceFlags1 & XP1_CONNECT_DATA) != 0)
        {
            /* Find out how much data is pending */
            PendingAcceptData.SequenceNumber = ListenReceiveData->SequenceNumber;
            PendingAcceptData.ReturnSize = TRUE;

            /* Send IOCTL */
            Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                           SockEvent,
                                           NULL,
                                           NULL,
                                           &IOSB,
                                           IOCTL_AFD_GET_PENDING_CONNECT_DATA,
                                           &PendingAcceptData,
                                           sizeof(PendingAcceptData),
                                           &PendingAcceptData,
                                           sizeof(PendingAcceptData));

            /* Wait for return */
            if (Status == STATUS_PENDING)
            {
                MsafdWaitForAlert(SockEvent);
                Status = IOSB.Status;
            }

            if (!NT_SUCCESS(Status))
            {
                NtClose( SockEvent );
                return MsafdReturnInvalidSocket(Status, lpErrno);
            }

            /* How much data to allocate */
            PendingDataLength = IOSB.Information;

            if (PendingDataLength)
            {
                /* Allocate needed space */
                PendingData = HeapAlloc(GlobalHeap, 0, PendingDataLength);
                if (!PendingData)
                {
                    NtClose(SockEvent);
                    return MsafdReturnInvalidSocket(STATUS_INSUFFICIENT_RESOURCES, lpErrno);
                }

                /* We want the data now */
                PendingAcceptData.ReturnSize = FALSE;

                /* Send IOCTL */
                Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                               SockEvent,
                                               NULL,
                                               NULL,
                                               &IOSB,
                                               IOCTL_AFD_GET_PENDING_CONNECT_DATA,
                                               &PendingAcceptData,
                                               sizeof(PendingAcceptData),
                                               PendingData,
                                               PendingDataLength);

                /* Wait for return */
                if (Status == STATUS_PENDING)
                {
                    MsafdWaitForAlert(SockEvent);
                    Status = IOSB.Status;
                }

                if (!NT_SUCCESS(Status))
                {
                    HeapFree(GlobalHeap, 0, PendingData);
                    NtClose( SockEvent );
                    return MsafdReturnInvalidSocket(Status, lpErrno);
                }
            }
        }

        if ((Socket->SharedData->ServiceFlags1 & XP1_QOS_SUPPORTED) != 0)
        {
            /* I don't support this yet */
        }

        /* Build Callee ID */
        CalleeID.buf = (PVOID)Socket->LocalAddress;
        CalleeID.len = Socket->SharedData->SizeOfLocalAddress;

        RemoteAddress = HeapAlloc(GlobalHeap, 0, sizeof(*RemoteAddress));
        if (!RemoteAddress)
        {
            if (PendingData)
                HeapFree(GlobalHeap, 0, PendingData);
            NtClose(SockEvent);
            return MsafdReturnInvalidSocket(STATUS_INSUFFICIENT_RESOURCES, lpErrno);
        }

        /* Set up Address in SOCKADDR Format */
        RtlCopyMemory (RemoteAddress,
                       &ListenReceiveData->Address.Address[0].AddressType,
                       sizeof(*RemoteAddress));

        /* Build Caller ID */
        CallerID.buf = (PVOID)RemoteAddress;
        CallerID.len = sizeof(*RemoteAddress);

        /* Build Caller Data */
        CallerData.buf = PendingData;
        CallerData.len = PendingDataLength;

        /* Check if socket supports Conditional Accept */
        if (Socket->SharedData->UseDelayedAcceptance != 0)
        {
            /* Allocate Buffer for Callee Data */
            CalleeDataBuffer = HeapAlloc(GlobalHeap, 0, 4096);
            if (!CalleeDataBuffer) {
                HeapFree(GlobalHeap, 0, RemoteAddress);
                if (PendingData)
                    HeapFree(GlobalHeap, 0, PendingData);
                NtClose(SockEvent);
                return MsafdReturnInvalidSocket(STATUS_INSUFFICIENT_RESOURCES, lpErrno);
            }
            CalleeData.buf = CalleeDataBuffer;
            CalleeData.len = 4096;
        }
        else
        {
            /* Nothing */
            CalleeData.buf = 0;
            CalleeData.len = 0;
        }

        /* Call the Condition Function */
        CallBack = (lpfnCondition)(&CallerID,
                                   CallerData.buf == NULL ? NULL : &CallerData,
                                   NULL,
                                   NULL,
                                   &CalleeID,
                                   CalleeData.buf == NULL ? NULL : &CalleeData,
                                   &GroupID,
                                   dwCallbackData);

        /* The condition function was the only user of these buffers */
        HeapFree(GlobalHeap, 0, RemoteAddress);
        RemoteAddress = NULL;
        if (PendingData)
            HeapFree(GlobalHeap, 0, PendingData);
        PendingData = NULL;
        if (CalleeDataBuffer)
            HeapFree(GlobalHeap, 0, CalleeDataBuffer);
        CalleeDataBuffer = NULL;

        if (((CallBack == CF_ACCEPT) && GroupID) != 0)
        {
            /* TBD: Check for Validity */
        }

        if (CallBack == CF_ACCEPT)
        {
            if ((Socket->SharedData->ServiceFlags1 & XP1_QOS_SUPPORTED) != 0)
            {
                /* I don't support this yet */
            }
            if (CalleeData.buf)
            {
                // SockSetConnectData Sockets(SocketID), IOCTL_AFD_SET_CONNECT_DATA, CalleeData.Buffer, CalleeData.BuffSize, 0
            }
        }
        else
        {
            /* Callback rejected. Build Defer Structure */
            DeferData.SequenceNumber = ListenReceiveData->SequenceNumber;
            DeferData.RejectConnection = (CallBack == CF_REJECT);

            /* Send IOCTL */
            Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                           SockEvent,
                                           NULL,
                                           NULL,
                                           &IOSB,
                                           IOCTL_AFD_DEFER_ACCEPT,
                                           &DeferData,
                                           sizeof(DeferData),
                                           NULL,
                                           0);

            /* Wait for return */
            if (Status == STATUS_PENDING)
            {
                MsafdWaitForAlert(SockEvent);
                Status = IOSB.Status;
            }

            NtClose( SockEvent );

            if (!NT_SUCCESS(Status))
            {
                return MsafdReturnInvalidSocket(Status, lpErrno);
            }

            if (CallBack == CF_REJECT )
            {
                if (lpErrno) *lpErrno = WSAECONNREFUSED;
                return INVALID_SOCKET;
            }
            else
            {
                if (lpErrno) *lpErrno = WSAECONNREFUSED;
                return INVALID_SOCKET;
            }
        }
    }

    /* Create a new Socket */
    AcceptSocket = WSPSocket (Socket->SharedData->AddressFamily,
                              Socket->SharedData->SocketType,
                              Socket->SharedData->Protocol,
                              &Socket->ProtocolInfo,
                              GroupID,
                              Socket->SharedData->CreateFlags,
                              lpErrno);
    if (AcceptSocket == INVALID_SOCKET)
    {
        NtClose(SockEvent);
        return INVALID_SOCKET;
    }

    /* Set up the Accept Structure */
    AcceptData.ListenHandle = (HANDLE)AcceptSocket;
    AcceptData.SequenceNumber = ListenReceiveData->SequenceNumber;

    /* Send IOCTL to Accept */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_ACCEPT,
                                   &AcceptData,
                                   sizeof(AcceptData),
                                   NULL,
                                   0);

    /* Wait for return */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    Socket->SharedData->SocketLastError = TranslateNtStatusError(Status);
    if (!NT_SUCCESS(Status))
    {
        NtClose(SockEvent);
        WSPCloseSocket( AcceptSocket, lpErrno );
        return MsafdReturnInvalidSocket(Status, lpErrno);
    }

    AcceptSocketInfo = GetSocketStructure(AcceptSocket);
    if (!AcceptSocketInfo)
    {
        NtClose(SockEvent);
        WSPCloseSocket( AcceptSocket, lpErrno );
        return MsafdReturnInvalidSocket(STATUS_PROTOCOL_NOT_SUPPORTED, lpErrno);
    }

    AcceptSocketInfo->SharedData->State = SocketConnected;
    AcceptSocketInfo->SharedData->ConnectTime = GetCurrentTimeInSeconds();
    AcceptSocketInfo->SharedData->NonBlocking = Socket->SharedData->NonBlocking;
    AcceptSocketInfo->SharedData->TcpNoDelay = Socket->SharedData->TcpNoDelay;
    AcceptSocketInfo->SharedData->RecvTimeout = Socket->SharedData->RecvTimeout;
    AcceptSocketInfo->SharedData->SendTimeout = Socket->SharedData->SendTimeout;

    /* Return Address in SOCKADDR FORMAT */
    if( SocketAddress )
    {
        RtlCopyMemory (SocketAddress,
                       &ListenReceiveData->Address.Address[0].AddressType,
                       sizeof(*RemoteAddress));
        if( SocketAddressLength )
            *SocketAddressLength = sizeof(*RemoteAddress);
    }

    NtClose( SockEvent );

    /* Re-enable Async Event */
    SockReenableAsyncSelectEvent(Socket, FD_ACCEPT);

    TRACE("Socket %x\n", AcceptSocket);

    if (Status == STATUS_SUCCESS && (Socket->HelperEvents & WSH_NOTIFY_ACCEPT))
    {
        Status = Socket->HelperData->WSHNotify(Socket->HelperContext,
                                               Socket->Handle,
                                               Socket->TdiAddressHandle,
                                               Socket->TdiConnectionHandle,
                                               WSH_NOTIFY_ACCEPT);

        if (Status)
        {
            if (lpErrno) *lpErrno = Status;
            return INVALID_SOCKET;
        }
    }

    if (lpErrno) *lpErrno = NO_ERROR;

    /* Return Socket */
    return AcceptSocket;
}

BOOL
WSPAPI
WSPAcceptEx(
    _In_ SOCKET sListenSocket,
    _In_ SOCKET sAcceptSocket,
    _Out_ PVOID lpOutputBuffer,
    _In_ DWORD dwReceiveDataLength,
    _In_ DWORD dwLocalAddressLength,
    _In_ DWORD dwRemoteAddressLength,
    _Out_ LPDWORD lpdwBytesReceived,
    _Inout_ LPOVERLAPPED lpOverlapped)
{
    PSOCKET_INFORMATION   ListenSocket = GetSocketStructure(sListenSocket);
    PSOCKET_INFORMATION   AcceptSocket = GetSocketStructure(sAcceptSocket);
    AFD_SUPER_ACCEPT_INFO AcceptInfo;
    NTSTATUS              Status;
    PIO_STATUS_BLOCK      IoStatusBlock = (PIO_STATUS_BLOCK)lpOverlapped;

    /* Validate sockets */
    if (!ListenSocket || !AcceptSocket)
    {
       SetLastError(WSAENOTSOCK);
       return FALSE;
    }

    if (!lpOverlapped)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    /* Check if this socket is listening and that AcceptEx hasn't already been invoked */
    if (!ListenSocket->SharedData->Listening)
    {
       SetLastError(WSAEINVAL);
       return FALSE;
    }

    /* Make sure that the accept socket is not already opened or connected */
    if (AcceptSocket->SharedData->State != SocketOpen)
    {
        SetLastError(WSAEINVAL);
        return FALSE;
    }

    /* Windows: the remote address area must hold at least 8 bytes */
    if (!lpOutputBuffer || dwRemoteAddressLength < 8)
    {
        SetLastError(WSAEFAULT);
        return FALSE;
    }

    /* Populate IOCTL super accept structure */
    AcceptInfo.SanActive = FALSE;
    AcceptInfo.FixAddressAlignment = TRUE;
    AcceptInfo.AcceptHandle = (HANDLE)AcceptSocket->Handle;
    AcceptInfo.ReceiveDataLength = dwReceiveDataLength;
    AcceptInfo.LocalAddressLength = dwLocalAddressLength;
    AcceptInfo.RemoteAddressLength = dwRemoteAddressLength;

    IoStatusBlock->Information = 0;
    IoStatusBlock->Status = STATUS_PENDING;
    
    Status = NtDeviceIoControlFile((HANDLE)ListenSocket->Handle,
                                   lpOverlapped->hEvent,
                                   NULL,
                                   lpOverlapped->hEvent ? NULL : lpOverlapped,
                                   IoStatusBlock,
                                   IOCTL_AFD_SUPER_ACCEPT,
                                   &AcceptInfo,
                                   sizeof(AcceptInfo),
                                   lpOutputBuffer,
                                   dwReceiveDataLength + dwLocalAddressLength + dwRemoteAddressLength);

    if (Status == STATUS_PENDING)
    {
        SetLastError(ERROR_IO_PENDING);
        return FALSE;
    }

    if (NT_SUCCESS(Status) && lpdwBytesReceived)
        *lpdwBytesReceived = IoStatusBlock->Information;

    SetLastError(TranslateNtStatusError(Status));

    return NT_SUCCESS(Status);
}

VOID
WSPAPI
WSPGetAcceptExSockaddrs(
    IN PVOID lpOutputBuffer,
    IN DWORD dwReceiveDataLength,
    IN DWORD dwLocalAddressLength,
    IN DWORD dwRemoteAddressLength,
    OUT struct sockaddr **LocalSockaddr,
    OUT LPINT LocalSockaddrLength,
    OUT struct sockaddr **RemoteSockaddr,
    OUT LPINT RemoteSockaddrLength)
{
    /* AFD_SUPER_ACCEPT outputs receive data + local address + local address length + remote address + remote address length */
    /* Length is located 2 bytes before address length */
    BYTE* LocalAddress = (BYTE *)lpOutputBuffer + dwReceiveDataLength;
    if (dwLocalAddressLength >= sizeof(WORD))
    {
        *LocalSockaddr = (struct sockaddr *)LocalAddress;
        *LocalSockaddrLength = *(WORD*)(LocalAddress + dwLocalAddressLength - sizeof(WORD));
    }

    if (dwRemoteAddressLength >= sizeof(WORD))
    {
        BYTE* RemoteAddress = LocalAddress + dwLocalAddressLength;
        *RemoteSockaddr = (struct sockaddr *)RemoteAddress;
        *RemoteSockaddrLength = *(WORD*)(RemoteAddress + dwRemoteAddressLength - sizeof(WORD));
    }
}

static
VOID
NTAPI
MsafdConnectAPC(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved)
{
    PMSAFD_CONNECT_APC_CONTEXT Context = ApcContext;

    TRACE("MsafdConnectAPC(%p %lx %lx)\n", ApcContext, IoStatusBlock->Status, IoStatusBlock->Information);

    PSOCKET_INFORMATION Socket = GetSocketStructure(Context->lpSocket);
    if (!Socket)
    {
        // FIXME: Socket is closed before this APC could run
        HeapFree(GlobalHeap, 0, ApcContext);
        return;
    }

    Socket->SharedData->SocketLastError = TranslateNtStatusError(IoStatusBlock->Status);
    if (IoStatusBlock->Status == STATUS_SUCCESS)
    {
        /* WSPGetPeerName may have recorded the connection already */
        if (Socket->SharedData->State != SocketConnected)
            Socket->SharedData->ConnectTime = GetCurrentTimeInSeconds();
        Socket->SharedData->State = SocketConnected;
        Socket->TdiConnectionHandle = (HANDLE)IoStatusBlock->Information;
    }

    /* Re-enable Async Event */
    SockReenableAsyncSelectEvent(Socket, FD_WRITE);

    /* FIXME: THIS IS NOT RIGHT!!! HACK HACK HACK! */
    SockReenableAsyncSelectEvent(Socket, FD_CONNECT);

    if (IoStatusBlock->Status == STATUS_SUCCESS && (Socket->HelperEvents & WSH_NOTIFY_CONNECT))
    {
        Socket->HelperData->WSHNotify(Socket->HelperContext,
                                      Socket->Handle,
                                      Socket->TdiAddressHandle,
                                      Socket->TdiConnectionHandle,
                                      WSH_NOTIFY_CONNECT);
    }
    else if (IoStatusBlock->Status != STATUS_SUCCESS && (Socket->HelperEvents & WSH_NOTIFY_CONNECT_ERROR))
    {
        Socket->HelperData->WSHNotify(Socket->HelperContext,
                                      Socket->Handle,
                                      Socket->TdiAddressHandle,
                                      Socket->TdiConnectionHandle,
                                      WSH_NOTIFY_CONNECT_ERROR);
    }

    HeapFree(GlobalHeap, 0, ApcContext);
}

int
WSPAPI
WSPConnect(SOCKET Handle,
           const struct sockaddr * SocketAddress,
           int SocketAddressLength,
           LPWSABUF lpCallerData,
           LPWSABUF lpCalleeData,
           LPQOS lpSQOS,
           LPQOS lpGQOS,
           LPINT lpErrno)
{
    IO_STATUS_BLOCK            DummyIOSB;
    PIO_STATUS_BLOCK           IOSB = &DummyIOSB;
    PAFD_CONNECT_INFO          ConnectInfo = NULL;
    PSOCKET_INFORMATION        Socket;
    NTSTATUS                   Status;
    INT                        Errno;
    ULONG                      ConnectDataLength;
    ULONG                      InConnectDataLength;
    HANDLE                     SockEvent;
    int                        SocketDataLength;
    PMSAFD_CONNECT_APC_CONTEXT APCContext = NULL;
    PIO_APC_ROUTINE            APCFunction = NULL;
    UCHAR                      Buffer[128];

    TRACE("WSPConnect(%x)\n", Handle);

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        if (lpErrno) *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }

    /* Bind us First */
    if (Socket->SharedData->State == SocketOpen)
    {
        INT BindAddressLength;
        PSOCKADDR BindAddress;
        INT BindError;

        /* Get the Wildcard Address */
        BindAddressLength = Socket->HelperData->MaxWSAddressLength;
        BindAddress = HeapAlloc(GetProcessHeap(), 0, BindAddressLength);
        if (!BindAddress)
        {
            return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, NULL);
        }
        Socket->HelperData->WSHGetWildcardSockaddr(Socket->HelperContext,
                                                   BindAddress,
                                                   &BindAddressLength);
        /* Bind it */
        BindError = WSPBind(Handle, BindAddress, BindAddressLength, lpErrno);
        HeapFree(GetProcessHeap(), 0, BindAddress);
        if (BindError == SOCKET_ERROR)
            return SOCKET_ERROR;
    }

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);
    if (!NT_SUCCESS(Status))
        return SOCKET_ERROR;

    /* Set the Connect Data */
    if (lpCallerData != NULL)
    {
        ConnectDataLength = lpCallerData->len;
        Status = NtDeviceIoControlFile((HANDLE)Handle,
                                        SockEvent,
                                        NULL,
                                        NULL,
                                        IOSB,
                                        IOCTL_AFD_SET_CONNECT_DATA,
                                        lpCallerData->buf,
                                        ConnectDataLength,
                                        NULL,
                                        0);
        /* Wait for return */
        if (Status == STATUS_PENDING)
        {
            MsafdWaitForAlert(SockEvent);
            Status = IOSB->Status;
        }

        if (Status != STATUS_SUCCESS)
            goto Leave;
    }

    /* Calculate the size of SocketAddress->sa_data */
    SocketDataLength = SocketAddressLength - FIELD_OFFSET(struct sockaddr, sa_data);

    ConnectInfo = (PAFD_CONNECT_INFO)Buffer;

    int connectionInfoSize = FIELD_OFFSET(AFD_CONNECT_INFO, RemoteAddress.Address[0].Address[SocketDataLength]);

    if (connectionInfoSize > 128)
    {
        *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    /* Set up Address in TDI Format */
    ConnectInfo->RemoteAddress.TAAddressCount = 1;
    ConnectInfo->RemoteAddress.Address[0].AddressLength = SocketDataLength;
    ConnectInfo->RemoteAddress.Address[0].AddressType = SocketAddress->sa_family;
    RtlCopyMemory(ConnectInfo->RemoteAddress.Address[0].Address,
                  SocketAddress->sa_data,
                  SocketDataLength);

    /*
    * Disable FD_WRITE and FD_CONNECT
    * The latter fixes a race condition where the FD_CONNECT is re-enabled
    * at the end of this function right after the Async Thread disables it.
    * This should only happen at the *next* WSPConnect
    */
    if (Socket->SharedData->AsyncEvents & FD_CONNECT)
    {
        Socket->SharedData->AsyncDisabledEvents |= FD_CONNECT | FD_WRITE;
    }

    /* Tell AFD that we want Connection Data back, have it allocate a buffer */
    if (lpCalleeData != NULL)
    {
        InConnectDataLength = lpCalleeData->len;
        Status = NtDeviceIoControlFile((HANDLE)Handle,
                                        SockEvent,
                                        NULL,
                                        NULL,
                                        IOSB,
                                        IOCTL_AFD_SET_CONNECT_DATA_SIZE,
                                        &InConnectDataLength,
                                        sizeof(InConnectDataLength),
                                        NULL,
                                        0);

        /* Wait for return */
        if (Status == STATUS_PENDING)
        {
            MsafdWaitForAlert(SockEvent);
            Status = IOSB->Status;
        }

        if (Status != STATUS_SUCCESS)
            goto Leave;
    }

    /* AFD doesn't seem to care if these are invalid, but let's 0 them anyways */
    ConnectInfo->Root = 0;
    ConnectInfo->UseSAN = FALSE;
    ConnectInfo->Unknown = 0;

    /* Verify if we should use APC */
    if (Socket->SharedData->NonBlocking)
    {
        APCContext = HeapAlloc(GlobalHeap, 0, sizeof(*APCContext));
        if (!APCContext)
        {
            ERR("Not enough memory for APC Context\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Leave;
        }
        APCContext->lpSocket = Handle;
        APCFunction = &MsafdConnectAPC;

        IOSB = &APCContext->IoStatusBlock;
    }

    IOSB->Status = STATUS_PENDING;
    IOSB->Information = 0;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                   APCFunction ? NULL : SockEvent,
                                   APCFunction,
                                   APCContext,
                                   IOSB,
                                   IOCTL_AFD_CONNECT,
                                   ConnectInfo,
                                   connectionInfoSize,
                                   NULL,
                                   0);

    /* A connect that AFD took up supersedes a ConnectEx that failed or was
     * cancelled, which nothing else reports; a rejected one changes nothing */
    if (NT_SUCCESS(Status))
        Socket->ConnectExPending = FALSE;

    if (Socket->SharedData->NonBlocking)
    {
        if (Status == STATUS_PENDING)
        {
            Status = STATUS_CANT_WAIT; // WSAEWOULDBLOCK
            goto Leave;
        }
        else
        {
            /* HACK: Allow APC to be processed */
            SleepEx(0, TRUE);
        }
    }
    else
    {
        /* Wait for completion if blocking */
        if (Status == STATUS_PENDING)
        {
            MsafdWaitForAlert(SockEvent);
            Status = IOSB->Status;
        }

        /* A blocking connect reports its failure itself: SO_ERROR stays clear, as on Windows.
         * Only a non-blocking connect leaves the error there (see MsafdConnectAPC). */
        Socket->SharedData->SocketLastError = 0;
        if (Status != STATUS_SUCCESS)
            goto Leave;

        Socket->SharedData->State = SocketConnected;
        Socket->TdiConnectionHandle = (HANDLE)IOSB->Information;
        Socket->SharedData->ConnectTime = GetCurrentTimeInSeconds();
    }

    /* Connecting to the unspecified family dissolved the association with the peer */
    if (Status == STATUS_SUCCESS && SocketAddress->sa_family == AF_UNSPEC &&
        Socket->SharedData->State == SocketConnected)
    {
        Socket->SharedData->State = SocketBound;
    }

    /* Get any pending connect data */
    if (lpCalleeData != NULL && Status == STATUS_SUCCESS)
    {
        IOSB = &DummyIOSB;
        Status = NtDeviceIoControlFile((HANDLE)Handle,
                                       SockEvent,
                                       NULL,
                                       NULL,
                                       IOSB,
                                       IOCTL_AFD_GET_CONNECT_DATA,
                                       NULL,
                                       0,
                                       lpCalleeData->buf,
                                       lpCalleeData->len);
        /* Wait for return */
        if (Status == STATUS_PENDING)
        {
            MsafdWaitForAlert(SockEvent);
            Status = IOSB->Status;
        }
    }

Leave:
    TRACE("Ending %lx\n", Status);

    NtClose(SockEvent);

    /* Re-enable Async Event */
    SockReenableAsyncSelectEvent(Socket, FD_WRITE);

    /* FIXME: THIS IS NOT RIGHT!!! HACK HACK HACK! */
    SockReenableAsyncSelectEvent(Socket, FD_CONNECT);

    if (Status == STATUS_SUCCESS && (Socket->HelperEvents & WSH_NOTIFY_CONNECT))
    {
        Errno = Socket->HelperData->WSHNotify(Socket->HelperContext,
                                              Socket->Handle,
                                              Socket->TdiAddressHandle,
                                              Socket->TdiConnectionHandle,
                                              WSH_NOTIFY_CONNECT);

        if (Errno)
        {
            if (lpErrno) *lpErrno = Errno;
            return SOCKET_ERROR;
        }
    }
    else if (Status != STATUS_SUCCESS && (Socket->HelperEvents & WSH_NOTIFY_CONNECT_ERROR))
    {
        Errno = Socket->HelperData->WSHNotify(Socket->HelperContext,
                                              Socket->Handle,
                                              Socket->TdiAddressHandle,
                                              Socket->TdiConnectionHandle,
                                              WSH_NOTIFY_CONNECT_ERROR);

        if (Errno)
        {
            if (lpErrno) *lpErrno = Errno;
            return SOCKET_ERROR;
        }
    }

    return MsafdReturnWithErrno(Status, lpErrno, 0, NULL);
}

BOOL
WSPAPI
WSPConnectEx(
    _In_ SOCKET Handle,
    _In_ const struct sockaddr *SocketAddress,
    _In_ int SocketAddressLength,
    _In_ PVOID lpSendBuffer,
    _In_ DWORD dwSendDataLength,
    _Out_ LPDWORD lpdwBytesSent,
    _Inout_ LPOVERLAPPED lpOverlapped)
{
    IO_STATUS_BLOCK DummyIOSB;
    PIO_STATUS_BLOCK IOSB = &DummyIOSB;
    PAFD_SUPER_CONNECT_INFO ConnectInfo = NULL;
    PSOCKET_INFORMATION Socket;
    NTSTATUS Status;
    int SocketDataLength;
    UCHAR Buffer[128];

    if (!lpOverlapped)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (!lpSendBuffer && dwSendDataLength)
    {
        SetLastError(WSAEFAULT);
        return FALSE;
    }

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        SetLastError(WSAENOTSOCK);
        return FALSE;
    }

    
    /* Cannot call on connectionless socket */
    if (SocketAddressLength > ARRAYSIZE(Buffer) - sizeof(AFD_CONNECT_INFO) || Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS)
    {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    if (Socket->SharedData->State == SocketOpen)
    {
        /* Socket already must be bound */
        SetLastError(WSAEINVAL);
        return FALSE;
    }

    ConnectInfo = (PAFD_SUPER_CONNECT_INFO)Buffer;
    ConnectInfo->SanActive = FALSE;

    /* Calculate the size of SocketAddress->sa_data */
    SocketDataLength = SocketAddressLength - FIELD_OFFSET(struct sockaddr, sa_data);

    /* Set up Address in TDI Format */
    ConnectInfo->RemoteAddress.TAAddressCount = 1;
    ConnectInfo->RemoteAddress.Address[0].AddressLength = SocketDataLength;
    ConnectInfo->RemoteAddress.Address[0].AddressType = SocketAddress->sa_family;
    RtlCopyMemory(ConnectInfo->RemoteAddress.Address[0].Address,
                  SocketAddress->sa_data,
                  SocketDataLength);

    /*
     * Disable FD_WRITE and FD_CONNECT.
     * The latter fixes a race condition where the FD_CONNECT is re-enabled
     * at the end of this function right after the Async Thread disables it.
     * This should only happen at the *next* WSPConnect.
     */
    if (Socket->SharedData->AsyncEvents & FD_CONNECT)
    {
        Socket->SharedData->AsyncDisabledEvents |= (FD_CONNECT | FD_WRITE);
    }

    IOSB = (PIO_STATUS_BLOCK)lpOverlapped;
    IOSB->Status = STATUS_PENDING;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                   lpOverlapped->hEvent,
                                   NULL,
                                   lpOverlapped->hEvent ? NULL : lpOverlapped,
                                   IOSB,
                                   IOCTL_AFD_SUPER_CONNECT,
                                   ConnectInfo,
                                   FIELD_OFFSET(AFD_SUPER_CONNECT_INFO, RemoteAddress.Address[0].Address[SocketDataLength]),
                                   lpSendBuffer,
                                   dwSendDataLength);

    SetLastError(TranslateNtStatusError(Status));

    /* Only SO_UPDATE_CONNECT_CONTEXT re-arms the asynchronous events */
    if (NT_SUCCESS(Status))
        Socket->ConnectExPending = TRUE;

    return Status == STATUS_SUCCESS;
}

int
WSPAPI
WSPShutdown(SOCKET Handle,
            int HowTo,
            LPINT lpErrno)

{
    IO_STATUS_BLOCK         IOSB;
    AFD_DISCONNECT_INFO     DisconnectInfo;
    PSOCKET_INFORMATION     Socket = NULL;
    NTSTATUS                Status;
    HANDLE                  SockEvent;

    TRACE("Called\n");

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
       if (lpErrno) *lpErrno = WSAENOTSOCK;
       return SOCKET_ERROR;
    }

    /* Shutting down a direction that is shut down already succeeds and does nothing, as on Windows */
    if ((HowTo == SD_RECEIVE && Socket->SharedData->ReceiveShutdown) ||
        (HowTo == SD_SEND && Socket->SharedData->SendShutdown) ||
        (HowTo == SD_BOTH && Socket->SharedData->ReceiveShutdown && Socket->SharedData->SendShutdown))
    {
        return 0;
    }

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if( !NT_SUCCESS(Status) )
        return SOCKET_ERROR;

    /* Set AFD Disconnect Type */
    switch (HowTo)
    {
        case SD_RECEIVE:
            DisconnectInfo.DisconnectType = AFD_DISCONNECT_RECV;
            Socket->SharedData->ReceiveShutdown = TRUE;
            break;
        case SD_SEND:
            DisconnectInfo.DisconnectType= AFD_DISCONNECT_SEND;
            Socket->SharedData->SendShutdown = TRUE;
            break;
        case SD_BOTH:
            DisconnectInfo.DisconnectType = AFD_DISCONNECT_RECV | AFD_DISCONNECT_SEND;
            Socket->SharedData->ReceiveShutdown = TRUE;
            Socket->SharedData->SendShutdown = TRUE;
            break;
    }

    DisconnectInfo.Timeout.QuadPart = -1000000LL;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_DISCONNECT,
                                   &DisconnectInfo,
                                   sizeof(DisconnectInfo),
                                   NULL,
                                   0);

    /* Wait for return */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    TRACE("Ending\n");

    NtClose( SockEvent );

    Socket->SharedData->SocketLastError = TranslateNtStatusError(Status);
    return MsafdReturnWithErrno( Status, lpErrno, 0, NULL );
}


INT
WSPAPI
WSPGetSockName(IN SOCKET Handle,
               OUT LPSOCKADDR Name,
               IN OUT LPINT NameLength,
               OUT LPINT lpErrno)
{
    IO_STATUS_BLOCK         IOSB;
    ULONG                   TdiAddressSize;
    PTDI_ADDRESS_INFO       TdiAddress;
    PTRANSPORT_ADDRESS      SocketAddress;
    PSOCKET_INFORMATION     Socket = NULL;
    NTSTATUS                Status;
    HANDLE                  SockEvent;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
       if (lpErrno) *lpErrno = WSAENOTSOCK;
       return SOCKET_ERROR;
    }

    if (!Name || !NameLength)
    {
        if (lpErrno) *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if( !NT_SUCCESS(Status) )
        return SOCKET_ERROR;

    /* A stream socket this process never bound or connected is not named yet, even when
     * AFD already holds a connection for it: AcceptEx connects its socket, which only
     * SO_UPDATE_ACCEPT_CONTEXT turns into a named one. Windows fails with WSAEINVAL. */
    if (Socket->SharedData->State == SocketOpen &&
        Socket->SharedData->SocketType == SOCK_STREAM)
    {
        SOCK_SHARED_INFO AfdData;

        Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                       SockEvent,
                                       NULL,
                                       NULL,
                                       &IOSB,
                                       IOCTL_AFD_GET_CONTEXT,
                                       NULL,
                                       0,
                                       &AfdData,
                                       sizeof(AfdData));
        if (Status == STATUS_PENDING)
        {
            MsafdWaitForAlert(SockEvent);
            Status = IOSB.Status;
        }

        if (NT_SUCCESS(Status) && AfdData.State == SocketConnected)
        {
            NtClose(SockEvent);
            if (lpErrno) *lpErrno = WSAEINVAL;
            return SOCKET_ERROR;
        }

        /* The event is reused: a synchronous completion left it signalled */
        NtResetEvent(SockEvent, NULL);
    }

    /* Allocate a buffer for the address */
    TdiAddressSize =
        sizeof(TRANSPORT_ADDRESS) + Socket->SharedData->SizeOfLocalAddress;
    TdiAddress = HeapAlloc(GlobalHeap, 0, TdiAddressSize);

    if ( TdiAddress == NULL )
    {
        NtClose( SockEvent );
        if (lpErrno) *lpErrno = WSAENOBUFS;
        return SOCKET_ERROR;
    }

    SocketAddress = &TdiAddress->Address;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_GET_SOCK_NAME,
                                   NULL,
                                   0,
                                   TdiAddress,
                                   TdiAddressSize);

    /* Wait for return */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    NtClose( SockEvent );

    if (NT_SUCCESS(Status))
    {
        if (*NameLength >= Socket->SharedData->SizeOfLocalAddress)
        {
            Name->sa_family = SocketAddress->Address[0].AddressType;
            RtlCopyMemory (Name->sa_data,
                           SocketAddress->Address[0].Address,
                           SocketAddress->Address[0].AddressLength);
            *NameLength = Socket->SharedData->SizeOfLocalAddress;
            TRACE("NameLength %d Address: %x Port %x\n",
                          *NameLength, ((struct sockaddr_in *)Name)->sin_addr.s_addr,
                          ((struct sockaddr_in *)Name)->sin_port);
            HeapFree(GlobalHeap, 0, TdiAddress);
            return 0;
        }
        else
        {
            HeapFree(GlobalHeap, 0, TdiAddress);
            if (lpErrno) *lpErrno = WSAEFAULT;
            return SOCKET_ERROR;
        }
    }

    HeapFree(GlobalHeap, 0, TdiAddress);

    return MsafdReturnWithErrno ( Status, lpErrno, 0, NULL );
}


INT
WSPAPI
WSPGetPeerName(IN SOCKET s,
               OUT LPSOCKADDR Name,
               IN OUT LPINT NameLength,
               OUT LPINT lpErrno)
{
    IO_STATUS_BLOCK         IOSB;
    ULONG                   TdiAddressSize;
    PTRANSPORT_ADDRESS      SocketAddress;
    PSOCKET_INFORMATION     Socket = NULL;
    NTSTATUS                Status;
    HANDLE                  SockEvent;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(s);
    if (!Socket)
    {
        if (lpErrno) *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }

    if (Socket->SharedData->State != SocketConnected)
    {
        INT AdoptError = MsafdAdoptConnectedState(Socket);

        if (AdoptError != NO_ERROR)
        {
            if (lpErrno) *lpErrno = AdoptError;
            return SOCKET_ERROR;
        }
    }

    if (Socket->SharedData->State != SocketConnected)
    {
        if (lpErrno) *lpErrno = WSAENOTCONN;
        return SOCKET_ERROR;
    }

    if (!Name || !NameLength)
    {
        if (lpErrno) *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if( !NT_SUCCESS(Status) )
        return SOCKET_ERROR;

    /* Allocate a buffer for the address */
    TdiAddressSize = sizeof(TRANSPORT_ADDRESS) + Socket->SharedData->SizeOfRemoteAddress;
    SocketAddress = HeapAlloc(GlobalHeap, 0, TdiAddressSize);

    if ( SocketAddress == NULL )
    {
        NtClose( SockEvent );
        if (lpErrno) *lpErrno = WSAENOBUFS;
        return SOCKET_ERROR;
    }

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_GET_PEER_NAME,
                                   NULL,
                                   0,
                                   SocketAddress,
                                   TdiAddressSize);

    /* Wait for return */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    NtClose( SockEvent );

    if (NT_SUCCESS(Status))
    {
        if (*NameLength >= Socket->SharedData->SizeOfRemoteAddress)
        {
            Name->sa_family = SocketAddress->Address[0].AddressType;
            RtlCopyMemory (Name->sa_data,
                           SocketAddress->Address[0].Address,
                           SocketAddress->Address[0].AddressLength);
            *NameLength = Socket->SharedData->SizeOfRemoteAddress;
            TRACE("NameLength %d Address: %x Port %x\n",
                          *NameLength, ((struct sockaddr_in *)Name)->sin_addr.s_addr,
                          ((struct sockaddr_in *)Name)->sin_port);
            HeapFree(GlobalHeap, 0, SocketAddress);
            return 0;
        }
        else
        {
            HeapFree(GlobalHeap, 0, SocketAddress);
            if (lpErrno) *lpErrno = WSAEFAULT;
            return SOCKET_ERROR;
        }
    }

    HeapFree(GlobalHeap, 0, SocketAddress);

    return MsafdReturnWithErrno ( Status, lpErrno, 0, NULL );
}

INT
WSPAPI
WSPIoctl(IN  SOCKET Handle,
         IN  DWORD dwIoControlCode,
         IN  LPVOID lpvInBuffer,
         IN  DWORD cbInBuffer,
         OUT LPVOID lpvOutBuffer,
         IN  DWORD cbOutBuffer,
         OUT LPDWORD lpcbBytesReturned,
         IN  LPWSAOVERLAPPED lpOverlapped,
         IN  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
         IN  LPWSATHREADID lpThreadId,
         OUT LPINT lpErrno)
{
    PSOCKET_INFORMATION Socket = NULL;
    BOOL NeedsCompletion = lpOverlapped != NULL;
    BOOLEAN NonBlocking;
    INT Errno = NO_ERROR, Ret = SOCKET_ERROR;
    DWORD cbRet = 0;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        if(lpErrno)
            *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }

    if (!lpcbBytesReturned && !lpOverlapped)
    {
        if(lpErrno)
            *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    switch( dwIoControlCode )
    {
        case FIONBIO:
            if( cbInBuffer < sizeof(INT) || IS_INTRESOURCE(lpvInBuffer) )
            {
                Errno = WSAEFAULT;
                break;
            }
            NonBlocking = *((PULONG)lpvInBuffer) ? TRUE : FALSE;
            /* Don't allow to go in blocking mode if WSPAsyncSelect or WSPEventSelect is pending */
            if (!NonBlocking)
            {
                /* If there is an WSPAsyncSelect pending, fail with WSAEINVAL */
                if (Socket->SharedData->AsyncEvents & (~Socket->SharedData->AsyncDisabledEvents))
                {
                    Errno = WSAEINVAL;
                    break;
                }
                /* If there is an WSPEventSelect pending, fail with WSAEINVAL */
                if (Socket->NetworkEvents)
                {
                    Errno = WSAEINVAL;
                    break;
                }
            }
            Socket->SharedData->NonBlocking = NonBlocking ? 1 : 0;
            NeedsCompletion = FALSE;
            Errno = SetSocketInformation(Socket, AFD_INFO_BLOCKING_MODE, &NonBlocking, NULL, NULL, lpOverlapped, lpCompletionRoutine);
            if (Errno == NO_ERROR)
                Ret = NO_ERROR;
            break;
        case FIONREAD:
            if (IS_INTRESOURCE(lpvOutBuffer) || cbOutBuffer == 0)
            {
                cbRet = sizeof(ULONG);
                Errno = WSAEFAULT;
                break;
            }
            if (cbOutBuffer < sizeof(ULONG))
            {
                Errno = WSAEINVAL;
                break;
            }
            NeedsCompletion = FALSE;
            Errno = GetSocketInformation(Socket, AFD_INFO_RECEIVE_CONTENT_SIZE, NULL, (PULONG)lpvOutBuffer, NULL, lpOverlapped, lpCompletionRoutine);
            if (Errno == NO_ERROR)
            {
                cbRet = sizeof(ULONG);
                Ret = NO_ERROR;
            }
            break;
        case SIOCATMARK:
            if (IS_INTRESOURCE(lpvOutBuffer) || cbOutBuffer == 0)
            {
                cbRet = sizeof(BOOL);
                Errno = WSAEFAULT;
                break;
            }
            if (cbOutBuffer < sizeof(BOOL))
            {
                Errno = WSAEINVAL;
                break;
            }
            if (Socket->SharedData->SocketType != SOCK_STREAM)
            {
                Errno = WSAEINVAL;
                break;
            }

            /* FIXME: Return false if OOBINLINE is true for now
               We should MSG_PEEK|MSG_OOB check with driver
            */
            *(BOOL*)lpvOutBuffer = !Socket->SharedData->OobInline;

            cbRet = sizeof(BOOL);
            Errno = NO_ERROR;
            Ret = NO_ERROR;
            break;
        case SIO_GET_EXTENSION_FUNCTION_POINTER:
            if (cbOutBuffer == 0)
            {
                cbRet = sizeof(PVOID);
                Errno = WSAEFAULT;
                break;
            }

            if (cbInBuffer < sizeof(GUID) ||
                cbOutBuffer < sizeof(PVOID))
            {
                Errno = WSAEINVAL;
                break;
            }

            {
                GUID AcceptExGUID = WSAID_ACCEPTEX;
                GUID ConnectExGUID = WSAID_CONNECTEX;
                GUID DisconnectExGUID = WSAID_DISCONNECTEX;
                GUID GetAcceptExSockaddrsGUID = WSAID_GETACCEPTEXSOCKADDRS;
                GUID RecvMsgGUID = WSAID_WSARECVMSG;
                GUID TransmitFileGUID = WSAID_TRANSMITFILE;
                GUID TransmitPacketsGUID = WSAID_TRANSMITPACKETS;

                if (IsEqualGUID(&AcceptExGUID, lpvInBuffer))
                {
                    *((PVOID *)lpvOutBuffer) = WSPAcceptEx;
                    cbRet = sizeof(PVOID);
                    Errno = NO_ERROR;
                    Ret = NO_ERROR;
                }
                else if (IsEqualGUID(&ConnectExGUID, lpvInBuffer))
                {
                    *((PVOID *)lpvOutBuffer) = WSPConnectEx;
                    cbRet = sizeof(PVOID);
                    Errno = NO_ERROR;
                    Ret = NO_ERROR;
                }
                else if (IsEqualGUID(&DisconnectExGUID, lpvInBuffer))
                {
                    *((PVOID *)lpvOutBuffer) = WSPDisconnectEx;
                    cbRet = sizeof(PVOID);
                    Errno = NO_ERROR;
                    Ret = NO_ERROR;
                }
                else if (IsEqualGUID(&GetAcceptExSockaddrsGUID, lpvInBuffer))
                {
                    *((PVOID *)lpvOutBuffer) = WSPGetAcceptExSockaddrs;
                    cbRet = sizeof(PVOID);
                    Errno = NO_ERROR;
                    Ret = NO_ERROR;
                }
                else if (IsEqualGUID(&RecvMsgGUID, lpvInBuffer))
                {
                    *((PVOID *)lpvOutBuffer) = WSPRecvMsg;
                    cbRet = sizeof(PVOID);
                    Errno = NO_ERROR;
                    Ret = NO_ERROR;
                }
                else if (IsEqualGUID(&TransmitFileGUID, lpvInBuffer))
                {
                    *((PVOID *)lpvOutBuffer) = WSPTransmitFile;
                    cbRet = sizeof(PVOID);
                    Errno = NO_ERROR;
                    Ret = NO_ERROR;
                }
                else if (IsEqualGUID(&TransmitPacketsGUID, lpvInBuffer))
                {
                    *((PVOID *)lpvOutBuffer) = WSPTransmitPackets;
                    cbRet = sizeof(PVOID);
                    Errno = NO_ERROR;
                    Ret = NO_ERROR;
                }
                else
                {
                    ERR("Querying unknown extension function: %x\n", ((GUID*)lpvInBuffer)->Data1);
                    Errno = WSAEOPNOTSUPP;
                }
            }

            break;
        case SIO_ADDRESS_LIST_QUERY:
            Errno = MsafdQueryAddressList(Socket, lpvOutBuffer, cbOutBuffer, &cbRet);
            if (Errno == NO_ERROR)
                Ret = NO_ERROR;
            break;
        case SIO_ADDRESS_LIST_CHANGE:
            /* Completes later (or never): the overlapped tail below does not apply */
            NeedsCompletion = FALSE;
            Errno = MsafdAddressListChange(Socket, cbInBuffer, cbOutBuffer, lpOverlapped, lpCompletionRoutine);
            if (Errno == NO_ERROR)
                Ret = NO_ERROR;
            break;
        case SIO_UDP_CONNRESET:
        case SIO_UDP_NETRESET:
            /* These control whether a datagram socket reports a prior ICMP
             * port- or network-unreachable as a receive error. Our transport
             * never reports it, so the state they request is already in effect;
             * accept the request on datagram sockets (Windows fails it with
             * WSAEINVAL on other socket types) so applications such as the Go
             * runtime, which disables connection reset on every UDP socket, can
             * create datagram sockets. */
            /* A rejected request fails at once; the overlapped tail would report success */
            if (Socket->SharedData->SocketType != SOCK_DGRAM)
            {
                Errno = WSAEINVAL;
                NeedsCompletion = FALSE;
                break;
            }
            if (IS_INTRESOURCE(lpvInBuffer) || cbInBuffer < sizeof(BOOL))
            {
                Errno = WSAEFAULT;
                NeedsCompletion = FALSE;
                break;
            }
            cbRet = 0;
            Errno = NO_ERROR;
            Ret = NO_ERROR;
            break;
        default:
            Errno = Socket->HelperData->WSHIoctl(Socket->HelperContext,
                                                 Handle,
                                                 Socket->TdiAddressHandle,
                                                 Socket->TdiConnectionHandle,
                                                 dwIoControlCode,
                                                 lpvInBuffer,
                                                 cbInBuffer,
                                                 lpvOutBuffer,
                                                 cbOutBuffer,
                                                 &cbRet,
                                                 lpOverlapped,
                                                 lpCompletionRoutine,
                                                 &NeedsCompletion);

            if (Errno == NO_ERROR)
                Ret = NO_ERROR;
            break;
    }
    if (lpOverlapped && NeedsCompletion)
    {
        lpOverlapped->Internal = Errno;
        lpOverlapped->InternalHigh = cbRet;
        if (lpCompletionRoutine != NULL)
        {
            lpCompletionRoutine(Errno, cbRet, lpOverlapped, 0);
        }
        if (lpOverlapped->hEvent)
            SetEvent(lpOverlapped->hEvent);
        if (!PostQueuedCompletionStatus((HANDLE)Handle, cbRet, 0, lpOverlapped))
        {
            ERR("PostQueuedCompletionStatus failed %d\n", GetLastError());
        }
        return NO_ERROR;
    }
    if (lpErrno)
        *lpErrno = Errno;
    if (lpcbBytesReturned)
        *lpcbBytesReturned = cbRet;
    return Ret;
}


INT
WSPAPI
WSPGetSockOpt(IN SOCKET Handle,
              IN INT Level,
              IN INT OptionName,
              OUT CHAR FAR* OptionValue,
              IN OUT LPINT OptionLength,
              OUT LPINT lpErrno)
{
    PSOCKET_INFORMATION Socket = NULL;
    PVOID Buffer;
    INT BufferSize;
    BOOL BoolBuffer;
    DWORD DwordBuffer;
    INT Errno;

    TRACE("Called\n");

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (Socket == NULL)
    {
        if (lpErrno) *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    if (!OptionLength || !OptionValue)
    {
        if (lpErrno) *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    /* IP_PKTINFO: AFD has no such option, WSARecvMsg asks AFD for the packet information
     * when the socket has it enabled (a datagram or raw socket; a stream socket: WSAEINVAL) */
    if (Level == IPPROTO_IP && OptionName == IP_PKTINFO)
    {
        if (!(Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS))
        {
            if (lpErrno) *lpErrno = WSAEINVAL;
            return SOCKET_ERROR;
        }
        if (*OptionLength < (INT)sizeof(DWORD))
        {
            if (lpErrno) *lpErrno = WSAEFAULT;
            return SOCKET_ERROR;
        }
        *(DWORD *)OptionValue = Socket->SharedData->IpPktInfo ? 1 : 0;
        *OptionLength = sizeof(DWORD);
        return NO_ERROR;
    }

    /* TCP_NODELAY: kept with the socket (the helper cannot read it back). Windows answers with a
     * one byte BOOLEAN whatever the size of the buffer, and refuses it on a socket that is not a stream */
    if (Level == IPPROTO_TCP && OptionName == TCP_NODELAY)
    {
        if (Socket->SharedData->SocketType != SOCK_STREAM)
        {
            if (lpErrno) *lpErrno = WSAEINVAL;
            return SOCKET_ERROR;
        }
        if (*OptionLength < (INT)sizeof(BOOLEAN))
        {
            if (lpErrno) *lpErrno = WSAEFAULT;
            return SOCKET_ERROR;
        }
        *(BOOLEAN *)OptionValue = Socket->SharedData->TcpNoDelay ? TRUE : FALSE;
        *OptionLength = sizeof(BOOLEAN);
        return NO_ERROR;
    }

    switch (Level)
    {
        case SOL_SOCKET:
            switch (OptionName)
            {
                case SO_TYPE:
                    Buffer = &Socket->SharedData->SocketType;
                    BufferSize = sizeof(INT);
                    break;

                case SO_RCVBUF:
                    Buffer = &Socket->SharedData->SizeOfRecvBuffer;
                    BufferSize = sizeof(ULONG);
                    break;

                case SO_SNDBUF:
                    Buffer = &Socket->SharedData->SizeOfSendBuffer;
                    BufferSize = sizeof(ULONG);
                    break;

                case SO_ACCEPTCONN:
                    BoolBuffer = Socket->SharedData->Listening;
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_BROADCAST:
                    BoolBuffer = Socket->SharedData->Broadcast;
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_DEBUG:
                    BoolBuffer = Socket->SharedData->Debug;
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_DONTLINGER:
                    BoolBuffer = (Socket->SharedData->LingerData.l_onoff == 0);
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_LINGER:
                    if (Socket->SharedData->SocketType == SOCK_DGRAM)
                    {
                        if (lpErrno) *lpErrno = WSAENOPROTOOPT;
                        return SOCKET_ERROR;
                    }
                    Buffer = &Socket->SharedData->LingerData;
                    BufferSize = sizeof(struct linger);
                    break;

                case SO_OOBINLINE:
                    BoolBuffer = (Socket->SharedData->OobInline != 0);
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_KEEPALIVE:
                case SO_DONTROUTE:
                   /* These guys go directly to the helper */
                   goto SendToHelper;

                case SO_CONDITIONAL_ACCEPT:
                    BoolBuffer = (Socket->SharedData->UseDelayedAcceptance != 0);
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_REUSEADDR:
                    BoolBuffer = (Socket->SharedData->ReuseAddresses != 0);
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_EXCLUSIVEADDRUSE:
                    BoolBuffer = (Socket->SharedData->ExclusiveAddressUse != 0);
                    Buffer = &BoolBuffer;
                    BufferSize = sizeof(BOOL);
                    break;

                case SO_ERROR:
                    /* The failure of a non-blocking connect is kept by AFD: its completion APC
                     * may not have run on this thread, or on any thread that asks */
                    if (Socket->SharedData->SocketLastError == 0)
                    {
                        ULONG ConnectStatus = 0;

                        if (GetSocketInformation(Socket, AFD_INFO_CONNECT_ERROR, NULL, &ConnectStatus, NULL, NULL, NULL) == NO_ERROR &&
                            ConnectStatus != 0)
                        {
                            Socket->SharedData->SocketLastError = TranslateNtStatusError((NTSTATUS)ConnectStatus);
                        }
                    }
                    Buffer = &Socket->SharedData->SocketLastError;
                    BufferSize = sizeof(INT);
                    break;

                case SO_CONNECT_TIME:
                    if (Socket->SharedData->ConnectTime)
                        DwordBuffer = GetCurrentTimeInSeconds() - Socket->SharedData->ConnectTime;
                    else
                        DwordBuffer = -1;
                    Buffer = &DwordBuffer;
                    BufferSize = sizeof(DWORD);
                    break;

                case SO_SNDTIMEO:
                    Buffer = &Socket->SharedData->SendTimeout;
                    BufferSize = sizeof(DWORD);
                    break;
                case SO_RCVTIMEO:
                    Buffer = &Socket->SharedData->RecvTimeout;
                    BufferSize = sizeof(DWORD);
                    break;
                case SO_PROTOCOL_INFOW:
                    Buffer = &Socket->ProtocolInfo;
                    BufferSize = sizeof(Socket->ProtocolInfo);
                    break;

                case SO_GROUP_ID:
                case SO_GROUP_PRIORITY:
                case SO_MAX_MSG_SIZE:

                default:
                    DbgPrint("MSAFD: Get unknown optname %x\n", OptionName);
                    if (lpErrno) *lpErrno = WSAENOPROTOOPT;
                    return SOCKET_ERROR;
            }

            if (*OptionLength < BufferSize)
            {
                if (lpErrno) *lpErrno = WSAEFAULT;
                *OptionLength = BufferSize;
                return SOCKET_ERROR;
            }
            RtlCopyMemory(OptionValue, Buffer, BufferSize);

            return 0;

        default:
            if (lpErrno) *lpErrno = WSAEINVAL;
            return SOCKET_ERROR;
    }

SendToHelper:
    Errno = Socket->HelperData->WSHGetSocketInformation(Socket->HelperContext,
                                                        Handle,
                                                        Socket->TdiAddressHandle,
                                                        Socket->TdiConnectionHandle,
                                                        Level,
                                                        OptionName,
                                                        OptionValue,
                                                        (LPINT)OptionLength);
    if (lpErrno) *lpErrno = Errno;
    return (Errno == NO_ERROR) ? NO_ERROR : SOCKET_ERROR;
}

static
INT
NTAPI
MsafdUpdateConnectionContext(
    _In_ SOCKET Handle,
    _Out_ LPINT lpErrno)
{
    IO_STATUS_BLOCK            DummyIOSB;
    PIO_STATUS_BLOCK           IOSB = &DummyIOSB;
    NTSTATUS                   Status;
    SOCK_SHARED_INFO SharedData;
    AFD_TDI_HANDLE_DATA HandleData;
    HANDLE SockEvent;
    BOOLEAN WasConnected;
    PSOCKET_INFORMATION Socket = GetSocketStructure(Handle);

    if (!Socket)
    {
        if (lpErrno) *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }

    /* A connected socket needs nothing, unless ConnectEx connected it and
     * WSPGetPeerName recorded that before this option re-armed the events */
    WasConnected = (Socket->SharedData->State == SocketConnected);
    if (WasConnected && !Socket->ConnectExPending)
    {
        return NO_ERROR;
    }

    /* Get the socket context from AFD because when ConnectEx is used, this information is not updated. */
    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);
    if (!NT_SUCCESS(Status))
        goto Quit;

    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   IOSB,
                                   IOCTL_AFD_GET_CONTEXT,
                                   NULL,
                                   0,
                                   &SharedData,
                                   sizeof(SharedData));
    
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB->Status;
    }

    if (!NT_SUCCESS(Status))
        goto Quit;

    ULONG flags = AFD_CONNECTION_HANDLE | AFD_ADDRESS_HANDLE;

    /* Get TDI handles from AFD */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   IOSB,
                                   IOCTL_AFD_GET_TDI_HANDLES,
                                   &flags,
                                   sizeof(flags),
                                   &HandleData,
                                   sizeof(HandleData));
    
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB->Status;
    }

    /* Bail out if the socket was destroyed */
    if (!NT_SUCCESS(Status))
        goto Quit;

    Socket->SharedData->State = SharedData.State;
    Socket->ConnectExPending = FALSE;

    if (SharedData.State == SocketConnected)
    {
        /* Socket is now connected, update usermode msafd socket structure, same as the end of WSPConnect */
        Socket->TdiConnectionHandle = HandleData.TdiConnectionHandle;
        Socket->TdiAddressHandle = HandleData.TdiAddressHandle;
        /* AFD keeps no connect time; WSPGetPeerName may have recorded it */
        if (!WasConnected)
            Socket->SharedData->ConnectTime = GetCurrentTimeInSeconds();

        /* Re-enable Async Event */
        SockReenableAsyncSelectEvent(Socket, FD_WRITE);

        /* FIXME: THIS IS NOT RIGHT!!! HACK HACK HACK! */
        SockReenableAsyncSelectEvent(Socket, FD_CONNECT);

        Socket->HelperData->WSHNotify(Socket->HelperContext,
                                      Socket->Handle,
                                      Socket->TdiAddressHandle,
                                      Socket->TdiConnectionHandle,
                                      WSH_NOTIFY_CONNECT);
    }

    NtClose(SockEvent);

Quit:
    if (Status == STATUS_SUCCESS)
        return NO_ERROR;
    if (lpErrno) *lpErrno = TranslateNtStatusError(Status);
    return SOCKET_ERROR;
}

INT
WSPAPI
WSPSetSockOpt(
    IN  SOCKET s,
    IN  INT level,
    IN  INT optname,
    IN  CONST CHAR FAR* optval,
    IN  INT optlen,
    OUT LPINT lpErrno)
{
    PSOCKET_INFORMATION Socket;
    INT Errno;

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(s);
    if (Socket == NULL)
    {
        if (lpErrno) *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    if (!optval && optlen)
    {
        if (lpErrno) *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    /* A negative length would pass every "optlen < sizeof(...)" check below,
     * which compares against an unsigned size, and the value would be read. */
    if (optlen < 0)
    {
        if (lpErrno) *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    /* IP_PKTINFO: a switch for WSARecvMsg, kept with the socket (see WSPGetSockOpt) */
    if (level == IPPROTO_IP && optname == IP_PKTINFO)
    {
        if (!(Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS))
        {
            if (lpErrno) *lpErrno = WSAEINVAL;
            return SOCKET_ERROR;
        }
        if (!optval || optlen < (INT)sizeof(DWORD))
        {
            if (lpErrno) *lpErrno = WSAEFAULT;
            return SOCKET_ERROR;
        }
        Socket->SharedData->IpPktInfo = (*(DWORD *)optval != 0) ? 1 : 0;
        return NO_ERROR;
    }

    /* TCP_NODELAY: a one byte switch on a stream socket (the value is read from the first byte of
     * the buffer, whatever its size), also kept with the socket for getsockopt */
    if (level == IPPROTO_TCP && optname == TCP_NODELAY)
    {
        if (Socket->SharedData->SocketType != SOCK_STREAM)
        {
            if (lpErrno) *lpErrno = WSAEINVAL;
            return SOCKET_ERROR;
        }
        if (optlen < (INT)sizeof(BOOLEAN))
        {
            if (lpErrno) *lpErrno = WSAEFAULT;
            return SOCKET_ERROR;
        }
        Errno = Socket->HelperData->WSHSetSocketInformation(Socket->HelperContext,
                                                            s,
                                                            Socket->TdiAddressHandle,
                                                            Socket->TdiConnectionHandle,
                                                            level,
                                                            optname,
                                                            (PCHAR)optval,
                                                            optlen);
        if (lpErrno) *lpErrno = Errno;
        if (Errno != NO_ERROR)
            return SOCKET_ERROR;
        Socket->SharedData->TcpNoDelay = (*(BOOLEAN *)optval != 0) ? 1 : 0;
        return NO_ERROR;
    }

    /* FIXME: We should handle some more cases here */
    if (level == SOL_SOCKET)
    {
        switch (optname)
        {
           case SO_BROADCAST:
              if (optlen < sizeof(BOOL))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }
              Socket->SharedData->Broadcast = (*optval != 0) ? 1 : 0;
              return NO_ERROR;

           case SO_OOBINLINE:
              if (optlen < sizeof(BOOL))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }
              Socket->SharedData->OobInline = (*optval != 0) ? 1 : 0;
              return NO_ERROR;

           case SO_DONTLINGER:
              if (optlen < sizeof(BOOL))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }
              Socket->SharedData->LingerData.l_onoff = (*optval != 0) ? 0 : 1;
              return NO_ERROR;

           case SO_REUSEADDR:
              if (optlen < sizeof(BOOL))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }
              Socket->SharedData->ReuseAddresses = (*optval != 0) ? 1 : 0;
              return NO_ERROR;

           case SO_EXCLUSIVEADDRUSE:
              if (optlen < sizeof(BOOL))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }
              Socket->SharedData->ExclusiveAddressUse = (*optval != 0) ? 1 : 0;
              return NO_ERROR;

           case SO_LINGER:
              if (optlen < sizeof(struct linger))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }
              RtlCopyMemory(&Socket->SharedData->LingerData,
                            optval,
                            sizeof(struct linger));
              return NO_ERROR;

           case SO_SNDBUF:
              if (optlen < sizeof(ULONG))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }

              /* Symmetric with SO_RCVBUF below: SO_SNDBUF is an advisory hint.
               * AFD never reports the caller's size back from
               * AFD_INFO_SEND_WINDOW_SIZE, so storing the read-back made
               * getsockopt(SO_SNDBUF) report the unchanged default (Chrome's
               * QUIC path treats that as ERR_SOCKET_SEND_BUFFER_SIZE_UNCHANGEABLE,
               * net error -163). Record the requested value as Windows does. */
              SetSocketInformation(Socket,
                                   AFD_INFO_SEND_WINDOW_SIZE,
                                   NULL,
                                   (PULONG)optval,
                                   NULL,
                                   NULL,
                                   NULL);
              Socket->SharedData->SizeOfSendBuffer = *(PULONG)optval;

              return NO_ERROR;

           case SO_RCVBUF:
              if (optlen < sizeof(ULONG))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }

              /* SO_RCVBUF is an advisory receive-buffer hint. Match Windows:
               * accept the requested size, record it as the value that
               * getsockopt(SO_RCVBUF) reads back, and pass it to AFD as a hint.
               *
               * AFD keeps its own bounded receive window: it only (re)allocates
               * within a small, safe range and never once a transport object is
               * attached (drivers/network/afd/afd/info.c, AfdSetInfo), and its
               * AFD_INFO_RECEIVE_WINDOW_SIZE query always reports that internal
               * window, not the caller's requested size (see the windowsize
               * apitest, which asserts the queried size never changes). So the
               * old code -- which stored the AFD read-back into
               * SizeOfRecvBuffer -- always reported the unchanged default,
               * making getsockopt(SO_RCVBUF) look like the buffer size could
               * not be changed. Chrome's QUIC path sets SO_RCVBUF, reads it
               * back, and on a smaller-than-requested read-back fails the UDP
               * socket with ERR_SOCKET_RECEIVE_BUFFER_SIZE_UNCHANGEABLE
               * (net error -162), which aborts the QUIC handshake.
               *
               * Record the requested value in SharedData, exactly as Windows'
               * provider records the hint, so getsockopt reads it back. The
               * former clamp to 0x2000 (a CORE-15804 work-around that mutated
               * the caller's buffer) is dropped: AFD already bounds any real
               * allocation, so there is nothing for msafd to clamp. */
              SetSocketInformation(Socket,
                                   AFD_INFO_RECEIVE_WINDOW_SIZE,
                                   NULL,
                                   (PULONG)optval,
                                   NULL,
                                   NULL,
                                   NULL);
              Socket->SharedData->SizeOfRecvBuffer = *(PULONG)optval;

              return NO_ERROR;

           case SO_UPDATE_CONNECT_CONTEXT:
           case SO_UPDATE_ACCEPT_CONTEXT:
              return MsafdUpdateConnectionContext(s, lpErrno);

           case SO_ERROR:
              if (optlen < sizeof(INT))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }

              RtlCopyMemory(&Socket->SharedData->SocketLastError,
                            optval,
                            sizeof(INT));
              return NO_ERROR;

           case SO_SNDTIMEO:
              if (optlen < sizeof(DWORD))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }

              RtlCopyMemory(&Socket->SharedData->SendTimeout,
                            optval,
                            sizeof(DWORD));
              return NO_ERROR;

           case SO_RCVTIMEO:
              if (optlen < sizeof(DWORD))
              {
                  if (lpErrno) *lpErrno = WSAEFAULT;
                  return SOCKET_ERROR;
              }

              RtlCopyMemory(&Socket->SharedData->RecvTimeout,
                            optval,
                            sizeof(DWORD));
              return NO_ERROR;

           case SO_KEEPALIVE:
           case SO_DONTROUTE:
              /* These go directly to the helper dll */
              goto SendToHelper;

           default:
              /* Obviously this is a hack */
              ERR("MSAFD: Set unknown optname %x\n", optname);
              return NO_ERROR;
        }
    }

SendToHelper:
    Errno = Socket->HelperData->WSHSetSocketInformation(Socket->HelperContext,
                                                        s,
                                                        Socket->TdiAddressHandle,
                                                        Socket->TdiConnectionHandle,
                                                        level,
                                                        optname,
                                                        (PCHAR)optval,
                                                        optlen);
    if (lpErrno) *lpErrno = Errno;
    return (Errno == NO_ERROR) ? NO_ERROR : SOCKET_ERROR;
}

/*
 * FUNCTION: Initialize service provider for a client
 * ARGUMENTS:
 *     wVersionRequested = Highest WinSock SPI version that the caller can use
 *     lpWSPData         = Address of WSPDATA structure to initialize
 *     lpProtocolInfo    = Pointer to structure that defines the desired protocol
 *     UpcallTable       = Pointer to upcall table of the WinSock DLL
 *     lpProcTable       = Address of procedure table to initialize
 * RETURNS:
 *     Status of operation
 */
_Must_inspect_result_
int
WSPAPI
WSPStartup(
    _In_ WORD wVersionRequested,
    _In_ LPWSPDATA lpWSPData,
    _In_ LPWSAPROTOCOL_INFOW lpProtocolInfo,
    _In_ WSPUPCALLTABLE UpcallTable,
    _Out_ LPWSPPROC_TABLE lpProcTable)
{
    NTSTATUS Status;

    if (((LOBYTE(wVersionRequested) == 2) && (HIBYTE(wVersionRequested) < 2)) ||
        (LOBYTE(wVersionRequested) < 2))
    {
        ERR("WSPStartup NOT SUPPORTED for version 0x%X\n", wVersionRequested);
        return WSAVERNOTSUPPORTED;
    }
    else
        Status = NO_ERROR;
    /* FIXME: Enable all cases of WSPStartup status */
    Upcalls = UpcallTable;

    if (Status == NO_ERROR)
    {
        lpProcTable->lpWSPAccept = WSPAccept;
        lpProcTable->lpWSPAddressToString = WSPAddressToString;
        lpProcTable->lpWSPAsyncSelect = WSPAsyncSelect;
        lpProcTable->lpWSPBind = WSPBind;
        lpProcTable->lpWSPCancelBlockingCall = WSPCancelBlockingCall;
        lpProcTable->lpWSPCleanup = WSPCleanup;
        lpProcTable->lpWSPCloseSocket = WSPCloseSocket;
        lpProcTable->lpWSPConnect = WSPConnect;
        lpProcTable->lpWSPDuplicateSocket = WSPDuplicateSocket;
        lpProcTable->lpWSPEnumNetworkEvents = WSPEnumNetworkEvents;
        lpProcTable->lpWSPEventSelect = WSPEventSelect;
        lpProcTable->lpWSPGetOverlappedResult = WSPGetOverlappedResult;
        lpProcTable->lpWSPGetPeerName = WSPGetPeerName;
        lpProcTable->lpWSPGetSockName = WSPGetSockName;
        lpProcTable->lpWSPGetSockOpt = WSPGetSockOpt;
        lpProcTable->lpWSPGetQOSByName = WSPGetQOSByName;
        lpProcTable->lpWSPIoctl = WSPIoctl;
        lpProcTable->lpWSPJoinLeaf = WSPJoinLeaf;
        lpProcTable->lpWSPListen = WSPListen;
        lpProcTable->lpWSPRecv = WSPRecv;
        lpProcTable->lpWSPRecvDisconnect = WSPRecvDisconnect;
        lpProcTable->lpWSPRecvFrom = WSPRecvFrom;
        lpProcTable->lpWSPSelect = WSPSelect;
        lpProcTable->lpWSPSend = WSPSend;
        lpProcTable->lpWSPSendDisconnect = WSPSendDisconnect;
        lpProcTable->lpWSPSendTo = WSPSendTo;
        lpProcTable->lpWSPSetSockOpt = WSPSetSockOpt;
        lpProcTable->lpWSPShutdown = WSPShutdown;
        lpProcTable->lpWSPSocket = WSPSocket;
        lpProcTable->lpWSPStringToAddress = WSPStringToAddress;
        lpWSPData->wVersion     = MAKEWORD(2, 2);
        lpWSPData->wHighVersion = MAKEWORD(2, 2);
        /* Save CatalogEntryId for all upcalls */
        CatalogEntryId = lpProtocolInfo->dwCatalogEntryId;
    }

    TRACE("Status (%d).\n", Status);
    return Status;
}


INT
WSPAPI
WSPAddressToString(IN LPSOCKADDR lpsaAddress,
                   IN DWORD dwAddressLength,
                   IN LPWSAPROTOCOL_INFOW lpProtocolInfo,
                   OUT LPWSTR lpszAddressString,
                   IN OUT LPDWORD lpdwAddressStringLength,
                   OUT LPINT lpErrno)
{
    SIZE_T size;
    WCHAR buffer[54]; /* 32 digits + 7':' + '[' + '%" + 5 digits + ']:' + 5 digits + '\0' */
    WCHAR *p;

    if (!lpsaAddress || !lpszAddressString || !lpdwAddressStringLength)
    {
        if (lpErrno) *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    switch (lpsaAddress->sa_family)
    {
        case AF_INET:
            if (dwAddressLength < sizeof(SOCKADDR_IN))
            {
                if (lpErrno) *lpErrno = WSAEINVAL;
                return SOCKET_ERROR;
            }
            _swprintf(buffer,
                      L"%u.%u.%u.%u:%u",
                      (unsigned int)(ntohl(((SOCKADDR_IN *)lpsaAddress)->sin_addr.s_addr) >> 24 & 0xff),
                      (unsigned int)(ntohl(((SOCKADDR_IN *)lpsaAddress)->sin_addr.s_addr) >> 16 & 0xff),
                      (unsigned int)(ntohl(((SOCKADDR_IN *)lpsaAddress)->sin_addr.s_addr) >> 8 & 0xff),
                      (unsigned int)(ntohl(((SOCKADDR_IN *)lpsaAddress)->sin_addr.s_addr) & 0xff),
                      ntohs(((SOCKADDR_IN *)lpsaAddress)->sin_port));

            p = wcschr(buffer, L':');
            if (!((SOCKADDR_IN *)lpsaAddress)->sin_port)
            {
                *p = 0;
            }
            break;
        default:
            if (lpErrno) *lpErrno = WSAEINVAL;
            return SOCKET_ERROR;
    }

    size = wcslen(buffer) + 1;

    if (*lpdwAddressStringLength < size)
    {
        *lpdwAddressStringLength = size;
        if (lpErrno) *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    *lpdwAddressStringLength = size;
    wcscpy(lpszAddressString, buffer);
    return 0;
}

INT
WSPAPI
WSPStringToAddress(IN LPWSTR AddressString,
                   IN INT AddressFamily,
                   IN LPWSAPROTOCOL_INFOW lpProtocolInfo,
                   OUT LPSOCKADDR lpAddress,
                   IN OUT LPINT lpAddressLength,
                   OUT LPINT lpErrno)
{
    int numdots = 0;
    USHORT port;
    LONG inetaddr = 0, ip_part;
    LPWSTR *bp = NULL;
    SOCKADDR_IN *sockaddr;

    if (!lpAddressLength || !lpAddress || !AddressString)
    {
        if (lpErrno) *lpErrno = WSAEINVAL;
        return SOCKET_ERROR;
    }

    sockaddr = (SOCKADDR_IN *)lpAddress;

    /* Set right address family */
    if (lpProtocolInfo != NULL)
    {
        sockaddr->sin_family = lpProtocolInfo->iAddressFamily;
    }
    else
    {
        sockaddr->sin_family = AddressFamily;
    }

    /* Report size */
    if (AddressFamily == AF_INET)
    {
        if (*lpAddressLength < (INT)sizeof(SOCKADDR_IN))
        {
            if (lpErrno) *lpErrno = WSAEFAULT;
        }
        else
        {
            // translate ip string to ip

            /* Get ip number */
            bp = &AddressString;
            inetaddr = 0;

            while (*bp < &AddressString[wcslen(AddressString)])
            {
                ip_part = wcstol(*bp, bp, 10);
                /* ip part number should be in range 0-255 */
                if (ip_part < 0 || ip_part > 255)
                {
                    if (lpErrno) *lpErrno = WSAEINVAL;
                    return SOCKET_ERROR;
                }
                inetaddr = (inetaddr << 8) + ip_part;
                /* we end on string end or port separator */
                if ((*bp)[0] == 0 || (*bp)[0] == L':')
                    break;
                /* ip parts are dot separated. verify it */
                if ((*bp)[0] != L'.')
                {
                    if (lpErrno) *lpErrno = WSAEINVAL;
                    return SOCKET_ERROR;
                }
                /* count the dots */
                numdots++;
                /* move over the dot to next ip part */
                (*bp)++;
            }

            /* check dots count */
            if (numdots != 3)
            {
                if (lpErrno) *lpErrno = WSAEINVAL;
                return SOCKET_ERROR;
            }

            /* Get port number */
            if ((*bp)[0] == L':')
            {
                /* move over the column to port part */
                (*bp)++;
                /* next char should be numeric */
                if ((*bp)[0] < L'0' || (*bp)[0] > L'9')
                {
                    if (lpErrno) *lpErrno = WSAEINVAL;
                    return SOCKET_ERROR;
                }
                port = wcstol(*bp, bp, 10);
            }
            else
            {
                port = 0;
            }

            if (lpErrno) *lpErrno = NO_ERROR;
            /* rest sockaddr.sin_addr.s_addr
            for we need to be sure it is zero when we come to while */
            *lpAddressLength = sizeof(*sockaddr);
            memset(lpAddress, 0, sizeof(*sockaddr));
            sockaddr->sin_family = AF_INET;
            /* The address and the port are in network order, as on Windows */
            sockaddr->sin_addr.s_addr = htonl((ULONG)inetaddr);
            sockaddr->sin_port = htons(port);
        }
    }

    if (lpErrno && !*lpErrno)
    {
        return 0;
    }

    return SOCKET_ERROR;
}

/*
 * FUNCTION: Cleans up service provider for a client
 * ARGUMENTS:
 *     lpErrno = Address of buffer for error information
 * RETURNS:
 *     0 if successful, or SOCKET_ERROR if not
 */
INT
WSPAPI
WSPCleanup(OUT LPINT lpErrno)

{
    TRACE("Leaving.\n");

    if (lpErrno) *lpErrno = NO_ERROR;

    return 0;
}

static
VOID
NTAPI
MsafdInfoAPC(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved)
{
    PMSAFD_INFO_APC_CONTEXT Context = ApcContext;

    TRACE("MsafdInfoAPC(%p %lx %lx)\n", ApcContext, IoStatusBlock->Status, IoStatusBlock->Information);

    if (Context->lpCompletionRoutine)
        Context->lpCompletionRoutine(IoStatusBlock->Status, IoStatusBlock->Information, Context->lpOverlapped, 0);

    /* Free IOCTL buffer */
    HeapFree(GlobalHeap, 0, Context->lpInfoData);

    HeapFree(GlobalHeap, 0, ApcContext);
}

/* shutdown(SD_RECEIVE) with unread or arriving data resets the connection of a stream socket (AFD); the
 * receives and sends of that socket then fail with WSAECONNABORTED rather than WSAESHUTDOWN */
BOOLEAN
MsafdConnectionAborted(PSOCKET_INFORMATION Socket)
{
    ULONG Aborted = 0;

    if (Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS)
        return FALSE;

    return GetSocketInformation(Socket, AFD_INFO_CONNECTION_ABORTED, NULL, &Aborted, NULL, NULL, NULL) == NO_ERROR &&
           Aborted != 0;
}

int
GetSocketInformation(PSOCKET_INFORMATION Socket,
                     ULONG AfdInformationClass,
                     PBOOLEAN Boolean OPTIONAL,
                     PULONG Ulong OPTIONAL,
                     PLARGE_INTEGER LargeInteger OPTIONAL,
                     LPWSAOVERLAPPED Overlapped OPTIONAL,
                     LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine OPTIONAL)
{
    PIO_STATUS_BLOCK        IOSB;
    IO_STATUS_BLOCK         DummyIOSB;
    PAFD_INFO               InfoData;
    NTSTATUS                Status;
    PMSAFD_INFO_APC_CONTEXT APCContext;
    PIO_APC_ROUTINE         APCFunction;
    HANDLE                  Event = NULL;
    HANDLE                  SockEvent;

    InfoData = HeapAlloc(GlobalHeap, 0, sizeof(*InfoData));
    if (!InfoData)
        return SOCKET_ERROR;

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);
    if (!NT_SUCCESS(Status))
    {
        HeapFree(GlobalHeap, 0, InfoData);
        return SOCKET_ERROR;
    }

    /* Set Info Class */
    InfoData->InformationClass = AfdInformationClass;

    /* Verify if we should use APC */
    if (!Overlapped)
    {
        /* Not using Overlapped structure, so use normal blocking on event */
        APCContext = NULL;
        APCFunction = NULL;
        Event = SockEvent;
        IOSB = &DummyIOSB;
    }
    else
    {
        /* Overlapped request for non overlapped opened socket */
        if ((Socket->SharedData->CreateFlags & SO_SYNCHRONOUS_NONALERT) != 0)
        {
            TRACE("Opened without flag WSA_FLAG_OVERLAPPED. Do nothing.\n");
            NtClose(SockEvent);
            HeapFree(GlobalHeap, 0, InfoData);
            return MsafdReturnWithErrno(STATUS_SUCCESS, NULL, 0, NULL);
        }

        APCContext = HeapAlloc(GlobalHeap, 0, sizeof(*APCContext));
        if (!APCContext)
        {
            ERR("Not enough memory for APC Context\n");
            NtClose(SockEvent);
            HeapFree(GlobalHeap, 0, InfoData);
            return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, NULL, 0, NULL);
        }
        APCContext->lpCompletionRoutine = CompletionRoutine;
        APCContext->lpOverlapped = Overlapped;
        APCContext->lpInfoData = InfoData;
        APCFunction = &MsafdInfoAPC;

        if (!CompletionRoutine)
            Event = Overlapped->hEvent;

        IOSB = (PIO_STATUS_BLOCK)&Overlapped->Internal;
    }

    IOSB->Status = STATUS_PENDING;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   Event,
                                   APCFunction,
                                   APCContext,
                                   IOSB,
                                   IOCTL_AFD_GET_INFO,
                                   InfoData,
                                   sizeof(*InfoData),
                                   InfoData,
                                   sizeof(*InfoData));

    /* Wait for completion if not overlapped */
    if (!Overlapped && Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB->Status;
    }

    TRACE("Status %lx\n", Status);

    if (Status == STATUS_SUCCESS)
    {
        /* Return Information */
        if (Ulong != NULL)
        {
            *Ulong = InfoData->Information.Ulong;
        }
        if (LargeInteger != NULL)
        {
            *LargeInteger = InfoData->Information.LargeInteger;
        }
        if (Boolean != NULL)
        {
            *Boolean = InfoData->Information.Boolean;
        }
    }

    NtClose(SockEvent);
    if (!APCFunction)
    {
        /* When using APC, this will be freed by the APC function */
        HeapFree(GlobalHeap, 0, InfoData);
    }

    return MsafdReturnWithErrno(Status, NULL, 0, NULL);
}


int
SetSocketInformation(PSOCKET_INFORMATION Socket,
                     ULONG AfdInformationClass,
                     PBOOLEAN Boolean OPTIONAL,
                     PULONG Ulong OPTIONAL,
                     PLARGE_INTEGER LargeInteger OPTIONAL,
                     LPWSAOVERLAPPED Overlapped OPTIONAL,
                     LPWSAOVERLAPPED_COMPLETION_ROUTINE CompletionRoutine OPTIONAL)
{
    PIO_STATUS_BLOCK        IOSB;
    IO_STATUS_BLOCK         DummyIOSB;
    PAFD_INFO               InfoData;
    NTSTATUS                Status;
    PMSAFD_INFO_APC_CONTEXT APCContext;
    PIO_APC_ROUTINE         APCFunction;
    HANDLE                  Event = NULL;
    HANDLE                  SockEvent;

    InfoData = HeapAlloc(GlobalHeap, 0, sizeof(*InfoData));
    if (!InfoData)
        return SOCKET_ERROR;

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);
    if (!NT_SUCCESS(Status))
    {
        HeapFree(GlobalHeap, 0, InfoData);
        return SOCKET_ERROR;
    }

    /* Set Info Class */
    InfoData->InformationClass = AfdInformationClass;

    /* Set Information */
    if (Ulong != NULL)
    {
        InfoData->Information.Ulong = *Ulong;
    }
    if (LargeInteger != NULL)
    {
        InfoData->Information.LargeInteger = *LargeInteger;
    }
    if (Boolean != NULL)
    {
        InfoData->Information.Boolean = *Boolean;
    }

    /* Verify if we should use APC */
    if (!Overlapped)
    {
        /* Not using Overlapped structure, so use normal blocking on event */
        APCContext = NULL;
        APCFunction = NULL;
        Event = SockEvent;
        IOSB = &DummyIOSB;
    }
    else
    {
        /* Overlapped request for non overlapped opened socket */
        if ((Socket->SharedData->CreateFlags & SO_SYNCHRONOUS_NONALERT) != 0)
        {
            TRACE("Opened without flag WSA_FLAG_OVERLAPPED. Do nothing.\n");
            NtClose(SockEvent);
            HeapFree(GlobalHeap, 0, InfoData);
            return MsafdReturnWithErrno(STATUS_SUCCESS, NULL, 0, NULL);
        }

        APCContext = HeapAlloc(GlobalHeap, 0, sizeof(*APCContext));
        if (!APCContext)
        {
            ERR("Not enough memory for APC Context\n");
            NtClose(SockEvent);
            HeapFree(GlobalHeap, 0, InfoData);
            return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, NULL, 0, NULL);
        }
        APCContext->lpCompletionRoutine = CompletionRoutine;
        APCContext->lpOverlapped = Overlapped;
        APCContext->lpInfoData = InfoData;
        APCFunction = &MsafdInfoAPC;

        if (!CompletionRoutine)
            Event = Overlapped->hEvent;

        IOSB = (PIO_STATUS_BLOCK)&Overlapped->Internal;
    }

    IOSB->Status = STATUS_PENDING;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   Event,
                                   APCFunction,
                                   APCContext,
                                   IOSB,
                                   IOCTL_AFD_SET_INFO,
                                   InfoData,
                                   sizeof(*InfoData),
                                   NULL,
                                   0);

    /* Wait for completion if not overlapped */
    if (!Overlapped && Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB->Status;
    }

    TRACE("Status %lx\n", Status);

    NtClose(SockEvent);
    if (!APCFunction)
    {
        /* When using APC, this will be freed by the APC function */
        HeapFree(GlobalHeap, 0, InfoData);
    }

    return MsafdReturnWithErrno(Status, NULL, 0, NULL);
}

static
PSOCKET_INFORMATION
MsafdFindSocket(SOCKET Handle)
{
    PSOCKET_INFORMATION CurrentSocket;

    EnterCriticalSection(&SocketListLock);

    CurrentSocket = SocketListHead;
    while (CurrentSocket)
    {
        if (CurrentSocket->Handle == Handle)
            break;

        CurrentSocket = CurrentSocket->NextSocket;
    }

    LeaveCriticalSection(&SocketListLock);

    return CurrentSocket;
}

/* One AFD ioctl that fills Out, waiting for it to finish */
static
NTSTATUS
MsafdAfdQuery(
    _In_ HANDLE Handle,
    _In_ ULONG IoControlCode,
    _In_opt_ PVOID In,
    _In_ ULONG InSize,
    _Out_ PVOID Out,
    _In_ ULONG OutSize)
{
    IO_STATUS_BLOCK IOSB;
    HANDLE SockEvent;
    NTSTATUS Status;

    Status = NtCreateEvent(&SockEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = NtDeviceIoControlFile(Handle, SockEvent, NULL, NULL, &IOSB, IoControlCode, In, InSize, Out, OutSize);
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }
    NtClose(SockEvent);

    return Status;
}

/*
 * A socket handle this process did not create: the child of a process that passed the handle through
 * CreateProcess (standard handle or handle list), as OpenSSH's sshd does with the connection. Rebuild the
 * socket from the context the creating process stored in AFD (the socket's family, type, protocol, options,
 * protocol info) and from what AFD knows now (the state of the endpoint). Returns the new entry of the
 * socket list, or NULL when the handle is no socket of this provider.
 */
static
PSOCKET_INFORMATION
MsafdAdoptInheritedSocket(SOCKET Handle)
{
    FILE_FS_DEVICE_INFORMATION DeviceInfo;
    IO_STATUS_BLOCK IOSB;
    SOCK_SHARED_INFO KernelShared;
    PMSAFD_CONTEXT_BLOB Blob = NULL;
    PSOCKET_INFORMATION Socket = NULL, Existing;
    UNICODE_STRING TransportName;
    ULONG ContextSize = 0, AfdState;
    INT AddressFamily, SocketType, Protocol;
    NTSTATUS Status;

    /* AFD's device is of the named pipe type here (Windows uses the network type): this keeps the ioctls
     * away from files, disks and the other devices. A pipe answers the ioctl with an error. */
    Status = NtQueryVolumeInformationFile((HANDLE)Handle, &IOSB, &DeviceInfo, sizeof(DeviceInfo), FileFsDeviceInformation);
    if (!NT_SUCCESS(Status) ||
        (DeviceInfo.DeviceType != FILE_DEVICE_NETWORK && DeviceInfo.DeviceType != FILE_DEVICE_NAMED_PIPE))
        return NULL;

    Status = MsafdAfdQuery((HANDLE)Handle, IOCTL_AFD_GET_CONTEXT_SIZE, NULL, 0, &ContextSize, sizeof(ContextSize));
    if (!NT_SUCCESS(Status) || ContextSize != sizeof(*Blob))
        return NULL;

    Blob = HeapAlloc(GlobalHeap, 0, sizeof(*Blob));
    if (!Blob)
        return NULL;
    Status = MsafdAfdQuery((HANDLE)Handle, IOCTL_AFD_GET_CONTEXT, NULL, 0, Blob, sizeof(*Blob));
    if (!NT_SUCCESS(Status) ||
        Blob->Context.SizeOfHelperData != sizeof(Blob->ProtocolInfo) ||
        Blob->Context.SharedData.State == SocketClosed)
        goto fail;

    /* The state the endpoint has now. AFD answers a request of the size of the shared data with its own copy */
    Status = MsafdAfdQuery((HANDLE)Handle, IOCTL_AFD_GET_CONTEXT, NULL, 0, &KernelShared, sizeof(KernelShared));
    if (!NT_SUCCESS(Status))
        goto fail;

    Socket = HeapAlloc(GlobalHeap, HEAP_ZERO_MEMORY, sizeof(*Socket));
    if (!Socket)
        goto fail;
    Socket->SharedData = HeapAlloc(GlobalHeap, 0, sizeof(*Socket->SharedData));
    if (!Socket->SharedData)
        goto fail;

    *Socket->SharedData = Blob->Context.SharedData;
    Socket->SharedData->RefCount = 1;
    Socket->SharedDataHandle = INVALID_HANDLE_VALUE;

    /* AFD's endpoint states: 0 created, 1 bound, 2 connecting, 3 connected, 4 listening */
    AfdState = (ULONG)KernelShared.State & 0xffff;
    switch (AfdState)
    {
        case 3:
            Socket->SharedData->State = SocketConnected;
            break;
        case 0:
            Socket->SharedData->State = SocketOpen;
            break;
        case 4:
            Socket->SharedData->State = SocketBound;
            Socket->SharedData->Listening = TRUE;
            break;
        default:
            Socket->SharedData->State = Socket->SharedData->SocketType == SOCK_DGRAM ? SocketBoundUdp : SocketBound;
            break;
    }

    AddressFamily = Socket->SharedData->AddressFamily;
    SocketType = Socket->SharedData->SocketType;
    Protocol = Socket->SharedData->Protocol;
    if (SockGetTdiName(&AddressFamily,
                       &SocketType,
                       &Protocol,
                       0,
                       Socket->SharedData->CreateFlags,
                       &TransportName,
                       &Socket->HelperContext,
                       &Socket->HelperData,
                       &Socket->HelperEvents) != NO_ERROR)
        goto fail;

    Socket->Handle = Handle;
    Socket->LocalAddress = &Socket->SharedData->WSLocalAddress;
    Socket->RemoteAddress = &Socket->SharedData->WSRemoteAddress;
    Socket->ProtocolInfo = Blob->ProtocolInfo;
    HeapFree(GlobalHeap, 0, Blob);
    Blob = NULL;

    /* Another thread may have adopted the handle while this one worked */
    EnterCriticalSection(&SocketListLock);
    for (Existing = SocketListHead; Existing; Existing = Existing->NextSocket)
    {
        if (Existing->Handle == Handle)
            break;
    }
    if (!Existing)
    {
        Socket->NextSocket = SocketListHead;
        SocketListHead = Socket;
    }
    LeaveCriticalSection(&SocketListLock);

    if (Existing)
    {
        HeapFree(GlobalHeap, 0, Socket->SharedData);
        HeapFree(GlobalHeap, 0, Socket);
        return Existing;
    }

    return Socket;

fail:
    if (Socket && Socket->SharedData)
        HeapFree(GlobalHeap, 0, Socket->SharedData);
    if (Socket)
        HeapFree(GlobalHeap, 0, Socket);
    if (Blob)
        HeapFree(GlobalHeap, 0, Blob);
    return NULL;
}

PSOCKET_INFORMATION
GetSocketStructure(SOCKET Handle)
{
    PSOCKET_INFORMATION CurrentSocket;

    CurrentSocket = MsafdFindSocket(Handle);
    if (CurrentSocket)
        return CurrentSocket;

    /* Not made by this process: a socket handle inherited from the parent */
    return MsafdAdoptInheritedSocket(Handle);
}

int CreateContext(PSOCKET_INFORMATION Socket)
{
    IO_STATUS_BLOCK     IOSB;
    MSAFD_CONTEXT_BLOB  ContextData;
    NTSTATUS            Status;
    HANDLE              SockEvent;

    Status = NtCreateEvent(&SockEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           SynchronizationEvent,
                           FALSE);

    if( !NT_SUCCESS(Status) )
        return SOCKET_ERROR;

    /* Create Context */
    RtlZeroMemory(&ContextData, sizeof(ContextData));
    ContextData.Context.SharedData = *Socket->SharedData;
    ContextData.Context.SizeOfHelperData = sizeof(ContextData.ProtocolInfo);
    RtlCopyMemory (&ContextData.Context.LocalAddress,
                   Socket->LocalAddress,
                   min(Socket->SharedData->SizeOfLocalAddress, sizeof(SOCKADDR)));
    RtlCopyMemory (&ContextData.Context.RemoteAddress,
                   Socket->RemoteAddress,
                   min(Socket->SharedData->SizeOfRemoteAddress, sizeof(SOCKADDR)));
    ContextData.ProtocolInfo = Socket->ProtocolInfo;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IOSB,
                                   IOCTL_AFD_SET_CONTEXT,
                                   &ContextData,
                                   sizeof(ContextData),
                                   NULL,
                                   0);

    /* Wait for Completion */
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IOSB.Status;
    }

    NtClose( SockEvent );

    return Status == STATUS_SUCCESS ? NO_ERROR : SOCKET_ERROR;
}

BOOLEAN SockCreateOrReferenceAsyncThread(VOID)
{
    HANDLE hAsyncThread;
    DWORD AsyncThreadId;
    HANDLE AsyncEvent;
    OBJECT_HANDLE_FLAG_INFORMATION HandleFlags;
    NTSTATUS Status;

    /* Check if the Thread Already Exists */
    if (SockAsyncThreadRefCount)
    {
        ASSERT(SockAsyncCompletionPort);
        return TRUE;
    }

    /* Create the Completion Port */
    if (!SockAsyncCompletionPort)
    {
        Status = NtCreateIoCompletion(&SockAsyncCompletionPort,
                                      IO_COMPLETION_ALL_ACCESS,
                                      NULL,
                                      2); // Allow 2 threads only
        if (!NT_SUCCESS(Status))
        {
             ERR("Failed to create completion port: 0x%08x\n", Status);
             return FALSE;
        }
        /* Protect Handle */
        HandleFlags.ProtectFromClose = TRUE;
        HandleFlags.Inherit = FALSE;
        Status = NtSetInformationObject(SockAsyncCompletionPort,
                                        ObjectHandleFlagInformation,
                                        &HandleFlags,
                                        sizeof(HandleFlags));
    }

    /* Create the Async Event */
    Status = NtCreateEvent(&AsyncEvent,
                           EVENT_ALL_ACCESS,
                           NULL,
                           NotificationEvent,
                           FALSE);

    /* Create the Async Thread */
    hAsyncThread = CreateThread(NULL,
                                0,
                                SockAsyncThread,
                                NULL,
                                0,
                                &AsyncThreadId);

    /* Close the Handle */
    NtClose(hAsyncThread);

    /* Increase the Reference Count */
    SockAsyncThreadRefCount++;
    return TRUE;
}

ULONG
NTAPI
SockAsyncThread(PVOID ThreadParam)
{
    PVOID AsyncContext;
    PASYNC_COMPLETION_ROUTINE AsyncCompletionRoutine;
    IO_STATUS_BLOCK IOSB;
    NTSTATUS Status;

    /* Make the Thread Higher Priority */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

    /* Do a KQUEUE/WorkItem Style Loop, thanks to IoCompletion Ports */
    do
    {
        Status =  NtRemoveIoCompletion (SockAsyncCompletionPort,
                                        (PVOID*)&AsyncCompletionRoutine,
                                        &AsyncContext,
                                        &IOSB,
                                        NULL);
        /* Call the Async Function */
        if (NT_SUCCESS(Status))
        {
            (*AsyncCompletionRoutine)(AsyncContext, &IOSB);
        }
        else
        {
            /* It Failed, sleep for a second */
            Sleep(1000);
        }
    } while ((Status != STATUS_TIMEOUT));

    /* The Thread has Ended */
    return 0;
}

BOOLEAN SockGetAsyncSelectHelperAfdHandle(VOID)
{
    UNICODE_STRING AfdHelper;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoSb;
    FILE_COMPLETION_INFORMATION CompletionInfo;
    OBJECT_HANDLE_FLAG_INFORMATION HandleFlags;

    /* First, make sure we're not already initialized */
    if (SockAsyncHelperAfdHandle)
    {
        return TRUE;
    }

    /* Set up Handle Name and Object */
    RtlInitUnicodeString(&AfdHelper, L"\\Device\\Afd\\AsyncSelectHlp" );
                         InitializeObjectAttributes(&ObjectAttributes,
                         &AfdHelper,
                         OBJ_INHERIT | OBJ_CASE_INSENSITIVE,
                         NULL,
                         NULL);

    /* Open the Handle to AFD */
    NtCreateFile(&SockAsyncHelperAfdHandle,
                 GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                 &ObjectAttributes,
                 &IoSb,
                 NULL,
                 0,
                 FILE_SHARE_READ | FILE_SHARE_WRITE,
                 FILE_OPEN_IF,
                 0,
                 NULL,
                 0);

    /*
     * Now Set up the Completion Port Information
     * This means that whenever a Poll is finished, the routine will be executed
     */
    CompletionInfo.Port = SockAsyncCompletionPort;
    CompletionInfo.Key = SockAsyncSelectCompletionRoutine;
    NtSetInformationFile(SockAsyncHelperAfdHandle,
                         &IoSb,
                         &CompletionInfo,
                         sizeof(CompletionInfo),
                         FileCompletionInformation);


    /* Protect the Handle */
    HandleFlags.ProtectFromClose = TRUE;
    HandleFlags.Inherit = FALSE;
    NtSetInformationObject(SockAsyncCompletionPort,
                           ObjectHandleFlagInformation,
                           &HandleFlags,
                           sizeof(HandleFlags));


    /* Set this variable to true so that Send/Recv/Accept will know wether to renable disabled events */
    SockAsyncSelectCalled = TRUE;
    return TRUE;
}

VOID SockAsyncSelectCompletionRoutine(PVOID Context, PIO_STATUS_BLOCK IoStatusBlock)
{

    PASYNC_DATA AsyncData = Context;
    PSOCKET_INFORMATION Socket;
    ULONG x, Pass, Ready, Events[8], Count = 0, i;
    HWND hWnd;
    UINT wMsg;
    BOOLEAN Done;

    /* Get the Socket */
    Socket = AsyncData->ParentSocket;

    /* Check we were manually called b/c of a failure */
    if (!NT_SUCCESS(IoStatusBlock->Status))
    {
        /* FIXME: Perform Upcall */
        return;
    }

    /*
     * The events are disabled before their messages are posted, and the check of the sequence number
     * is made under the same lock as the change of the selection by WSPAsyncSelect and by the
     * re-enabling of events. A program reads when it gets a message and selects the events again:
     * with the message first, it could do both before the event was disabled here, the event would
     * then stay disabled although the selection is new, and the program would wait for a message
     * about data that is already there.
     */
    EnterCriticalSection(&AsyncSelectLock);

    /* Check if the Sequence  Number Changed behind our back */
    if (AsyncData->SequenceNumber != Socket->SharedData->SequenceNumber )
    {
        LeaveCriticalSection(&AsyncSelectLock);
        return;
    }

    hWnd = Socket->SharedData->hWnd;
    wMsg = Socket->SharedData->wMsg;
    Ready = AsyncData->AsyncSelectInfo.Handles[0].Events;

    /* FD_CONNECT is posted before FD_WRITE, as on Windows (measured on Windows 10: a connect that
     * completes while the socket is selected for both gives FD_CONNECT, then FD_WRITE). */
    for (Pass = 0; Pass < 2; Pass++)
    for (x = 1; x; x<<=1)
    {
        if ((Pass == 0) != ((x & (AFD_EVENT_CONNECT | AFD_EVENT_CONNECT_FAIL)) != 0))
            continue;

        switch (Ready & x)
        {
            case AFD_EVENT_RECEIVE:
                if (0 != (Socket->SharedData->AsyncEvents & FD_READ) &&
                    0 == (Socket->SharedData->AsyncDisabledEvents & FD_READ))
                {
                    /* Disable this event until the next read(); */
                    Socket->SharedData->AsyncDisabledEvents |= FD_READ;
                    Events[Count++] = FD_READ;
                }
            break;

            case AFD_EVENT_OOB_RECEIVE:
            if (0 != (Socket->SharedData->AsyncEvents & FD_OOB) &&
                0 == (Socket->SharedData->AsyncDisabledEvents & FD_OOB))
            {
                /* Disable this event until the next read(); */
                Socket->SharedData->AsyncDisabledEvents |= FD_OOB;
                Events[Count++] = FD_OOB;
            }
            break;

            case AFD_EVENT_SEND:
                if (0 != (Socket->SharedData->AsyncEvents & FD_WRITE) &&
                    0 == (Socket->SharedData->AsyncDisabledEvents & FD_WRITE))
                {
                    /* Disable this event until the next write(); */
                    Socket->SharedData->AsyncDisabledEvents |= FD_WRITE;
                    Events[Count++] = FD_WRITE;
                }
                break;

                /* FIXME: THIS IS NOT RIGHT!!! HACK HACK HACK! */
            case AFD_EVENT_CONNECT:
            case AFD_EVENT_CONNECT_FAIL:
                if (0 != (Socket->SharedData->AsyncEvents & FD_CONNECT) &&
                    0 == (Socket->SharedData->AsyncDisabledEvents & FD_CONNECT))
                {
                    /* Disable this event forever; */
                    Socket->SharedData->AsyncDisabledEvents |= FD_CONNECT;
                    Events[Count++] = FD_CONNECT;
                }
                break;

            case AFD_EVENT_ACCEPT:
                if (0 != (Socket->SharedData->AsyncEvents & FD_ACCEPT) &&
                    0 == (Socket->SharedData->AsyncDisabledEvents & FD_ACCEPT))
                {
                    /* Disable this event until the next accept(); */
                    Socket->SharedData->AsyncDisabledEvents |= FD_ACCEPT;
                    Events[Count++] = FD_ACCEPT;
                }
                break;

            case AFD_EVENT_DISCONNECT:
            case AFD_EVENT_ABORT:
            case AFD_EVENT_CLOSE:
                if (0 != (Socket->SharedData->AsyncEvents & FD_CLOSE) &&
                    0 == (Socket->SharedData->AsyncDisabledEvents & FD_CLOSE))
                {
                    /* Disable this event forever; */
                    Socket->SharedData->AsyncDisabledEvents |= FD_CLOSE;
                    Events[Count++] = FD_CLOSE;
                }
                 break;
            /* FIXME: Support QOS */
        }
    }

    /* Check if there are any events left for us to check */
    Done = (Socket->SharedData->AsyncEvents & (~Socket->SharedData->AsyncDisabledEvents)) == 0;

    LeaveCriticalSection(&AsyncSelectLock);

    /* Make the notifications */
    for (i = 0; i < Count; i++)
    {
        (Upcalls.lpWPUPostMessage)(hWnd,
                                   wMsg,
                                   Socket->Handle,
                                   WSAMAKESELECTREPLY(Events[i], 0));
    }

    if (Done)
        return;

    /* Keep Polling */
    SockProcessAsyncSelect(Socket, AsyncData);
    return;
}

VOID SockProcessAsyncSelect(PSOCKET_INFORMATION Socket, PASYNC_DATA AsyncData)
{

    ULONG lNetworkEvents;
    NTSTATUS Status;

    /* Set up the Async Data Event Info */
    AsyncData->AsyncSelectInfo.Timeout.HighPart = 0x7FFFFFFF;
    AsyncData->AsyncSelectInfo.Timeout.LowPart = 0xFFFFFFFF;
    AsyncData->AsyncSelectInfo.HandleCount = 1;
    AsyncData->AsyncSelectInfo.Exclusive = TRUE;
    AsyncData->AsyncSelectInfo.Handles[0].Handle = Socket->Handle;
    AsyncData->AsyncSelectInfo.Handles[0].Events = 0;

    /* Remove unwanted events */
    lNetworkEvents = Socket->SharedData->AsyncEvents & (~Socket->SharedData->AsyncDisabledEvents);

    /* Set Events to wait for */
    if (lNetworkEvents & FD_READ)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_RECEIVE;
    }

    if (lNetworkEvents & FD_WRITE)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_SEND;
    }

    if (lNetworkEvents & FD_OOB)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_OOB_RECEIVE;
    }

    if (lNetworkEvents & FD_ACCEPT)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_ACCEPT;
    }

    /* FIXME: THIS IS NOT RIGHT!!! HACK HACK HACK! */
    if (lNetworkEvents & FD_CONNECT)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_CONNECT | AFD_EVENT_CONNECT_FAIL;
    }

    if (lNetworkEvents & FD_CLOSE)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_DISCONNECT | AFD_EVENT_ABORT | AFD_EVENT_CLOSE;
    }

    if (lNetworkEvents & FD_QOS)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_QOS;
    }

    if (lNetworkEvents & FD_GROUP_QOS)
    {
        AsyncData->AsyncSelectInfo.Handles[0].Events |= AFD_EVENT_GROUP_QOS;
    }

    /* Send IOCTL */
    Status = NtDeviceIoControlFile (SockAsyncHelperAfdHandle,
                                    NULL,
                                    NULL,
                                    AsyncData,
                                    &AsyncData->IoStatusBlock,
                                    IOCTL_AFD_SELECT,
                                    &AsyncData->AsyncSelectInfo,
                                    sizeof(AsyncData->AsyncSelectInfo),
                                    &AsyncData->AsyncSelectInfo,
                                    sizeof(AsyncData->AsyncSelectInfo));

    /* I/O Manager Won't call the completion routine, let's do it manually */
    if (NT_SUCCESS(Status))
    {
        return;
    }
    else
    {
        AsyncData->IoStatusBlock.Status = Status;
        SockAsyncSelectCompletionRoutine(AsyncData, &AsyncData->IoStatusBlock);
    }
}

VOID SockProcessQueuedAsyncSelect(PVOID Context, PIO_STATUS_BLOCK IoStatusBlock)
{
    PASYNC_DATA AsyncData = Context;
    BOOL FreeContext = TRUE;
    PSOCKET_INFORMATION Socket;

    /* Get the Socket */
    Socket = AsyncData->ParentSocket;

    /* If someone closed it, stop the function */
    if (Socket->SharedData->State != SocketClosed)
    {
        /* Check if the Sequence Number changed by now, in which case quit */
        EnterCriticalSection(&AsyncSelectLock);
        if (AsyncData->SequenceNumber == Socket->SharedData->SequenceNumber &&
            (Socket->SharedData->AsyncEvents & (~Socket->SharedData->AsyncDisabledEvents)))
        {
            /* Do the actual select, with the events as they are now */
            FreeContext = FALSE;
        }
        LeaveCriticalSection(&AsyncSelectLock);
        if (!FreeContext)
            SockProcessAsyncSelect(Socket, AsyncData);
    }

    /* Free the Context */
    if (FreeContext)
    {
        HeapFree(GetProcessHeap(), 0, AsyncData);
    }

    return;
}

VOID
SockReenableAsyncSelectEvent (IN PSOCKET_INFORMATION Socket,
                              IN ULONG Event)
{
    PASYNC_DATA AsyncData;

    EnterCriticalSection(&AsyncSelectLock);

    /* Make sure the event is actually disabled */
    if (!(Socket->SharedData->AsyncDisabledEvents & Event))
    {
        LeaveCriticalSection(&AsyncSelectLock);
        return;
    }

    /* Re-enable it */
    Socket->SharedData->AsyncDisabledEvents &= ~Event;

    /* Return if no more events are being polled */
    if ((Socket->SharedData->AsyncEvents & (~Socket->SharedData->AsyncDisabledEvents)) == 0 )
    {
        LeaveCriticalSection(&AsyncSelectLock);
        return;
    }

    /* Wait on new events */
    AsyncData = HeapAlloc(GetProcessHeap(), 0, sizeof(ASYNC_DATA));
    if (!AsyncData)
    {
        LeaveCriticalSection(&AsyncSelectLock);
        return;
    }

    /* Increase the sequence number to stop anything else */
    Socket->SharedData->SequenceNumber++;

    /* Set up the Async Data */
    AsyncData->ParentSocket = Socket;
    AsyncData->SequenceNumber = Socket->SharedData->SequenceNumber;

    LeaveCriticalSection(&AsyncSelectLock);

    /* Create the Asynch Thread if Needed */
    SockCreateOrReferenceAsyncThread();

    /* Begin Async Select by using I/O Completion */
    NtSetIoCompletion(SockAsyncCompletionPort,
                     (PVOID)&SockProcessQueuedAsyncSelect,
                     AsyncData,
                     0,
                     0);

    /* All done */
    return;
}

BOOL
WINAPI
DllMain(HANDLE hInstDll,
        ULONG dwReason,
        PVOID Reserved)
{

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:

        TRACE("Loading MSAFD.DLL \n");

        /* Don't need thread attach notifications
        so disable them to improve performance */
        DisableThreadLibraryCalls(hInstDll);

        /* List of DLL Helpers */
        InitializeListHead(&SockHelpersListHead);

        /* Heap to use when allocating */
        GlobalHeap = GetProcessHeap();

        /* Initialize the lock that protects our socket list */
        InitializeCriticalSection(&SocketListLock);
        InitializeCriticalSection(&AsyncSelectLock);
        MsafdAddrChangeInit();
        MsafdTransmitInit();

        TRACE("MSAFD.DLL has been loaded\n");

        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:

        /* Delete the socket list lock */
        DeleteCriticalSection(&SocketListLock);
        DeleteCriticalSection(&AsyncSelectLock);
        MsafdTransmitExit();
        MsafdAddrChangeExit();

        break;
    }

    TRACE("DllMain of msafd.dll (leaving)\n");

    return TRUE;
}

/* EOF */
