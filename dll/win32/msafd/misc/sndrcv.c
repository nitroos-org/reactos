/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS Ancillary Function Driver DLL
 * FILE:        dll/win32/msafd/misc/sndrcv.c
 * PURPOSE:     Send/receive routines
 * PROGRAMMERS: Casper S. Hornstrup (chorns@users.sourceforge.net)
 *              Alex Ionescu (alex@relsoft.net)
 * REVISIONS:
 *              CSH 01/09-2000 Created
 *              Alex 16/07/2004 - Complete Rewrite
 */

#include <msafd.h>

extern CRITICAL_SECTION AsyncSelectLock;

/*
 * Has the connect of this socket completed already? AFD keeps the connect event of a poll set from then
 * on, and a poll that does not wait says so. The state in the shared data is no help: it changes in the
 * completion routine of the connect, which a program that does not wait alertably never runs.
 */
static
BOOLEAN
MsafdConnectCompleted(IN PSOCKET_INFORMATION Socket)
{
    AFD_POLL_INFO PollInfo;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE SockEvent;
    NTSTATUS Status;
    BOOLEAN Completed = FALSE;

    if (Socket->SharedData->State == SocketConnected)
        return TRUE;
    if (Socket->SharedData->State == SocketClosed || (Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS))
        return FALSE;

    Status = NtCreateEvent(&SockEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return FALSE;

    RtlZeroMemory(&PollInfo, sizeof(PollInfo));
    PollInfo.Timeout.QuadPart = 0;
    PollInfo.HandleCount = 1;
    PollInfo.Exclusive = FALSE;
    PollInfo.Handles[0].Handle = Socket->Handle;
    PollInfo.Handles[0].Events = AFD_EVENT_CONNECT;

    Status = NtDeviceIoControlFile((HANDLE)Socket->Handle,
                                   SockEvent,
                                   NULL,
                                   NULL,
                                   &IoStatusBlock,
                                   IOCTL_AFD_SELECT,
                                   &PollInfo,
                                   sizeof(PollInfo),
                                   &PollInfo,
                                   sizeof(PollInfo));
    if (Status == STATUS_PENDING)
    {
        MsafdWaitForAlert(SockEvent);
        Status = IoStatusBlock.Status;
    }
    if (NT_SUCCESS(Status) && PollInfo.HandleCount != 0 && (PollInfo.Handles[0].Events & AFD_EVENT_CONNECT))
        Completed = TRUE;

    NtClose(SockEvent);
    return Completed;
}

INT
WSPAPI
WSPAsyncSelect(IN  SOCKET Handle,
               IN  HWND hWnd,
               IN  UINT wMsg,
               IN  LONG lEvent,
               OUT LPINT lpErrno)
{
    PSOCKET_INFORMATION Socket = NULL;
    PASYNC_DATA                 AsyncData;
    BOOLEAN                     BlockMode;
    BOOLEAN                     ConnectOver;

    /* Get the Socket Structure associated to this Socket */
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
       *lpErrno = WSAENOTSOCK;
       return SOCKET_ERROR;
    }

    /* Allocate the Async Data Structure to pass on to the Thread later */
    AsyncData = HeapAlloc(GetProcessHeap(), 0, sizeof(*AsyncData));
    if (!AsyncData)
    {
        MsafdReturnWithErrno( STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, NULL );
        return INVALID_SOCKET;
    }

    /* Change the Socket to Non Blocking */
    BlockMode = TRUE;
    SetSocketInformation(Socket, AFD_INFO_BLOCKING_MODE, &BlockMode, NULL, NULL, NULL, NULL);
    Socket->SharedData->NonBlocking = TRUE;

    /* Deactivate WSPEventSelect */
    if (Socket->SharedData->AsyncEvents)
    {
        if (WSPEventSelect(Handle, NULL, 0, lpErrno) == SOCKET_ERROR)
        {
            HeapFree(GetProcessHeap(), 0, AsyncData);
            return SOCKET_ERROR;
        }
    }

    /* Create the Asynch Thread if Needed */
    SockCreateOrReferenceAsyncThread();

    /* Open a Handle to AFD's Async Helper */
    SockGetAsyncSelectHelperAfdHandle();

    /* A poll that waits for nothing, so it is made before the lock is taken */
    ConnectOver = (lEvent & FD_CONNECT) && MsafdConnectCompleted(Socket);

    /* Store Socket Data */
    EnterCriticalSection(&AsyncSelectLock);
    Socket->SharedData->hWnd = hWnd;
    Socket->SharedData->wMsg = wMsg;
    Socket->SharedData->AsyncEvents = lEvent;
    Socket->SharedData->AsyncDisabledEvents = 0;
    /*
     * FD_CONNECT reports a connect that completes while the socket is selected. AFD keeps answering
     * "connected" to a poll for it, so a socket whose connect is over already (it finished before this
     * call, or the socket was accepted) must not have it: Windows posts FD_WRITE only (measured).
     */
    if (ConnectOver)
        Socket->SharedData->AsyncDisabledEvents |= FD_CONNECT;
    Socket->SharedData->SequenceNumber++;
    AsyncData->SequenceNumber = Socket->SharedData->SequenceNumber;
    LeaveCriticalSection(&AsyncSelectLock);

    /* A change of the address list that came while it was not selected is reported now */
    MsafdAddrChangeSelectionChanged(Socket);

    /* Return if there are no more Events */
    if ((Socket->SharedData->AsyncEvents & (~Socket->SharedData->AsyncDisabledEvents)) == 0)
    {
        HeapFree(GetProcessHeap(), 0, AsyncData);
        return 0;
    }

    /* Set up the Async Data */
    AsyncData->ParentSocket = Socket;

    /* Begin Async Select by using I/O Completion */
    NtSetIoCompletion(SockAsyncCompletionPort,
                      (PVOID)&SockProcessQueuedAsyncSelect,
                      AsyncData,
                      0,
                      0);

    /* Return */
    return ERROR_SUCCESS;
}


BOOL
WSPAPI
WSPGetOverlappedResult(
    IN  SOCKET Handle,
    IN  LPWSAOVERLAPPED lpOverlapped,
    OUT LPDWORD lpdwBytes,
    IN  BOOL fWait,
    OUT LPDWORD lpdwFlags,
    OUT LPINT lpErrno)
{
    PSOCKET_INFORMATION     Socket;
    PIO_STATUS_BLOCK        IoStatusBlock;
    BOOL                    Ret;

    TRACE("Called (%x)\n", Handle);

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        if(lpErrno)
            *lpErrno = WSAENOTSOCK;
        return FALSE;
    }
    /* The flags are optional */
    if (!lpOverlapped || !lpdwBytes)
    {
        if (lpErrno)
            *lpErrno = WSAEFAULT;
        return FALSE;
    }

    IoStatusBlock = (PIO_STATUS_BLOCK)lpOverlapped;
    Ret = GetOverlappedResult((HANDLE)Handle, lpOverlapped, lpdwBytes, fWait);

    /* HACK: Allow APC to be processed */
    SleepEx(0, TRUE);

    if (!fWait && IoStatusBlock->Status == STATUS_PENDING)
    {
        if (lpErrno)
            *lpErrno = WSA_IO_INCOMPLETE;
        return FALSE;
    }

    if (Ret)
    {

        /* Re-enable Async Event */
        SockReenableAsyncSelectEvent(Socket, FD_OOB);
        SockReenableAsyncSelectEvent(Socket, FD_WRITE);
        SockReenableAsyncSelectEvent(Socket, FD_READ);
    }

    switch (IoStatusBlock->Status)
    {
        case STATUS_RECEIVE_EXPEDITED:
            if (lpdwFlags)
                *lpdwFlags = MSG_OOB;
            break;
        case STATUS_RECEIVE_PARTIAL_EXPEDITED:
            if (lpdwFlags)
                *lpdwFlags = MSG_PARTIAL | MSG_OOB;
            break;
        case STATUS_RECEIVE_PARTIAL:
            if (lpdwFlags)
                *lpdwFlags = MSG_PARTIAL;
            break;
        default:
            /* A failed request leaves the flags as they were, as on Windows */
            if (lpdwFlags && NT_SUCCESS(IoStatusBlock->Status))
                *lpdwFlags = 0;
            if (lpErrno)
                *lpErrno = TranslateNtStatusError(IoStatusBlock->Status);
            break;
    }

    return Ret;
}

static
VOID
NTAPI
MsafdRecvAPC(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved)
{
    PMSAFD_RECV_APC_CONTEXT Context = ApcContext;

    TRACE("MsafdRecvAPC(%p %lx %lx)\n", ApcContext, IoStatusBlock->Status, IoStatusBlock->Information);

    /* Re-enable Async Event */
    if (IoStatusBlock->Status == STATUS_RECEIVE_EXPEDITED ||
        IoStatusBlock->Status == STATUS_RECEIVE_PARTIAL_EXPEDITED)
    {
        SockReenableAsyncSelectEvent(Context->lpSocket, FD_OOB);
    }
    else
    {
        SockReenableAsyncSelectEvent(Context->lpSocket, FD_READ);
    }

    if (Context->lpCompletionRoutine)
        Context->lpCompletionRoutine(IoStatusBlock->Status, IoStatusBlock->Information, (LPWSAOVERLAPPED)IoStatusBlock, 0);

    HeapFree(GlobalHeap, 0, ApcContext);
}

/*
 * AFD takes a stream send into its send window and completes it with the bytes it took, at most the
 * window (8 KB by default), while Windows completes a send of a connected stream socket only when all of it
 * is sent. A caller of WSASend (OpenSSH's sshd) relies on that, so the rest is sent here. Only blocking
 * stream sockets: a non-blocking one keeps the partial count, as on Windows.
 */
static
BOOLEAN
MsafdSendStreamWhole(
    _In_ PSOCKET_INFORMATION Socket,
    _In_ DWORD iFlags,
    _In_ BOOLEAN Overlapped)
{
    /* An overlapped send completes whole on Windows whether or not the socket is in non-blocking
     * mode; a plain send on a non-blocking socket takes what fits */
    return Socket->SharedData->SocketType == SOCK_STREAM &&
           (Overlapped || !Socket->SharedData->NonBlocking) &&
           !(iFlags & (MSG_OOB | MSG_PARTIAL));
}

/* The buffers of a send that are left after Sent bytes of the Total. Returns the new count. */
static
ULONG
MsafdSendAdvance(
    _Inout_ PAFD_WSABUF Buffers,
    _In_ ULONG Count,
    _In_ ULONG Skip,
    _Out_ PAFD_WSABUF *First)
{
    ULONG i = 0;

    while (i < Count && Skip >= Buffers[i].len)
    {
        Skip -= Buffers[i].len;
        i++;
    }
    if (i < Count && Skip)
    {
        Buffers[i].buf += Skip;
        Buffers[i].len -= Skip;
    }
    *First = Buffers + i;
    return Count - i;
}

static
VOID
NTAPI
MsafdSendAPC(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved)
{
    PMSAFD_SEND_APC_CONTEXT Context = ApcContext;
    PMSAFD_SEND_REST Rest = Context->lpRest;

    TRACE("MsafdSendAPC(%p %lx %lx)\n", ApcContext, IoStatusBlock->Status, IoStatusBlock->Information);

    if (Rest)
    {
        ULONG Done = (ULONG)IoStatusBlock->Information;
        PAFD_WSABUF First;
        AFD_SEND_INFO SendInfo;
        ULONG Left;
        NTSTATUS Status;

        Rest->Sent += Done;
        Left = MsafdSendAdvance(Rest->Buffers, Rest->BufferCount, Done, &First);
        if (NT_SUCCESS(IoStatusBlock->Status) && Left != 0 && Done != 0)
        {
            /* Send what AFD did not take */
            RtlZeroMemory(&SendInfo, sizeof(SendInfo));
            SendInfo.BufferArray = First;
            SendInfo.BufferCount = Left;
            SendInfo.AfdFlags = Rest->AfdFlags;
            SendInfo.TdiFlags = Rest->TdiFlags;
            Rest->BufferCount = Left;
            if (First != Rest->Buffers)
                RtlMoveMemory(Rest->Buffers, First, Left * sizeof(AFD_WSABUF));
            SendInfo.BufferArray = Rest->Buffers;

            IoStatusBlock->Information = 0;
            IoStatusBlock->Status = STATUS_PENDING;
            Status = NtDeviceIoControlFile((HANDLE)Context->lpSocket->Handle,
                                           NULL,
                                           MsafdSendAPC,
                                           Context,
                                           IoStatusBlock,
                                           IOCTL_AFD_SEND,
                                           &SendInfo,
                                           sizeof(SendInfo),
                                           NULL,
                                           0);
            if (NT_SUCCESS(Status))
                return; /* this routine runs again when AFD completes it */

            /* The send failed: report it with what was sent before */
            IoStatusBlock->Status = Status;
        }
        IoStatusBlock->Information = Rest->Sent;
    }

    /* Re-enable Async Event */
    SockReenableAsyncSelectEvent(Context->lpSocket, FD_WRITE);

    if (Context->lpCompletionRoutine)
        Context->lpCompletionRoutine(IoStatusBlock->Status, IoStatusBlock->Information, (LPWSAOVERLAPPED)IoStatusBlock, 0);

    /* Free IOCTL buffers */
    if (Rest)
        HeapFree(GlobalHeap, 0, Rest);
    HeapFree(GlobalHeap, 0, ApcContext);
}

int
WSPAPI
WSPRecv(SOCKET Handle,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesRead,
        LPDWORD ReceiveFlags,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
        LPWSATHREADID lpThreadId,
        LPINT lpErrno)
{
    PIO_STATUS_BLOCK        IOSB;
    IO_STATUS_BLOCK         DummyIOSB;
    AFD_RECV_INFO           RecvInfo;
    NTSTATUS                Status;
    PMSAFD_RECV_APC_CONTEXT APCContext;
    PIO_APC_ROUTINE         APCFunction = NULL;
    HANDLE                  Event = NULL;
    HANDLE                  SockEvent;
    PSOCKET_INFORMATION     Socket;
    DWORD                   NumberOfBytesRead;
    int                     Ret;

    TRACE("WSPRecv(%x)\n", Handle);

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        if (lpErrno)
            *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    if (!lpNumberOfBytesRead && !lpOverlapped)
    {
        if (lpErrno)
            *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }
    if (Socket->SharedData->OobInline && ReceiveFlags && (*ReceiveFlags & MSG_OOB) != 0)
    {
        if (lpErrno)
            *lpErrno = WSAEINVAL;
        return SOCKET_ERROR;
    }
    if (Socket->SharedData->ReceiveShutdown)
    {
        /* After shutdown(SD_RECEIVE) a new receive fails, as on Windows, which leaves the
         * status of its OVERLAPPED pending */
        if (lpOverlapped)
        {
            ((PIO_STATUS_BLOCK)lpOverlapped)->Status = STATUS_PENDING;
            ((PIO_STATUS_BLOCK)lpOverlapped)->Information = 0;
        }
        if (lpErrno)
            *lpErrno = MsafdConnectionAborted(Socket) ? WSAECONNABORTED : WSAESHUTDOWN;
        return SOCKET_ERROR;
    }

    memset(&RecvInfo, 0, sizeof(RecvInfo));

    Status = NtCreateEvent( &SockEvent, EVENT_ALL_ACCESS,
                            NULL, SynchronizationEvent, FALSE );

    if (!NT_SUCCESS(Status))
    {
        return SOCKET_ERROR;
    }

    /* Set up the Receive Structure */
    RecvInfo.BufferArray = (PAFD_WSABUF)lpBuffers;
    RecvInfo.BufferCount = dwBufferCount;
    RecvInfo.TdiFlags = 0;
    RecvInfo.AfdFlags = Socket->SharedData->NonBlocking ? AFD_IMMEDIATE : 0;

    /* Set the TDI Flags */
    if (!ReceiveFlags || *ReceiveFlags == 0)
    {
        RecvInfo.TdiFlags |= TDI_RECEIVE_NORMAL;
    }
    else
    {
        if (*ReceiveFlags & MSG_OOB)
        {
            RecvInfo.TdiFlags |= TDI_RECEIVE_EXPEDITED;
        }

        if (*ReceiveFlags & MSG_PEEK)
        {
            RecvInfo.TdiFlags |= TDI_RECEIVE_PEEK;
        }

        if (*ReceiveFlags & MSG_PARTIAL)
        {
            RecvInfo.TdiFlags |= TDI_RECEIVE_PARTIAL;
        }
    }

    /* Verify if we should use APC */
    if (!lpOverlapped)
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
            return MsafdReturnWithErrno(STATUS_SUCCESS, lpErrno, 0, lpNumberOfBytesRead);
        }

        IOSB = (PIO_STATUS_BLOCK)lpOverlapped;
        if (lpCompletionRoutine)
        {
            RecvInfo.AfdFlags |= AFD_SKIP_FIO;
            APCFunction = &MsafdRecvAPC;
            APCContext = HeapAlloc(GlobalHeap, 0, sizeof(*APCContext));
            if (!APCContext)
            {
                ERR("Not enough memory for APC Context\n");
                NtClose(SockEvent);
                return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, lpNumberOfBytesRead);
            }
            APCContext->lpCompletionRoutine = lpCompletionRoutine;
            APCContext->lpOverlapped = lpOverlapped;
            APCContext->lpSocket = Socket;
            Event = NULL;
        }
        else
        {
            // .NET expects APCContext to be a pointer to lpOverlapped, because it adds some additional metadata past OVERLAPPED structure
            // Do not use APC when there is no completion context
            Event = lpOverlapped->hEvent;
            
            APCFunction = NULL;
            /* As Windows: the overlapped is the completion key of a completion port even
             * when an event is given; only an event with the low bit set suppresses the packet */
            if ((ULONG_PTR)Event & 1)
            {
                APCContext = NULL;
            }
            else
            {
                APCContext = (PMSAFD_RECV_APC_CONTEXT)lpOverlapped;
            }
        }

        RecvInfo.AfdFlags |= AFD_OVERLAPPED;
    }

    IOSB->Information = 0;
    IOSB->Status = STATUS_PENDING;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                   Event,
                                   APCFunction,
                                   APCContext,
                                   IOSB,
                                   IOCTL_AFD_RECV,
                                   &RecvInfo,
                                   sizeof(RecvInfo),
                                   NULL,
                                   0);

    /* Wait for completion if not overlapped */
    if (!lpOverlapped && Status == STATUS_PENDING)
    {
        MsafdWaitForRequest((HANDLE)Handle, SockEvent, IOSB,
                            MsafdSocketTimeout(Socket, Socket->SharedData->RecvTimeout));
        Status = IOSB->Status;
    }

    NtClose(SockEvent);

    if (Status == STATUS_PENDING)
    {
        TRACE("Leaving (Pending)\n");
        return MsafdReturnWithErrno(Status, lpErrno, 0, NULL);
    }

    NumberOfBytesRead = (DWORD)IOSB->Information;

    /* Return the Flags */
    if (ReceiveFlags)
    {
        switch (Status)
        {
            case STATUS_RECEIVE_EXPEDITED:
                *ReceiveFlags = MSG_OOB;
                break;
            case STATUS_RECEIVE_PARTIAL_EXPEDITED:
                *ReceiveFlags = MSG_PARTIAL | MSG_OOB;
                break;
            case STATUS_RECEIVE_PARTIAL:
                *ReceiveFlags = MSG_PARTIAL;
                break;
            default:
                *ReceiveFlags = 0;
                break;
        }
    }

    /* Re-enable Async Event */
    if (ReceiveFlags && (*ReceiveFlags & MSG_OOB))
    {
        SockReenableAsyncSelectEvent(Socket, FD_OOB);
    }
    else
    {
        SockReenableAsyncSelectEvent(Socket, FD_READ);
    }

    TRACE("Leaving (%lx %ld)\n", Status, NumberOfBytesRead);

    /* A timed out receive leaves the caller's byte count unchanged */
    Ret = MsafdReturnWithErrno(Status, lpErrno, NumberOfBytesRead,
                               (Status == STATUS_IO_TIMEOUT) ? NULL : lpNumberOfBytesRead);

    /* A datagram larger than the buffers (a connected datagram socket): the failure
     * reports the bytes that were received, as Windows does */
    if (Status == STATUS_BUFFER_OVERFLOW && lpNumberOfBytesRead)
        *lpNumberOfBytesRead = NumberOfBytesRead;

    return Ret;
}

/*
 * The datagram receive of WSPRecvFrom and WSPRecvMsg. With a message, AFD also gets the
 * message's control buffer, control length and flags to fill in (see AFD_RECV_INFO_MSG), and
 * the socket's IP_PKTINFO setting; the address buffer may then be absent.
 */
static
int
MsafdRecvFrom(SOCKET Handle,
              LPWSABUF lpBuffers,
              DWORD dwBufferCount,
              LPDWORD lpNumberOfBytesRead,
              LPDWORD ReceiveFlags,
              struct sockaddr *SocketAddress,
              int *SocketAddressLength,
              LPWSAOVERLAPPED lpOverlapped,
              LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
              LPWSATHREADID lpThreadId,
              LPINT lpErrno,
              LPWSAMSG Msg)
{
    PIO_STATUS_BLOCK            IOSB;
    IO_STATUS_BLOCK             DummyIOSB;
    AFD_RECV_INFO_MSG           RecvInfo;
    NTSTATUS                    Status;
    PMSAFD_RECV_APC_CONTEXT     APCContext;
    PIO_APC_ROUTINE             APCFunction = NULL;
    HANDLE                      Event = NULL;
    HANDLE                      SockEvent;
    PSOCKET_INFORMATION         Socket;
    DWORD                       NumberOfBytesRead;
    int                         Ret;

    TRACE("WSPRecvFrom(%x)\n", Handle);

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        if (lpErrno)
            *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    if (!lpNumberOfBytesRead && !lpOverlapped)
    {
        if (lpErrno)
            *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }
    if (Socket->SharedData->OobInline && ReceiveFlags && (*ReceiveFlags & MSG_OOB) != 0)
    {
        if (lpErrno)
            *lpErrno = WSAEINVAL;
        return SOCKET_ERROR;
    }
    if (Socket->SharedData->ReceiveShutdown)
    {
        /* After shutdown(SD_RECEIVE) a new receive fails, as on Windows, which leaves the
         * status of its OVERLAPPED pending */
        if (lpOverlapped)
        {
            ((PIO_STATUS_BLOCK)lpOverlapped)->Status = STATUS_PENDING;
            ((PIO_STATUS_BLOCK)lpOverlapped)->Information = 0;
        }
        if (lpErrno)
            *lpErrno = MsafdConnectionAborted(Socket) ? WSAECONNABORTED : WSAESHUTDOWN;
        return SOCKET_ERROR;
    }

    if (!Msg && !(Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS))
    {
        /* Call WSPRecv for a non-datagram socket */
        return WSPRecv(Handle,
                       lpBuffers,
                       dwBufferCount,
                       lpNumberOfBytesRead,
                       ReceiveFlags,
                       lpOverlapped,
                       lpCompletionRoutine,
                       lpThreadId,
                       lpErrno);
    }

    /* Bind us First */
    if (Socket->SharedData->State == SocketOpen)
    {
        SOCKADDR_STORAGE Wildcard;
        INT WildcardLength = sizeof(Wildcard);

        /* A message without an address buffer still needs the socket bound */
        if (!SocketAddress || !SocketAddressLength)
        {
            SocketAddress = (struct sockaddr *)&Wildcard;
            SocketAddressLength = &WildcardLength;
        }

        Socket->HelperData->WSHGetWildcardSockaddr(Socket->HelperContext,
            SocketAddress,
            SocketAddressLength);
        /* Bind it */
        if (WSPBind(Handle, SocketAddress, *SocketAddressLength, lpErrno) == SOCKET_ERROR)
            return SOCKET_ERROR;

        if (SocketAddress == (struct sockaddr *)&Wildcard)
        {
            SocketAddress = NULL;
            SocketAddressLength = NULL;
        }
    }
    memset(&RecvInfo, 0, sizeof(RecvInfo));

    Status = NtCreateEvent( &SockEvent, EVENT_ALL_ACCESS,
                            NULL, SynchronizationEvent, FALSE );

    if( !NT_SUCCESS(Status) )
    {
        return SOCKET_ERROR;
    }

    /* Set up the Receive Structure */
    RecvInfo.Udp.BufferArray = (PAFD_WSABUF)lpBuffers;
    RecvInfo.Udp.BufferCount = dwBufferCount;
    RecvInfo.Udp.TdiFlags = 0;
    RecvInfo.Udp.AfdFlags = Socket->SharedData->NonBlocking ? AFD_IMMEDIATE : 0;
    RecvInfo.Udp.AddressLength = SocketAddressLength;
    RecvInfo.Udp.Address = SocketAddress;

    if (Msg)
    {
        RecvInfo.Udp.AfdFlags |= AFD_RECV_MSG;
        RecvInfo.ControlBuffer = Msg->Control.buf;
        RecvInfo.ControlLength = &Msg->Control.len;
        RecvInfo.MsgFlags = &Msg->dwFlags;
        RecvInfo.Options = Socket->SharedData->IpPktInfo ? AFD_RECV_MSG_PKTINFO : 0;
        RecvInfo.CmsgHdrSize = sizeof(WSACMSGHDR);
    }

    /* Set the TDI Flags */
    if (!ReceiveFlags || *ReceiveFlags == 0)
    {
        RecvInfo.Udp.TdiFlags |= TDI_RECEIVE_NORMAL;
    }
    else
    {
        if (*ReceiveFlags & MSG_OOB)
        {
            RecvInfo.Udp.TdiFlags |= TDI_RECEIVE_EXPEDITED;
        }

        if (*ReceiveFlags & MSG_PEEK)
        {
            RecvInfo.Udp.TdiFlags |= TDI_RECEIVE_PEEK;
        }

        if (*ReceiveFlags & MSG_PARTIAL)
        {
            RecvInfo.Udp.TdiFlags |= TDI_RECEIVE_PARTIAL;
        }
    }

    /* Verify if we should use APC */
    if (!lpOverlapped)
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
            return MsafdReturnWithErrno(STATUS_SUCCESS, lpErrno, 0, lpNumberOfBytesRead);
        }

        IOSB = (PIO_STATUS_BLOCK)lpOverlapped;
        if (lpCompletionRoutine)
        {
            RecvInfo.Udp.AfdFlags |= AFD_SKIP_FIO;
            APCFunction = &MsafdRecvAPC;
            APCContext = HeapAlloc(GlobalHeap, 0, sizeof(*APCContext));
            if (!APCContext)
            {
                ERR("Not enough memory for APC Context\n");
                NtClose(SockEvent);
                return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, lpNumberOfBytesRead);
            }
            APCContext->lpCompletionRoutine = lpCompletionRoutine;
            APCContext->lpOverlapped = lpOverlapped;
            APCContext->lpSocket = Socket;
            Event = NULL;
        }
        else
        {
            // .NET expects APCContext to be a pointer to lpOverlapped, because it adds some additional metadata past OVERLAPPED structure
            // Do not use APC when there is no completion context
            Event = lpOverlapped->hEvent;
            
            APCFunction = NULL;
            /* As Windows: the overlapped is the completion key of a completion port even
             * when an event is given; only an event with the low bit set suppresses the packet */
            if ((ULONG_PTR)Event & 1)
            {
                APCContext = NULL;
            }
            else
            {
                APCContext = (PMSAFD_RECV_APC_CONTEXT)lpOverlapped;
            }
        }

        RecvInfo.Udp.AfdFlags |= AFD_OVERLAPPED;
    }

    IOSB->Information = 0;
    IOSB->Status = STATUS_PENDING;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                    Event,
                                    APCFunction,
                                    APCContext,
                                    IOSB,
                                    IOCTL_AFD_RECV_DATAGRAM,
                                    &RecvInfo,
                                    Msg ? sizeof(RecvInfo) : sizeof(RecvInfo.Udp),
                                    NULL,
                                    0);

    /* Wait for completion if not overlapped */
    if (!lpOverlapped && Status == STATUS_PENDING)
    {
        MsafdWaitForRequest((HANDLE)Handle, SockEvent, IOSB,
                            MsafdSocketTimeout(Socket, Socket->SharedData->RecvTimeout));
        Status = IOSB->Status;
    }

    /* Return the Flags */
    if (ReceiveFlags)
    {
        switch (Status)
        {
            case STATUS_RECEIVE_EXPEDITED:
                *ReceiveFlags = MSG_OOB;
                break;
            case STATUS_RECEIVE_PARTIAL_EXPEDITED:
                *ReceiveFlags = MSG_PARTIAL | MSG_OOB;
                break;
            case STATUS_RECEIVE_PARTIAL:
                *ReceiveFlags = MSG_PARTIAL;
                break;
            default:
                *ReceiveFlags = 0;
                break;
        }
    }

    NtClose(SockEvent);

    if (Status == STATUS_PENDING)
    {
        TRACE("Leaving (Pending)\n");
        *lpErrno = WSA_IO_PENDING;
        return MsafdReturnWithErrno(Status, lpErrno, 0, NULL);
    }

    NumberOfBytesRead = (DWORD)IOSB->Information;

    /* Re-enable Async Event */
    if (ReceiveFlags && (*ReceiveFlags & MSG_OOB))
    {
        SockReenableAsyncSelectEvent(Socket, FD_OOB);
    }
    else
    {
        SockReenableAsyncSelectEvent(Socket, FD_READ);
    }

    TRACE("Leaving (%lx %ld)\n", Status, NumberOfBytesRead);

    /* A timed out receive leaves the caller's byte count unchanged */
    Ret = MsafdReturnWithErrno(Status, lpErrno, NumberOfBytesRead,
                               (Status == STATUS_IO_TIMEOUT) ? NULL : lpNumberOfBytesRead);

    /* A datagram larger than the buffers: the failure reports the bytes that were
     * received, as Windows does */
    if (Status == STATUS_BUFFER_OVERFLOW && lpNumberOfBytesRead)
        *lpNumberOfBytesRead = NumberOfBytesRead;

    return Ret;
}

int
WSPAPI
WSPRecvFrom(SOCKET Handle,
            LPWSABUF lpBuffers,
            DWORD dwBufferCount,
            LPDWORD lpNumberOfBytesRead,
            LPDWORD ReceiveFlags,
            struct sockaddr *SocketAddress,
            int *SocketAddressLength,
            LPWSAOVERLAPPED lpOverlapped,
            LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
            LPWSATHREADID lpThreadId,
            LPINT lpErrno )
{
    return MsafdRecvFrom(Handle, lpBuffers, dwBufferCount, lpNumberOfBytesRead, ReceiveFlags,
                         SocketAddress, SocketAddressLength, lpOverlapped, lpCompletionRoutine,
                         lpThreadId, lpErrno, NULL);
}


/*
 * WSARecvMsg, handed out through SIO_GET_EXTENSION_FUNCTION_POINTER(WSAID_WSARECVMSG). Windows
 * implements it in its provider and ws2_32 does not export it; Chrome's UDP sockets fetch it
 * (the read path of a socket that asked for IP_RECVTOS), and a refused lookup fails every UDP
 * read of the QUIC session with ERR_FAILED.
 *
 * The message is received as a datagram receive with the message's own address buffer, flags
 * and buffers, and AFD fills in its control data (see AFD_RECV_INFO_MSG), also when an
 * overlapped receive completes after this returns: the message must stay valid until then, as
 * on Windows (the address length is written there too). The control data is an IP_PKTINFO
 * message when the socket enabled it, none otherwise. The control length is its full size,
 * the buffer takes as much as fits, and MSG_CTRUNC / MSG_TRUNC flag what was cut off, with
 * WSAEMSGSIZE (the received bytes are still counted).
 */
INT
WSPAPI
WSPRecvMsg(
    _In_ SOCKET Handle,
    _Inout_ LPWSAMSG lpMsg,
    _Out_opt_ LPDWORD lpNumberOfBytesRecvd,
    _Inout_opt_ LPWSAOVERLAPPED lpOverlapped,
    _In_opt_ LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    DWORD Flags;
    INT Errno = NO_ERROR;
    INT Ret;
    PSOCKET_INFORMATION Socket;

    if (!lpMsg)
    {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    /* Only datagram and raw sockets, as on Windows (an unconnected stream socket: WSAEINVAL) */
    if (!(Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS))
    {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }

    /* A control buffer needs a size and a size needs a buffer, else nothing is received
     * (the datagram stays queued and the message is not touched), as on Windows */
    if ((lpMsg->Control.buf == NULL) != (lpMsg->Control.len == 0))
    {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }

    Flags = lpMsg->dwFlags;
    lpMsg->dwFlags = 0;

    Ret = MsafdRecvFrom(Handle,
                        lpMsg->lpBuffers,
                        lpMsg->dwBufferCount,
                        lpNumberOfBytesRecvd,
                        &Flags,
                        lpMsg->name,
                        lpMsg->name ? &lpMsg->namelen : NULL,
                        lpOverlapped,
                        lpCompletionRoutine,
                        NULL,
                        &Errno,
                        lpMsg);

    if (Ret == NO_ERROR)
        return NO_ERROR;

    /* An error before the request reached AFD leaves the control length as it was */
    SetLastError(Errno ? Errno : WSASYSCALLFAILURE);
    return SOCKET_ERROR;
}

int
WSPAPI
WSPSend(SOCKET Handle,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesSent,
        DWORD iFlags,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
        LPWSATHREADID lpThreadId,
        LPINT lpErrno)
{
    PIO_STATUS_BLOCK        IOSB;
    IO_STATUS_BLOCK         DummyIOSB;
    AFD_SEND_INFO          SendInfo;
    NTSTATUS                Status;
    PMSAFD_SEND_APC_CONTEXT APCContext;
    PIO_APC_ROUTINE         APCFunction = NULL;
    HANDLE                  Event = NULL;
    HANDLE                  SockEvent;
    PSOCKET_INFORMATION     Socket;
    DWORD                   NumberOfBytesSent;
    
    TRACE("WSPSend(%x)\n", Handle);

    /* Get the Socket Structure associate to this Socket*/
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        if (lpErrno)
            *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    if (!lpNumberOfBytesSent && !lpOverlapped)
    {
        if (lpErrno)
            *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }
    if (Socket->SharedData->SendShutdown)
    {
        /* After shutdown(SD_SEND) a send fails, as on Windows (with WSAECONNABORTED when
         * shutdown(SD_RECEIVE) reset the connection) */
        if (lpErrno)
            *lpErrno = MsafdConnectionAborted(Socket) ? WSAECONNABORTED : WSAESHUTDOWN;
        return SOCKET_ERROR;
    }

    memset(&SendInfo, 0, sizeof(SendInfo));

    Status = NtCreateEvent( &SockEvent, EVENT_ALL_ACCESS,
                            NULL, SynchronizationEvent, FALSE );

    if( !NT_SUCCESS(Status) )
    {
        return SOCKET_ERROR;
    }

    /* Set up the Send Structure */
    SendInfo.BufferArray = (PAFD_WSABUF)lpBuffers;
    SendInfo.BufferCount = dwBufferCount;
    SendInfo.TdiFlags = 0;
    SendInfo.AfdFlags = Socket->SharedData->NonBlocking ? AFD_IMMEDIATE : 0;

    /* Set the TDI Flags */
    if (iFlags)
    {
        if (iFlags & MSG_OOB)
        {
            SendInfo.TdiFlags |= TDI_SEND_EXPEDITED;
        }
        if (iFlags & MSG_PARTIAL)
        {
            SendInfo.TdiFlags |= TDI_SEND_PARTIAL;
        }
    }

    /* Verify if we should use APC */
    if (!lpOverlapped)
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
            return MsafdReturnWithErrno(STATUS_SUCCESS, lpErrno, 0, lpNumberOfBytesSent);
        }

        IOSB = (PIO_STATUS_BLOCK)lpOverlapped;
        if (lpCompletionRoutine)
        {
            SendInfo.AfdFlags |= AFD_SKIP_FIO;
            APCFunction = &MsafdSendAPC;
            APCContext = HeapAlloc(GlobalHeap, 0, sizeof(*APCContext));
            if (!APCContext)
            {
                ERR("Not enough memory for APC Context\n");
                NtClose(SockEvent);
                return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, NULL);
            }
            APCContext->lpCompletionRoutine = lpCompletionRoutine;
            APCContext->lpOverlapped = lpOverlapped;
            APCContext->lpSocket = Socket;
            APCContext->lpRemoteAddress = NULL;
            APCContext->lpRest = NULL;
            Event = NULL;

            /* A stream send is sent whole: keep the buffers to send what AFD does not take */
            if (dwBufferCount != 0 && MsafdSendStreamWhole(Socket, iFlags, TRUE))
            {
                PMSAFD_SEND_REST Rest = HeapAlloc(GlobalHeap, 0,
                    FIELD_OFFSET(MSAFD_SEND_REST, Buffers) + dwBufferCount * sizeof(AFD_WSABUF));
                if (Rest)
                {
                    Rest->BufferCount = dwBufferCount;
                    Rest->Sent = 0;
                    Rest->AfdFlags = SendInfo.AfdFlags | AFD_OVERLAPPED;
                    Rest->TdiFlags = SendInfo.TdiFlags;
                    RtlCopyMemory(Rest->Buffers, lpBuffers, dwBufferCount * sizeof(AFD_WSABUF));
                    APCContext->lpRest = Rest;
                    SendInfo.BufferArray = Rest->Buffers;
                }
            }
        }
        else
        {
            // .NET expects APCContext to be a pointer to lpOverlapped, because it adds some additional metadata past OVERLAPPED structure
            // Do not use APC when there is no completion context
            Event = lpOverlapped->hEvent;

            /* A stream send is completed whole by AFD: nothing here can continue it later */
            if (dwBufferCount != 0 && MsafdSendStreamWhole(Socket, iFlags, TRUE))
            {
                /* AFD copies all of it, so the send does not return early on a non-blocking socket */
                SendInfo.AfdFlags = (SendInfo.AfdFlags & ~AFD_IMMEDIATE) | AFD_SEND_WHOLE;
            }

            APCFunction = NULL;
            /* As Windows: the overlapped is the completion key of a completion port even
             * when an event is given; only an event with the low bit set suppresses the packet */
            if ((ULONG_PTR)Event & 1)
            {
                APCContext = NULL;
            }
            else
            {
                APCContext = (PMSAFD_SEND_APC_CONTEXT)lpOverlapped;
            }
        }
        
        Event = lpOverlapped->hEvent;
        // APCContext is unsupported when using event
        if (Event)
        {
            if (lpCompletionRoutine)
                HeapFree(GetProcessHeap(), 0, APCContext);
            APCContext = NULL;
        }

        SendInfo.AfdFlags |= AFD_OVERLAPPED;
    }

    IOSB->Information = 0;
    IOSB->Status = STATUS_PENDING;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                    Event,
                                    APCFunction,
                                    APCContext,
                                    IOSB,
                                    IOCTL_AFD_SEND,
                                    &SendInfo,
                                    sizeof(SendInfo),
                                    NULL,
                                    0);

    /* Wait for completion if not overlapped */
    if (!lpOverlapped && Status == STATUS_PENDING)
    {
        /* FIXME: Shouldn't wait infinitely for send... */
        MsafdWaitForAlert(SockEvent);
        Status = IOSB->Status;
    }

    /* A blocking stream send is sent whole: send what AFD did not take */
    if (!lpOverlapped && NT_SUCCESS(Status) && Status != STATUS_PENDING &&
        dwBufferCount != 0 && MsafdSendStreamWhole(Socket, iFlags, FALSE))
    {
        PAFD_WSABUF Rest = HeapAlloc(GlobalHeap, 0, dwBufferCount * sizeof(AFD_WSABUF)), First;
        ULONG Total = 0, Left;

        if (Rest)
        {
            RtlCopyMemory(Rest, lpBuffers, dwBufferCount * sizeof(AFD_WSABUF));
            Left = MsafdSendAdvance(Rest, dwBufferCount, (ULONG)IOSB->Information, &First);
            Total = (ULONG)IOSB->Information;
            while (Left != 0 && NT_SUCCESS(Status) && IOSB->Information != 0)
            {
                SendInfo.BufferArray = First;
                SendInfo.BufferCount = Left;
                IOSB->Information = 0;
                IOSB->Status = STATUS_PENDING;
                Status = NtDeviceIoControlFile((HANDLE)Handle, Event, NULL, NULL, IOSB, IOCTL_AFD_SEND,
                                               &SendInfo, sizeof(SendInfo), NULL, 0);
                if (Status == STATUS_PENDING)
                {
                    MsafdWaitForAlert(SockEvent);
                    Status = IOSB->Status;
                }
                Total += (ULONG)IOSB->Information;
                Left = MsafdSendAdvance(First, Left, (ULONG)IOSB->Information, &First);
            }
            IOSB->Information = Total;
            HeapFree(GlobalHeap, 0, Rest);
        }
    }

    NtClose(SockEvent);

    if (Status == STATUS_PENDING)
    {
        TRACE("Leaving (Pending)\n");
        return MsafdReturnWithErrno(Status, lpErrno, 0, NULL);
    }

    NumberOfBytesSent = (DWORD)IOSB->Information;

    /* Re-enable Async Event */
    SockReenableAsyncSelectEvent(Socket, FD_WRITE);

    TRACE("Leaving (%lx %ld)\n", Status, NumberOfBytesSent);

    /* A failed send leaves the caller's byte count unchanged */
    return MsafdReturnWithErrno(Status, lpErrno, NumberOfBytesSent,
                                (Status == STATUS_SUCCESS) ? lpNumberOfBytesSent : NULL);
}

int
WSPAPI
WSPSendTo(SOCKET Handle,
          LPWSABUF lpBuffers,
          DWORD dwBufferCount,
          LPDWORD lpNumberOfBytesSent,
          DWORD iFlags,
          const struct sockaddr *SocketAddress,
          int SocketAddressLength,
          LPWSAOVERLAPPED lpOverlapped,
          LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
          LPWSATHREADID lpThreadId,
          LPINT lpErrno)
{
    PIO_STATUS_BLOCK        IOSB;
    IO_STATUS_BLOCK         DummyIOSB;
    AFD_SEND_INFO_UDP       SendInfo;
    NTSTATUS                Status;
    PMSAFD_SEND_APC_CONTEXT APCContext;
    PIO_APC_ROUTINE         APCFunction = NULL;
    HANDLE                  Event = NULL;
    PTRANSPORT_ADDRESS      RemoteAddress;
    HANDLE                  SockEvent;
    PSOCKET_INFORMATION     Socket;
    DWORD                   NumberOfBytesSent;
    UCHAR                   Buffer[128];

    TRACE("WSPSendTo(%x)\n", Handle);

    /* Get the Socket Structure associate to this Socket */
    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        if (lpErrno)
            *lpErrno = WSAENOTSOCK;
        return SOCKET_ERROR;
    }
    if (!lpNumberOfBytesSent && !lpOverlapped)
    {
        if (lpErrno)
            *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    if (!(Socket->SharedData->ServiceFlags1 & XP1_CONNECTIONLESS))
    {
        /* Use WSPSend for connection-oriented sockets */
        return WSPSend(Handle,
                       lpBuffers,
                       dwBufferCount,
                       lpNumberOfBytesSent,
                       iFlags,
                       lpOverlapped,
                       lpCompletionRoutine,
                       lpThreadId,
                       lpErrno);
    }

    /* Bind us First */
    if (Socket->SharedData->State == SocketOpen)
    {
        INT BindAddressLength;
        PSOCKADDR BindAddress;
        INT BindError;

        /* Get the Wildcard Address */
        BindAddressLength = Socket->HelperData->MaxWSAddressLength;
        BindAddress = HeapAlloc(GlobalHeap, 0, BindAddressLength);
        if (!BindAddress)
        {
            MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, NULL);
            return INVALID_SOCKET;
        }

        Socket->HelperData->WSHGetWildcardSockaddr(Socket->HelperContext,
                                                   BindAddress,
                                                   &BindAddressLength);
        /* Bind it */
        BindError = WSPBind(Handle, BindAddress, BindAddressLength, lpErrno);
        HeapFree(GlobalHeap, 0, BindAddress);
        if (BindError == SOCKET_ERROR)
            return SOCKET_ERROR;
    }

    Status = NtCreateEvent(&SockEvent,
                        EVENT_ALL_ACCESS,
                        NULL, SynchronizationEvent, FALSE);

    if (!NT_SUCCESS(Status))
    {
        return SOCKET_ERROR;
    }

    RemoteAddress = (PTRANSPORT_ADDRESS)Buffer;

    if (SocketAddressLength > 128 - sizeof(TRANSPORT_ADDRESS)) {
        *lpErrno = WSAEFAULT;
        return SOCKET_ERROR;
    }

    /* Fill TDI address */
    RemoteAddress->TAAddressCount = 1;
    RemoteAddress->Address[0].AddressLength = SocketAddressLength - sizeof(SocketAddress->sa_family);
    RtlCopyMemory(&RemoteAddress->Address[0].AddressType, SocketAddress, SocketAddressLength);

    /* Set up Structure */
    SendInfo.BufferArray = (PAFD_WSABUF)lpBuffers;
    SendInfo.AfdFlags = Socket->SharedData->NonBlocking ? AFD_IMMEDIATE : 0;
    SendInfo.BufferCount = dwBufferCount;
    SendInfo.TdiConnection.RemoteAddress = RemoteAddress;
    SendInfo.TdiConnection.RemoteAddressLength = Socket->HelperData->MaxTDIAddressLength;

    /* Verify if we should use APC */
    if (!lpOverlapped)
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
            return MsafdReturnWithErrno(STATUS_SUCCESS, lpErrno, 0, lpNumberOfBytesSent);
        }

        IOSB = (PIO_STATUS_BLOCK)lpOverlapped;
        if (lpCompletionRoutine)
        {
            SendInfo.AfdFlags |= AFD_SKIP_FIO;
            APCFunction = &MsafdSendAPC;
            APCContext = HeapAlloc(GlobalHeap, 0, sizeof(*APCContext));
            if (!APCContext)
            {
                ERR("Not enough memory for APC Context\n");
                NtClose(SockEvent);
                return MsafdReturnWithErrno(STATUS_INSUFFICIENT_RESOURCES, lpErrno, 0, lpNumberOfBytesSent);
            }
            APCContext->lpCompletionRoutine = lpCompletionRoutine;
            APCContext->lpOverlapped = lpOverlapped;
            APCContext->lpSocket = Socket;
            APCContext->lpRemoteAddress = RemoteAddress;
            APCContext->lpRest = NULL;
            Event = NULL;
        }
        else
        {
            // .NET expects APCContext to be a pointer to lpOverlapped, because it adds some additional metadata past OVERLAPPED structure
            // Do not use APC when there is no completion context
            Event = lpOverlapped->hEvent;
            
            APCFunction = NULL;
            /* As Windows: the overlapped is the completion key of a completion port even
             * when an event is given; only an event with the low bit set suppresses the packet */
            if ((ULONG_PTR)Event & 1)
            {
                APCContext = NULL;
            }
            else
            {
                APCContext = (PMSAFD_SEND_APC_CONTEXT)lpOverlapped;
            }
        }

        SendInfo.AfdFlags |= AFD_OVERLAPPED;
    }

    IOSB->Information = 0;
    IOSB->Status = STATUS_PENDING;

    /* Send IOCTL */
    Status = NtDeviceIoControlFile((HANDLE)Handle,
                                   Event,
                                   APCFunction,
                                   APCContext,
                                   IOSB,
                                   IOCTL_AFD_SEND_DATAGRAM,
                                   &SendInfo,
                                   sizeof(SendInfo),
                                   NULL,
                                   0);

    /* Wait for completion if not overlapped */
    if (!lpOverlapped && Status == STATUS_PENDING)
    {
        /* FIXME: Shouldn't wait infinitely for send... */
        MsafdWaitForAlert(SockEvent);
        Status = IOSB->Status;
    }

    NtClose(SockEvent);

    if (Status == STATUS_PENDING)
    {
        TRACE("Leaving (Pending)\n");
        return MsafdReturnWithErrno(Status, lpErrno, 0, NULL);
    }

    NumberOfBytesSent = (DWORD)IOSB->Information;

    /* Re-enable Async Event */
    SockReenableAsyncSelectEvent(Socket, FD_WRITE);

    TRACE("Leaving (%lx %ld)\n", Status, NumberOfBytesSent);
    return MsafdReturnWithErrno(Status, lpErrno, NumberOfBytesSent, lpNumberOfBytesSent);
}

INT
WSPAPI
WSPRecvDisconnect(IN  SOCKET s,
                  OUT LPWSABUF lpInboundDisconnectData,
                  OUT LPINT lpErrno)
{
    UNIMPLEMENTED;
    return 0;
}



INT
WSPAPI
WSPSendDisconnect(IN  SOCKET s,
                  IN  LPWSABUF lpOutboundDisconnectData,
                  OUT LPINT lpErrno)
{
    UNIMPLEMENTED;
    return 0;
}

/* EOF */
