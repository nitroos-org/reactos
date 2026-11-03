/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS Ancillary Function Driver DLL
 * FILE:        dll/win32/msafd/misc/transmit.c
 * PURPOSE:     TransmitFile and TransmitPackets (SIO_GET_EXTENSION_FUNCTION_POINTER)
 */

/*
 * AFD has no transmit-file request, so both functions are done in user mode: the data of the
 * elements (the head buffer, the file, the tail buffer; or the elements of TransmitPackets) is
 * read and sent in pieces with ordinary AFD sends.
 *
 *  - without an OVERLAPPED the call does the whole transfer in the caller's thread;
 *  - with an OVERLAPPED the call returns FALSE/WSA_IO_PENDING and a worker thread (one per
 *    request) does the transfer. It then fills in Internal and InternalHigh of the OVERLAPPED
 *    (status, bytes sent), signals hEvent and, unless the low bit of hEvent is set, queues a
 *    packet on the completion port of the socket, if it has one.
 *
 * The worker uses a duplicate of the socket handle, so a closesocket can never make it work on
 * another socket that reuses the handle value. WSPCloseSocket calls MsafdTransmitSocketClosing,
 * which cancels the requests of the socket (the pending AFD send is cancelled by the worker; the
 * request completes with STATUS_CANCELLED).
 *
 * The packet of the completion port is made by a small request that AFD completes at once on the
 * socket, with the OVERLAPPED as the context: the I/O manager queues it as it queues the packet
 * of any request of the socket (a request that fails at once would queue none). The packet says
 * success and 0 bytes, whatever the transfer did: the transfer's own status and byte count are
 * in Internal/InternalHigh, which is what GetOverlappedResult reads. See the commit message for
 * the differences from Windows.
 */

#include <msafd.h>

#define TF_DEFAULT_SEND     0x10000
#define TF_MAX_SEND         0x100000
#define TF_KNOWN_FLAGS      (TF_DISCONNECT | TF_REUSE_SOCKET | TF_WRITE_BEHIND | \
                             TF_USE_SYSTEM_THREAD | TF_USE_KERNEL_APC)
#define TF_MAX_ELEMENTS     0x10000

typedef struct _TF_ELEMENT
{
    HANDLE File;            /* NULL: a memory element */
    PVOID Buffer;
    ULONGLONG Offset;       /* file */
    ULONGLONG Length;       /* the bytes to send (resolved: the file size is taken for "to the end") */
} TF_ELEMENT, *PTF_ELEMENT;

typedef struct _TF_REQUEST
{
    LIST_ENTRY Link;
    SOCKET Original;            /* the handle the application uses, to find the requests of a closing socket */
    HANDLE Socket;              /* the duplicate the transfer works on */
    LPOVERLAPPED Overlapped;    /* NULL: the caller waits */
    HANDLE CancelEvent;         /* signalled when the socket is closed */
    volatile BOOLEAN Cancelled;
    ULONG Flags;
    ULONG SendSize;
    ULONG Count;
    ULONGLONG Sent;
    NTSTATUS Status;
    ULONG Error;                /* what the call reports: a Winsock error, or a Win32 error of the file */
    PTF_ELEMENT Elements;       /* follow the request */
    HMODULE Module;             /* msafd, held for the worker thread */
    BOOLEAN NoDelaySet;         /* TfSetNoDelay switched it on */
    PVOID Copy;                 /* the copied head and tail of TransmitFile, owned by the request */
} TF_REQUEST, *PTF_REQUEST;

static CRITICAL_SECTION TransmitLock;
static LIST_ENTRY TransmitList;
static BOOLEAN TransmitInitialised;

VOID
MsafdTransmitInit(VOID)
{
    InitializeCriticalSection(&TransmitLock);
    InitializeListHead(&TransmitList);
    TransmitInitialised = TRUE;
}

VOID
MsafdTransmitExit(VOID)
{
    TransmitInitialised = FALSE;
    DeleteCriticalSection(&TransmitLock);
}

/* Before the socket goes: the requests of it are cancelled (they hold a duplicate of the handle, not the socket) */
VOID
MsafdTransmitSocketClosing(PSOCKET_INFORMATION Socket)
{
    PLIST_ENTRY Entry;
    PTF_REQUEST Request;

    if (!TransmitInitialised)
        return;

    EnterCriticalSection(&TransmitLock);
    for (Entry = TransmitList.Flink; Entry != &TransmitList; Entry = Entry->Flink)
    {
        Request = CONTAINING_RECORD(Entry, TF_REQUEST, Link);
        if (Request->Original == Socket->Handle)
        {
            Request->Original = INVALID_SOCKET;
            Request->Cancelled = TRUE;
            SetEvent(Request->CancelEvent);
        }
    }
    LeaveCriticalSection(&TransmitLock);
}

/* Waits for a request on the socket; a close of the socket cancels it */
static
NTSTATUS
TfWaitSend(
    _In_ PTF_REQUEST Request,
    _In_ HANDLE Event,
    _In_ PIO_STATUS_BLOCK Iosb)
{
    HANDLE Handles[2];
    NTSTATUS Status;
    IO_STATUS_BLOCK CancelIosb;

    Handles[0] = Event;
    Handles[1] = Request->CancelEvent;
    Status = NtWaitForMultipleObjects(2, Handles, WaitAny, FALSE, NULL);
    if (Status == STATUS_WAIT_1)
    {
        /* Our own request: NtCancelIoFile cancels the requests of this thread on the handle */
        NtCancelIoFile(Request->Socket, &CancelIosb);
        NtWaitForSingleObject(Event, FALSE, NULL);
    }
    return Iosb->Status;
}

/* Sends all of the buffer: a send of a stream may take part of it */
static
NTSTATUS
TfSend(
    _In_ PTF_REQUEST Request,
    _In_ HANDLE Event,
    _In_reads_bytes_(Length) PUCHAR Data,
    _In_ ULONG Length)
{
    AFD_SEND_INFO SendInfo;
    AFD_WSABUF Buffer;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;

    while (Length != 0)
    {
        if (Request->Cancelled)
            return STATUS_CANCELLED;

        Buffer.len = Length;
        Buffer.buf = (CHAR *)Data;
        RtlZeroMemory(&SendInfo, sizeof(SendInfo));
        SendInfo.BufferArray = &Buffer;
        SendInfo.BufferCount = 1;
        SendInfo.AfdFlags = 0;      /* blocks until AFD has taken the data, whatever the mode of the socket */
        SendInfo.TdiFlags = 0;

        Iosb.Status = STATUS_PENDING;
        Iosb.Information = 0;
        NtResetEvent(Event, NULL);
        Status = NtDeviceIoControlFile(Request->Socket, Event, NULL, NULL, &Iosb,
                                       IOCTL_AFD_SEND, &SendInfo, sizeof(SendInfo), NULL, 0);
        if (Status == STATUS_PENDING)
            Status = TfWaitSend(Request, Event, &Iosb);
        if (!NT_SUCCESS(Status))
            return Status;
        if (Iosb.Information == 0)
            return STATUS_CONNECTION_RESET;     /* no progress: never loop on it */

        Request->Sent += Iosb.Information;
        Data += Iosb.Information;
        Length -= (ULONG)Iosb.Information;
    }

    return STATUS_SUCCESS;
}

/*
 * The transport delivers loopback data a moment after AFD completes the send (measured on this stack: a
 * plain send followed at once by a non-blocking recv on the peer finds nothing in 13% of the tries, the
 * same after TransmitFile in 65%; 50 microseconds of waiting made it 0 of 200), while on Windows the data
 * is there when the send completes. A peer on the same host that reads as soon as TransmitFile returns or
 * completes (the Wine test does) expects it. A short wait after the last send; a sleep would cost a whole
 * clock tick (15.6 ms).
 */
static
VOID
TfDeliveryPause(VOID)
{
    LARGE_INTEGER Frequency, Start, Now;

    if (!QueryPerformanceFrequency(&Frequency) || !QueryPerformanceCounter(&Start))
    {
        Sleep(0);
        return;
    }

    do
    {
        YieldProcessor();
        QueryPerformanceCounter(&Now);
    } while ((Now.QuadPart - Start.QuadPart) * 1000000 / Frequency.QuadPart < 250);
}

/*
 * TCP_NODELAY for the length of the transfer. The data of a transfer should not wait for the
 * acknowledgement of an earlier small segment (Nagle): on this stack the loopback acknowledgement is
 * delayed, so the second of two small TransmitFile calls in a row reached the peer 200 ms late (the
 * Wine test reads at once and found nothing). The socket's own TCP_NODELAY setting (SharedData) is
 * not changed and is put back.
 */
static
VOID
TfSetNoDelay(
    _In_ PTF_REQUEST Request,
    _In_ BOOLEAN Enable)
{
    PSOCKET_INFORMATION Socket;
    BOOLEAN Value = Enable;

    EnterCriticalSection(&TransmitLock);
    if (!Request->Cancelled && Request->Original != INVALID_SOCKET)
    {
        Socket = GetSocketStructure(Request->Original);
        if (Socket && Socket->HelperData && Socket->SharedData->SocketType == SOCK_STREAM &&
            !Socket->SharedData->TcpNoDelay)
        {
            Socket->HelperData->WSHSetSocketInformation(Socket->HelperContext,
                                                        Socket->Handle,
                                                        Socket->TdiAddressHandle,
                                                        Socket->TdiConnectionHandle,
                                                        IPPROTO_TCP,
                                                        TCP_NODELAY,
                                                        (PCHAR)&Value,
                                                        sizeof(Value));
            Request->NoDelaySet = Enable;
        }
    }
    LeaveCriticalSection(&TransmitLock);
}

static
VOID
TfRestorePosition(
    _In_ HANDLE File,
    _In_ PFILE_POSITION_INFORMATION Saved,
    _In_ BOOLEAN Valid)
{
    IO_STATUS_BLOCK Iosb;
    FILE_POSITION_INFORMATION Now;

    if (Valid &&
        NT_SUCCESS(NtQueryInformationFile(File, &Iosb, &Now, sizeof(Now), FilePositionInformation)) &&
        Now.CurrentByteOffset.QuadPart != Saved->CurrentByteOffset.QuadPart)
    {
        NtSetInformationFile(File, &Iosb, Saved, sizeof(*Saved), FilePositionInformation);
    }
}

/* The transfer. Returns the status; Request->Sent has the bytes sent */
static
NTSTATUS
TfTransfer(
    _In_ PTF_REQUEST Request)
{
    HANDLE SendEvent = NULL, FileEvent = NULL;
    PUCHAR Buffer = NULL;
    ULONG Piece = Request->SendSize ? Request->SendSize : TF_DEFAULT_SEND;
    NTSTATUS Status;
    ULONG i;
    BOOLEAN FileFailed = FALSE, SavedValid = FALSE, Started;
    FILE_POSITION_INFORMATION Saved;
    HANDLE SavedFile = NULL;
    ULONGLONG Left = 0, Offset = 0;
    PUCHAR Data = NULL;

    if (Piece > TF_MAX_SEND)
        Piece = TF_MAX_SEND;

    Status = NtCreateEvent(&SendEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (NT_SUCCESS(Status))
        Status = NtCreateEvent(&FileEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        goto done;

    Buffer = HeapAlloc(GlobalHeap, 0, Piece);
    if (!Buffer)
    {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    /*
     * The data of all the elements is one stream: a send takes up to Piece bytes from as many elements
     * as they come from, so that the head, a small file and the tail go out together (they are one
     * segment on Windows; two small sends in a row would leave the second to Nagle until the first
     * is acknowledged).
     */
    TfSetNoDelay(Request, TRUE);
    i = 0;
    Started = FALSE;
    for (;;)
    {
        ULONG Fill = 0;

        while (Fill < Piece && i < Request->Count)
        {
            PTF_ELEMENT Element = &Request->Elements[i];
            ULONG Now;

            if (!Started)
            {
                Left = Element->Length;
                Offset = Element->Offset;
                Data = Element->Buffer;
                Started = TRUE;

                if (Element->File)
                {
                    /* Reading at an offset moves the file pointer of a synchronous handle: Windows leaves it where it was */
                    IO_STATUS_BLOCK PositionIosb;

                    SavedValid = NT_SUCCESS(NtQueryInformationFile(Element->File, &PositionIosb, &Saved,
                                                                   sizeof(Saved), FilePositionInformation));
                    SavedFile = Element->File;
                }
            }

            if (Left == 0)
            {
                if (SavedFile)
                {
                    TfRestorePosition(SavedFile, &Saved, SavedValid);
                    SavedFile = NULL;
                }
                i++;
                Started = FALSE;
                continue;
            }

            Now = (Left > Piece - Fill) ? Piece - Fill : (ULONG)Left;

            if (!Element->File)
            {
                RtlCopyMemory(Buffer + Fill, Data, Now);
                Data += Now;
            }
            else
            {
                IO_STATUS_BLOCK Iosb;
                LARGE_INTEGER ByteOffset;

                if (Request->Cancelled)
                {
                    Status = STATUS_CANCELLED;
                    goto done;
                }

                ByteOffset.QuadPart = (LONGLONG)Offset;
                Iosb.Status = STATUS_PENDING;
                Iosb.Information = 0;
                NtResetEvent(FileEvent, NULL);
                Status = NtReadFile(Element->File, FileEvent, NULL, NULL, &Iosb, Buffer + Fill, Now, &ByteOffset, NULL);
                if (Status == STATUS_PENDING)
                {
                    NtWaitForSingleObject(FileEvent, FALSE, NULL);
                    Status = Iosb.Status;
                }
                if (Status == STATUS_END_OF_FILE || (NT_SUCCESS(Status) && Iosb.Information == 0))
                {
                    /* The file got shorter than it was at the call */
                    Status = STATUS_END_OF_FILE;
                    FileFailed = TRUE;
                    goto done;
                }
                if (!NT_SUCCESS(Status))
                {
                    FileFailed = TRUE;
                    goto done;
                }
                Now = (ULONG)Iosb.Information;
                Offset += Now;
            }

            Fill += Now;
            Left -= Now;
        }

        if (Fill == 0)
            break;

        Status = TfSend(Request, SendEvent, Buffer, Fill);
        if (!NT_SUCCESS(Status))
            goto done;
    }

    /* See TfDeliveryPause */
    if (Request->Sent != 0)
        TfDeliveryPause();

    /* TF_REUSE_SOCKET disconnects as well: after a call with it alone Windows reports the socket as not connected */
    if (Request->Flags & (TF_DISCONNECT | TF_REUSE_SOCKET))
    {
        /* As DisconnectEx: the connection is closed, gracefully (what was sent is delivered first) */
        AFD_DISCONNECT_INFO DisconnectInfo;
        IO_STATUS_BLOCK Iosb;

        DisconnectInfo.DisconnectType = AFD_DISCONNECT_SEND | AFD_DISCONNECT_RECV;
        DisconnectInfo.Timeout.QuadPart = -1000000LL;
        Iosb.Status = STATUS_PENDING;
        NtResetEvent(SendEvent, NULL);
        Status = NtDeviceIoControlFile(Request->Socket, SendEvent, NULL, NULL, &Iosb,
                                       IOCTL_AFD_DISCONNECT, &DisconnectInfo, sizeof(DisconnectInfo), NULL, 0);
        if (Status == STATUS_PENDING)
            Status = TfWaitSend(Request, SendEvent, &Iosb);
        if (NT_SUCCESS(Status))
        {
            /* The socket structure is still there until the close has seen the request */
            EnterCriticalSection(&TransmitLock);
            if (!Request->Cancelled && Request->Original != INVALID_SOCKET)
            {
                PSOCKET_INFORMATION Socket = GetSocketStructure(Request->Original);

                if (Socket)
                {
                    Socket->SharedData->SendShutdown = TRUE;
                    Socket->SharedData->ReceiveShutdown = TRUE;
                }
            }
            LeaveCriticalSection(&TransmitLock);
        }
    }

done:
    if (Request->NoDelaySet)
        TfSetNoDelay(Request, FALSE);
    if (SavedFile)
        TfRestorePosition(SavedFile, &Saved, SavedValid);
    if (Buffer)
        HeapFree(GlobalHeap, 0, Buffer);
    if (FileEvent)
        NtClose(FileEvent);
    if (SendEvent)
        NtClose(SendEvent);

    Request->Status = NT_SUCCESS(Status) ? STATUS_SUCCESS : Status;
    if (NT_SUCCESS(Status))
        Request->Error = NO_ERROR;
    else if (FileFailed)
        Request->Error = RtlNtStatusToDosError(Status);
    else
        Request->Error = TranslateNtStatusError(Status);
    return Request->Status;
}

/* Queues the packet of the completion port of the socket, if it has one, with the OVERLAPPED as the context */
static
VOID
TfPostPacket(
    _In_ HANDLE Socket,
    _In_ LPOVERLAPPED Overlapped)
{
    AFD_INFO Info;
    IO_STATUS_BLOCK Iosb;
    HANDLE Event;
    NTSTATUS Status;

    if (!NT_SUCCESS(NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE)))
        return;

    RtlZeroMemory(&Info, sizeof(Info));
    Info.InformationClass = AFD_INFO_BLOCKING_MODE;
    Iosb.Status = STATUS_PENDING;
    Status = NtDeviceIoControlFile(Socket, NULL, NULL, Overlapped, &Iosb,
                                   IOCTL_AFD_GET_INFO, &Info, sizeof(Info), &Info, sizeof(Info));
    if (Status == STATUS_PENDING)
        NtWaitForSingleObject(Event, FALSE, NULL);     /* not reached: AFD answers this at once */

    NtClose(Event);
}

/* The OVERLAPPED is complete: the result is in it first, then whoever waits is told */
static
VOID
TfCompleteOverlapped(
    _In_ PTF_REQUEST Request)
{
    LPOVERLAPPED Overlapped = Request->Overlapped;
    HANDLE Event = Overlapped->hEvent;

    Overlapped->InternalHigh = (ULONG_PTR)Request->Sent;
    Overlapped->Internal = (ULONG_PTR)Request->Status;
    MemoryBarrier();

    if (!((ULONG_PTR)Event & 1))
        TfPostPacket(Request->Socket, Overlapped);

    if (Event)
        SetEvent((HANDLE)((ULONG_PTR)Event & ~(ULONG_PTR)1));
}

static
VOID
TfFree(
    _In_ PTF_REQUEST Request)
{
    EnterCriticalSection(&TransmitLock);
    RemoveEntryList(&Request->Link);
    LeaveCriticalSection(&TransmitLock);

    if (Request->CancelEvent)
        CloseHandle(Request->CancelEvent);
    if (Request->Socket)
        CloseHandle(Request->Socket);
    if (Request->Copy)
        HeapFree(GlobalHeap, 0, Request->Copy);
    HeapFree(GlobalHeap, 0, Request);
}

static
DWORD
WINAPI
TfWorker(PVOID Param)
{
    PTF_REQUEST Request = Param;
    HMODULE Module = Request->Module;

    TfTransfer(Request);
    TfCompleteOverlapped(Request);
    TfFree(Request);

    /* Last thing: the DLL goes when the thread has gone */
    FreeLibraryAndExitThread(Module, 0);
    return 0;
}

/*
 * The common part: the request is made from the elements and run. The elements are copied;
 * Copy (the copied head and tail of TransmitFile) is taken over, on every path. Returns what
 * the extension function returns.
 */
static
BOOL
TfStart(
    _In_ SOCKET Handle,
    _In_ PTF_ELEMENT Elements,
    _In_ ULONG Count,
    _In_ ULONG SendSize,
    _In_ ULONG Flags,
    _In_opt_ LPOVERLAPPED Overlapped,
    _In_opt_ PVOID Copy)
{
    PSOCKET_INFORMATION Socket;
    PTF_REQUEST Request;
    HANDLE Thread;
    BOOL Ret;
    DWORD Error;

    if (Flags & ~TF_KNOWN_FLAGS)
    {
        Error = WSAEINVAL;
        goto fail;
    }

    Socket = GetSocketStructure(Handle);
    if (!Socket)
    {
        DWORD HandleFlags;

        if (Handle == INVALID_SOCKET)
        {
            Error = WSAENOTSOCK;
            goto fail;
        }

        /* A handle that is not a socket (a file) is WSAEINVAL on Windows; one that is no handle at all WSAENOTSOCK */
        Error = GetHandleInformation((HANDLE)Handle, &HandleFlags) ? WSAEINVAL : WSAENOTSOCK;
        goto fail;
    }

    /* Only a stream (or sequenced packet) socket: the others have no connection to transmit on */
    if (Socket->SharedData->SocketType != SOCK_STREAM && Socket->SharedData->SocketType != SOCK_SEQPACKET)
    {
        Error = WSAENOTCONN;
        goto fail;
    }

    if (Socket->SharedData->SendShutdown)
    {
        /* Disconnected (by TF_DISCONNECT, or shutdown of both directions): not connected any more */
        Error = Socket->SharedData->ReceiveShutdown ? WSAENOTCONN : WSAESHUTDOWN;
        goto fail;
    }

    /* Nothing to send is still a request on a connection (an AcceptEx socket not yet updated is not
     * refused when there is data: AFD decides) */
    if (Count == 0 && Socket->SharedData->State != SocketConnected)
    {
        Error = WSAENOTCONN;
        goto fail;
    }

    Request = HeapAlloc(GlobalHeap, HEAP_ZERO_MEMORY, sizeof(*Request) + Count * sizeof(TF_ELEMENT));
    if (!Request)
    {
        Error = WSAENOBUFS;
        goto fail;
    }

    Request->Elements = (PTF_ELEMENT)(Request + 1);
    RtlCopyMemory(Request->Elements, Elements, Count * sizeof(TF_ELEMENT));
    Request->Count = Count;
    Request->Flags = Flags;
    Request->SendSize = SendSize;
    Request->Overlapped = Overlapped;
    Request->Original = Handle;
    Request->Copy = Copy;           /* the request owns it from here */
    Copy = NULL;

    Request->CancelEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!Request->CancelEvent ||
        !DuplicateHandle(GetCurrentProcess(), (HANDLE)Handle, GetCurrentProcess(), &Request->Socket,
                         0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        /* Not in the list: the entry unlinks from itself */
        InitializeListHead(&Request->Link);
        TfFree(Request);
        SetLastError(WSAENOBUFS);
        return FALSE;
    }

    EnterCriticalSection(&TransmitLock);
    InsertTailList(&TransmitList, &Request->Link);
    LeaveCriticalSection(&TransmitLock);

    if (!Overlapped)
    {
        Ret = NT_SUCCESS(TfTransfer(Request));
        Error = Request->Error;
        TfFree(Request);
        SetLastError(Error);
        return Ret;
    }

    Overlapped->Internal = STATUS_PENDING;
    Overlapped->InternalHigh = 0;

    /* The worker runs msafd's code: keep the DLL mapped until the thread has gone */
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)TfWorker, &Request->Module))
        Thread = NULL;
    else
    {
        Thread = CreateThread(NULL, 0, TfWorker, Request, 0, NULL);
        if (!Thread)
            FreeLibrary(Request->Module);
    }

    if (!Thread)
    {
        Overlapped->Internal = STATUS_INSUFFICIENT_RESOURCES;
        TfFree(Request);
        SetLastError(WSAENOBUFS);
        return FALSE;
    }
    CloseHandle(Thread);

    SetLastError(WSA_IO_PENDING);
    return FALSE;

fail:
    if (Copy)
        HeapFree(GlobalHeap, 0, Copy);
    SetLastError(Error);
    return FALSE;
}

/* A file element: the start, and the bytes (0: to the end of the file) */
static
BOOL
TfFileElement(
    _Out_ PTF_ELEMENT Element,
    _In_ HANDLE File,
    _In_ ULONGLONG Offset,
    _In_ ULONGLONG Length)
{
    LARGE_INTEGER Size;

    if (!GetFileSizeEx(File, &Size))
        return FALSE;

    Element->File = File;
    Element->Buffer = NULL;
    Element->Offset = Offset;
    if (Length == 0)
    {
        Element->Length = (Offset < (ULONGLONG)Size.QuadPart) ? (ULONGLONG)Size.QuadPart - Offset : 0;
    }
    else
    {
        /* Windows refuses a length beyond the end of the file at once, nothing is sent (measured, TransmitFile) */
        if (Offset > (ULONGLONG)Size.QuadPart || Length > (ULONGLONG)Size.QuadPart - Offset)
        {
            SetLastError(WSAEINVAL);
            return FALSE;
        }
        Element->Length = Length;
    }
    return TRUE;
}

BOOL
WSPAPI
WSPTransmitFile(
    _In_ SOCKET Handle,
    _In_opt_ HANDLE File,
    _In_ DWORD NumberOfBytesToWrite,
    _In_ DWORD NumberOfBytesPerSend,
    _Inout_opt_ LPOVERLAPPED Overlapped,
    _In_opt_ LPTRANSMIT_FILE_BUFFERS TransmitBuffers,
    _In_ DWORD Flags)
{
    TF_ELEMENT Elements[3];
    ULONG Count = 0;
    PUCHAR Copy = NULL;
    ULONGLONG Offset = 0;
    ULONG HeadLength = 0, TailLength = 0;

    if (File == INVALID_HANDLE_VALUE)
        File = NULL;

    RtlZeroMemory(Elements, sizeof(Elements));

    if (TransmitBuffers)
    {
        HeadLength = TransmitBuffers->HeadLength;
        TailLength = TransmitBuffers->TailLength;
        if ((HeadLength && !TransmitBuffers->Head) || (TailLength && !TransmitBuffers->Tail))
        {
            SetLastError(WSAEFAULT);
            return FALSE;
        }
    }

    if (File)
    {
        /* The start is the offset of the OVERLAPPED, or the file pointer if that is zero (measured) */
        if (Overlapped && (Overlapped->Offset || Overlapped->OffsetHigh))
        {
            Offset = ((ULONGLONG)Overlapped->OffsetHigh << 32) | Overlapped->Offset;
        }
        else
        {
            LARGE_INTEGER Zero, Position;

            Zero.QuadPart = 0;
            if (!SetFilePointerEx(File, Zero, &Position, FILE_CURRENT))
                return FALSE;   /* the error of the file */
            Offset = (ULONGLONG)Position.QuadPart;
        }
    }

    /* The head and the tail are copied: the call may return before they are sent */
    if (HeadLength || TailLength)
    {
        Copy = HeapAlloc(GlobalHeap, 0, (SIZE_T)HeadLength + TailLength);
        if (!Copy)
        {
            SetLastError(WSAENOBUFS);
            return FALSE;
        }
        if (HeadLength)
            RtlCopyMemory(Copy, TransmitBuffers->Head, HeadLength);
        if (TailLength)
            RtlCopyMemory(Copy + HeadLength, TransmitBuffers->Tail, TailLength);
    }

    if (HeadLength)
    {
        Elements[Count].Buffer = Copy;
        Elements[Count].Length = HeadLength;
        Count++;
    }

    if (File)
    {
        if (!TfFileElement(&Elements[Count], File, Offset, NumberOfBytesToWrite))
        {
            DWORD Error = GetLastError();

            if (Copy)
                HeapFree(GlobalHeap, 0, Copy);
            SetLastError(Error);
            return FALSE;
        }
        Count++;
    }

    if (TailLength)
    {
        Elements[Count].Buffer = Copy + HeadLength;
        Elements[Count].Length = TailLength;
        Count++;
    }

    return TfStart(Handle, Elements, Count, NumberOfBytesPerSend, Flags, Overlapped, Copy);
}

BOOL
WSPAPI
WSPTransmitPackets(
    _In_ SOCKET Handle,
    _In_opt_ LPTRANSMIT_PACKETS_ELEMENT PacketArray,
    _In_ DWORD ElementCount,
    _In_ DWORD SendSize,
    _Inout_opt_ LPOVERLAPPED Overlapped,
    _In_ DWORD Flags)
{
    PTF_ELEMENT Elements;
    ULONG i, Count = 0;
    BOOL Ret;

    if ((!PacketArray && ElementCount) || ElementCount > TF_MAX_ELEMENTS)
    {
        SetLastError(WSAEINVAL);
        return FALSE;
    }

    Elements = HeapAlloc(GlobalHeap, HEAP_ZERO_MEMORY, (ElementCount + 1) * sizeof(*Elements));
    if (!Elements)
    {
        SetLastError(WSAENOBUFS);
        return FALSE;
    }

    for (i = 0; i < ElementCount; i++)
    {
        ULONG ElFlags = PacketArray[i].dwElFlags & (TP_ELEMENT_MEMORY | TP_ELEMENT_FILE);

        /* One kind each; an element that is only a mark of the end of a packet (datagrams) sends nothing */
        if (ElFlags == (TP_ELEMENT_MEMORY | TP_ELEMENT_FILE))
        {
            HeapFree(GlobalHeap, 0, Elements);
            SetLastError(WSAEINVAL);
            return FALSE;
        }

        if (ElFlags == TP_ELEMENT_MEMORY)
        {
            if (PacketArray[i].cLength == 0)
                continue;
            if (!PacketArray[i].pBuffer)
            {
                HeapFree(GlobalHeap, 0, Elements);
                SetLastError(WSAEINVAL);
                return FALSE;
            }
            /* The buffers must stay valid until the call completes, as on Windows */
            Elements[Count].Buffer = PacketArray[i].pBuffer;
            Elements[Count].Length = PacketArray[i].cLength;
            Count++;
        }
        else if (ElFlags == TP_ELEMENT_FILE)
        {
            if (PacketArray[i].nFileOffset.QuadPart < 0 ||
                !TfFileElement(&Elements[Count], PacketArray[i].hFile,
                               (ULONGLONG)PacketArray[i].nFileOffset.QuadPart, PacketArray[i].cLength))
            {
                DWORD Error = GetLastError();

                HeapFree(GlobalHeap, 0, Elements);
                SetLastError(PacketArray[i].nFileOffset.QuadPart < 0 ? WSAEINVAL : Error);
                return FALSE;
            }
            Count++;
        }
    }

    Ret = TfStart(Handle, Elements, Count, SendSize, Flags, Overlapped, NULL);
    {
        DWORD Error = GetLastError();

        HeapFree(GlobalHeap, 0, Elements);
        SetLastError(Error);
    }
    return Ret;
}
