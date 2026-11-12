/*
 * PROJECT:     ReactOS WinSock 2 API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     WSAPoll
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *              Based on WSAPoll in Wine's ws2_32 (dlls/ws2_32/socket.c),
 *              Copyright 1993,1994,1996 John Brezak, Erik Bos, Alex Korobka,
 *              Copyright 2001 Stefan Leichter, Copyright 2020 Zebediah Figura
 *              for CodeWeavers, and other Wine contributors.
 */

/* INCLUDES ******************************************************************/

/* WSAPOLLFD needs the Vista Winsock headers, the rest of the DLL builds as 5.2 */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x600
#include <ws2_32.h>
#include <ndk/iofuncs.h>
#include <tdi.h>
#include <afd/shared.h>

#define NDEBUG
#include <debug.h>

#define POLL_REQUEST_EVENTS (POLLRDNORM | POLLRDBAND | POLLWRNORM)

/* FUNCTIONS *****************************************************************/

/* The socket of a handle, with a reference that the caller releases; NULL for anything else */
static
PWSSOCKET
WsPollGetSocket(IN SOCKET Handle)
{
    if ((INT_PTR)Handle < 0)
        return NULL;

    return WsSockGetSocket(Handle);
}

/* The handle was closed, or its value belongs to another socket or object by now */
static
BOOL
WsPollIsStale(IN SOCKET Handle,
              IN PWSSOCKET Context)
{
    PWSSOCKET Current;
    ULONG Flags;
    BOOL Same;

    if (!GetHandleInformation((HANDLE)Handle, &Flags))
        return TRUE;

    Current = WsPollGetSocket(Handle);
    if (!Current)
        return TRUE;

    Same = (Current == Context);
    WsSockDereference(Current);
    return !Same;
}

static
INT
WsPollStatusToError(IN NTSTATUS Status)
{
    switch (Status)
    {
        case STATUS_SUCCESS:
        case STATUS_TIMEOUT:
            return NO_ERROR;
        case STATUS_INVALID_HANDLE:
        case STATUS_OBJECT_TYPE_MISMATCH:
            return WSAENOTSOCK;
        case STATUS_NO_MEMORY:
        case STATUS_INSUFFICIENT_RESOURCES:
            return WSAENOBUFS;
        case STATUS_CANCELLED:
            return WSAEINTR;
        case STATUS_ACCESS_VIOLATION:
            return WSAEFAULT;
        default:
            return WSAEINVAL;
    }
}

/*
 * @implemented
 */
INT
WSAAPI
WSAPoll(IN OUT LPWSAPOLLFD fdArray,
        IN ULONG fds,
        IN INT timeout)
{
    PAFD_POLL_INFO PollInfo;
    PWSSOCKET *Context;
    PULONG Index;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Event;
    NTSTATUS Status;
    ULONG PollSize, Count = 0, i, j, k;
    INT ErrorCode, Ready = 0;
    BOOL Invalid;

    ErrorCode = WsQuickProlog();
    if (ErrorCode != ERROR_SUCCESS)
    {
        SetLastError(ErrorCode);
        return SOCKET_ERROR;
    }

    if (!fds)
    {
        SetLastError(WSAEINVAL);
        return SOCKET_ERROR;
    }
    if (!fdArray)
    {
        SetLastError(WSAEFAULT);
        return SOCKET_ERROR;
    }
    if (fds > (MAXLONG - sizeof(AFD_POLL_INFO)) / (sizeof(AFD_HANDLE) + sizeof(ULONG) + sizeof(PWSSOCKET)))
    {
        SetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }

    PollSize = FIELD_OFFSET(AFD_POLL_INFO, Handles) + fds * sizeof(AFD_HANDLE);
    PollInfo = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                         PollSize + fds * sizeof(ULONG) + fds * sizeof(PWSSOCKET));
    if (!PollInfo)
    {
        SetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }
    Index = (PULONG)((PUCHAR)PollInfo + PollSize);
    Context = (PWSSOCKET *)(Index + fds);

    /* One pass: the sockets that exist, each kept referenced so that a reused handle value is told from them */
    for (i = 0; i < fds; i++)
    {
        PWSSOCKET Socket;
        ULONG Events = AFD_EVENT_DISCONNECT | AFD_EVENT_ABORT | AFD_EVENT_CONNECT_FAIL;

        fdArray[i].revents = 0;

        Socket = WsPollGetSocket(fdArray[i].fd);
        if (!Socket)
            continue;

        if (fdArray[i].events & POLLRDNORM)
            Events |= AFD_EVENT_ACCEPT | AFD_EVENT_RECEIVE;
        if (fdArray[i].events & POLLRDBAND)
            Events |= AFD_EVENT_OOB_RECEIVE;
        if (fdArray[i].events & POLLWRNORM)
            Events |= AFD_EVENT_SEND;

        PollInfo->Handles[Count].Handle = fdArray[i].fd;
        PollInfo->Handles[Count].Events = Events;
        Context[Count] = Socket;
        Index[Count++] = i;
    }

    if (!Count)
    {
        for (i = 0; i < fds; i++)
            fdArray[i].revents = POLLNVAL;
        HeapFree(GetProcessHeap(), 0, PollInfo);
        SetLastError(WSAENOTSOCK);
        return SOCKET_ERROR;
    }

    /* The requested events are checked for every entry that is not a negative handle */
    Invalid = FALSE;
    for (i = 0; i < fds; i++)
    {
        if ((INT_PTR)fdArray[i].fd >= 0 && (fdArray[i].events & ~POLL_REQUEST_EVENTS))
            Invalid = TRUE;
    }

    Event = Invalid ? NULL : CreateEventW(NULL, FALSE, FALSE, NULL);
    if (Invalid || !Event)
    {
        for (k = 0; k < Count; k++)
            WsSockDereference(Context[k]);
        HeapFree(GetProcessHeap(), 0, PollInfo);
        SetLastError(Invalid ? WSAEINVAL : WSAENOBUFS);
        return SOCKET_ERROR;
    }

    /* Entries that are not sockets */
    for (i = 0, j = 0; i < fds; i++)
    {
        if (j < Count && Index[j] == i)
            j++;
        else
            fdArray[i].revents = POLLNVAL;
    }

    if (timeout >= 0)
        PollInfo->Timeout.QuadPart = (LONGLONG)timeout * -10000;
    else
        PollInfo->Timeout.QuadPart = MAXLONGLONG;

    for (;;)
    {
        PollInfo->HandleCount = Count;
        PollSize = FIELD_OFFSET(AFD_POLL_INFO, Handles) + Count * sizeof(AFD_HANDLE);

        Status = NtDeviceIoControlFile((HANDLE)PollInfo->Handles[0].Handle,
                                       Event,
                                       NULL,
                                       NULL,
                                       &IoStatus,
                                       IOCTL_AFD_SELECT,
                                       PollInfo,
                                       PollSize,
                                       PollInfo,
                                       PollSize);
        if (Status == STATUS_PENDING)
        {
            /* Queued APCs run, the poll goes on */
            while (WaitForSingleObjectEx(Event, INFINITE, TRUE) == WAIT_IO_COMPLETION)
                ;
            Status = IoStatus.Status;
        }

        /* A socket closed before AFD took the request: report it and ask again for the others. AFD reports the failed
         * reference of a secondary handle as no memory, so that status counts only when a stale entry is confirmed */
        if (Status == STATUS_INVALID_HANDLE || Status == STATUS_OBJECT_TYPE_MISMATCH || Status == STATUS_NO_MEMORY)
        {
            ULONG Kept = 0;

            for (k = 0; k < Count; k++)
            {
                if (WsPollIsStale(PollInfo->Handles[k].Handle, Context[k]))
                {
                    fdArray[Index[k]].revents = POLLNVAL;
                    Ready++;
                    WsSockDereference(Context[k]);
                }
                else
                {
                    PollInfo->Handles[Kept] = PollInfo->Handles[k];
                    Context[Kept] = Context[k];
                    Index[Kept++] = Index[k];
                }
            }

            if (Kept != Count)
            {
                Count = Kept;
                if (!Count)
                {
                    Status = STATUS_SUCCESS;
                    break;
                }
                /* The stale entries are already a result: look at the others without waiting */
                PollInfo->Timeout.QuadPart = 0;
                continue;
            }
        }

        break;
    }

    if (Status == STATUS_CANCELLED)
    {
        /* AFD cancels the poll, without events, when a socket of the set is closed */
        for (k = 0; k < Count; k++)
        {
            if (WsPollIsStale(PollInfo->Handles[k].Handle, Context[k]))
            {
                fdArray[Index[k]].revents = POLLNVAL;
                Ready++;
            }
        }
        if (Ready)
            Status = STATUS_SUCCESS;
    }
    else if (NT_SUCCESS(Status))
    {
        for (k = 0; k < Count && k < PollInfo->HandleCount; k++)
        {
            ULONG Flags = PollInfo->Handles[k].Events;
            ULONG Revents = 0;
            PWSAPOLLFD Entry = &fdArray[Index[k]];

            if (Flags & (AFD_EVENT_ACCEPT | AFD_EVENT_RECEIVE))
                Revents |= POLLRDNORM;
            if (Flags & AFD_EVENT_OOB_RECEIVE)
                Revents |= POLLRDBAND;
            if (Flags & AFD_EVENT_SEND)
                Revents |= POLLWRNORM;
            if (Flags & (AFD_EVENT_ABORT | AFD_EVENT_DISCONNECT | AFD_EVENT_CONNECT_FAIL))
                Revents |= POLLHUP;
            /* A failed connect also reports POLLWRNORM, as on Windows (measured on Windows 10: 0x13) */
            if (Flags & AFD_EVENT_CONNECT_FAIL)
                Revents |= POLLWRNORM;
            if (Flags & (AFD_EVENT_ABORT | AFD_EVENT_CONNECT_FAIL))
                Revents |= POLLERR;
            if (Flags & AFD_EVENT_CLOSE)
                Revents |= POLLNVAL;

            Entry->revents = (SHORT)(Revents & (Entry->events | POLLHUP | POLLERR | POLLNVAL));
            if (Entry->revents)
                Ready++;
        }
    }

    for (k = 0; k < Count; k++)
        WsSockDereference(Context[k]);
    CloseHandle(Event);
    HeapFree(GetProcessHeap(), 0, PollInfo);

    ErrorCode = WsPollStatusToError(Status);
    SetLastError(ErrorCode);
    return ErrorCode != NO_ERROR ? SOCKET_ERROR : Ready;
}
