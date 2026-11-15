/*
 * PROJECT:         ReactOS IP Helper API
 * LICENSE:         LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:         ICMP functions
 * COPYRIGHT:       2016 Tim Crawford (crawfxrd@gmail.com)
 *                  2019 Victor Perevertkin (victor.perevertkin@reactos.org)
 */

#include "iphlpapi_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(iphlpapi);

HANDLE
WINAPI
Icmp6CreateFile(void)
{
    HANDLE IcmpFile;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Ip6");
    NTSTATUS Status;

    InitializeObjectAttributes(
        &ObjectAttributes,
        &DeviceName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = NtCreateFile(
        &IcmpFile,
        GENERIC_EXECUTE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        0,
        NULL,
        0);

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return INVALID_HANDLE_VALUE;
    }

    return IcmpFile;
}

DWORD
WINAPI
Icmp6ParseReplies(
    _In_ LPVOID ReplyBuffer,
    _In_ DWORD  ReplySize)
{
    PICMPV6_ECHO_REPLY pEcho;

    if (ReplyBuffer == NULL || ReplySize == 0)
        return 0;

    pEcho = (PICMPV6_ECHO_REPLY)ReplyBuffer;

    // XXX: MSDN also says IP_TTL_EXPIRED_TRANSIT.
    if (pEcho->Status == IP_SUCCESS)
    {
        return 1;
    }

    SetLastError(pEcho->Status);
    return 0;
}

/* The IO_STATUS_BLOCK of an asynchronous echo lives in the end of the caller's reply buffer, as the buffer
 * is the only memory that outlives the call. It is placed 8-byte aligned: the system call of a 32-bit process on
 * the 64-bit system refuses an unaligned status block (ERROR_NOACCESS), and the end of a caller's buffer is
 * anywhere. On return *Size is what is left of the buffer for the reply (up to the status block). NULL when
 * the reply, then the status block do not fit */
static
PIO_STATUS_BLOCK
PlaceIoStatusBlock(
    _In_ PVOID ReplyBuffer,
    _Inout_ PDWORD ReplySize,
    _In_ DWORD MinReply)
{
    ULONG_PTR Start = (ULONG_PTR)ReplyBuffer;
    ULONG_PTR End = Start + *ReplySize;
    ULONG_PTR Iosb;

    if (*ReplySize < MinReply + sizeof(IO_STATUS_BLOCK))
        return NULL;

    Iosb = (End - sizeof(IO_STATUS_BLOCK)) & ~(ULONG_PTR)7;
    if (Iosb < Start + MinReply)
        return NULL;

    *ReplySize = (DWORD)(Iosb - Start);
    return (PIO_STATUS_BLOCK)Iosb;
}

DWORD
WINAPI
Icmp6SendEcho2(
    _In_     HANDLE                 IcmpHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _In_     struct sockaddr_in6    *SourceAddress,
    _In_     struct sockaddr_in6    *DestinationAddress,
    _In_     LPVOID                 RequestData,
    _In_     WORD                   RequestSize,
    _In_     PIP_OPTION_INFORMATION RequestOptions,
    _Out_    LPVOID                 ReplyBuffer,
    _In_     DWORD                  ReplySize,
    _In_     DWORD                  Timeout)
{
    HANDLE hEvent;
    PIO_STATUS_BLOCK IoStatusBlock;
    IO_STATUS_BLOCK SyncIoStatusBlock;
    PVOID InputBuffer;
    ULONG InputBufferLength;
    //ULONG OutputBufferLength;
    PICMPV6_ECHO_REQUEST Request;
    NTSTATUS Status;

    InputBufferLength = sizeof(ICMPV6_ECHO_REQUEST) + RequestSize;

    /* The reply and the echoed data must fit: otherwise IP_GENERAL_FAILURE, also in the reply when it has room
     * for one (Windows 10, oracle: 36 + 32 bytes take a 32-byte echo, 36 + 8 do not) */
    if (ReplySize < sizeof(ICMPV6_ECHO_REPLY) + RequestSize)
    {
        if (ReplyBuffer && ReplySize >= sizeof(ICMPV6_ECHO_REPLY))
        {
            ZeroMemory(ReplyBuffer, sizeof(ICMPV6_ECHO_REPLY));
            ((PICMPV6_ECHO_REPLY)ReplyBuffer)->Status = IP_GENERAL_FAILURE;
        }
        SetLastError(IP_GENERAL_FAILURE);
        return 0;
    }

    if (Event == NULL && ApcRoutine == NULL)
    {
        /* Synchronous: the whole buffer is the caller's */
        IoStatusBlock = &SyncIoStatusBlock;
    }
    else
    {
        // IO_STATUS_BLOCK will be stored inside ReplyBuffer (in the end)
        // that's because the function may return before device request ends
        IoStatusBlock = PlaceIoStatusBlock(ReplyBuffer, &ReplySize, sizeof(ICMPV6_ECHO_REPLY));
        if (IoStatusBlock == NULL)
        {
            SetLastError(IP_BUF_TOO_SMALL);
            return 0;
        }
    }

    InputBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, InputBufferLength);
    if (InputBuffer == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    Request = (PICMPV6_ECHO_REQUEST)InputBuffer;

    Request->DestinationAddress.sin6_port = DestinationAddress->sin6_port;
    Request->DestinationAddress.sin6_flowinfo = DestinationAddress->sin6_flowinfo;
    CopyMemory(&(Request->DestinationAddress.sin6_addr), &(DestinationAddress->sin6_addr), sizeof(Request->DestinationAddress.sin6_addr));
    Request->DestinationAddress.sin6_scope_id = DestinationAddress->sin6_scope_id;

    Request->SourceAddress.sin6_port = SourceAddress->sin6_port;
    Request->SourceAddress.sin6_flowinfo = SourceAddress->sin6_flowinfo;
    CopyMemory(&(Request->SourceAddress.sin6_addr), &(SourceAddress->sin6_addr), sizeof(Request->SourceAddress.sin6_addr));
    Request->SourceAddress.sin6_scope_id = SourceAddress->sin6_scope_id;

    // XXX: What is this and why is it sometimes 0x72?
    Request->Unknown1 = 0x72;

    Request->Timeout = Timeout;
    /* The options are optional: no options, the default hop limit */
    Request->Ttl = RequestOptions ? RequestOptions->Ttl : 0;
    Request->Flags = RequestOptions ? RequestOptions->Flags : 0;

    if (RequestSize > 0)
    {
        CopyMemory((PBYTE)InputBuffer + sizeof(ICMPV6_ECHO_REQUEST), RequestData, RequestSize);
    }

    if (Event == NULL && ApcRoutine == NULL)
    {
        hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    }
    else
    {
        hEvent = Event;
    }

    Status = NtDeviceIoControlFile(
        IcmpHandle,
        hEvent,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        IOCTL_ICMP_ECHO_REQUEST,
        InputBuffer,
        InputBufferLength,
        ReplyBuffer,
        ReplySize);         // TODO: Determine how Windows calculates OutputBufferLength.

    if (Event != NULL || ApcRoutine != NULL)
    {
        SetLastError(RtlNtStatusToDosError(Status));
        HeapFree(GetProcessHeap(), 0, InputBuffer);
        return 0;
    }

    if (Status == STATUS_PENDING)
    {
        Status = NtWaitForSingleObject(hEvent, FALSE, NULL);

        if (NT_SUCCESS(Status))
        {
            Status = IoStatusBlock->Status;
        }
    }

    CloseHandle(hEvent);
    HeapFree(GetProcessHeap(), 0, InputBuffer);

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }

    Status = ((PICMPV6_ECHO_REPLY)ReplyBuffer)->Status;
    if (Status != IP_SUCCESS)
    {
        SetLastError(Status);
        return 0;
    }

    return 1;
}

BOOL
WINAPI
IcmpCloseHandle(
    _In_ HANDLE IcmpHandle)
{
    NTSTATUS Status;

    /* Windows rejects the two values that are never a handle with ERROR_INVALID_PARAMETER. */
    if (IcmpHandle == NULL || IcmpHandle == INVALID_HANDLE_VALUE)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    Status = NtClose(IcmpHandle);
    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return FALSE;
    }

    return TRUE;
}

HANDLE
WINAPI
IcmpCreateFile(void)
{
    HANDLE IcmpFile;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\Ip");
    NTSTATUS Status;

    InitializeObjectAttributes(
        &ObjectAttributes,
        &DeviceName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    Status = NtCreateFile(
        &IcmpFile,
        GENERIC_EXECUTE,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN_IF,
        0,
        NULL,
        0);

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return INVALID_HANDLE_VALUE;
    }

    return IcmpFile;
}

DWORD
WINAPI
IcmpParseReplies(
    _In_ LPVOID ReplyBuffer,
    _In_ DWORD  ReplySize)
{
    PICMP_ECHO_REPLY pEcho;
    DWORD nReplies;

    if (ReplyBuffer == NULL || ReplySize == 0)
    {
        SetLastError(ERROR_GEN_FAILURE);
        return 0;
    }

    // TODO: Handle ReplyBuffer having more than 1 ICMP_ECHO_REPLY.

    pEcho = (PICMP_ECHO_REPLY)ReplyBuffer;

    if (pEcho->Reserved == 0)
    {
        SetLastError(pEcho->Status);
    }

    nReplies = pEcho->Reserved;
    pEcho->Reserved = 0;

    return nReplies;
}

/*
 * IcmpSendEcho2 and IcmpSendEcho2Ex. With an Event or an ApcRoutine the call
 * returns 0 and GetLastError() is ERROR_IO_PENDING; the caller waits for the
 * event (or runs the APC) and then reads the reply with IcmpParseReplies.
 * Without them the call waits for the reply and returns the number of replies.
 */
static
DWORD
IcmpSendEcho2Common(
    _In_     HANDLE                 IcmpHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _In_     IPAddr                 SourceAddress,
    _In_     IPAddr                 DestinationAddress,
    _In_     LPVOID                 RequestData,
    _In_     WORD                   RequestSize,
    _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
    _Out_    LPVOID                 ReplyBuffer,
    _In_     DWORD                  ReplySize,
    _In_     DWORD                  Timeout)
{
    HANDLE hEvent;
    IO_STATUS_BLOCK SyncIoStatusBlock;
    PIO_STATUS_BLOCK IoStatusBlock;
    BOOL Async = (Event != NULL || ApcRoutine != NULL);
    PVOID InputBuffer;
    PICMP_ECHO_REQUEST Request;
    ULONG InputBufferLength;
    DWORD nReplies;
    NTSTATUS Status;

    if (IcmpHandle == NULL || IcmpHandle == INVALID_HANDLE_VALUE ||
        ReplyBuffer == NULL || ReplySize < sizeof(ICMP_ECHO_REPLY) ||
        Timeout == 0 || Timeout == (DWORD)-1 ||
        (RequestSize != 0 && RequestData == NULL))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (ReplySize < RequestSize + sizeof(ICMP_ECHO_REPLY))
    {
        SetLastError(IP_GENERAL_FAILURE);
        return 0;
    }

    if (Async)
    {
        // The call may return before the request ends, so the IO_STATUS_BLOCK
        // lives inside ReplyBuffer (in the end).
        IoStatusBlock = PlaceIoStatusBlock(ReplyBuffer, &ReplySize, sizeof(ICMP_ECHO_REPLY));
        if (IoStatusBlock == NULL)
        {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
    }
    else
    {
        // Nothing outlives the call, so the reply keeps all of its buffer.
        IoStatusBlock = &SyncIoStatusBlock;
    }

    // The request must fit whatever ReplySize is left (an event/APC call gave the
    // IO_STATUS_BLOCK part of it away), as IcmpSendEcho does.
    InputBufferLength = sizeof(ICMP_ECHO_REQUEST) + RequestSize;
    if (RequestOptions != NULL)
        InputBufferLength += RequestOptions->OptionsSize;
    if (InputBufferLength < ReplySize)
        InputBufferLength = ReplySize;

    InputBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, InputBufferLength);
    if (InputBuffer == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    Request = (PICMP_ECHO_REQUEST)InputBuffer;
    Request->Address = DestinationAddress;
    Request->SourceAddress = SourceAddress;
    Request->Timeout = Timeout;
    Request->OptionsOffset = sizeof(ICMP_ECHO_REQUEST);
    Request->DataOffset = sizeof(ICMP_ECHO_REQUEST);

    if (RequestOptions != NULL)
    {
        Request->HasOptions = TRUE;
        Request->Ttl = RequestOptions->Ttl;
        Request->Tos = RequestOptions->Tos;
        Request->Flags = RequestOptions->Flags;

        if (RequestOptions->OptionsSize > 0)
        {
            Request->OptionsSize = RequestOptions->OptionsSize;
            Request->DataOffset += Request->OptionsSize;

            CopyMemory(
                (PUCHAR)InputBuffer + sizeof(ICMP_ECHO_REQUEST),
                RequestOptions->OptionsData,
                Request->OptionsSize);
        }
    }

    if (RequestSize > 0)
    {
        Request->DataSize = RequestSize;
        CopyMemory((PUCHAR)InputBuffer + Request->DataOffset, RequestData, RequestSize);
    }

    if (Async)
    {
        hEvent = Event;
    }
    else
    {
        hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (hEvent == NULL)
        {
            HeapFree(GetProcessHeap(), 0, InputBuffer);
            return 0;
        }
    }

    Status = NtDeviceIoControlFile(
        IcmpHandle,
        hEvent,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        IOCTL_ICMP_ECHO_REQUEST,
        InputBuffer,
        InputBufferLength,
        ReplyBuffer,
        ReplySize);         // TODO: Determine how Windows calculates OutputBufferLength.

    // If called asynchronously, return for the caller to handle.
    if (Async)
    {
        SetLastError(RtlNtStatusToDosError(Status));
        HeapFree(GetProcessHeap(), 0, InputBuffer);
        return 0;
    }

    // Otherwise handle it like IcmpSendEcho.
    if (Status == STATUS_PENDING)
    {
        Status = NtWaitForSingleObject(hEvent, FALSE, NULL);

        if (NT_SUCCESS(Status))
        {
            Status = IoStatusBlock->Status;
        }
    }

    CloseHandle(hEvent);
    HeapFree(GetProcessHeap(), 0, InputBuffer);

    if (!NT_SUCCESS(Status))
    {
        // A source address that is not on this machine.
        if (SourceAddress != 0 && Status == STATUS_INVALID_ADDRESS)
            SetLastError(ERROR_INVALID_NETNAME);
        else
            SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }

    nReplies = ((PICMP_ECHO_REPLY)ReplyBuffer)->Reserved;
    ((PICMP_ECHO_REPLY)ReplyBuffer)->Reserved = 0;

    // The status of the reply is the error only when there is no reply to read
    // (a timeout); an ICMP error message still counts as a reply.
    if (nReplies == 0)
        SetLastError(((PICMP_ECHO_REPLY)ReplyBuffer)->Status);

    return nReplies;
}

DWORD
WINAPI
IcmpSendEcho2(
    _In_     HANDLE                 IcmpHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _In_     IPAddr                 DestinationAddress,
    _In_     LPVOID                 RequestData,
    _In_     WORD                   RequestSize,
    _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
    _Out_    LPVOID                 ReplyBuffer,
    _In_     DWORD                  ReplySize,
    _In_     DWORD                  Timeout)
{
    return IcmpSendEcho2Common(IcmpHandle, Event, ApcRoutine, ApcContext, 0, DestinationAddress,
                               RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
}

DWORD
WINAPI
IcmpSendEcho2Ex(
    _In_     HANDLE                 IcmpHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _In_     IPAddr                 SourceAddress,
    _In_     IPAddr                 DestinationAddress,
    _In_     LPVOID                 RequestData,
    _In_     WORD                   RequestSize,
    _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
    _Out_    LPVOID                 ReplyBuffer,
    _In_     DWORD                  ReplySize,
    _In_     DWORD                  Timeout)
{
    return IcmpSendEcho2Common(IcmpHandle, Event, ApcRoutine, ApcContext, SourceAddress, DestinationAddress,
                               RequestData, RequestSize, RequestOptions, ReplyBuffer, ReplySize, Timeout);
}

DWORD
WINAPI
IcmpSendEcho(
    _In_     HANDLE                 IcmpHandle,
    _In_     IPAddr                 DestinationAddress,
    _In_     LPVOID                 RequestData,
    _In_     WORD                   RequestSize,
    _In_opt_ PIP_OPTION_INFORMATION RequestOptions,
    _Out_    LPVOID                 ReplyBuffer,
    _In_     DWORD                  ReplySize,
    _In_     DWORD                  Timeout)
{
    HANDLE hEvent;
    IO_STATUS_BLOCK IoStatusBlock;
    PVOID InputBuffer;
    ULONG InputBufferLength;
    PICMP_ECHO_REQUEST Request;
    DWORD nReplies;
    NTSTATUS Status;

    if (Timeout == 0 || Timeout == (DWORD)-1)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }

    if (ReplySize < sizeof(ICMP_ECHO_REPLY))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    if (ReplySize < RequestSize + sizeof(ICMP_ECHO_REPLY))
    {
        SetLastError(IP_GENERAL_FAILURE);
        return 0;
    }

    InputBufferLength = sizeof(ICMP_ECHO_REQUEST) + RequestSize;
    if (RequestOptions != NULL)
        InputBufferLength += RequestOptions->OptionsSize;

    if (InputBufferLength < ReplySize)
        InputBufferLength = ReplySize;

    InputBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, InputBufferLength);
    if (InputBuffer == NULL)
    {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return 0;
    }

    Request = (PICMP_ECHO_REQUEST)InputBuffer;
    Request->Address = DestinationAddress;
    Request->Timeout = Timeout;
    Request->OptionsOffset = sizeof(ICMP_ECHO_REQUEST);
    Request->DataOffset = sizeof(ICMP_ECHO_REQUEST);

    if (RequestOptions != NULL)
    {
        Request->HasOptions = TRUE;
        Request->Ttl = RequestOptions->Ttl;
        Request->Tos = RequestOptions->Tos;
        Request->Flags = RequestOptions->Flags;

        if (RequestOptions->OptionsSize > 0)
        {
            Request->OptionsSize = RequestOptions->OptionsSize;
            Request->DataOffset += Request->OptionsSize;

            CopyMemory(
                (PUCHAR)InputBuffer + sizeof(ICMP_ECHO_REQUEST),
                RequestOptions->OptionsData,
                Request->OptionsSize);
        }
    }

    if (RequestSize > 0)
    {
        Request->DataSize = RequestSize;
        CopyMemory((PUCHAR)InputBuffer + Request->DataOffset, RequestData, RequestSize);
    }

    hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL)
    {
        HeapFree(GetProcessHeap(), 0, InputBuffer);
        return 0;
    }

    Status = NtDeviceIoControlFile(
        IcmpHandle,
        hEvent,
        NULL,
        NULL,
        &IoStatusBlock,
        IOCTL_ICMP_ECHO_REQUEST,
        InputBuffer,
        InputBufferLength,
        ReplyBuffer,
        ReplySize);

    if (Status == STATUS_PENDING)
    {
        Status = NtWaitForSingleObject(hEvent, FALSE, NULL);

        if (NT_SUCCESS(Status))
        {
            Status = IoStatusBlock.Status;
        }
    }

    CloseHandle(hEvent);
    HeapFree(GetProcessHeap(), 0, InputBuffer);

    if (!NT_SUCCESS(Status))
    {
        SetLastError(RtlNtStatusToDosError(Status));
        return 0;
    }

    nReplies = ((PICMP_ECHO_REPLY)ReplyBuffer)->Reserved;
    ((PICMP_ECHO_REPLY)ReplyBuffer)->Reserved = 0;

    if (nReplies == 0)
        SetLastError(((PICMP_ECHO_REPLY)ReplyBuffer)->Status);

    return nReplies;
}
