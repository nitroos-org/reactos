/*
* PROJECT:         Filesystem Filter Manager library
* LICENSE:         GPL - See COPYING in the top level directory
* FILE:            dll/win32/fltlib/message.c
* PURPOSE:         Handles messaging to and from the filter manager
* PROGRAMMERS:     Ged Murphy (ged.murphy@reactos.org)
*/

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>

#define NTOS_MODE_USER
#include <ndk/iofuncs.h>
#include <ndk/exfuncs.h>
#include <ndk/obfuncs.h>
#include <ndk/rtlfuncs.h>
#include <fltuser.h>
#include <fltmgr_shared.h>

#include "fltlib.h"

/* DATA ****************************************************************************/

/*
 * The result of an I/O control request for a communication port. The handle is for asynchronous
 * I/O, so we wait on an event of our own. Overlapped is for requests which may take long: that
 * one gets the result by the event of the caller.
 */
static
HRESULT
PortIoctl(_In_ HANDLE hPort,
          _In_ ULONG IoControlCode,
          _In_reads_bytes_opt_(InSize) PVOID In,
          _In_ ULONG InSize,
          _Out_writes_bytes_opt_(OutSize) PVOID Out,
          _In_ ULONG OutSize,
          _Out_opt_ PULONG Returned,
          _Inout_opt_ LPOVERLAPPED lpOverlapped)
{
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;
    HANDLE Event = NULL;

    if (Returned)
        *Returned = 0;

    if (lpOverlapped)
    {
        PIO_STATUS_BLOCK Block = (PIO_STATUS_BLOCK)lpOverlapped;

        Block->Status = STATUS_PENDING;
        Status = NtDeviceIoControlFile(hPort, lpOverlapped->hEvent, NULL, NULL, Block, IoControlCode,
                                       In, InSize, Out, OutSize);
        if (Status == STATUS_PENDING)
            return HRESULT_FROM_WIN32(ERROR_IO_PENDING);
        if (NT_SUCCESS(Status) && Returned)
            *Returned = (ULONG)Block->Information;
        return NT_SUCCESS(Status) ? S_OK : NtStatusToHResult(Status);
    }

    Status = NtCreateEvent(&Event, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (!NT_SUCCESS(Status))
        return NtStatusToHResult(Status);

    Status = NtDeviceIoControlFile(hPort, Event, NULL, NULL, &IoStatusBlock, IoControlCode,
                                   In, InSize, Out, OutSize);
    if (Status == STATUS_PENDING)
    {
        NtWaitForSingleObject(Event, FALSE, NULL);
        Status = IoStatusBlock.Status;
    }
    NtClose(Event);

    if (NT_SUCCESS(Status) && Returned)
        *Returned = (ULONG)IoStatusBlock.Information;
    return NT_SUCCESS(Status) ? S_OK : NtStatusToHResult(Status);
}

_Must_inspect_result_
HRESULT
WINAPI
FilterConnectCommunicationPort(_In_ LPCWSTR lpPortName,
                               _In_ DWORD dwOptions,
                               _In_reads_bytes_opt_(wSizeOfContext) LPCVOID lpContext,
                               _In_ WORD wSizeOfContext,
                               _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                               _Outptr_ HANDLE *hPort)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    PFILE_FULL_EA_INFORMATION Ea;
    PFLT_CONNECT_REQUEST Request;
    UNICODE_STRING DeviceName;
    HANDLE FileHandle;
    SIZE_T PortNameSize;
    ULONG ValueSize, BufferSize;
    NTSTATUS Status;
    HRESULT hr;

    *hPort = INVALID_HANDLE_VALUE;

    /* Sanity check */
    if (lpContext && wSizeOfContext == 0)
    {
        return E_INVALIDARG;
    }

    PortNameSize = wcslen(lpPortName) * sizeof(WCHAR);
    if (PortNameSize == 0 || PortNameSize > 0xFFFF)
        return E_INVALIDARG;

    /* The request travels as an extended attribute of the create */
    ValueSize = sizeof(FLT_CONNECT_REQUEST) + (ULONG)PortNameSize + (lpContext ? wSizeOfContext : 0);
    BufferSize = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + sizeof(FLT_CONNECT_EA_NAME) + ValueSize;
    Ea = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferSize);
    if (Ea == NULL) return E_OUTOFMEMORY;

    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = sizeof(FLT_CONNECT_EA_NAME) - 1;
    Ea->EaValueLength = (USHORT)ValueSize;
    RtlCopyMemory(Ea->EaName, FLT_CONNECT_EA_NAME, sizeof(FLT_CONNECT_EA_NAME));

    Request = (PFLT_CONNECT_REQUEST)(Ea->EaName + sizeof(FLT_CONNECT_EA_NAME));
    Request->Options = dwOptions;
    Request->NameLength = (USHORT)PortNameSize;
    Request->ContextSize = lpContext ? wSizeOfContext : 0;
    RtlCopyMemory(Request + 1, lpPortName, PortNameSize);
    if (lpContext)
        RtlCopyMemory((PUCHAR)(Request + 1) + PortNameSize, lpContext, wSizeOfContext);

    /* Initialize the object attributes */
    RtlInitUnicodeString(&DeviceName, L"\\??\\FltMgrMsg");
    InitializeObjectAttributes(&ObjectAttributes,
                               &DeviceName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    /* Check if we were passed any security attributes */
    if (lpSecurityAttributes)
    {
        /* Add these manually and update the flags if we were asked to make it inheritable */
        ObjectAttributes.SecurityDescriptor = lpSecurityAttributes->lpSecurityDescriptor;
        if (lpSecurityAttributes->bInheritHandle)
        {
            ObjectAttributes.Attributes |= OBJ_INHERIT;
        }
    }

    /* Now get a handle to the device, which connects to the port. The handle is for asynchronous I/O */
    Status = NtCreateFile(&FileHandle,
                          SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                          &ObjectAttributes,
                          &IoStatusBlock,
                          NULL,
                          0,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          FILE_OPEN,
                          0,
                          Ea,
                          BufferSize);
    if (NT_SUCCESS(Status))
    {
        *hPort = FileHandle;
        hr = S_OK;
    }
    else
    {
        hr = NtStatusToHResult(Status);
    }

    /* Cleanup and return */
    RtlFreeHeap(GetProcessHeap(), 0, Ea);
    return hr;
}

_Must_inspect_result_
HRESULT
WINAPI
FilterSendMessage(_In_ HANDLE hPort,
                  _In_reads_bytes_(dwInBufferSize) LPVOID lpInBuffer,
                  _In_ DWORD dwInBufferSize,
                  _Out_writes_bytes_to_opt_(dwOutBufferSize, *lpBytesReturned) LPVOID lpOutBuffer,
                  _In_ DWORD dwOutBufferSize,
                  _Out_ LPDWORD lpBytesReturned)
{
    return PortIoctl(hPort, IOCTL_FILTER_SEND_MESSAGE, lpInBuffer, dwInBufferSize,
                     lpOutBuffer, dwOutBufferSize, lpBytesReturned, NULL);
}

_Must_inspect_result_
HRESULT
WINAPI
FilterGetMessage(_In_ HANDLE hPort,
                 _Out_writes_bytes_(dwMessageBufferSize) PFILTER_MESSAGE_HEADER lpMessageBuffer,
                 _In_ DWORD dwMessageBufferSize,
                 _Inout_opt_ LPOVERLAPPED lpOverlapped)
{
    return PortIoctl(hPort, IOCTL_FILTER_GET_MESSAGE, NULL, 0,
                     lpMessageBuffer, dwMessageBufferSize, NULL, lpOverlapped);
}

_Must_inspect_result_
HRESULT
WINAPI
FilterReplyMessage(_In_ HANDLE hPort,
                   _In_reads_bytes_(dwReplyBufferSize) PFILTER_REPLY_HEADER lpReplyBuffer,
                   _In_ DWORD dwReplyBufferSize)
{
    return PortIoctl(hPort, IOCTL_FILTER_REPLY_MESSAGE, lpReplyBuffer, dwReplyBufferSize,
                     NULL, 0, NULL, NULL);
}
