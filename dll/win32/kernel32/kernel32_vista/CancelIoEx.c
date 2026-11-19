/*
 * PROJECT:     ReactOS Win32 Base API
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     CancelIoEx
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "k32_vista.h"

#include <ndk/iofuncs.h>
#include <wincon.h>
#include <wincon_undoc.h>
#include <csr/csr.h>
#include <win/console.h>
#include <win/conmsg.h>

/*
 * A console input handle is not a file object: the reads blocked on it wait inside the console server.
 * Ask the server to end them (ERROR_OPERATION_ABORTED), as the console host of Windows 10 does.
 */
static BOOL
CancelConsoleIo(
    _In_ HANDLE hConsoleInput)
{
    CONSOLE_API_MESSAGE ApiMessage;
    PCONSOLE_CANCELIO CancelIoRequest = &ApiMessage.Data.CancelIoRequest;

    CancelIoRequest->ConsoleHandle = NtCurrentPeb()->ProcessParameters->ConsoleHandle;
    CancelIoRequest->InputHandle   = hConsoleInput;

    CsrClientCallServer((PCSR_API_MESSAGE)&ApiMessage,
                        NULL,
                        CSR_CREATE_API_NUMBER(CONSRV_SERVERDLL_INDEX, ConsolepCancelIo),
                        sizeof(*CancelIoRequest));
    if (!NT_SUCCESS(ApiMessage.Status))
    {
        BaseSetLastNTError(ApiMessage.Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
CancelIoEx(
    _In_ HANDLE hFile,
    _In_opt_ LPOVERLAPPED lpOverlapped)
{
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;

    if (IsConsoleHandle(hFile) && lpOverlapped == NULL)
        return CancelConsoleIo(hFile);

    /* An overlapped request is identified by its OVERLAPPED, which is also its I/O status block */
    Status = NtCancelIoFileEx(hFile, (PIO_STATUS_BLOCK)lpOverlapped, &IoStatusBlock);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}
