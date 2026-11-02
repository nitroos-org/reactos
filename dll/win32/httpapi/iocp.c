/*
 * PROJECT:     ReactOS HTTP Server API
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Request queue handles that completion ports can be bound to
 * COPYRIGHT:   Copyright 2026 Tomas Srnka
 *
 * http.sys hands out a file handle for a request queue. Programs bind it to a completion port
 * (BindIoCompletionCallback, CreateIoCompletionPort) and start overlapped calls on it; the packet that the
 * kernel queues when such a call finishes carries their OVERLAPPED. There is no driver here, so the handle is
 * the server end of a message mode named pipe, and the packet comes from a real read on that pipe:
 *
 *   - the read is issued with the caller's OVERLAPPED and as many bytes as the call is to report,
 *   - the other end of the pipe then writes exactly that many bytes (ERROR_SUCCESS), one more (the read
 *     ends with STATUS_BUFFER_OVERFLOW, ERROR_MORE_DATA, and still reports the bytes it was given) or the
 *     read is cancelled (STATUS_CANCELLED, ERROR_OPERATION_ABORTED).
 *
 * Measured the same on Windows 10 and on ReactOS. The kernel decides about FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
 * and the event of the OVERLAPPED itself, as it does for http.sys. The reads are always started pending, so a
 * packet is always queued.
 */

#include "httpapip.h"

CRITICAL_SECTION g_Lock;
HL g_Queues, g_Sessions, g_Urls, g_Listeners, g_Conns;
LONG g_Init;
static LONG g_IdSeq;

ULONGLONG New_Id(void)
{
    /* never zero (zero is HTTP_NULL_ID) */
    return ((ULONGLONG)0x40 << 32) | (ULONG)InterlockedIncrement(&g_IdSeq);
}

BOOL Queue_Create(RQ **Out, BOOL V2, SECURITY_ATTRIBUTES *Sa)
{
    static LONG Seq;
    WCHAR Name[96];
    DWORD Mode = PIPE_READMODE_MESSAGE;
    RQ *Q = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*Q));

    if (!Q)
        return FALSE;
    _snwprintf(Name, 96, L"\\\\.\\pipe\\httpapi.%lu.%lu.%ld", GetCurrentProcessId(), GetTickCount(), InterlockedIncrement(&Seq));
    Q->hA = CreateNamedPipeW(Name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                             PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 65536, 65536, 0, Sa);
    if (Q->hA == INVALID_HANDLE_VALUE)
    {
        HeapFree(GetProcessHeap(), 0, Q);
        return FALSE;
    }
    Q->hB = CreateFileW(Name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (Q->hB == INVALID_HANDLE_VALUE)
    {
        CloseHandle(Q->hA);
        HeapFree(GetProcessHeap(), 0, Q);
        return FALSE;
    }
    SetNamedPipeHandleState(Q->hB, &Mode, NULL, NULL);
    InitializeCriticalSection(&Q->PostLock);
    HL_INIT(&Q->Reqs);
    HL_INIT(&Q->Waiters);
    HL_INIT(&Q->Urls);
    Q->V2 = V2;
    EnterCriticalSection(&g_Lock);
    HL_ADD(&g_Queues, &Q->Link);
    LeaveCriticalSection(&g_Lock);
    *Out = Q;
    return TRUE;
}

/* g_Lock held */
RQ *Queue_Find(HANDLE h)
{
    HL *E;

    for (E = g_Queues.Next; E != &g_Queues; E = E->Next)
    {
        RQ *Q = HL_ENTRY(E, RQ, Link);

        if (Q->hA == h && !Q->Closed)
            return Q;
    }
    return NULL;
}

void Post_Completion(RQ *Q, OVERLAPPED *Ovl, int Kind, ULONG Bytes)
{
    OVERLAPPED Drain;
    DWORD Done;
    ULONG Need = Bytes + 1;

    EnterCriticalSection(&Q->PostLock);
    if (Q->ScratchSize < Need)
    {
        PUCHAR New = Q->Scratch ? HeapReAlloc(GetProcessHeap(), 0, Q->Scratch, Need) : HeapAlloc(GetProcessHeap(), 0, Need);

        if (!New)
        {
            LeaveCriticalSection(&Q->PostLock);
            return;
        }
        Q->Scratch = New;
        Q->ScratchSize = Need;
    }

    if (ReadFile(Q->hA, Q->Scratch, Bytes, NULL, Ovl) || GetLastError() != ERROR_IO_PENDING)
    {
        /* Nothing is queued on the pipe, so this cannot finish at once; if it did, the program has closed the
         * handle or the pipe is broken and there is nobody to tell */
        LeaveCriticalSection(&Q->PostLock);
        return;
    }

    switch (Kind)
    {
        case POST_OK:
            WriteFile(Q->hB, Q->Scratch, Bytes, &Done, NULL);
            break;
        case POST_MORE:
            WriteFile(Q->hB, Q->Scratch, Bytes + 1, &Done, NULL);
            /* the byte that did not fit stays queued: read it away without a packet (low bit of the event) */
            RtlZeroMemory(&Drain, sizeof(Drain));
            Drain.hEvent = (HANDLE)((ULONG_PTR)CreateEventW(NULL, TRUE, FALSE, NULL) | 1);
            if (Drain.hEvent != (HANDLE)1)
            {
                if (!ReadFile(Q->hA, Q->Scratch, 16, &Done, &Drain) && GetLastError() == ERROR_IO_PENDING)
                    WaitForSingleObject((HANDLE)((ULONG_PTR)Drain.hEvent & ~(ULONG_PTR)1), 1000);
                CloseHandle((HANDLE)((ULONG_PTR)Drain.hEvent & ~(ULONG_PTR)1));
            }
            break;
        default:
            CancelIoEx(Q->hA, Ovl);
            break;
    }
    LeaveCriticalSection(&Q->PostLock);
}

/* Ends a call: synchronous callers get the result, overlapped ones get a packet and ERROR_IO_PENDING */
ULONG Op_Finish(RQ *Q, OVERLAPPED *Ovl, ULONG Status, int Kind, ULONG Bytes, ULONG *Ret)
{
    if (!Ovl)
    {
        if (Ret)
            *Ret = Bytes;
        return Status;
    }
    if (Ret)
        *Ret = 0;
    Post_Completion(Q, Ovl, Kind, Bytes);
    return ERROR_IO_PENDING;
}

/* g_Lock held */
void Waiter_Complete(RQ *Q, WAITER *W, ULONG Status, int Kind, ULONG Bytes)
{
    HL_DEL(&W->Link);
    if (W->Ovl)
    {
        Post_Completion(Q, W->Ovl, Kind, Bytes);
        HeapFree(GetProcessHeap(), 0, W);
    }
    else
    {
        W->Result = Status;
        W->Bytes = Bytes;
        W->Done = TRUE;
        SetEvent(W->hDone);
    }
}

/* g_Lock held */
void Queue_CancelWaiters(RQ *Q)
{
    while (!HL_EMPTY(&Q->Waiters))
        Waiter_Complete(Q, HL_ENTRY(Q->Waiters.Next, WAITER, Link), ERROR_OPERATION_ABORTED, POST_CANCEL, 0);
}

/* g_Lock held. Takes the queue out of the lists; the pipe ends are closed here, the structure is leaked on
 * purpose when something may still look at it (a connection thread that has a request of it) */
void Queue_Close(RQ *Q)
{
    Q->Closed = TRUE;
    Queue_CancelWaiters(Q);
    Queue_AbortRequests(Q);
    Url_RemoveAll(NULL, Q);
    HL_DEL(&Q->Link);
    EnterCriticalSection(&Q->PostLock);
    CloseHandle(Q->hA);
    CloseHandle(Q->hB);
    Q->hA = Q->hB = INVALID_HANDLE_VALUE;
    LeaveCriticalSection(&Q->PostLock);
}
