/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Communication ports under stress: clients connect, the filter sends them messages and waits
 *              for the answer without a timeout, the clients answer or go away in the middle, while
 *              another thread loads and unloads the filter. Nothing may hang (the filter's sends end
 *              with the answer or with the disconnect), the filter gets a DisconnectNotify for every
 *              connection it accepted before its unregister returns, and nothing bugchecks.
 *              FLTMGR_PORTRACE_SECONDS sets the length (default 60).
 */

#include "precomp.h"
#include <fltuser.h>

#define SERVICE_Q   L"FltSampleQ"
#define PORT_Q      L"\\FltSampleQPort"
#define WORKERS     4
#define HANG_MS     60000

#ifndef STATUS_PORT_DISCONNECTED
#define STATUS_PORT_DISCONNECTED ((NTSTATUS)0xC0000037L)
#endif

typedef struct _ASK_THREAD
{
    HANDLE Port;
    HRESULT Result;
    FLTSAMPLE_ASK_RESULT Ask;

} ASK_THREAD;

static volatile LONG Stop;
static volatile LONG Hangs;
static volatile LONG Connected, Refused, Answered, Abandoned, Closed, AskDisconnected, AskOther;
static volatile LONG Cycles, CountMismatches;

/* The filter sends the client a message and waits for the answer for ever (Data[0] = 0 ms) */
static
DWORD
WINAPI
AskThread(PVOID Parameter)
{
    ASK_THREAD *T = Parameter;
    UCHAR Buffer[64];
    PFLTSAMPLE_MSG Message = (PFLTSAMPLE_MSG)Buffer;
    DWORD Bytes = 0;

    Message->Code = FLTSAMPLE_MSG_ASK;
    Message->Arg = 16;
    *(PULONG)Message->Data = 0;
    T->Result = FilterSendMessage(T->Port, Message, FIELD_OFFSET(FLTSAMPLE_MSG, Data) + sizeof(ULONG),
                                  &T->Ask, sizeof(T->Ask), &Bytes);
    return 0;
}

/* The message of the filter, if one comes within Ms */
static
HRESULT
GetMessageWithin(HANDLE Port, PFILTER_MESSAGE_HEADER Header, DWORD Size, DWORD Ms)
{
    OVERLAPPED Overlapped = { 0 };
    DWORD Bytes;
    HRESULT hr;

    Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    hr = FilterGetMessage(Port, Header, Size, &Overlapped);
    if (hr == HRESULT_FROM_WIN32(ERROR_IO_PENDING))
    {
        if (WaitForSingleObject(Overlapped.hEvent, Ms) != WAIT_OBJECT_0)
        {
            CancelIo(Port);
            if (WaitForSingleObject(Overlapped.hEvent, HANG_MS) != WAIT_OBJECT_0)
                InterlockedIncrement(&Hangs);
            CloseHandle(Overlapped.hEvent);
            return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
        }
        hr = GetOverlappedResult(Port, &Overlapped, &Bytes, FALSE) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    }
    CloseHandle(Overlapped.hEvent);
    return hr;
}

static
DWORD
WINAPI
Worker(PVOID Parameter)
{
    ULONG Seed = (ULONG)(ULONG_PTR)Parameter * 7919 + GetTickCount();
    UCHAR Buffer[sizeof(FILTER_MESSAGE_HEADER) + 64];
    PFILTER_MESSAGE_HEADER Header = (PFILTER_MESSAGE_HEADER)Buffer;
    struct { FILTER_REPLY_HEADER Header; ULONG Verdict; } Reply;
    ASK_THREAD T;
    HANDLE Port, Thread;
    HRESULT hr;
    ULONG What;

    while (!Stop)
    {
        Seed = Seed * 1103515245 + 12345;
        What = (Seed >> 16) % 5;

        Port = INVALID_HANDLE_VALUE;
        hr = FilterConnectCommunicationPort(PORT_Q, 0, NULL, 0, NULL, &Port);
        if (FAILED(hr))
        {
            /* Somebody else has the one connection, or the filter isn't there (being loaded or unloaded) */
            InterlockedIncrement(&Refused);
            Sleep((Seed >> 8) % 4);
            continue;
        }
        InterlockedIncrement(&Connected);

        if (What == 0)
        {
            /* In and out */
            CloseHandle(Port);
            InterlockedIncrement(&Closed);
            continue;
        }

        ZeroMemory(&T, sizeof(T));
        T.Port = Port;
        T.Result = E_PENDING;
        Thread = CreateThread(NULL, 0, AskThread, &T, 0, NULL);
        if (!Thread)
        {
            CloseHandle(Port);
            continue;
        }

        hr = GetMessageWithin(Port, Header, sizeof(Buffer), 2000);
        if (SUCCEEDED(hr) && (What == 1 || What == 2))
        {
            /* An answer, maybe a little later */
            if (What == 2)
                Sleep((Seed >> 4) % 20);
            ZeroMemory(&Reply, sizeof(Reply));
            Reply.Header.MessageId = Header->MessageId;
            Reply.Header.Status = 0;
            Reply.Verdict = 0x5A5A;
            (void)FilterReplyMessage(Port, &Reply.Header, sizeof(Reply));
            InterlockedIncrement(&Answered);
        }
        else if (SUCCEEDED(hr))
        {
            /* The filter waits for an answer that never comes: the client goes away */
            if (What == 4)
                Sleep((Seed >> 4) % 10);
            InterlockedIncrement(&Abandoned);
        }

        /* Gone: whatever the filter still waits for ends with the disconnect */
        CloseHandle(Port);

        if (WaitForSingleObject(Thread, HANG_MS) != WAIT_OBJECT_0)
        {
            InterlockedIncrement(&Hangs);
            trace("A FilterSendMessage of an ASK didn't come back within %u ms\n", HANG_MS);
            /* The thread and its block are left as they are */
            Stop = TRUE;
            break;
        }
        CloseHandle(Thread);

        if (SUCCEEDED(T.Result) && T.Ask.Status == STATUS_PORT_DISCONNECTED)
            InterlockedIncrement(&AskDisconnected);
        else if (FAILED(T.Result) || T.Ask.Status != STATUS_SUCCESS)
            InterlockedIncrement(&AskOther);
    }

    return 0;
}

/* Load, a moment of traffic, unload: the unregister meets connects, sends and disconnects in flight */
static
DWORD
WINAPI
Unloader(PVOID Parameter)
{
    ULONG Seed = GetTickCount();
    SAMPLE S;

    UNREFERENCED_PARAMETER(Parameter);

    while (!Stop)
    {
        Seed = Seed * 1103515245 + 12345;

        if (!LoadSample(&S, SERVICE_Q, L"384000.5", 0))
        {
            trace("Load of %ls failed\n", SERVICE_Q);
            Sleep(200);
            continue;
        }
        Sleep(20 + (Seed >> 16) % 300);

        if (!UnloadSample(&S, TRUE))
        {
            Stop = TRUE;
            break;
        }
        InterlockedIncrement(&Cycles);

        if (S.LastPortConnects != S.LastPortDisconnects)
        {
            InterlockedIncrement(&CountMismatches);
            trace("Cycle %ld: %lu connections accepted, %lu DisconnectNotify at the end of the unregister\n",
                  Cycles, S.LastPortConnects, S.LastPortDisconnects);
        }
    }

    return 0;
}

START_TEST(portrace)
{
    HANDLE Threads[WORKERS + 1];
    ULONG Seconds = 60, i, Count = 0;
    WCHAR Value[16];
    DWORD Start;

    if (!StartFilterManager())
    {
        skip("No filter manager\n");
        return;
    }

    if (GetEnvironmentVariableW(L"FLTMGR_PORTRACE_SECONDS", Value, RTL_NUMBER_OF(Value)))
        Seconds = wcstoul(Value, NULL, 10);

    Threads[Count++] = CreateThread(NULL, 0, Unloader, NULL, 0, NULL);
    for (i = 0; i < WORKERS; i++)
        Threads[Count++] = CreateThread(NULL, 0, Worker, (PVOID)(ULONG_PTR)(i + 1), 0, NULL);

    Start = GetTickCount();
    while (!Stop && GetTickCount() - Start < Seconds * 1000)
        Sleep(500);
    Stop = TRUE;

    /* Every thread comes back: a load/unload cycle, a connect or a send that doesn't is a hang */
    for (i = 0; i < Count; i++)
    {
        if (!Threads[i])
            continue;
        if (WaitForSingleObject(Threads[i], 3 * HANG_MS) != WAIT_OBJECT_0)
        {
            InterlockedIncrement(&Hangs);
            trace("Thread %lu didn't finish\n", i);
        }
        else
        {
            CloseHandle(Threads[i]);
        }
    }

    trace("%lu s: %ld load/unload cycles, %ld connects (%ld refused or not there), %ld answered, %ld abandoned, "
          "%ld closed at once; asks ended disconnected %ld, other %ld\n",
          Seconds, Cycles, Connected, Refused, Answered, Abandoned, Closed, AskDisconnected, AskOther);

    ok(Hangs == 0, "%ld hangs\n", Hangs);
    ok(CountMismatches == 0, "%ld cycles where the filter didn't hear of every connection's end\n", CountMismatches);
    ok(Cycles > 0, "No load/unload cycle\n");
    ok(Connected > 0, "No connection\n");
}
