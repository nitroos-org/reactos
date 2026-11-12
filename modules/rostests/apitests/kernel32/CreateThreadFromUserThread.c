/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     A thread that kernel32 did not create (RtlCreateUserThread, the thread pool) can use CreateThread
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *FN_RtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T,
                                                 PVOID, PVOID, PHANDLE, PCLIENT_ID);

static LONG s_InnerRuns;
static DWORD s_CreateError;
static DWORD s_InnerExit;

static DWORD WINAPI InnerProc(LPVOID Param)
{
    InterlockedIncrement(&s_InnerRuns);
    return 0x1234;
}

/* The body of a thread that CSRSS was never told about: it creates a thread through kernel32 and waits for it */
static DWORD CreateInnerThread(void)
{
    HANDLE hInner;
    DWORD Result = 0;

    SetLastError(0xdeadbeef);
    hInner = CreateThread(NULL, 0, InnerProc, NULL, 0, NULL);
    if (!hInner)
    {
        s_CreateError = GetLastError();
        return 1;
    }
    if (WaitForSingleObject(hInner, 20000) != WAIT_OBJECT_0)
        Result = 2;
    else if (!GetExitCodeThread(hInner, &s_InnerExit))
        Result = 3;
    CloseHandle(hInner);
    return Result;
}

static NTSTATUS NTAPI UserThreadProc(PVOID Param)
{
    /* Ends the thread itself, as the thread pool does: the amd64 RtlCreateUserThread start has no return address */
    ExitThread(CreateInnerThread());
    return 0;
}

static DWORD WINAPI WorkItemProc(LPVOID Param)
{
    *(DWORD *)Param = CreateInnerThread();
    return 0;
}

static void Reset(void)
{
    s_InnerRuns = 0;
    s_CreateError = 0;
    s_InnerExit = 0;
}

START_TEST(CreateThreadFromUserThread)
{
    FN_RtlCreateUserThread pRtlCreateUserThread;
    HANDLE hThread;
    CLIENT_ID Cid;
    NTSTATUS Status;
    DWORD ExitCode, WorkResult;
    HANDLE hDone;

    pRtlCreateUserThread = (FN_RtlCreateUserThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
    if (!pRtlCreateUserThread)
    {
        skip("RtlCreateUserThread is not available\n");
        return;
    }

    /* A thread made by RtlCreateUserThread */
    Reset();
    hThread = NULL;
    Status = pRtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (PVOID)UserThreadProc, NULL, &hThread, &Cid);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok_dec(WaitForSingleObject(hThread, 30000), WAIT_OBJECT_0);
        ExitCode = 0xdeadbeef;
        ok_int(GetExitCodeThread(hThread, &ExitCode), TRUE);
        ok_dec(ExitCode, 0);
        ok_hex(s_CreateError, 0);
        ok_dec(s_InnerRuns, 1);
        ok_hex(s_InnerExit, 0x1234);
        CloseHandle(hThread);
    }

    /* A thread of the thread pool, which is made the same way */
    Reset();
    WorkResult = 0xdeadbeef;
    ok_int(QueueUserWorkItem(WorkItemProc, &WorkResult, WT_EXECUTEDEFAULT), TRUE);
    {
        ULONG i;
        for (i = 0; i < 300 && WorkResult == 0xdeadbeef; i++)
            Sleep(100);
    }
    ok_dec(WorkResult, 0);
    ok_hex(s_CreateError, 0);
    ok_dec(s_InnerRuns, 1);

    /* The thread may ask again later and from more threads */
    Reset();
    hDone = NULL;
    Status = pRtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (PVOID)UserThreadProc, NULL, &hDone, &Cid);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        WaitForSingleObject(hDone, 30000);
        CloseHandle(hDone);
        ok_hex(s_CreateError, 0);
        ok_dec(s_InnerRuns, 1);
    }
}
