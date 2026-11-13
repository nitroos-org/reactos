/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     CSRSS drops the records of threads it adopted (RtlCreateUserThread, thread pool) when they end
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * The number of iterations is taken from the environment variable CSRCHURN_N (default 1500).
 * CSRCHURN_MASK selects the requests (1 CreateThread, 2 a console request, 4 DefineDosDevice from every
 * thread: off by default, the DefineDosDevice phase below covers it).
 * Every CSR thread holds a handle of its thread in CSRSS, so the handle count of CSRSS is the measure.
 * The last phase defines and removes a drive letter CSRDDD_N times (default 12000) from this thread: the broadcast
 * thread that CSRSS starts for each of them must leave nothing behind (it ended without the loader and
 * left about 260 bytes of the process heap per pair).
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *FN_RtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, SIZE_T, SIZE_T,
                                                 PVOID, PVOID, PHANDLE, PCLIENT_ID);

#define MAX_PARALLEL 8
#define TID_SLOTS    (1 << 20)

static LONG s_Failures;        /* a call of an adopted thread that CSRSS refused */
static LONG s_Impersonation;   /* of which: a stale record (the impersonation of the dead thread failed) */
static LONG s_Done;
static BOOL s_DosProbe;
static BYTE s_TidSeen[TID_SLOTS / 8];
static LONG s_Reuses;
static LONG s_Ready;
static ULONG s_Mask = 3;   /* CSRCHURN_MASK: 1 CreateThread, 2 console request, 4 DefineDosDevice (impersonates the caller) */
static HANDLE s_Gate;

static DWORD WINAPI InnerProc(LPVOID Param)
{
    return 0;
}

static BOOL GetCsrssStats(ULONG *Handles, SIZE_T *PrivateBytes)
{
    ULONG Size = 256 * 1024, Needed;
    DWORD Session = 0;
    PVOID Buffer;
    NTSTATUS Status;
    BOOL Found = FALSE;

    ProcessIdToSessionId(GetCurrentProcessId(), &Session);
    for (;;)
    {
        Buffer = HeapAlloc(GetProcessHeap(), 0, Size);
        if (!Buffer) return FALSE;
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, &Needed);
        if (Status != STATUS_INFO_LENGTH_MISMATCH) break;
        HeapFree(GetProcessHeap(), 0, Buffer);
        Size = Needed + 65536;
    }
    if (NT_SUCCESS(Status))
    {
        PSYSTEM_PROCESS_INFORMATION Info = Buffer;
        for (;;)
        {
            if (Info->ImageName.Buffer && Info->ImageName.Length == 9 * sizeof(WCHAR) &&
                !_wcsnicmp(Info->ImageName.Buffer, L"csrss.exe", 9) && Info->SessionId == Session)
            {
                *Handles = Info->HandleCount;
                *PrivateBytes = Info->PrivatePageCount;
                Found = TRUE;
                break;
            }
            if (!Info->NextEntryOffset) break;
            Info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
        }
    }
    HeapFree(GetProcessHeap(), 0, Buffer);
    return Found;
}

/* The body of a thread that CSRSS never heard of from kernel32: CSR calls of both kinds */
static void ThreadBody(void)
{
    HANDLE hInner;

    if (s_Mask & 1)
    {
        hInner = CreateThread(NULL, 0, InnerProc, NULL, 0, NULL);
        if (!hInner)
        {
            InterlockedIncrement(&s_Failures);
            return;
        }
        WaitForSingleObject(hInner, 20000);
        CloseHandle(hInner);
    }

    if (s_Mask & 2)
        GetConsoleCP();

    if ((s_Mask & 4) && s_DosProbe)
    {
        /* This request impersonates the calling thread through its CSR record */
        SetLastError(0);
        if (!DefineDosDeviceW(0, L"Y:", L"C:\\"))
        {
            if (GetLastError() == ERROR_BAD_IMPERSONATION_LEVEL)
                InterlockedIncrement(&s_Impersonation);
            InterlockedIncrement(&s_Failures);
        }
        else
        {
            DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, L"Y:", L"C:\\");
        }
    }
}

static NTSTATUS NTAPI UserThreadProc(PVOID Param)
{
    ThreadBody();
    InterlockedIncrement(&s_Done);
    ExitThread(0);
    return 0;
}

static DWORD WINAPI WorkItemProc(LPVOID Param)
{
    ThreadBody();
    InterlockedIncrement(&s_Done);
    return 0;
}

/* A thread that makes one CSR request and stays alive: with many of them every thread id is different */
static NTSTATUS NTAPI HoldThreadProc(PVOID Param)
{
    GetConsoleCP();
    InterlockedIncrement(&s_Ready);
    WaitForSingleObject(s_Gate, 120000);
    ExitThread(0);
    return 0;
}

static void NoteTid(ULONG_PTR Tid)
{
    ULONG Slot = (ULONG)((Tid / 4) % TID_SLOTS);

    if (s_TidSeen[Slot / 8] & (1 << (Slot % 8)))
        s_Reuses++;
    s_TidSeen[Slot / 8] |= 1 << (Slot % 8);
}

START_TEST(CsrAdoptedThreadChurn)
{
    FN_RtlCreateUserThread pRtlCreateUserThread;
    ULONG Handles0, Handles1, HandlesEnd, Peak = 0, N, i, n;
    SIZE_T Private0, Private1, PrivateEnd;
    WCHAR Env[32];
    HANDLE Threads[MAX_PARALLEL];
    CLIENT_ID Cid;
    NTSTATUS Status;
    DWORD Tick;

    HandlesEnd = 0;
    PrivateEnd = 0;

    pRtlCreateUserThread = (FN_RtlCreateUserThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
    if (!pRtlCreateUserThread)
    {
        skip("RtlCreateUserThread is not available\n");
        return;
    }

    N = 1500;
    if (GetEnvironmentVariableW(L"CSRCHURN_N", Env, RTL_NUMBER_OF(Env)) && _wtoi(Env) > 0)
        N = _wtoi(Env);

    if (GetEnvironmentVariableW(L"CSRCHURN_MASK", Env, RTL_NUMBER_OF(Env)))
        s_Mask = _wtoi(Env);

    /* Whether the impersonating request can be used here (it needs the right to define a DOS device) */
    s_DosProbe = (s_Mask & 4) && DefineDosDeviceW(0, L"Y:", L"C:\\");
    if (s_DosProbe)
        DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, L"Y:", L"C:\\");
    trace("DOS device probe: %d\n", s_DosProbe);

    if (!GetCsrssStats(&Handles0, &Private0))
    {
        skip("csrss.exe of this session is not in the process list\n");
        return;
    }

    /* One thread first, so that everything a first use allocates is already there */
    s_Done = 0;
    Status = pRtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (PVOID)UserThreadProc, NULL, &Threads[0], &Cid);
    ok_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status)) return;
    WaitForSingleObject(Threads[0], 30000);
    CloseHandle(Threads[0]);
    Sleep(1000);
    GetCsrssStats(&Handles0, &Private0);
    trace("csrss before: %lu handles, %Iu private bytes, N = %lu\n", Handles0, Private0, N);

    s_Failures = 0;
    s_Impersonation = 0;
    s_Reuses = 0;
    s_Done = 0;
    Tick = GetTickCount();
    for (i = 0; i < N;)
    {
        n = min(MAX_PARALLEL, N - i);
        for (ULONG j = 0; j < n; j++)
        {
            Status = pRtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (PVOID)UserThreadProc, NULL,
                                          &Threads[j], &Cid);
            if (!NT_SUCCESS(Status))
            {
                Threads[j] = NULL;
                InterlockedIncrement(&s_Failures);
            }
            else
            {
                NoteTid((ULONG_PTR)Cid.UniqueThread);
            }
        }
        for (ULONG j = 0; j < n; j++)
        {
            if (Threads[j])
            {
                WaitForSingleObject(Threads[j], 60000);
                CloseHandle(Threads[j]);
            }
        }
        i += n;
        if (i % 1000 < MAX_PARALLEL)
        {
            if (GetCsrssStats(&Handles1, &Private1) && Handles1 > Peak)
                Peak = Handles1;
        }
    }
    trace("%lu threads in %lu ms, TID reuses %ld, failures %ld (stale record %ld)\n",
          N, GetTickCount() - Tick, s_Reuses, s_Failures, s_Impersonation);
    ok_dec(s_Failures, 0);
    ok_dec(s_Impersonation, 0);
    ok(s_Reuses > 0, "no thread id was reused in %lu threads\n", N);

    /* Thread pool threads too (a few: the pool keeps its threads) */
    s_Done = 0;
    for (i = 0; i < min(N, 200); i++)
        QueueUserWorkItem(WorkItemProc, NULL, WT_EXECUTEDEFAULT);
    for (i = 0; i < 600 && s_Done < (LONG)min(N, 200); i++)
        Sleep(100);
    ok_dec(s_Done, (LONG)min(N, 200));
    ok_dec(s_Failures, 0);

    /* Many adopted threads alive at once (all thread ids differ), then all gone: the records must go with them */
    {
        ULONG K = min(N, 600), Made = 0, Waited;
        HANDLE *Hold = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, K * sizeof(HANDLE));

        s_Ready = 0;
        s_Gate = CreateEventW(NULL, TRUE, FALSE, NULL);
        for (i = 0; i < K; i++)
        {
            if (NT_SUCCESS(pRtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (PVOID)HoldThreadProc, NULL,
                                                &Hold[Made], &Cid)))
                Made++;
        }
        for (Waited = 0; Waited < 600 && s_Ready < (LONG)Made; Waited++)
            Sleep(100);
        ok_dec(s_Ready, (LONG)Made);
        if (GetCsrssStats(&Handles1, &Private1))
            trace("csrss with %lu adopted threads alive: %lu handles, %Iu private bytes\n", Made, Handles1, Private1);
        ok(Handles1 >= Handles0 + Made / 2, "csrss holds %lu handles with %lu adopted threads alive\n", Handles1, Made);
        SetEvent(s_Gate);
        for (i = 0; i < Made; i++)
        {
            WaitForSingleObject(Hold[i], 60000);
            CloseHandle(Hold[i]);
        }
        CloseHandle(s_Gate);
        HeapFree(GetProcessHeap(), 0, Hold);
    }

    /* The termination messages are handled by CSRSS asynchronously */
    for (i = 0; i < 40; i++)
    {
        if (!GetCsrssStats(&HandlesEnd, &PrivateEnd)) break;
        if (HandlesEnd <= Handles0 + 16) break;
        Sleep(500);
    }
    trace("csrss after: %lu handles (peak %lu), %Iu private bytes\n", HandlesEnd, Peak, PrivateEnd);
    ok(HandlesEnd <= Handles0 + 64, "csrss handles %lu -> %lu after %lu adopted threads\n", Handles0, HandlesEnd, N);
    ok(PrivateEnd <= Private0 + 2 * 1024 * 1024, "csrss private bytes %Iu -> %Iu\n", Private0, PrivateEnd);

    /* DefineDosDevice of a drive letter: CSRSS starts a thread to broadcast the change, its private bytes must stay flat (within 1.5 MB: the first broadcast thread allocates some once) */
    {
        SIZE_T Before = 0, After = 0;
        ULONG D = 12000, Pairs = 0;

        if (GetEnvironmentVariableW(L"CSRDDD_N", Env, RTL_NUMBER_OF(Env)) && _wtoi(Env) > 0)
            D = _wtoi(Env);

        if (!DefineDosDeviceW(0, L"Y:", L"C:\\"))
        {
            skip("DefineDosDevice is not allowed here (error %lu)\n", GetLastError());
            return;
        }
        DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, L"Y:", L"C:\\");
        Sleep(1000);
        if (!GetCsrssStats(&Handles1, &Before))
            return;
        Tick = GetTickCount();
        for (i = 0; i < D; i++)
        {
            if (!DefineDosDeviceW(0, L"Y:", L"C:\\"))
                break;
            if (!DefineDosDeviceW(DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, L"Y:", L"C:\\"))
                break;
            Pairs++;
        }
        ok(Pairs == D, "%lu of %lu define/remove pairs done (error %lu)\n", Pairs, D, GetLastError());
        for (i = 0; i < 20; i++)
        {
            Sleep(500);
            if (GetCsrssStats(&Handles1, &After) && After <= Before + 3 * 512 * 1024)
                break;
        }
        trace("%lu DefineDosDevice pairs in %lu ms: csrss private bytes %Iu -> %Iu\n", Pairs, GetTickCount() - Tick, Before, After);
        ok(After <= Before + 3 * 512 * 1024, "csrss private bytes %Iu -> %Iu after %lu DefineDosDevice pairs\n", Before, After, Pairs);
    }
}
