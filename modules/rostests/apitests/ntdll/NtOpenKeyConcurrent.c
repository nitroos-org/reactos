/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Concurrent registry key lookups through the KCB cache must not deadlock
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include "precomp.h"
#include <stdlib.h>

/*
 * Many threads open, query, enumerate and close the same deep key paths at
 * once, mixed with opens of children that do not exist. A cached key with no
 * open handles (in the delayed close table) needs its KCB hash lock held
 * exclusively to be referenced, while a lookup holds the sorted array of the
 * path's hash locks shared; lookups of uncached names lock that array
 * exclusively. Before the fix the kernel converted one lock of a shared array
 * out of order and the threads deadlocked on the KCB push locks, freezing the
 * registry for the whole system.
 *
 * CMKCB_STRESS_SECONDS in the environment sets the run time (default 20).
 */

#define ROOT_NAME       L"Software\\NitroCmKcbStress"
#define BRANCHES        16
#define LEAVES          8
#define CHAIN           L"\\Lv1\\Lv2\\Lv3\\Lv4\\Lv5"
#define MAX_WORKERS     32
#define STALL_SECONDS   30

static HANDLE UserRoot;
static volatile LONG Stop;
static volatile LONG Round;
static volatile LONG Progress[MAX_WORKERS];
static volatile LONG Failures;

static
NTSTATUS
OpenRel(HANDLE Root, PCWSTR Name, ACCESS_MASK Access, PHANDLE Key)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING String;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&Attributes, &String, OBJ_CASE_INSENSITIVE, Root, NULL);
    return NtOpenKey(Key, Access, &Attributes);
}

static
NTSTATUS
CreateRel(HANDLE Root, PCWSTR Name, PHANDLE Key)
{
    OBJECT_ATTRIBUTES Attributes;
    UNICODE_STRING String;

    RtlInitUnicodeString(&String, Name);
    InitializeObjectAttributes(&Attributes, &String, OBJ_CASE_INSENSITIVE, Root, NULL);
    return NtCreateKey(Key, KEY_ALL_ACCESS, &Attributes, 0, NULL, REG_OPTION_VOLATILE, NULL);
}

/* Path of branch B down to level Depth (0 = branch key, 5 = Lv5, 6 = leaf L) */
static
VOID
BuildPath(PWSTR Buffer, SIZE_T Count, ULONG Branch, ULONG Depth, ULONG Leaf, PCWSTR Suffix)
{
    static const PCWSTR Levels[] = { L"", L"\\Lv1", L"\\Lv1\\Lv2", L"\\Lv1\\Lv2\\Lv3",
                                     L"\\Lv1\\Lv2\\Lv3\\Lv4", CHAIN };
    if (Depth > 5)
        StringCchPrintfW(Buffer, Count, ROOT_NAME L"\\Branch%02lu" CHAIN L"\\Leaf%lu%s",
                         Branch, Leaf, Suffix);
    else
        StringCchPrintfW(Buffer, Count, ROOT_NAME L"\\Branch%02lu%s%s",
                         Branch, Levels[Depth], Suffix);
}

static
BOOLEAN
CreateTree(VOID)
{
    WCHAR Path[256];
    HANDLE Key;
    NTSTATUS Status;
    ULONG b, d, l;

    Status = CreateRel(UserRoot, ROOT_NAME, &Key);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return FALSE;
    NtClose(Key);

    for (b = 0; b < BRANCHES; b++)
    {
        for (d = 0; d <= 5 + 1; d++)
        {
            for (l = 0; l < (d > 5 ? LEAVES : 1); l++)
            {
                BuildPath(Path, _countof(Path), b, d, l, L"");
                Status = CreateRel(UserRoot, Path, &Key);
                if (!NT_SUCCESS(Status))
                {
                    ok(FALSE, "NtCreateKey(%ls) failed: 0x%lx\n", Path, Status);
                    return FALSE;
                }
                NtClose(Key);
            }
        }
    }
    return TRUE;
}

static
VOID
DeleteTree(VOID)
{
    WCHAR Path[256];
    HANDLE Key;
    LONG b, d, l;

    for (b = 0; b < BRANCHES; b++)
    {
        for (d = 5 + 1; d >= 0; d--)
        {
            for (l = 0; l < (d > 5 ? LEAVES : 1); l++)
            {
                BuildPath(Path, _countof(Path), b, d, l, L"");
                if (NT_SUCCESS(OpenRel(UserRoot, Path, DELETE, &Key)))
                {
                    NtDeleteKey(Key);
                    NtClose(Key);
                }
            }
        }
    }
    if (NT_SUCCESS(OpenRel(UserRoot, ROOT_NAME, DELETE, &Key)))
    {
        NtDeleteKey(Key);
        NtClose(Key);
    }
}

static
ULONG
NextRandom(PULONG State)
{
    ULONG x = *State;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return *State = x;
}

static
DWORD
WINAPI
Worker(PVOID Parameter)
{
    ULONG Index = (ULONG)(ULONG_PTR)Parameter;
    ULONG Seed = 0x9E3779B9u * (Index + 1);
    WCHAR Path[256];
    UCHAR Buffer[512];
    ULONG Length, r, Branch, Depth;
    HANDLE Key, Sub;
    NTSTATUS Status;

    while (!Stop)
    {
        r = NextRandom(&Seed);
        /* Four branches per round, so the threads keep meeting on the same KCBs */
        Branch = (r >> 8) % 4 + (Round % (BRANCHES / 4)) * 4;

        switch (r % 10)
        {
            case 0: case 1: case 2: case 3: case 4:
                /* Deep existing key: query and close */
                BuildPath(Path, _countof(Path), Branch, 6, (r >> 4) % LEAVES, L"");
                Status = OpenRel(UserRoot, Path, KEY_READ, &Key);
                if (NT_SUCCESS(Status))
                {
                    NtQueryKey(Key, KeyBasicInformation, Buffer, sizeof(Buffer), &Length);
                    NtClose(Key);
                }
                else
                {
                    InterlockedIncrement(&Failures);
                }
                break;

            case 5: case 6:
                /* Intermediate level: enumerate and close */
                Depth = (r >> 4) % 6;
                BuildPath(Path, _countof(Path), Branch, Depth, 0, L"");
                Status = OpenRel(UserRoot, Path, KEY_READ, &Key);
                if (NT_SUCCESS(Status))
                {
                    NtEnumerateKey(Key, 0, KeyBasicInformation, Buffer, sizeof(Buffer), &Length);
                    NtClose(Key);
                }
                else
                {
                    InterlockedIncrement(&Failures);
                }
                break;

            case 7: case 8:
                /* Missing child of a deep key: always a partial cache match */
                Depth = 3 + (r >> 4) % 4;
                BuildPath(Path, _countof(Path), Branch, Depth, (r >> 7) % LEAVES, L"\\Missing");
                Status = OpenRel(UserRoot, Path, KEY_READ, &Key);
                if (NT_SUCCESS(Status))
                {
                    NtClose(Key);
                    InterlockedIncrement(&Failures);
                }
                break;

            default:
                /* Relative open from a mid-level handle */
                BuildPath(Path, _countof(Path), Branch, 2, 0, L"");
                Status = OpenRel(UserRoot, Path, KEY_READ, &Key);
                if (NT_SUCCESS(Status))
                {
                    StringCchPrintfW(Path, _countof(Path), L"Lv3\\Lv4\\Lv5\\Leaf%lu", (r >> 4) % LEAVES);
                    if (NT_SUCCESS(OpenRel(Key, Path, KEY_READ, &Sub)))
                        NtClose(Sub);
                    else
                        InterlockedIncrement(&Failures);
                    NtClose(Key);
                }
                else
                {
                    InterlockedIncrement(&Failures);
                }
                break;
        }

        InterlockedIncrement(&Progress[Index]);
    }
    return 0;
}

static
ULONG
GetSeconds(VOID)
{
    WCHAR Value[16];
    ULONG Seconds;

    if (!GetEnvironmentVariableW(L"CMKCB_STRESS_SECONDS", Value, _countof(Value)))
        return 20;
    Seconds = wcstoul(Value, NULL, 10);
    return Seconds ? Seconds : 20;
}

static
LONGLONG
TotalProgress(ULONG Workers)
{
    LONGLONG Total = 0;
    ULONG i;

    for (i = 0; i < Workers; i++)
        Total += Progress[i];
    return Total;
}

START_TEST(NtOpenKeyConcurrent)
{
    HANDLE Threads[MAX_WORKERS];
    SYSTEM_INFO Info;
    ULONG Workers, i, Seconds, Elapsed, Stalled;
    LONGLONG Last, Now;
    NTSTATUS Status;

    Status = RtlOpenCurrentUser(KEY_ALL_ACCESS, &UserRoot);
    ok_ntstatus(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return;

    DeleteTree();
    if (!CreateTree())
    {
        DeleteTree();
        NtClose(UserRoot);
        return;
    }

    GetSystemInfo(&Info);
    Workers = 2 * Info.dwNumberOfProcessors;
    if (Workers < 8)
        Workers = 8;
    if (Workers > MAX_WORKERS)
        Workers = MAX_WORKERS;
    Seconds = GetSeconds();

    for (i = 0; i < Workers; i++)
    {
        Threads[i] = CreateThread(NULL, 0, Worker, (PVOID)(ULONG_PTR)i, 0, NULL);
        ok(Threads[i] != NULL, "CreateThread failed: %lu\n", GetLastError());
        if (!Threads[i])
        {
            Workers = i;
            break;
        }
    }

    /* Watchdog: the lookups never block for long, a stall means a deadlock */
    Last = 0;
    Stalled = 0;
    for (Elapsed = 0; Elapsed < Seconds; Elapsed++)
    {
        Sleep(1000);
        InterlockedIncrement(&Round);
        Now = TotalProgress(Workers);
        if (Now == Last)
        {
            if (++Stalled >= STALL_SECONDS)
                break;
        }
        else
        {
            Stalled = 0;
        }
        Last = Now;
        if (Elapsed % 60 == 59)
        {
            trace("%lu s: %I64d operations\n", Elapsed + 1, Now);
            fflush(stdout);
        }
    }

    if (Stalled >= STALL_SECONDS)
    {
        /* The workers are stuck in the kernel; joining or exiting would hang */
        ok(FALSE, "NtOpenKeyConcurrent: no progress for %u s after %I64d operations: "
                  "KCB lock deadlock\n", STALL_SECONDS, Last);
        printf("CMKCB-STRESS: HANG\n");
        fflush(stdout);
        fflush(stderr);
        Sleep(INFINITE);
    }

    Stop = TRUE;
    ok(WaitForMultipleObjects(Workers, Threads, TRUE, 60 * 1000) == WAIT_OBJECT_0,
       "Workers did not finish\n");
    for (i = 0; i < Workers; i++)
        CloseHandle(Threads[i]);

    Now = TotalProgress(Workers);
    ok(Now > 0, "No operations done\n");
    ok(Failures == 0, "%ld lookups failed\n", Failures);
    trace("%lu workers, %lu s, %I64d operations\n", Workers, Elapsed, Now);
    printf("CMKCB-STRESS: OK %I64d\n", Now);

    DeleteTree();
    NtClose(UserRoot);
}
