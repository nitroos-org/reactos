/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     NtQueryOpenSubKeys and NtQueryOpenSubKeysEx must not put a handle in the
 *              handle table of the caller while they work: another thread of the process
 *              that closes handle values at the same time must neither change the result
 *              nor lose a handle of its own.
 */

#include "precomp.h"

#define CANARIES        24
#define ITERATIONS      3000
#define MAX_TICKS       15000

static HANDLE g_Events[CANARIES];
static BOOLEAN g_Keep[CANARIES];
static ULONG g_Lo, g_Hi;
static ULONG_PTR g_ThreadHandle;   /* the handle of the sweeping thread, which is not swept */
static volatile LONG g_Go;
static volatile LONG g_Done;
static volatile LONG g_Hits;       /* handle values the sweeping thread could close */
static volatile LONG g_Stolen;     /* handles of the sweeping thread that were closed under it */

/* Handles that were open before the window was made, and that lie in it: never swept */
static BOOLEAN g_Protect[1024];

static BOOLEAN IsKept(ULONG_PTR Value)
{
    ULONG i;
    if (Value == g_ThreadHandle)
        return TRUE;
    if (Value >= g_Lo && (Value - g_Lo) / sizeof(ULONG) < RTL_NUMBER_OF(g_Protect) &&
        g_Protect[(Value - g_Lo) / sizeof(ULONG)])
        return TRUE;
    for (i = 0; i < CANARIES; i++)
        if (g_Keep[i] && (ULONG_PTR)g_Events[i] == Value)
            return TRUE;
    return FALSE;
}

static DWORD WINAPI SweepThread(PVOID Context)
{
    OBJECT_ATTRIBUTES Attributes;
    OBJECT_BASIC_INFORMATION Basic;
    HANDLE Mine;
    ULONG_PTR Value;
    ULONG Spin;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);

    /* The window of handle values is only known when the main thread has made it */
    while (!g_Go)
        Sleep(1);

    while (!g_Done)
    {
        /* Close every value of the window that is not the main thread's */
        for (Value = g_Lo; Value <= g_Hi; Value += sizeof(ULONG))
        {
            if (IsKept(Value))
                continue;
            if (NT_SUCCESS(NtClose((HANDLE)Value)))
                InterlockedIncrement(&g_Hits);
        }

        /* A handle of this thread takes a free slot; it must stay valid while it is held */
        Status = NtCreateEvent(&Mine, EVENT_ALL_ACCESS, &Attributes, NotificationEvent, FALSE);
        if (!NT_SUCCESS(Status))
            continue;
        for (Spin = 0; Spin < 200; Spin++)
            YieldProcessor();
        Status = NtQueryObject(Mine, ObjectBasicInformation, &Basic, sizeof(Basic), NULL);
        if (!NT_SUCCESS(Status))
            InterlockedIncrement(&g_Stolen);
        else
            NtClose(Mine);
    }
    return 0;
}

static void CreateCanaries(void)
{
    OBJECT_ATTRIBUTES Attributes;
    ULONG i;
    ULONG_PTR Value;
    NTSTATUS Status;

    InitializeObjectAttributes(&Attributes, NULL, 0, NULL, NULL);
    g_Lo = (ULONG)-1;
    g_Hi = 0;
    for (i = 0; i < CANARIES; i++)
    {
        Status = NtCreateEvent(&g_Events[i], EVENT_ALL_ACCESS, &Attributes, NotificationEvent, FALSE);
        ok_ntstatus(Status, STATUS_SUCCESS);
        if ((ULONG_PTR)g_Events[i] < g_Lo) g_Lo = (ULONG)(ULONG_PTR)g_Events[i];
        if ((ULONG_PTR)g_Events[i] > g_Hi) g_Hi = (ULONG)(ULONG_PTR)g_Events[i];
    }

    /* Every third handle goes back: these free slots are where a temporary handle lands */
    for (i = 0; i < CANARIES; i++)
    {
        g_Keep[i] = (i % 3) != 1;
        if (!g_Keep[i])
            NtClose(g_Events[i]);
    }

    /* What is open in the window now, besides the kept handles, was open before */
    RtlZeroMemory(g_Protect, sizeof(g_Protect));
    for (Value = g_Lo; Value <= g_Hi; Value += sizeof(ULONG))
    {
        OBJECT_BASIC_INFORMATION Basic;

        if ((Value - g_Lo) / sizeof(ULONG) >= RTL_NUMBER_OF(g_Protect))
            break;
        if (NT_SUCCESS(NtQueryObject((HANDLE)Value, ObjectBasicInformation, &Basic, sizeof(Basic), NULL)))
            g_Protect[(Value - g_Lo) / sizeof(ULONG)] = TRUE;
    }
}

static void CheckCanaries(void)
{
    OBJECT_BASIC_INFORMATION Basic;
    ULONG i;
    NTSTATUS Status;

    for (i = 0; i < CANARIES; i++)
    {
        if (!g_Keep[i])
            continue;
        Status = NtQueryObject(g_Events[i], ObjectBasicInformation, &Basic, sizeof(Basic), NULL);
        ok(NT_SUCCESS(Status), "handle %p of the test is gone, 0x%lx\n", g_Events[i], Status);
        NtClose(g_Events[i]);
    }
}

typedef NTSTATUS (*SERVICE_CALL)(POBJECT_ATTRIBUTES Attributes);

static NTSTATUS CallQueryOpenSubKeys(POBJECT_ATTRIBUTES Attributes)
{
    ULONG Count = 0;
    return NtQueryOpenSubKeys(Attributes, &Count);
}

static NTSTATUS CallQueryOpenSubKeysEx(POBJECT_ATTRIBUTES Attributes)
{
    static UCHAR Buffer[0x10000];
    ULONG Required = 0;
    return NtQueryOpenSubKeysEx(Attributes, sizeof(Buffer), Buffer, &Required);
}

static void RunRace(const char *Name, SERVICE_CALL Call)
{
    UNICODE_STRING Key = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE");
    OBJECT_ATTRIBUTES Attributes;
    NTSTATUS Expected, Status;
    HANDLE Thread;
    ULONG i, Failures = 0;
    ULONG Start;

    InitializeObjectAttributes(&Attributes, &Key, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Expected = Call(&Attributes);
    ok(NT_SUCCESS(Expected) || Expected == STATUS_BUFFER_OVERFLOW || Expected == STATUS_BUFFER_TOO_SMALL,
       "%s: baseline status 0x%lx\n", Name, Expected);

    /* The thread, with its handle, comes first: its handle must lie below the window */
    g_Go = 0;
    g_Done = 0;
    g_Hits = 0;
    g_Stolen = 0;
    Thread = CreateThread(NULL, 0, SweepThread, NULL, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    if (!Thread)
        return;
    g_ThreadHandle = (ULONG_PTR)Thread;
    CreateCanaries();
    g_Go = 1;

    Start = GetTickCount();
    for (i = 0; i < ITERATIONS && GetTickCount() - Start < MAX_TICKS; i++)
    {
        Status = Call(&Attributes);
        if (Status != Expected)
            Failures++;
    }
    g_Done = 1;
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);

    trace("%s: %lu calls, %lu changed results, %ld closed temporary handles, %ld stolen handles\n",
          Name, i, Failures, g_Hits, g_Stolen);
    ok(Failures == 0, "%s: %lu results changed\n", Name, Failures);
    ok(g_Hits == 0, "%s: a handle of the service was closed by another thread %ld times\n", Name, g_Hits);
    ok(g_Stolen == 0, "%s: a handle of another thread was closed %ld times\n", Name, g_Stolen);
    CheckCanaries();
}

START_TEST(NtOpenSubKeysRace)
{
    BOOLEAN Old;

    RunRace("NtQueryOpenSubKeys", CallQueryOpenSubKeys);

    if (!NT_SUCCESS(RtlAdjustPrivilege(SE_RESTORE_PRIVILEGE, TRUE, FALSE, &Old)))
    {
        skip("The token has no SeRestorePrivilege\n");
        return;
    }
    RunRace("NtQueryOpenSubKeysEx", CallQueryOpenSubKeysEx);
}
