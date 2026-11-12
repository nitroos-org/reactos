/*
 * PROJECT:     ReactOS API tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Tests for NtCreateWaitCompletionPacket, NtAssociateWaitCompletionPacket and NtCancelWaitCompletionPacket
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 *
 * Measured on Windows 10 22H2 (19045), x64 and x86 (WOW64) with the same results:
 *  - Object type "WaitCompletionPacket": valid access 0x1F0001, generic mapping 0x20001 / 0x20001 / 0x20001 / 0xF0001,
 *    invalid attributes 0x110 (OBJ_PERMANENT, OBJ_OPENLINK); desired-access bits outside the mask are dropped
 *    (0 -> 0, 3 -> 1, 0x1F0003 -> 0x1F0001, MAXIMUM_ALLOWED and GENERIC_ALL -> 0xF0001). NULL or unwritable handle
 *    pointer: STATUS_ACCESS_VIOLATION.
 *  - Associate (packet handle needs access bit 1, port IO_COMPLETION_MODIFY_STATE, target SYNCHRONIZE; STATUS_ACCESS_DENIED
 *    otherwise, STATUS_OBJECT_TYPE_MISMATCH for a wrong type, STATUS_INVALID_HANDLE for NULL or a closed handle). Targets:
 *    events, semaphores, timers, threads, processes (also the pseudo handle), files; a mutant, a completion port or a
 *    wait completion packet is STATUS_INVALID_PARAMETER_3. A packet that is already associated (waiting, or queued and not
 *    yet removed) is STATUS_INVALID_PARAMETER_1.
 *  - A target already signalled: the wait is satisfied inside the call (an auto-reset event is reset, a semaphore count
 *    taken), one packet is queued, *AlreadySignaled = TRUE. Otherwise AlreadySignaled = FALSE and one packet is queued
 *    when the target is signalled; the packet carries the key, context, status and information of the call. A bad
 *    AlreadySignaled pointer is not an error.
 *  - Cancel: nothing associated (never, or the packet was removed) STATUS_CANCELLED; waiting STATUS_SUCCESS (no packet
 *    follows); queued: with RemoveSignaledPacket FALSE STATUS_PENDING and the packet stays, with TRUE STATUS_SUCCESS and the
 *    packet is gone.
 *  - Closing the last packet handle cancels a waiting association and removes a queued packet.
 */

#include "precomp.h"

typedef NTSTATUS (NTAPI *PFN_CREATE)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *PFN_ASSOC)(HANDLE, HANDLE, HANDLE, PVOID, PVOID, NTSTATUS, ULONG_PTR, PBOOLEAN);
typedef NTSTATUS (NTAPI *PFN_CANCEL)(HANDLE, BOOLEAN);

static PFN_CREATE pCreate;
static PFN_ASSOC pAssoc;
static PFN_CANCEL pCancel;
typedef NTSTATUS (NTAPI *PFN_CREATETIMER2)(PHANDLE, PVOID, POBJECT_ATTRIBUTES, ULONG, ACCESS_MASK);
typedef NTSTATUS (NTAPI *PFN_SETTIMER2)(HANDLE, PLARGE_INTEGER, PLARGE_INTEGER, PT2_SET_PARAMETERS);
static PFN_CREATETIMER2 pCreateTimer2;
static PFN_SETTIMER2 pSetTimer2;

#define TARGET_KEY      ((PVOID)(ULONG_PTR)0x11111111)
#define TARGET_CONTEXT  ((PVOID)(ULONG_PTR)0x22222222)
#define TARGET_INFO     ((ULONG_PTR)0x33333333)

static HANDLE MakePacket(void)
{
    HANDLE Handle = NULL;
    NTSTATUS Status = pCreate(&Handle, 0x1F0003, NULL);

    ok_hex(Status, STATUS_SUCCESS);
    return Handle;
}

static HANDLE MakePort(void)
{
    HANDLE Handle = NULL;
    NTSTATUS Status = NtCreateIoCompletion(&Handle, IO_COMPLETION_ALL_ACCESS, NULL, 0);

    ok_hex(Status, STATUS_SUCCESS);
    return Handle;
}

static HANDLE MakeEvent(EVENT_TYPE Type, BOOLEAN Signaled)
{
    HANDLE Handle = NULL;
    NTSTATUS Status = NtCreateEvent(&Handle, EVENT_ALL_ACCESS, NULL, Type, Signaled);

    ok_hex(Status, STATUS_SUCCESS);
    return Handle;
}

static ULONG Depth(HANDLE Port)
{
    IO_COMPLETION_BASIC_INFORMATION Info = { 0xDEAD };
    NTSTATUS Status = NtQueryIoCompletion(Port, IoCompletionBasicInformation, &Info, sizeof(Info), NULL);

    ok_hex(Status, STATUS_SUCCESS);
    return Info.Depth;
}

/* A packet is delivered by another thread: wait up to two seconds for the depth to be the expected one */
static ULONG WaitDepth(HANDLE Port, ULONG Expected)
{
    ULONG i, Current = Depth(Port);
    LARGE_INTEGER Delay;

    Delay.QuadPart = -10 * 1000 * 10;   /* 10 ms */
    for (i = 0; i < 200 && Current != Expected; i++)
    {
        NtDelayExecution(FALSE, &Delay);
        Current = Depth(Port);
    }
    return Current;
}

/* After a negative check: give a wrongly queued packet time to show up */
static ULONG SettleDepth(HANDLE Port)
{
    LARGE_INTEGER Delay;

    Delay.QuadPart = -10 * 1000 * 100;  /* 100 ms */
    NtDelayExecution(FALSE, &Delay);
    return Depth(Port);
}

static NTSTATUS Remove(HANDLE Port, PVOID *Key, PVOID *Context, PIO_STATUS_BLOCK Iosb)
{
    LARGE_INTEGER Timeout;

    Timeout.QuadPart = 0;
    return NtRemoveIoCompletion(Port, Key, Context, Iosb, &Timeout);
}

static void TestCreate(void)
{
    static const struct { ACCESS_MASK Desired, Granted; } Cases[] =
    {
        { 0, 0 }, { 1, 1 }, { 2, 0 }, { 3, 1 }, { 4, 0 }, { SYNCHRONIZE, SYNCHRONIZE }, { 0x1F0003, 0x1F0001 },
        { GENERIC_ALL, 0xF0001 }, { GENERIC_EXECUTE, 0x20001 }, { MAXIMUM_ALLOWED, 0xF0001 }
    };
    OBJECT_BASIC_INFORMATION Basic;
    BYTE Buffer[512];
    POBJECT_TYPE_INFORMATION Type = (POBJECT_TYPE_INFORMATION)Buffer;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE Handle = NULL;
    ULONG Length, i;
    NTSTATUS Status;

    for (i = 0; i < RTL_NUMBER_OF(Cases); i++)
    {
        Handle = NULL;
        Status = pCreate(&Handle, Cases[i].Desired, NULL);
        ok_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status)) continue;
        Status = NtQueryObject(Handle, ObjectBasicInformation, &Basic, sizeof(Basic), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok(Basic.GrantedAccess == Cases[i].Granted, "desired %lx: granted %lx, expected %lx\n",
           Cases[i].Desired, Basic.GrantedAccess, Cases[i].Granted);
        NtClose(Handle);
    }

    Handle = MakePacket();
    RtlZeroMemory(Buffer, sizeof(Buffer));
    Status = NtQueryObject(Handle, ObjectTypeInformation, Buffer, sizeof(Buffer), &Length);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        ok(Type->TypeName.Length == sizeof(L"WaitCompletionPacket") - sizeof(WCHAR) &&
           !_wcsnicmp(Type->TypeName.Buffer, L"WaitCompletionPacket", 20),
           "type name %.*ls\n", (int)(Type->TypeName.Length / sizeof(WCHAR)), Type->TypeName.Buffer);
        ok_hex(Type->ValidAccessMask, 0x1F0001);
        ok_hex(Type->GenericMapping.GenericRead, 0x20001);
        ok_hex(Type->GenericMapping.GenericWrite, 0x20001);
        ok_hex(Type->GenericMapping.GenericExecute, 0x20001);
        ok_hex(Type->GenericMapping.GenericAll, 0xF0001);
        ok_hex(Type->InvalidAttributes, 0x110);
    }
    NtClose(Handle);

    InitializeObjectAttributes(&Attributes, NULL, OBJ_INHERIT, NULL, NULL);
    Handle = NULL;
    Status = pCreate(&Handle, 0x1F0003, &Attributes);
    ok_hex(Status, STATUS_SUCCESS);
    if (NT_SUCCESS(Status))
    {
        OBJECT_HANDLE_FLAG_INFORMATION Flags = { 0xFF, 0xFF };

        Status = NtQueryObject(Handle, ObjectHandleFlagInformation, &Flags, sizeof(Flags), &Length);
        ok_hex(Status, STATUS_SUCCESS);
        ok_int(Flags.Inherit, 1);
        NtClose(Handle);
    }

    _SEH2_TRY
    {
        Status = pCreate(NULL, 0x1F0003, NULL);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;
    ok_hex(Status, STATUS_ACCESS_VIOLATION);

    Handle = (HANDLE)(ULONG_PTR)0x77;
    Status = pCreate(&Handle, 0x1F0003, (POBJECT_ATTRIBUTES)(ULONG_PTR)8);
    ok_hex(Status, STATUS_ACCESS_VIOLATION);
    ok(Handle == (HANDLE)(ULONG_PTR)0x77, "handle changed to %p\n", Handle);
}

static void TestLifecycle(void)
{
    HANDLE Packet = MakePacket(), Port = MakePort(), Event = MakeEvent(NotificationEvent, FALSE);
    PVOID Key, Context;
    IO_STATUS_BLOCK Iosb;
    BOOLEAN Already = 0xAA;
    NTSTATUS Status;

    /* Waiting, then signalled: one packet with the call's values */
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, (NTSTATUS)0x12345678, (ULONG_PTR)-2, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Already, 0);
    ok_dec(Depth(Port), 0);
    NtSetEvent(Event, NULL);
    ok_dec(WaitDepth(Port, 1), 1);
    Key = Context = (PVOID)(ULONG_PTR)0xAB;
    RtlFillMemory(&Iosb, sizeof(Iosb), 0xCC);
    Status = Remove(Port, &Key, &Context, &Iosb);
    ok_hex(Status, STATUS_SUCCESS);
    ok_ptr(Key, TARGET_KEY);
    ok_ptr(Context, TARGET_CONTEXT);
    ok_hex(Iosb.Status, 0x12345678);
    ok(Iosb.Information == (ULONG_PTR)-2, "information %lx\n", (ULONG)Iosb.Information);

    /* The manual-reset event is still set: no second packet without an association */
    ok_dec(SettleDepth(Port), 0);

    /* Associate with a signalled target: queued before the call returns */
    Already = 0xAA;
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Already, 1);
    ok_dec(Depth(Port), 1);

    /* Queued, not removed: associating again is refused, cancel without removal is too late, with removal it works */
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_INVALID_PARAMETER_1);
    Status = pCancel(Packet, FALSE);
    ok_hex(Status, STATUS_PENDING);
    ok_dec(Depth(Port), 1);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Depth(Port), 0);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_CANCELLED);

    /* Delivered and removed: nothing left to cancel */
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    Status = Remove(Port, &Key, &Context, &Iosb);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pCancel(Packet, FALSE);
    ok_hex(Status, STATUS_CANCELLED);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_CANCELLED);

    /* Waiting: a second association is refused, cancel succeeds and no packet follows */
    NtResetEvent(Event, NULL);
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_INVALID_PARAMETER_1);
    Status = pCancel(Packet, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pCancel(Packet, FALSE);
    ok_hex(Status, STATUS_CANCELLED);
    NtSetEvent(Event, NULL);
    ok_dec(SettleDepth(Port), 0);

    /* A packet that was never associated */
    NtClose(Packet);
    Packet = MakePacket();
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_CANCELLED);

    NtClose(Packet);
    NtClose(Port);
    NtClose(Event);
}

static void TestTargets(void)
{
    HANDLE Packet = MakePacket(), Port = MakePort(), Event, Semaphore, Timer, Other;
    PVOID Key, Context;
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Due;
    BOOLEAN Already;
    NTSTATUS Status;
    LARGE_INTEGER NoWait = { { 0 } };

    /* Auto-reset event, signalled: consumed by the association */
    Event = MakeEvent(SynchronizationEvent, TRUE);
    Already = 0xAA;
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Already, 1);
    ok_dec(Depth(Port), 1);
    Status = NtWaitForSingleObject(Event, FALSE, &NoWait);
    ok_hex(Status, STATUS_TIMEOUT);
    Status = Remove(Port, &Key, &Context, &Iosb);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Event);

    /* Auto-reset event, signalled later: consumed by the delivery */
    Event = MakeEvent(SynchronizationEvent, FALSE);
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    NtSetEvent(Event, NULL);
    ok_dec(WaitDepth(Port, 1), 1);
    Status = NtWaitForSingleObject(Event, FALSE, &NoWait);
    ok_hex(Status, STATUS_TIMEOUT);
    Status = Remove(Port, &Key, &Context, &Iosb);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Event);

    /* Semaphore with a count of 2: one unit is taken */
    Status = NtCreateSemaphore(&Semaphore, SEMAPHORE_ALL_ACCESS, NULL, 2, 5);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Packet, Port, Semaphore, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Already, 1);
    Status = NtWaitForSingleObject(Semaphore, FALSE, &NoWait);
    ok_hex(Status, STATUS_SUCCESS);
    Status = NtWaitForSingleObject(Semaphore, FALSE, &NoWait);
    ok_hex(Status, STATUS_TIMEOUT);
    Status = Remove(Port, &Key, &Context, &Iosb);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Semaphore);

    /* A timer, the way the Go runtime uses it: associate, then it expires */
    Status = NtCreateTimer(&Timer, TIMER_ALL_ACCESS, NULL, SynchronizationTimer);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Packet, Port, Timer, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Already, 0);
    Due.QuadPart = -10 * 1000 * 50; /* 50 ms */
    Status = NtSetTimer(Timer, &Due, NULL, NULL, FALSE, 0, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(WaitDepth(Port, 1), 1);
    Status = Remove(Port, &Key, &Context, &Iosb);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_CANCELLED);
    NtClose(Timer);

    /* A NtCreateTimer2 timer (type IRTimer): what the Go runtime's high-resolution timer is */
    if (pCreateTimer2 && pSetTimer2)
    {
        T2_SET_PARAMETERS Parameters = { 0 };

        Timer = NULL;
        Status = pCreateTimer2(&Timer, NULL, NULL, 0, TIMER_ALL_ACCESS);
        ok_hex(Status, STATUS_SUCCESS);
        if (NT_SUCCESS(Status))
        {
            Status = pAssoc(Packet, Port, Timer, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
            ok_hex(Status, STATUS_SUCCESS);
            ok_dec(Already, 0);
            Due.QuadPart = -10 * 1000 * 50;
            Status = pSetTimer2(Timer, &Due, NULL, &Parameters);
            ok_hex(Status, STATUS_SUCCESS);
            ok_dec(WaitDepth(Port, 1), 1);
            Status = Remove(Port, &Key, &Context, &Iosb);
            ok_hex(Status, STATUS_SUCCESS);
            NtClose(Timer);
        }
    }

    /* The current process (pseudo handle) is a valid target that is not signalled */
    Status = pAssoc(Packet, Port, NtCurrentProcess(), TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    ok_dec(Already, 0);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_SUCCESS);

    /* A mutant, a completion port and a wait completion packet are not accepted */
    Status = NtCreateMutant(&Other, MUTANT_ALL_ACCESS, NULL, FALSE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Packet, Port, Other, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_INVALID_PARAMETER_3);
    NtClose(Other);
    Status = pAssoc(Packet, Port, Port, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_INVALID_PARAMETER_3);
    Status = pAssoc(Packet, Port, Packet, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_INVALID_PARAMETER_3);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_CANCELLED);

    NtClose(Packet);
    NtClose(Port);
}

static void TestHandles(void)
{
    HANDLE Packet = MakePacket(), Port = MakePort(), Event = MakeEvent(NotificationEvent, TRUE), Dup;
    BOOLEAN Already;
    NTSTATUS Status;

    Status = pAssoc(NULL, Port, Event, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = pAssoc(Packet, NULL, Event, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = pAssoc(Packet, Port, NULL, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = pAssoc(Packet, Port, (HANDLE)(ULONG_PTR)0x1234, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = pAssoc(Event, Port, Event, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    Status = pAssoc(Packet, Event, Event, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);
    Status = pCancel(NULL, FALSE);
    ok_hex(Status, STATUS_INVALID_HANDLE);
    Status = pCancel(Event, FALSE);
    ok_hex(Status, STATUS_OBJECT_TYPE_MISMATCH);

    /* Access: packet bit 1, port modify state, target synchronize */
    Status = NtDuplicateObject(NtCurrentProcess(), Packet, NtCurrentProcess(), &Dup, 0, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Dup, Port, Event, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    Status = pCancel(Dup, TRUE);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    NtClose(Dup);
    Status = NtDuplicateObject(NtCurrentProcess(), Packet, NtCurrentProcess(), &Dup, 1, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Dup, Port, Event, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pCancel(Dup, TRUE);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Dup);
    Status = NtDuplicateObject(NtCurrentProcess(), Port, NtCurrentProcess(), &Dup, IO_COMPLETION_QUERY_STATE, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Packet, Dup, Event, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    NtClose(Dup);
    Status = NtDuplicateObject(NtCurrentProcess(), Event, NtCurrentProcess(), &Dup, EVENT_ALL_ACCESS & ~SYNCHRONIZE, 0, 0);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Packet, Port, Dup, NULL, NULL, 0, 0, &Already);
    ok_hex(Status, STATUS_ACCESS_DENIED);
    NtClose(Dup);

    /* A bad AlreadySignaled pointer is not an error */
    Status = pAssoc(Packet, Port, Event, NULL, NULL, 0, 0, (PBOOLEAN)(ULONG_PTR)8);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pAssoc(Packet, Port, Event, NULL, NULL, 0, 0, NULL);
    ok_hex(Status, STATUS_SUCCESS);
    Status = pCancel(Packet, TRUE);
    ok_hex(Status, STATUS_SUCCESS);

    NtClose(Packet);
    NtClose(Port);
    NtClose(Event);
}

static void TestClose(void)
{
    HANDLE Packet, Port = MakePort(), Event = MakeEvent(NotificationEvent, FALSE);
    PVOID Key, Context;
    IO_STATUS_BLOCK Iosb;
    BOOLEAN Already;
    NTSTATUS Status;

    /* Closing the handle of a waiting packet cancels it */
    Packet = MakePacket();
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Packet);
    NtSetEvent(Event, NULL);
    ok_dec(SettleDepth(Port), 0);
    NtResetEvent(Event, NULL);

    /* Closing the handle of a queued packet removes it */
    Packet = MakePacket();
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    NtSetEvent(Event, NULL);
    ok_dec(WaitDepth(Port, 1), 1);
    NtClose(Packet);
    ok_dec(Depth(Port), 0);
    Status = Remove(Port, &Key, &Context, &Iosb);
    ok_hex(Status, STATUS_TIMEOUT);
    NtResetEvent(Event, NULL);

    /* Two packets on one manual-reset event: both are delivered; on an auto-reset event one per signal */
    {
        HANDLE Packet2 = MakePacket(), Auto = MakeEvent(SynchronizationEvent, FALSE);

        Packet = MakePacket();
        pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        pAssoc(Packet2, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        NtSetEvent(Event, NULL);
        ok_dec(WaitDepth(Port, 2), 2);
        NtClose(Packet);
        NtClose(Packet2);
        ok_dec(Depth(Port), 0);

        Packet = MakePacket();
        Packet2 = MakePacket();
        pAssoc(Packet, Port, Auto, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        pAssoc(Packet2, Port, Auto, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        NtSetEvent(Auto, NULL);
        ok_dec(WaitDepth(Port, 1), 1);
        ok_dec(SettleDepth(Port), 1);
        NtSetEvent(Auto, NULL);
        ok_dec(WaitDepth(Port, 2), 2);
        NtClose(Packet);
        NtClose(Packet2);
        NtClose(Auto);
    }

    NtClose(Port);
    NtClose(Event);
}

/* Number of threads of the System process (PID 4), or 0 */
static ULONG SystemThreadCount(void)
{
    ULONG Size = 0x40000, Count = 0;
    PBYTE Buffer;
    NTSTATUS Status;

    for (;;)
    {
        Buffer = RtlAllocateHeap(RtlGetProcessHeap(), 0, Size);
        if (!Buffer) return 0;
        Status = NtQuerySystemInformation(SystemProcessInformation, Buffer, Size, NULL);
        if (Status != STATUS_INFO_LENGTH_MISMATCH) break;
        RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
        Size *= 2;
    }
    if (NT_SUCCESS(Status))
    {
        PSYSTEM_PROCESS_INFORMATION Info = (PSYSTEM_PROCESS_INFORMATION)Buffer;

        for (;;)
        {
            if (Info->UniqueProcessId == (HANDLE)(ULONG_PTR)4) Count = Info->NumberOfThreads;
            if (!Info->NextEntryOffset) break;
            Info = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)Info + Info->NextEntryOffset);
        }
    }
    RtlFreeHeap(RtlGetProcessHeap(), 0, Buffer);
    return Count;
}

/* Many associated packets, closed with their association pending or queued: no kernel thread stays behind */
static void TestNoLeak(void)
{
    enum { COUNT = 64 };
    HANDLE Port = MakePort(), Event = MakeEvent(NotificationEvent, FALSE), Packets[COUNT];
    LARGE_INTEGER Delay;
    ULONG Before, After, i;
    BOOLEAN Already;
    NTSTATUS Status;

    Before = SystemThreadCount();
    for (i = 0; i < COUNT; i++)
    {
        Packets[i] = MakePacket();
        Status = pAssoc(Packets[i], Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        ok_hex(Status, STATUS_SUCCESS);
    }
    for (i = 0; i < COUNT; i++)
    {
        if (i == COUNT / 2) NtSetEvent(Event, NULL);    /* the remaining ones are queued by now or waiting */
        NtClose(Packets[i]);
    }
    NtClose(Port);
    NtClose(Event);
    Delay.QuadPart = -10 * 1000 * 500;
    NtDelayExecution(FALSE, &Delay);
    After = SystemThreadCount();
    ok(After <= Before + 1, "System threads before %lu, after %lu\n", Before, After);
}

/*
 * Every associated packet costs a kernel thread, which is charged to the process quota and capped system-wide
 * (ReactOS only): associate packets until a resource failure or a bound, check the failure is a clean status, and
 * that closing them all gives everything back (System thread count, and a packet can be associated again).
 */
static void TestResources(void)
{
    enum { BOUND = 4300 };
    HANDLE Port = MakePort(), Event = MakeEvent(NotificationEvent, FALSE), Check;
    HANDLE *Packets = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BOUND * sizeof(HANDLE));
    ULONG Before, Peak, After, Count = 0, i;
    LARGE_INTEGER Delay;
    BOOLEAN Already;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!Packets)
    {
        skip("no memory for the packet handles\n");
        return;
    }
    Before = SystemThreadCount();
    for (i = 0; i < BOUND; i++)
    {
        Status = pCreate(&Packets[i], 0x1F0003, NULL);
        if (!NT_SUCCESS(Status)) break;
        Status = pAssoc(Packets[i], Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        if (!NT_SUCCESS(Status)) break;
        Count++;
    }
    Peak = SystemThreadCount();
    ok(Count == BOUND || Status == STATUS_INSUFFICIENT_RESOURCES || Status == STATUS_QUOTA_EXCEEDED ||
       Status == STATUS_NO_MEMORY, "stopped after %lu packets with %08lx\n", Count, Status);
    trace("%lu packets associated, last status %08lx, System threads %lu -> %lu\n", Count, Status, Before, Peak);

    /* The system is fine while they exist */
    Check = MakeEvent(NotificationEvent, TRUE);
    ok(Check != NULL, "cannot create an event\n");
    NtClose(Check);

    for (i = 0; i < BOUND; i++)
        if (Packets[i]) NtClose(Packets[i]);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Packets);
    Delay.QuadPart = -10 * 1000 * 1000;
    NtDelayExecution(FALSE, &Delay);
    After = SystemThreadCount();
    ok(After <= Before + 1, "System threads before %lu, after closing %lu\n", Before, After);

    /* Released: a new packet can be associated */
    Check = MakePacket();
    Status = pAssoc(Check, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    ok_hex(Status, STATUS_SUCCESS);
    NtClose(Check);
    NtClose(Port);
    NtClose(Event);
}

typedef struct _RACE
{
    HANDLE Port;
    volatile LONG Stop;
} RACE;

static DWORD WINAPI RaceConsumer(LPVOID Parameter)
{
    RACE *Race = Parameter;
    PVOID Key, Context;
    IO_STATUS_BLOCK Iosb;

    while (!Race->Stop)
        Remove(Race->Port, &Key, &Context, &Iosb);
    return 0;
}

/*
 * What the Go runtime does around every idle poll: cancel the packet (removing a queued one), and associate it again
 * unless the cancel said it was too late (STATUS_PENDING). Meanwhile another thread takes packets out of the port, so
 * a cancel can meet a packet that was just removed: it must answer STATUS_PENDING or have the packet idle.
 */
static void TestRace(void)
{
    RACE Race;
    HANDLE Packet = MakePacket(), Event = MakeEvent(NotificationEvent, TRUE), Thread;
    ULONG i, Pending = 0, Bad = 0;
    BOOLEAN Already;
    NTSTATUS Status;

    Race.Port = MakePort();
    Race.Stop = 0;
    Thread = CreateThread(NULL, 0, RaceConsumer, &Race, 0, NULL);
    ok(Thread != NULL, "CreateThread failed\n");
    for (i = 0; i < 100000; i++)
    {
        Status = pCancel(Packet, TRUE);
        if (Status == STATUS_PENDING)
        {
            Pending++;
            continue;
        }
        if (Status != STATUS_SUCCESS && Status != STATUS_CANCELLED)
        {
            Bad++;
            continue;
        }
        /* The event is set: this queues the packet before the call returns */
        Status = pAssoc(Packet, Race.Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        if (Status != STATUS_SUCCESS)
            Bad++;
    }
    Race.Stop = 1;
    WaitForSingleObject(Thread, INFINITE);
    CloseHandle(Thread);
    ok(Bad == 0, "%lu unexpected statuses (%lu pending)\n", Bad, Pending);
    NtClose(Packet);
    NtClose(Race.Port);
    NtClose(Event);
}

START_TEST(NtWaitCompletionPacket)
{
    HMODULE Ntdll = GetModuleHandleW(L"ntdll.dll");

    pCreate = (PFN_CREATE)GetProcAddress(Ntdll, "NtCreateWaitCompletionPacket");
    pAssoc = (PFN_ASSOC)GetProcAddress(Ntdll, "NtAssociateWaitCompletionPacket");
    pCancel = (PFN_CANCEL)GetProcAddress(Ntdll, "NtCancelWaitCompletionPacket");
    pCreateTimer2 = (PFN_CREATETIMER2)GetProcAddress(Ntdll, "NtCreateTimer2");
    pSetTimer2 = (PFN_SETTIMER2)GetProcAddress(Ntdll, "NtSetTimer2");
    if (!pCreate || !pAssoc || !pCancel)
    {
        skip("Wait completion packets are not available\n");
        return;
    }

    TestCreate();
    TestLifecycle();
    TestTargets();
    TestHandles();
    TestClose();
    TestNoLeak();
    TestRace();
    TestResources();
}
