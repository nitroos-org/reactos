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
 *  - Signalling (x64): a packet fires like a WaitAny waiter in line with the threads waiting on the object (first come,
 *    first served) and takes the object as that wait would: one packet per set of an auto-reset event, one per
 *    semaphore count, all of them (and the event stays set) for a manual-reset event; NtPulseEvent and
 *    NtSetEventBoostPriority fire them too, a synchronization timer is reset by the packet it fires; a cancelled
 *    packet takes nothing. 20000 packets associated in one process, each with its own event, with no failure.
 */

#include "precomp.h"
#include <strsafe.h>

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


static LONG EventState(HANDLE Event)
{
    EVENT_BASIC_INFORMATION Info = { 0, -1 };
    NTSTATUS Status = NtQueryEvent(Event, EventBasicInformation, &Info, sizeof(Info), NULL);

    ok_hex(Status, STATUS_SUCCESS);
    return Info.EventState;
}

static LONG SemaphoreCount(HANDLE Semaphore)
{
    SEMAPHORE_BASIC_INFORMATION Info = { -1, -1 };
    NTSTATUS Status = NtQuerySemaphore(Semaphore, SemaphoreBasicInformation, &Info, sizeof(Info), NULL);

    ok_hex(Status, STATUS_SUCCESS);
    return Info.CurrentCount;
}

static ULONG PointerCount(HANDLE Handle)
{
    OBJECT_BASIC_INFORMATION Info;
    NTSTATUS Status;

    RtlZeroMemory(&Info, sizeof(Info));
    Status = NtQueryObject(Handle, ObjectBasicInformation, &Info, sizeof(Info), NULL);
    ok_hex(Status, STATUS_SUCCESS);
    return Info.PointerCount;
}

/* Takes every queued packet out of the port; how many */
static ULONG Drain(HANDLE Port)
{
    PVOID Key, Context;
    IO_STATUS_BLOCK Iosb;
    ULONG Count = 0;

    while (Remove(Port, &Key, &Context, &Iosb) == STATUS_SUCCESS) Count++;
    return Count;
}

static NTSTATUS Associate(HANDLE Packet, HANDLE Port, HANDLE Target, PBOOLEAN Already)
{
    return pAssoc(Packet, Port, Target, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, Already);
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
        ok(Flags.Inherit != 0, "OBJ_INHERIT not applied\n");
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

/*
 * The target is consumed exactly once per packet that fires, as by a satisfied wait, and never for a cancelled one.
 * Measured on Windows 10 22H2 (19045, x64) with the same sequence.
 */
static void TestConsumption(void)
{
    HANDLE Port = MakePort(), Packets[4], Event, Semaphore, Timer;
    LARGE_INTEGER Due;
    BOOLEAN Already;
    NTSTATUS Status;
    ULONG i;

    for (i = 0; i < 4; i++) Packets[i] = MakePacket();

    /* Auto-reset event, three packets: one per set */
    Event = MakeEvent(SynchronizationEvent, FALSE);
    for (i = 0; i < 3; i++)
    {
        Already = 0xCC;
        ok_hex(Associate(Packets[i], Port, Event, &Already), STATUS_SUCCESS);
        ok_int(Already, FALSE);
    }
    NtSetEvent(Event, NULL);
    ok_int(SettleDepth(Port), 1);
    ok_long(EventState(Event), 0);
    NtSetEvent(Event, NULL);
    NtSetEvent(Event, NULL);
    ok_int(WaitDepth(Port, 3), 3);
    NtSetEvent(Event, NULL);
    ok_int(SettleDepth(Port), 3);
    ok_long(EventState(Event), 1);
    ok_int(Drain(Port), 3);
    NtClose(Event);

    /* Semaphore: one count per packet, the rest stays */
    Status = NtCreateSemaphore(&Semaphore, SEMAPHORE_ALL_ACCESS, NULL, 0, 100);
    ok_hex(Status, STATUS_SUCCESS);
    for (i = 0; i < 3; i++) ok_hex(Associate(Packets[i], Port, Semaphore, &Already), STATUS_SUCCESS);
    NtReleaseSemaphore(Semaphore, 2, NULL);
    ok_int(WaitDepth(Port, 2), 2);
    ok_long(SemaphoreCount(Semaphore), 0);
    NtReleaseSemaphore(Semaphore, 2, NULL);
    ok_int(WaitDepth(Port, 3), 3);
    ok_long(SemaphoreCount(Semaphore), 1);
    Already = 0xCC;
    ok_hex(Associate(Packets[3], Port, Semaphore, &Already), STATUS_SUCCESS);
    ok_int(Already, TRUE);
    ok_long(SemaphoreCount(Semaphore), 0);
    ok_int(Drain(Port), 4);
    NtClose(Semaphore);

    /* Manual-reset event: every packet fires and the event stays set */
    Event = MakeEvent(NotificationEvent, FALSE);
    for (i = 0; i < 3; i++) ok_hex(Associate(Packets[i], Port, Event, &Already), STATUS_SUCCESS);
    NtSetEvent(Event, NULL);
    ok_int(WaitDepth(Port, 3), 3);
    ok_long(EventState(Event), 1);
    ok_int(Drain(Port), 3);
    Already = 0xCC;
    ok_hex(Associate(Packets[0], Port, Event, &Already), STATUS_SUCCESS);
    ok_int(Already, TRUE);
    ok_int(Drain(Port), 1);
    NtClose(Event);

    /* A cancelled packet takes nothing */
    Event = MakeEvent(SynchronizationEvent, FALSE);
    ok_hex(Associate(Packets[0], Port, Event, &Already), STATUS_SUCCESS);
    ok_hex(pCancel(Packets[0], TRUE), STATUS_SUCCESS);
    NtSetEvent(Event, NULL);
    ok_int(SettleDepth(Port), 0);
    ok_long(EventState(Event), 1);
    NtClose(Event);

    /* A pulse satisfies the packets as it satisfies waiting threads */
    Event = MakeEvent(SynchronizationEvent, FALSE);
    ok_hex(Associate(Packets[0], Port, Event, &Already), STATUS_SUCCESS);
    ok_hex(NtPulseEvent(Event, NULL), STATUS_SUCCESS);
    ok_int(WaitDepth(Port, 1), 1);
    ok_long(EventState(Event), 0);
    ok_int(Drain(Port), 1);
    NtClose(Event);
    Event = MakeEvent(NotificationEvent, FALSE);
    ok_hex(Associate(Packets[0], Port, Event, &Already), STATUS_SUCCESS);
    ok_hex(Associate(Packets[1], Port, Event, &Already), STATUS_SUCCESS);
    ok_hex(NtPulseEvent(Event, NULL), STATUS_SUCCESS);
    ok_int(WaitDepth(Port, 2), 2);
    ok_long(EventState(Event), 0);
    ok_int(Drain(Port), 2);
    NtClose(Event);

    /* NtSetEventBoostPriority has no thread to boost: the packet takes the event */
    Event = MakeEvent(SynchronizationEvent, FALSE);
    ok_hex(Associate(Packets[0], Port, Event, &Already), STATUS_SUCCESS);
    ok_hex(NtSetEventBoostPriority(Event), STATUS_SUCCESS);
    ok_int(WaitDepth(Port, 1), 1);
    ok_long(EventState(Event), 0);
    ok_int(Drain(Port), 1);
    NtClose(Event);

    /* Synchronization timer: reset by the packet that fires */
    Status = NtCreateTimer(&Timer, TIMER_ALL_ACCESS, NULL, SynchronizationTimer);
    ok_hex(Status, STATUS_SUCCESS);
    ok_hex(Associate(Packets[0], Port, Timer, &Already), STATUS_SUCCESS);
    Due.QuadPart = -10 * 1000 * 20;
    ok_hex(NtSetTimer(Timer, &Due, NULL, NULL, FALSE, 0, NULL), STATUS_SUCCESS);
    ok_int(WaitDepth(Port, 1), 1);
    {
        TIMER_BASIC_INFORMATION Info;

        Info.SignalState = 0xCC;
        ok_hex(NtQueryTimer(Timer, TimerBasicInformation, &Info, sizeof(Info), NULL), STATUS_SUCCESS);
        ok_int(Info.SignalState, FALSE);
    }
    ok_int(Drain(Port), 1);
    NtClose(Timer);

    for (i = 0; i < 4; i++) NtClose(Packets[i]);
    NtClose(Port);
}

static HANDLE FifoEvent;
static volatile LONG FifoWoken;

static DWORD WINAPI FifoWaiter(LPVOID Parameter)
{
    if (WaitForSingleObject(FifoEvent, 5000) == WAIT_OBJECT_0) InterlockedIncrement(&FifoWoken);
    return 0;
}

/* A packet waits in line with the threads that wait on the object: first come, first served */
static void TestFifo(void)
{
    HANDLE Port = MakePort(), Packet = MakePacket(), Thread;
    LARGE_INTEGER Delay;
    BOOLEAN Already;

    Delay.QuadPart = -10 * 1000 * 200;

    /* The thread first */
    FifoEvent = MakeEvent(SynchronizationEvent, FALSE);
    FifoWoken = 0;
    Thread = CreateThread(NULL, 0, FifoWaiter, NULL, 0, NULL);
    NtDelayExecution(FALSE, &Delay);
    ok_hex(Associate(Packet, Port, FifoEvent, &Already), STATUS_SUCCESS);
    NtSetEvent(FifoEvent, NULL);
    NtDelayExecution(FALSE, &Delay);
    ok_long(FifoWoken, 1);
    ok_int(Depth(Port), 0);
    NtSetEvent(FifoEvent, NULL);
    ok_int(WaitDepth(Port, 1), 1);
    ok_long(EventState(FifoEvent), 0);
    WaitForSingleObject(Thread, 6000);
    CloseHandle(Thread);
    ok_int(Drain(Port), 1);

    /* The packet first */
    FifoWoken = 0;
    ok_hex(Associate(Packet, Port, FifoEvent, &Already), STATUS_SUCCESS);
    Thread = CreateThread(NULL, 0, FifoWaiter, NULL, 0, NULL);
    NtDelayExecution(FALSE, &Delay);
    NtSetEvent(FifoEvent, NULL);
    ok_int(WaitDepth(Port, 1), 1);
    NtDelayExecution(FALSE, &Delay);
    ok_long(FifoWoken, 0);
    NtSetEvent(FifoEvent, NULL);
    WaitForSingleObject(Thread, 6000);
    CloseHandle(Thread);
    ok_long(FifoWoken, 1);
    ok_long(EventState(FifoEvent), 0);
    ok_int(Drain(Port), 1);

    NtClose(FifoEvent);
    NtClose(Packet);
    NtClose(Port);
}

static DWORD WINAPI BlockOn(LPVOID Parameter)
{
    WaitForSingleObject((HANDLE)Parameter, INFINITE);
    return 0;
}

/*
 * An association keeps its target and its port: a thread whose handle was closed still fires the packet when it
 * ends, a port whose handle was closed still gets it; everything is released once the packet is removed or closed.
 */
static void TestReferences(void)
{
    enum { THREADS = 64 };
    HANDLE Port = MakePort(), Go = MakeEvent(NotificationEvent, FALSE), Event = MakeEvent(NotificationEvent, FALSE);
    HANDLE Packets[THREADS], Thread, Port2, Port3, Packet;
    ULONG i, Idle, Count;
    BOOLEAN Already;

    for (i = 0; i < THREADS; i++)
    {
        Packets[i] = MakePacket();
        Thread = CreateThread(NULL, 0, BlockOn, Go, 0, NULL);
        ok(Thread != NULL, "CreateThread failed\n");
        ok_hex(Associate(Packets[i], Port, Thread, &Already), STATUS_SUCCESS);
        CloseHandle(Thread);
    }
    NtSetEvent(Go, NULL);
    ok_int(WaitDepth(Port, THREADS), THREADS);
    ok_int(Drain(Port), THREADS);
    for (i = 0; i < THREADS; i++) NtClose(Packets[i]);

    /* Pointer count of the target: back to what it was once the association is over */
    Idle = PointerCount(Event);
    Packet = MakePacket();
    ok_hex(Associate(Packet, Port, Event, &Already), STATUS_SUCCESS);
    ok(PointerCount(Event) > Idle, "pointer count %lu while associated, %lu idle\n", PointerCount(Event), Idle);
    ok_hex(pCancel(Packet, TRUE), STATUS_SUCCESS);
    ok_long(PointerCount(Event), Idle);
    ok_hex(Associate(Packet, Port, Event, &Already), STATUS_SUCCESS);
    NtSetEvent(Event, NULL);
    ok_int(WaitDepth(Port, 1), 1);
    ok_int(Drain(Port), 1);
    ok_long(PointerCount(Event), Idle);
    NtResetEvent(Event, NULL);

    /* The port handle closed while the packet waits: it is still delivered (to a duplicate handle) */
    Port2 = MakePort();
    ok_hex(NtDuplicateObject(NtCurrentProcess(), Port2, NtCurrentProcess(), &Port3, 0, 0, DUPLICATE_SAME_ACCESS), STATUS_SUCCESS);
    ok_hex(Associate(Packet, Port2, Event, &Already), STATUS_SUCCESS);
    NtClose(Port2);
    NtSetEvent(Event, NULL);
    ok_int(WaitDepth(Port3, 1), 1);
    Count = Drain(Port3);
    ok_int(Count, 1);
    NtClose(Port3);
    NtClose(Port);
    ok_long(PointerCount(Event), Idle);

    NtClose(Packet);
    NtClose(Event);
    NtClose(Go);
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

static DWORD WINAPI ChildThread(LPVOID Parameter)
{
    return 0x600D;
}

/* The child process: one thread and one associated packet that fires; returns the first failure, or 0 */
static NTSTATUS RunChild(void)
{
    HANDLE Port = MakePort(), Event = MakeEvent(SynchronizationEvent, FALSE), Packet = NULL, Thread;
    PVOID Key, Context;
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Timeout;
    BOOLEAN Already = 0xCC;
    DWORD Code = 0;
    NTSTATUS Status;

    Thread = CreateThread(NULL, 0, ChildThread, NULL, 0, NULL);
    if (!Thread) return 0xC1000001;
    WaitForSingleObject(Thread, 10000);
    GetExitCodeThread(Thread, &Code);
    CloseHandle(Thread);
    if (Code != 0x600D) return 0xC1000002;

    Status = pCreate(&Packet, 0x1F0003, NULL);
    if (!NT_SUCCESS(Status)) return Status;
    Status = pAssoc(Packet, Port, Event, TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
    if (!NT_SUCCESS(Status)) return Status;
    if (Already != FALSE) return 0xC1000003;
    NtSetEvent(Event, NULL);
    Timeout.QuadPart = -10 * 1000 * 1000 * 5;
    Status = NtRemoveIoCompletion(Port, &Key, &Context, &Iosb, &Timeout);
    if (Status != STATUS_SUCCESS) return Status ? Status : 0xC1000004;
    if (Key != TARGET_KEY || Context != TARGET_CONTEXT) return 0xC1000005;
    NtClose(Packet);
    NtClose(Port);
    NtClose(Event);
    return STATUS_SUCCESS;
}

/* Runs this test in a child process with RunChild: its result */
static NTSTATUS StartChild(void)
{
    WCHAR FileName[MAX_PATH], CommandLine[MAX_PATH + 64];
    STARTUPINFOW StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    DWORD ExitCode = 0xC1000010;

    GetModuleFileNameW(NULL, FileName, _countof(FileName));
    StringCbPrintfW(CommandLine, sizeof(CommandLine), L"\"%ls\" NtWaitCompletionPacket child", FileName);
    RtlZeroMemory(&StartupInfo, sizeof(StartupInfo));
    StartupInfo.cb = sizeof(StartupInfo);
    if (!CreateProcessW(FileName, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo))
        return 0xC1000011;
    CloseHandle(ProcessInfo.hThread);
    if (WaitForSingleObject(ProcessInfo.hProcess, 60000) != WAIT_OBJECT_0)
    {
        TerminateProcess(ProcessInfo.hProcess, 0xC1000012);
        WaitForSingleObject(ProcessInfo.hProcess, 10000);
    }
    GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
    CloseHandle(ProcessInfo.hProcess);
    return (NTSTATUS)ExitCode;
}

/*
 * A packet costs its object only (no thread): one process associates 10000 packets, each with its own target, with
 * no failure and no new System thread (as on Windows, where 20000 associate); meanwhile another process creates a
 * thread and uses a packet; closing them all gives everything back and a packet can be associated again.
 */
static void TestResources(void)
{
    enum { BOUND = 10000 };
    HANDLE Port = MakePort(), Event = MakeEvent(NotificationEvent, FALSE), Check;
    HANDLE *Packets = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BOUND * sizeof(HANDLE));
    HANDLE *Targets = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, BOUND * sizeof(HANDLE));
    ULONG Before, Peak, After, Count = 0, i;
    LARGE_INTEGER Delay;
    BOOLEAN Already;
    NTSTATUS Status = STATUS_SUCCESS;

    if (!Packets || !Targets)
    {
        skip("no memory for the packet handles\n");
        return;
    }
    Before = SystemThreadCount();
    for (i = 0; i < BOUND; i++)
    {
        Status = NtCreateEvent(&Targets[i], EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
        if (!NT_SUCCESS(Status)) break;
        Status = pCreate(&Packets[i], 0x1F0003, NULL);
        if (!NT_SUCCESS(Status)) break;
        Status = pAssoc(Packets[i], Port, Targets[i], TARGET_KEY, TARGET_CONTEXT, STATUS_SUCCESS, TARGET_INFO, &Already);
        if (!NT_SUCCESS(Status)) break;
        Count++;
    }
    Peak = SystemThreadCount();
    ok(Count == BOUND, "stopped after %lu packets with %08lx\n", Count, Status);
    ok(Peak <= Before + 4, "System threads %lu -> %lu\n", Before, Peak);
    trace("%lu packets associated, last status %08lx, System threads %lu -> %lu\n", Count, Status, Before, Peak);

    /* What this process holds does not stop another one */
    Status = StartChild();
    ok_hex(Status, STATUS_SUCCESS);

    /* The system is fine while they exist */
    Check = MakeEvent(NotificationEvent, TRUE);
    ok(Check != NULL, "cannot create an event\n");
    NtClose(Check);

    /* One target set: its packet alone fires */
    if (Count)
    {
        NtSetEvent(Targets[Count / 2], NULL);
        ok_int(SettleDepth(Port), 1);
    }

    for (i = 0; i < BOUND; i++)
    {
        if (Packets[i]) NtClose(Packets[i]);
        if (Targets[i]) NtClose(Targets[i]);
    }
    ok_int(Depth(Port), 0);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Packets);
    RtlFreeHeap(RtlGetProcessHeap(), 0, Targets);
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

/* Many packets on one object: one signal fires them all (notification) or as many as there are counts (semaphore) */
static void TestManyOnOne(void)
{
    enum { COUNT = 10000 };
    HANDLE Port = MakePort(), Event = MakeEvent(NotificationEvent, FALSE), Semaphore = NULL;
    HANDLE *Packets = RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, COUNT * sizeof(HANDLE));
    ULONG i, Made = 0, EventIdle, SemaphoreIdle;
    BOOLEAN Already;
    NTSTATUS Status;

    if (!Packets)
    {
        skip("no memory for the packet handles\n");
        return;
    }
    ok_hex(NtCreateSemaphore(&Semaphore, SEMAPHORE_ALL_ACCESS, NULL, 0, COUNT), STATUS_SUCCESS);
    EventIdle = PointerCount(Event);
    SemaphoreIdle = PointerCount(Semaphore);

    for (i = 0; i < COUNT; i++)
    {
        Status = pCreate(&Packets[i], 0x1F0003, NULL);
        if (!NT_SUCCESS(Status)) break;
        Status = Associate(Packets[i], Port, Event, &Already);
        if (!NT_SUCCESS(Status)) break;
        Made++;
    }
    ok(Made == COUNT, "%lu packets associated, then %08lx\n", Made, Status);
    NtSetEvent(Event, NULL);
    ok_int(WaitDepth(Port, Made), Made);
    ok_int(Drain(Port), Made);
    ok_long(PointerCount(Event), EventIdle);

    for (i = 0; i < Made; i++) ok_hex(Associate(Packets[i], Port, Semaphore, &Already), STATUS_SUCCESS);
    NtReleaseSemaphore(Semaphore, COUNT / 2, NULL);
    ok_int(WaitDepth(Port, COUNT / 2), COUNT / 2);
    ok_long(SemaphoreCount(Semaphore), 0);
    /* Closing them cancels the waiting half and removes the queued half; nothing more is consumed */
    for (i = 0; i < COUNT; i++)
        if (Packets[i]) NtClose(Packets[i]);
    ok_int(Depth(Port), 0);
    NtReleaseSemaphore(Semaphore, 1, NULL);
    ok_long(SemaphoreCount(Semaphore), 1);
    ok_long(PointerCount(Semaphore), SemaphoreIdle);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Packets);
    NtClose(Semaphore);
    NtClose(Event);
    NtClose(Port);
}

typedef struct _SIGNAL_RACE
{
    HANDLE Port;
    HANDLE Target;
    volatile LONG Stop;
    volatile LONG Removed;
    volatile LONG Released;
} SIGNAL_RACE;

static DWORD WINAPI SignalRaceConsumer(LPVOID Parameter)
{
    SIGNAL_RACE *Race = Parameter;
    PVOID Key, Context;
    IO_STATUS_BLOCK Iosb;
    LARGE_INTEGER Timeout;

    Timeout.QuadPart = -10 * 1000;
    while (!Race->Stop)
        if (NtRemoveIoCompletion(Race->Port, &Key, &Context, &Iosb, &Timeout) == STATUS_SUCCESS)
            InterlockedIncrement(&Race->Removed);
    return 0;
}

static DWORD WINAPI SignalRaceReleaser(LPVOID Parameter)
{
    SIGNAL_RACE *Race = Parameter;

    while (!Race->Stop)
    {
        if (NtReleaseSemaphore(Race->Target, 1, NULL) == STATUS_SUCCESS)
            InterlockedIncrement(&Race->Released);
        if ((Race->Released & 0xFF) == 0) YieldProcessor();
    }
    return 0;
}

static DWORD WINAPI SignalRaceSetter(LPVOID Parameter)
{
    SIGNAL_RACE *Race = Parameter;

    while (!Race->Stop)
        NtSetEvent(Race->Target, NULL);
    return 0;
}

/*
 * Associate, cancel and signal at the same time, on a semaphore that another thread keeps releasing: every count is
 * either taken by exactly one packet that is then removed, or still in the semaphore at the end (a cancelled packet
 * takes nothing, a fired one takes exactly one).
 */
static void TestSignalCancelRace(void)
{
    enum { PACKETS = 4, ROUNDS = 40000 };
    SIGNAL_RACE Race;
    HANDLE Packets[PACKETS], Threads[2];
    ULONG i, Round, Bad = 0, Busy = 0, Pending = 0, Fired = 0, Idle;
    BOOLEAN Already;
    NTSTATUS Status;
    LONG Left;

    RtlZeroMemory(&Race, sizeof(Race));
    Race.Port = MakePort();
    ok_hex(NtCreateSemaphore(&Race.Target, SEMAPHORE_ALL_ACCESS, NULL, 0, MAXLONG), STATUS_SUCCESS);
    Idle = PointerCount(Race.Target);
    for (i = 0; i < PACKETS; i++) Packets[i] = MakePacket();
    Threads[0] = CreateThread(NULL, 0, SignalRaceConsumer, &Race, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, SignalRaceReleaser, &Race, 0, NULL);
    ok(Threads[0] && Threads[1], "CreateThread failed\n");

    for (Round = 0; Round < ROUNDS; Round++)
    {
        HANDLE Packet = Packets[Round % PACKETS];

        Status = Associate(Packet, Race.Port, Race.Target, &Already);
        if (Status == STATUS_INVALID_PARAMETER_1)
        {
            /* still queued: the consumer has not taken it yet */
            Busy++;
            continue;
        }
        if (Status != STATUS_SUCCESS)
        {
            Bad++;
            continue;
        }
        /*
         * Not removing a queued packet: it stays for the consumer, so every fired packet is counted there.
         * STATUS_CANCELLED: it fired and the consumer already took it.
         */
        Status = pCancel(Packet, FALSE);
        if (Status == STATUS_PENDING)
            Pending++;
        else if (Status != STATUS_SUCCESS && Status != STATUS_CANCELLED)
            Bad++;
    }
    Race.Stop = 1;
    WaitForMultipleObjects(2, Threads, TRUE, INFINITE);
    CloseHandle(Threads[0]);
    CloseHandle(Threads[1]);

    /* Whatever still waits takes nothing more once cancelled; whatever fired is in the port */
    for (i = 0; i < PACKETS; i++)
    {
        Status = pCancel(Packets[i], FALSE);
        ok(Status == STATUS_SUCCESS || Status == STATUS_PENDING || Status == STATUS_CANCELLED, "cancel %08lx\n", Status);
    }
    Fired = Race.Removed + Drain(Race.Port);
    Left = SemaphoreCount(Race.Target);
    ok(Bad == 0, "%lu unexpected statuses\n", Bad);
    ok((LONG)Fired + Left == Race.Released, "released %ld, fired %lu, left %ld (pending %lu, busy %lu)\n",
       Race.Released, Fired, Left, Pending, Busy);
    trace("signal race: released %ld, fired %lu, left %ld, pending %lu, busy %lu\n", Race.Released, Fired, Left, Pending, Busy);
    for (i = 0; i < PACKETS; i++) NtClose(Packets[i]);
    ok_long(PointerCount(Race.Target), Idle);
    NtClose(Race.Target);
    NtClose(Race.Port);
}

/*
 * Packets created, associated and closed while another thread keeps setting the target and a third removes from the
 * port; the port handle is closed and replaced now and then. Nothing is left behind: the target's pointer count is
 * back to its start and the last port is empty.
 */
static void TestCloseRace(void)
{
    enum { ROUNDS = 20000 };
    SIGNAL_RACE Race;
    HANDLE Threads[2], Packet, Port;
    ULONG Round, Bad = 0, Idle;
    BOOLEAN Already;
    NTSTATUS Status;

    RtlZeroMemory(&Race, sizeof(Race));
    Race.Port = MakePort();
    Race.Target = MakeEvent(SynchronizationEvent, FALSE);
    Idle = PointerCount(Race.Target);
    Threads[0] = CreateThread(NULL, 0, SignalRaceConsumer, &Race, 0, NULL);
    Threads[1] = CreateThread(NULL, 0, SignalRaceSetter, &Race, 0, NULL);
    ok(Threads[0] && Threads[1], "CreateThread failed\n");

    for (Round = 0; Round < ROUNDS; Round++)
    {
        Status = pCreate(&Packet, 0x1F0003, NULL);
        if (Status != STATUS_SUCCESS)
        {
            Bad++;
            continue;
        }
        if (Round % 1000 == 999)
        {
            /* a packet on a port whose only handle goes away at once */
            Port = MakePort();
            Status = Associate(Packet, Port, Race.Target, &Already);
            NtClose(Port);
        }
        else
        {
            Status = Associate(Packet, Race.Port, Race.Target, &Already);
        }
        if (Status != STATUS_SUCCESS) Bad++;
        if (Round & 1) pCancel(Packet, (Round & 2) != 0);
        NtClose(Packet);
    }
    Race.Stop = 1;
    WaitForMultipleObjects(2, Threads, TRUE, INFINITE);
    CloseHandle(Threads[0]);
    CloseHandle(Threads[1]);
    ok(Bad == 0, "%lu unexpected statuses\n", Bad);
    ok_int(Depth(Race.Port), 0);
    ok_long(PointerCount(Race.Target), Idle);
    trace("close race: %ld packets removed by the consumer\n", Race.Removed);
    NtClose(Race.Target);
    NtClose(Race.Port);
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
    char **argv;
    int argc;

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

    argc = winetest_get_mainargs(&argv);
    if (argc >= 3 && !strcmp(argv[2], "child"))
        ExitProcess(RunChild());

    TestCreate();
    TestLifecycle();
    TestTargets();
    TestHandles();
    TestClose();
    TestNoLeak();
    TestRace();
    TestConsumption();
    TestFifo();
    TestReferences();
    TestManyOnOne();
    TestSignalCancelRace();
    TestCloseRace();
    TestResources();
}
