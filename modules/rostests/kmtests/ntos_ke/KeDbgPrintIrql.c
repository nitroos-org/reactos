/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite test of the IRQL after DbgPrint when processors print at once
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * DbgPrint enters the kernel debugger (on a system with a debugger or the checked kernel's own: KDBG), which freezes the
 * other processors, raises to HIGH_LEVEL and goes back to the IRQL of the caller when it is done. With processors that
 * print from different IRQLs at once the one that leaves the debugger must go back to the IRQL it had, not to the one
 * of the processor that entered after it. A checked kernel stops in the trap exit (an assertion) when it does not.
 * One thread per processor, bound to it, prints in a loop at PASSIVE_LEVEL, APC_LEVEL or DISPATCH_LEVEL, one after
 * the other, and checks the IRQL after each print.
 */

#define TEST_SECONDS 10
#define TEST_PRIORITY (LOW_REALTIME_PRIORITY + 2)

typedef struct _PRINT_THREAD
{
    HANDLE Handle;
    ULONG Processor;
    ULONG Prints;
    ULONG Wrong;
    KIRQL FirstWrong;
    KIRQL FirstExpected;
} PRINT_THREAD, *PPRINT_THREAD;

static KEVENT StartEvent;
static ULONGLONG StopTime;

static
VOID
NTAPI
PrintThread(
    _In_ PVOID Context)
{
    PPRINT_THREAD Thread = Context;
    static const KIRQL Levels[] = { PASSIVE_LEVEL, APC_LEVEL, DISPATCH_LEVEL };
    KIRQL OldIrql, Expected, After;
    ULONG Round = Thread->Processor;

    KeSetPriorityThread(KeGetCurrentThread(), TEST_PRIORITY);
    KeSetSystemAffinityThread((KAFFINITY)1 << Thread->Processor);
    KeWaitForSingleObject(&StartEvent, Executive, KernelMode, FALSE, NULL);

    while ((ULONGLONG)KeQueryInterruptTime() < StopTime)
    {
        Expected = Levels[Round++ % RTL_NUMBER_OF(Levels)];
        if (Expected != PASSIVE_LEVEL)
            KeRaiseIrql(Expected, &OldIrql);

        DbgPrint("KeDbgPrintIrql: processor %lu at %u\n", Thread->Processor, Expected);
        After = KeGetCurrentIrql();
        if (After != Expected)
        {
            if (!Thread->Wrong++)
            {
                Thread->FirstWrong = After;
                Thread->FirstExpected = Expected;
            }
            /* Leave the IRQL the thread started with, whatever the print did to it */
            if (After > Expected)
            {
                KeLowerIrql(Expected);
            }
        }
        Thread->Prints++;

        if (Expected != PASSIVE_LEVEL)
            KeLowerIrql(OldIrql);
    }

    KeRevertToUserAffinityThread();
    PsTerminateSystemThread(STATUS_SUCCESS);
}

START_TEST(KeDbgPrintIrql)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PPRINT_THREAD Threads;
    ULONG ThreadCount, Created, i, Prints = 0, Wrong = 0;

    if (skip(KeNumberProcessors >= 2, "Needs at least two processors\n"))
        return;

    ThreadCount = KeNumberProcessors;
    Threads = ExAllocatePoolWithTag(NonPagedPool, ThreadCount * sizeof(*Threads), 'pDKT');
    if (skip(Threads != NULL, "Out of memory\n"))
        return;
    RtlZeroMemory(Threads, ThreadCount * sizeof(*Threads));

    KeInitializeEvent(&StartEvent, NotificationEvent, FALSE);
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    for (Created = 0; Created < ThreadCount; Created++)
    {
        Threads[Created].Processor = Created;
        Status = PsCreateSystemThread(&Threads[Created].Handle, SYNCHRONIZE, &ObjectAttributes,
                                      NULL, NULL, PrintThread, &Threads[Created]);
        ok_eq_hex(Status, STATUS_SUCCESS);
        if (!NT_SUCCESS(Status))
            break;
    }

    StopTime = KeQueryInterruptTime() + TEST_SECONDS * 10000000ULL;
    KeSetEvent(&StartEvent, IO_NO_INCREMENT, FALSE);

    for (i = 0; i < Created; i++)
    {
        /* The threads use this driver's code and data: wait for all of them */
        Status = ZwWaitForSingleObject(Threads[i].Handle, FALSE, NULL);
        ok_eq_hex(Status, STATUS_SUCCESS);
        ZwClose(Threads[i].Handle);

        Prints += Threads[i].Prints;
        Wrong += Threads[i].Wrong;
        ok(Threads[i].Wrong == 0, "Processor %lu: IRQL %u after DbgPrint at %u (%lu times of %lu)\n",
           Threads[i].Processor, Threads[i].FirstWrong, Threads[i].FirstExpected, Threads[i].Wrong, Threads[i].Prints);
    }

    trace("%lu threads, %lu prints, %lu with another IRQL afterwards\n", Created, Prints, Wrong);
    ok(Prints != 0, "Nothing was printed\n");

    ExFreePoolWithTag(Threads, 'pDKT');
}
