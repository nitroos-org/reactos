/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Kernel-Mode Test Suite for symbol load reports while another processor uses the loaded module list
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

/*
 * A symbol load report enters the kernel debugger, which freezes the other
 * processors and looks the image up in the loaded module list. A processor
 * that is frozen while it holds the list's lock (RtlPcToFileHeader takes it
 * for every call) must not keep the debugger waiting for good: both
 * processors then spin forever. Here a thread on one processor calls
 * RtlPcToFileHeader without a pause while a thread on the other sends load
 * reports for an address that is in no image (the debugger walks the whole
 * list and finds nothing, so the reports change nothing). Before the
 * debugger stopped waiting for the lock in that state, this hung the machine
 * at the first reports.
 */

#include <kmt_test.h>
#include <ndk/rtlfuncs.h>

#define REPORTS 800
#define LIMIT_MS 60000

#ifdef _M_AMD64
NTSYSAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue, _Out_ PVOID *BaseOfImage);

static volatile LONG StopHammer;
static volatile LONG HammerCalls;
static PVOID FakeImage;
static LONG ReportsSent;

static
VOID
NTAPI
HammerThread(
    _In_ PVOID Context)
{
    ULONGLONG End = KeQueryInterruptTime() + LIMIT_MS * 10000ULL;
    PVOID Base;

    UNREFERENCED_PARAMETER(Context);

    /* Processor 1, above the other threads there, so it keeps taking the lock */
    KeSetSystemAffinityThread((KAFFINITY)2);
    KeSetPriorityThread(KeGetCurrentThread(), HIGH_PRIORITY - 1);

    while (!StopHammer && (KeQueryInterruptTime() < End))
    {
        RtlPcToFileHeader((PVOID)HammerThread, &Base);
        InterlockedIncrement(&HammerCalls);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
VOID
NTAPI
ReportThread(
    _In_ PVOID Context)
{
    ULONGLONG End = KeQueryInterruptTime() + LIMIT_MS * 10000ULL;
    STRING Name;
    LONG i;

    UNREFERENCED_PARAMETER(Context);

    /* Processor 0 */
    KeSetSystemAffinityThread((KAFFINITY)1);

    /* Wait until the other processor uses the lock */
    while (!HammerCalls && (KeQueryInterruptTime() < End))
        YieldProcessor();

    RtlInitString(&Name, "kmtest-no-such-image.sys");
    for (i = 0; i < REPORTS; i++)
    {
        DbgLoadImageSymbols(&Name, FakeImage, (ULONG_PTR)-1);
        ReportsSent++;
    }

    InterlockedExchange(&StopHammer, 1);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static
PVOID
StartThread(
    _In_ PKSTART_ROUTINE Routine)
{
    HANDLE Handle;
    PVOID Thread = NULL;
    NTSTATUS Status;

    /* System threads: the debugger then has no user-mode module list to look at */
    Status = PsCreateSystemThread(&Handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, Routine, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    if (!NT_SUCCESS(Status))
        return NULL;
    Status = ObReferenceObjectByHandle(Handle, SYNCHRONIZE, *PsThreadType, KernelMode, &Thread, NULL);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ZwClose(Handle);
    return NT_SUCCESS(Status) ? Thread : NULL;
}

static
VOID
WaitThread(
    _In_opt_ PVOID Thread)
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    if (!Thread)
        return;
    Timeout.QuadPart = -10000LL * (LIMIT_MS + 10000);
    Status = KeWaitForSingleObject(Thread, Executive, KernelMode, FALSE, &Timeout);
    ok_eq_hex(Status, STATUS_SUCCESS);
    ObDereferenceObject(Thread);
}
#endif

START_TEST(KdLoadSymbolsFrozen)
{
#ifdef _M_AMD64
    PVOID Hammer, Reporter;

    if (!KD_DEBUGGER_ENABLED || KD_DEBUGGER_NOT_PRESENT)
    {
        skip(FALSE, "No kernel debugger: symbol load reports do not enter it\n");
        return;
    }
    if (KeNumberProcessors < 2)
    {
        skip(FALSE, "Needs two processors, %u present\n", (ULONG)KeNumberProcessors);
        return;
    }

    /* An address in no image: zeroed pool has no image header */
    FakeImage = ExAllocatePoolZero(NonPagedPool, PAGE_SIZE, 'sLdK');
    if (!FakeImage)
    {
        skip(FALSE, "Out of memory\n");
        return;
    }

    StopHammer = 0;
    HammerCalls = 0;
    ReportsSent = 0;

    Hammer = StartThread(HammerThread);
    Reporter = StartThread(ReportThread);
    WaitThread(Reporter);
    InterlockedExchange(&StopHammer, 1);
    WaitThread(Hammer);

    ok_eq_long(ReportsSent, REPORTS);
    ok(HammerCalls > 0, "The other processor never took the lock\n");
    trace("%ld load reports while the other processor made %ld RtlPcToFileHeader calls\n",
          ReportsSent, HammerCalls);

    ExFreePoolWithTag(FakeImage, 'sLdK');
#else
    skip(FALSE, "The lock is taken by stack captures on amd64 only\n");
#endif
}
