/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Kernel-Mode Test Suite: a page fault at raised IRQL stops the system (Debug builds)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * Hidden tests: each makes a bad access at an IRQL above APC_LEVEL on purpose and must stop the system at once
 * with IRQL_NOT_LESS_OR_EQUAL (0xA) when the faulting instruction is in the kernel, DRIVER_IRQL_NOT_LESS_OR_EQUAL
 * (0xD1) when it is in a driver (this test driver), parameters (address, IRQL, 0 read / 1 write, instruction).
 * Only Debug builds do it; a Release kernel turns the fault into an exception that the test would have to catch.
 * IRQL values are those of this kernel (SYNCH_LEVEL is DISPATCH_LEVEL on a uniprocessor build, higher on amd64).
 *  -MmIrqlFaultNullDriver:  read of NULL + 0x94 in this driver at SYNCH_LEVEL           -> 0xD1 (0x94, SYNCH_LEVEL, 0, ..)
 *  -MmIrqlFaultNullKernel:  RtlCompareMemory of NULL + 0x94 at DISPATCH_LEVEL (kernel)  -> 0x0A (0x94, 2, 0, ..)
 *  -MmIrqlFaultPagedWrite:  write to freed paged pool at DISPATCH_LEVEL                 -> 0xD1 (addr, 2, 1, ..)
 */

START_TEST(MmIrqlFaultNullDriver)
{
    KIRQL OldIrql;

    KeRaiseIrql(SYNCH_LEVEL, &OldIrql);
    (void)*(volatile UCHAR *)(ULONG_PTR)0x94;
    KeLowerIrql(OldIrql);
    ok(0, "The read of NULL + 0x94 at SYNCH_LEVEL did not stop the system\n");
}

START_TEST(MmIrqlFaultNullKernel)
{
    KIRQL OldIrql;
    UCHAR Other[16] = { 0 };

    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    (void)RtlCompareMemory((PVOID)(ULONG_PTR)0x94, Other, sizeof(Other));
    KeLowerIrql(OldIrql);
    ok(0, "The read of NULL + 0x94 in the kernel at DISPATCH_LEVEL did not stop the system\n");
}

START_TEST(MmIrqlFaultPagedWrite)
{
    PUCHAR Buffer;
    KIRQL OldIrql;

    Buffer = ExAllocatePoolWithTag(PagedPool, 4 * PAGE_SIZE, 'fImK');
    if (skip(Buffer != NULL, "No paged pool\n"))
        return;

    ExFreePoolWithTag(Buffer, 'fImK');
    KeRaiseIrql(DISPATCH_LEVEL, &OldIrql);
    *(volatile UCHAR *)Buffer = 0xF1;
    KeLowerIrql(OldIrql);
    ok(0, "The write to freed paged pool at DISPATCH_LEVEL did not stop the system\n");
}
