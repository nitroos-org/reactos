/*
 * PROJECT:     ReactOS kernel-mode tests
 * LICENSE:     MIT (https://spdx.org/licenses/MIT)
 * PURPOSE:     Kernel-Mode Test Suite test for the report of an unexplained kernel #GP (amd64)
 * COPYRIGHT:   Copyright 2026 Tomas Srnka <tomas.srnka@e2b.dev>
 */

#include <kmt_test.h>

/*
 * A read from a non-canonical address in kernel mode is a #GP the trap handler does not explain. It is
 * dispatched as an exception, which a handler here catches; the trap prints its report (KE-GP: lines with
 * RIP, error code, registers and instruction bytes) on the debug port first: check them in the debug log.
 * Hidden from the test list (run it by name): on a checked build the handler's assertion stops in the
 * debugger before the exception is dispatched.
 *
 * The reports are limited in number. A handler that catches the same fault over and over must not use them
 * up: the first site is read many times (one report in the log), then a second site is read (its report must
 * still be there). The debug log of this test holds "KE-GP: unexplained" lines for the two sites and no
 * "no more reports" line.
 */

#define SAME_SITE_READS 40

#ifdef _M_AMD64
static
NTSTATUS
ReadNonCanonicalFirst(VOID)
{
    volatile ULONG *NonCanonical = (volatile ULONG *)0x8000000000000040ULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Value = 0;

    _SEH2_TRY
    {
        Value = *NonCanonical;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    ok(!NT_SUCCESS(Status), "No exception for a non-canonical read (value %lx)\n", Value);
    return Status;
}

static
NTSTATUS
ReadNonCanonicalSecond(VOID)
{
    volatile ULONG64 *NonCanonical = (volatile ULONG64 *)0x8000000000000080ULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG64 Value = 0;

    _SEH2_TRY
    {
        Value = *NonCanonical;
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    ok(!NT_SUCCESS(Status), "No exception for a second non-canonical read (value %I64x)\n", Value);
    return Status;
}
#endif

START_TEST(KeGeneralProtection)
{
#ifdef _M_AMD64
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG i;

    DbgPrint("KeGeneralProtection: reading a non-canonical address %u times, expecting one set of KE-GP lines\n",
             SAME_SITE_READS);
    for (i = 0; i < SAME_SITE_READS; i++)
        Status = ReadNonCanonicalFirst();
    trace("Exception 0x%lx\n", Status);
    DbgPrint("KeGeneralProtection: exception 0x%lx\n", Status);

    DbgPrint("KeGeneralProtection: a second site, expecting KE-GP lines for it too\n");
    Status = ReadNonCanonicalSecond();
    DbgPrint("KeGeneralProtection: second exception 0x%lx\n", Status);
#else
    skip(FALSE, "amd64 only\n");
#endif
}
