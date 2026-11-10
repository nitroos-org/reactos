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
 */

START_TEST(KeGeneralProtection)
{
#ifdef _M_AMD64
    volatile ULONG *NonCanonical = (volatile ULONG *)0x8000000000000040ULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG Value = 0;

    DbgPrint("KeGeneralProtection: reading %p, expecting KE-GP lines\n", (PVOID)NonCanonical);
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
    trace("Exception 0x%lx\n", Status);
    DbgPrint("KeGeneralProtection: exception 0x%lx\n", Status);
#else
    skip(FALSE, "amd64 only\n");
#endif
}
